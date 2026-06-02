// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// ============================================================================
// INTERFACCE
// ============================================================================

interface IIdentityRegistry {
    enum Role    { PA, PP, DEG, AUDITOR, AA, EV }
    enum Domain  { NETWORK, SYSTEM, APPLICATION }
    enum DIDType { ANYWISE, PAIRWISE }

    struct DIDDocument {
        address  owner;
        bytes    publicKey;
        bool     active;
        DIDType  didType;
        Role     role;
        Domain[] scope;
        uint256  registeredAt;
        uint256  updatedAt;
        string   registeredBy;
        uint256  expiresAt;
    }

    function isActive(string calldata did) external view returns (bool);
    function getDIDByAddress(address owner) external view returns (string memory);
    function resolve(string calldata did) external view returns (DIDDocument memory);
}

interface ICredentialValidationContract {
    function consumeValidation(
        bytes32 validationId,
        string  calldata expectedDID,
        uint8   expectedRole,
        uint8   expectedDomain
    ) external returns (bool);
}

// ============================================================================
// CONTRATTO
// ============================================================================

/**
 * @title  PolicyRegistry
 * @notice Registro permanente delle Logging Security Policy del consorzio.
 *
 * @dev    Macchina a stati: Active → Archived (atomica con nuova Active) → Retired
 *         confirmEnforcement richiede validationId del CVC — l'AA presenta VP
 *         con la propria TemporaryVC prima di confermare l'enforcement (WP2 §4.3.4).
 */
contract PolicyRegistry {

    // =========================================================================
    // TIPI
    // =========================================================================

    enum PolicyStatus { Active, Archived, Retired }

    struct PolicyRecord {
        bytes32      proposalId;
        string       cid;
        string       cidKeyDistrib;
        uint8        domain;
        uint32       version;
        PolicyStatus status;
        uint256      certifiedAt;
        uint256      updatedAt;
    }

    struct EnforcementRecord {
        string  aaDID;
        string  appliedCid;
        uint256 confirmedAt;
    }

    // =========================================================================
    // STORAGE
    // =========================================================================

    IIdentityRegistry             private _identityRegistry;
    ICredentialValidationContract private _cvc;
    address                       private _governanceContract;

    mapping(bytes32 => PolicyRecord)        private _policies;
    mapping(uint8   => bytes32)             private _activeByDomain;
    mapping(uint8   => bytes32[])           private _historyByDomain;
    mapping(uint8   => uint32)              private _currentVersion;
    mapping(uint8   => string)              private _safeDefaults;
    mapping(bytes32 => EnforcementRecord[]) private _enforcements;

    address private _deployer;
    bool    private _bootstrapComplete;

    // =========================================================================
    // EVENTI
    // =========================================================================

    event PolicyCertified(bytes32 indexed proposalId, uint8 domain, uint32 version, string cid, string cidKeyDistrib, bytes32 archivedProposalId, uint256 timestamp);
    event PolicyRetired(bytes32 indexed proposalId, uint8 domain, uint32 version, string safeDefaultCid, uint256 timestamp);
    event KeyDistribUpdated(bytes32 indexed proposalId, string updatedByDID, string newCidKeyDistrib, uint256 timestamp);
    event EnforcementConfirmed(bytes32 indexed proposalId, string aaDID, string appliedCid, uint256 timestamp);
    event SafeDefaultUpdated(uint8 domain, string newSafeDefaultCid, uint256 timestamp);
    event BootstrapFinalized(address indexed deployer, address identityRegistry, address governanceContract, uint256 timestamp);
    event IdentityRegistrySet(address indexed registry, uint256 timestamp);
    event GovernanceContractSet(address indexed governance, uint256 timestamp);
    event CVCSet(address indexed cvc, uint256 timestamp);

    // =========================================================================
    // ERRORI
    // =========================================================================

    error BootstrapAlreadyComplete();
    error BootstrapNotComplete();
    error NotAuthorized(string reason);
    error InvalidInput(string reason);
    error PolicyNotFound(bytes32 proposalId);
    error PolicyNotActive(bytes32 proposalId);
    error DomainHasNoActivePolicy(uint8 domain);
    error SafeDefaultRequired(uint8 domain);
    error ProposalIdAlreadyUsed(bytes32 proposalId);
    error DomainInvalid(uint8 domain);

    constructor() { _deployer = msg.sender; }

    // =========================================================================
    // MODIFIER
    // =========================================================================

    modifier onlyBootstrap() {
        if (_bootstrapComplete)      revert BootstrapAlreadyComplete();
        if (msg.sender != _deployer) revert NotAuthorized("Solo il deployer durante il bootstrap");
        _;
    }

    modifier onlyPostBootstrap() {
        if (!_bootstrapComplete) revert BootstrapNotComplete();
        _;
    }

    modifier onlyGovernance() {
        if (msg.sender != _governanceContract)
            revert NotAuthorized("Solo il GovernanceContract");
        _;
    }

    modifier onlyActivePA() {
        _requireCallerRole(IIdentityRegistry.Role.PA);
        _;
    }

    modifier onlyActiveAA() {
        _requireCallerRole(IIdentityRegistry.Role.AA);
        _;
    }

    // =========================================================================
    // BOOTSTRAP
    // =========================================================================

    function setIdentityRegistry(address registry) external onlyBootstrap {
        if (registry == address(0)) revert InvalidInput("Indirizzo non valido");
        _identityRegistry = IIdentityRegistry(registry);
        emit IdentityRegistrySet(registry, block.timestamp);
    }

    function setGovernanceContract(address governance) external onlyBootstrap {
        if (governance == address(0)) revert InvalidInput("Indirizzo non valido");
        _governanceContract = governance;
        emit GovernanceContractSet(governance, block.timestamp);
    }

    function setCVC(address cvc) external onlyBootstrap {
        if (cvc == address(0)) revert InvalidInput("Indirizzo non valido");
        _cvc = ICredentialValidationContract(cvc);
        emit CVCSet(cvc, block.timestamp);
    }

    function finalizeBootstrap() external onlyBootstrap {
        if (address(_identityRegistry) == address(0)) revert InvalidInput("IdentityRegistry non impostato");
        if (_governanceContract == address(0))        revert InvalidInput("GovernanceContract non impostato");
        if (address(_cvc) == address(0))              revert InvalidInput("CVC non impostato");

        _bootstrapComplete = true;
        emit BootstrapFinalized(_deployer, address(_identityRegistry), _governanceContract, block.timestamp);
    }

    // =========================================================================
    // CICLO DI VITA DELLE POLICY — solo GovernanceContract
    // =========================================================================

    function certifyPolicy(
        bytes32         proposalId,
        string calldata cid,
        string calldata cidKeyDistrib,
        uint8           domain,
        uint32          version,
        string calldata safeDefaultCid
    ) external onlyPostBootstrap onlyGovernance {
        if (proposalId == bytes32(0))                       revert InvalidInput("proposalId non valido");
        if (_policies[proposalId].proposalId != bytes32(0)) revert ProposalIdAlreadyUsed(proposalId);
        if (bytes(cid).length == 0)                         revert InvalidInput("CID non valido");
        if (bytes(cidKeyDistrib).length == 0)               revert InvalidInput("CID key distribution non valido");
        if (domain > 2)                                     revert DomainInvalid(domain);
        if (version == 0)                                   revert InvalidInput("version deve essere >= 1");

        if (bytes(_safeDefaults[domain]).length == 0) {
            if (bytes(safeDefaultCid).length == 0) revert SafeDefaultRequired(domain);
            _safeDefaults[domain] = safeDefaultCid;
        }

        bytes32 archivedId    = bytes32(0);
        bytes32 currentActive = _activeByDomain[domain];
        if (currentActive != bytes32(0)) {
            _policies[currentActive].status    = PolicyStatus.Archived;
            _policies[currentActive].updatedAt = block.timestamp;
            archivedId = currentActive;
        }

        _policies[proposalId] = PolicyRecord({
            proposalId:    proposalId,
            cid:           cid,
            cidKeyDistrib: cidKeyDistrib,
            domain:        domain,
            version:       version,
            status:        PolicyStatus.Active,
            certifiedAt:   block.timestamp,
            updatedAt:     block.timestamp
        });

        _activeByDomain[domain] = proposalId;
        _currentVersion[domain] = version;
        _historyByDomain[domain].push(proposalId);

        emit PolicyCertified(proposalId, domain, version, cid, cidKeyDistrib, archivedId, block.timestamp);
    }

    function retirePolicy(bytes32 proposalId) external onlyPostBootstrap onlyGovernance {
        PolicyRecord storage record = _policies[proposalId];
        if (record.proposalId == bytes32(0))      revert PolicyNotFound(proposalId);
        if (record.status != PolicyStatus.Active) revert PolicyNotActive(proposalId);

        uint8 domain = record.domain;
        if (bytes(_safeDefaults[domain]).length == 0) revert SafeDefaultRequired(domain);
        if (_activeByDomain[domain] != proposalId)    revert PolicyNotActive(proposalId);

        record.status    = PolicyStatus.Retired;
        record.updatedAt = block.timestamp;
        _activeByDomain[domain] = bytes32(0);

        emit PolicyRetired(proposalId, domain, record.version, _safeDefaults[domain], block.timestamp);
    }

    function updateSafeDefault(uint8 domain, string calldata newSafeDefaultCid)
        external onlyPostBootstrap onlyGovernance
    {
        if (domain > 2)                           revert DomainInvalid(domain);
        if (bytes(newSafeDefaultCid).length == 0) revert InvalidInput("CID safe default non valido");
        if (bytes(_safeDefaults[domain]).length == 0)
            revert InvalidInput("Safe default non dichiarato: usare certifyPolicy per la prima dichiarazione");

        _safeDefaults[domain] = newSafeDefaultCid;
        emit SafeDefaultUpdated(domain, newSafeDefaultCid, block.timestamp);
    }

    // =========================================================================
    // KEY DISTRIBUTION DOCUMENT — qualsiasi PA attiva
    // =========================================================================

    function updateKeyDistrib(bytes32 proposalId, string calldata newCidKeyDistrib)
        external onlyPostBootstrap onlyActivePA
    {
        if (bytes(newCidKeyDistrib).length == 0) revert InvalidInput("CID key distribution non valido");

        PolicyRecord storage record = _policies[proposalId];
        if (record.proposalId == bytes32(0)) revert PolicyNotFound(proposalId);

        string memory callerDID = _identityRegistry.getDIDByAddress(msg.sender);
        record.cidKeyDistrib = newCidKeyDistrib;
        record.updatedAt     = block.timestamp;

        emit KeyDistribUpdated(proposalId, callerDID, newCidKeyDistrib, block.timestamp);
    }

    // =========================================================================
    // CONFERMA ENFORCEMENT — AA attivo con validationId (WP2 §4.3.4)
    // L'AA presenta VP con TemporaryVC prima di chiamare questa funzione.
    // Il validationId viene consumato dal CVC — protezione anti-replay.
    // =========================================================================

    function confirmEnforcement(
        bytes32 proposalId,
        string  calldata appliedCid,
        bytes32 validationId
    ) external onlyPostBootstrap onlyActiveAA {
        if (bytes(appliedCid).length == 0) revert InvalidInput("CID applicato non valido");

        PolicyRecord storage record = _policies[proposalId];
        if (record.proposalId == bytes32(0)) revert PolicyNotFound(proposalId);

        string memory aaDID = _identityRegistry.getDIDByAddress(msg.sender);

        // Verifica e consuma il validationId della VP dell'AA
        bool valid = _cvc.consumeValidation(
            validationId,
            aaDID,
            uint8(IIdentityRegistry.Role.AA),
            record.domain
        );
        if (!valid) revert NotAuthorized("Validazione non riuscita");

        _enforcements[proposalId].push(EnforcementRecord({
            aaDID:       aaDID,
            appliedCid:  appliedCid,
            confirmedAt: block.timestamp
        }));

        emit EnforcementConfirmed(proposalId, aaDID, appliedCid, block.timestamp);
    }

    // =========================================================================
    // VIEW
    // =========================================================================

    function getCurrentVersion(uint8 domain) external view onlyPostBootstrap returns (uint32) {
        return _currentVersion[domain];
    }

    function hasSafeDefault(uint8 domain) external view onlyPostBootstrap returns (bool) {
        return bytes(_safeDefaults[domain]).length > 0;
    }

    function getSafeDefault(uint8 domain) external view onlyPostBootstrap returns (string memory) {
        return _safeDefaults[domain];
    }

    function getPolicy(bytes32 proposalId) external view onlyPostBootstrap returns (PolicyRecord memory) {
        if (_policies[proposalId].proposalId == bytes32(0)) revert PolicyNotFound(proposalId);
        return _policies[proposalId];
    }

    function getActivePolicy(uint8 domain) external view onlyPostBootstrap returns (bytes32) {
        return _activeByDomain[domain];
    }

    function getActivePolicyRecord(uint8 domain) external view onlyPostBootstrap returns (PolicyRecord memory) {
        bytes32 activeId = _activeByDomain[domain];
        if (activeId == bytes32(0)) revert DomainHasNoActivePolicy(domain);
        return _policies[activeId];
    }

    function getDomainHistory(uint8 domain) external view onlyPostBootstrap returns (bytes32[] memory) {
        return _historyByDomain[domain];
    }

    function getEnforcements(bytes32 proposalId) external view onlyPostBootstrap returns (EnforcementRecord[] memory) {
        return _enforcements[proposalId];
    }

    function isBootstrapComplete()  external view returns (bool)    { return _bootstrapComplete; }
    function getIdentityRegistry()  external view returns (address) { return address(_identityRegistry); }
    function getGovernanceContract() external view returns (address) { return _governanceContract; }
    function getCVC()               external view returns (address) { return address(_cvc); }

    // =========================================================================
    // INTERNE
    // =========================================================================

    function _requireCallerRole(IIdentityRegistry.Role expectedRole) internal view returns (string memory callerDID) {
        callerDID = _identityRegistry.getDIDByAddress(msg.sender);
        if (bytes(callerDID).length == 0) revert NotAuthorized("Chiamante non registrato");

        IIdentityRegistry.DIDDocument memory doc = _identityRegistry.resolve(callerDID);
        if (doc.role != expectedRole)
            revert NotAuthorized("Ruolo non autorizzato");
        if (!doc.active || (doc.expiresAt > 0 && block.timestamp > doc.expiresAt))
            revert NotAuthorized("DID revocato o scaduto");
    }
}
