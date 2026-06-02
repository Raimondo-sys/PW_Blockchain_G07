// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title  IdentityRegistry
 * @notice Registro DID del consorzio. Fonte di verità per identità e ruoli.
 *         publicKey contiene la chiave RSA pubblica PEM dell'entità (per JWT RS256).
 *
 * @dev    Bootstrap: setGovernanceContract → registerPA(×4) → registerAuditor(×2) → finalizeBootstrap
 *         Revoca lazy cascade: revocare un DID invalida tutte le VC emesse da quell'issuer.
 *         Sostituzione atomica PA: replacePAByGovernance mantiene _activePACount stabile.
 *         Auditor: registrati con credentialId per tracciare formalmente la nomina tramite VC.
 */
contract IdentityRegistry {

    enum DIDType { ANYWISE, PAIRWISE }
    enum Role    { PA, PP, DEG, AUDITOR, AA, EV }
    enum Domain  { NETWORK, SYSTEM, APPLICATION }

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

    mapping(string  => DIDDocument) private _dids;
    mapping(address => string)      private _ownerToDID;
    mapping(bytes32 => bool)        private _revokedCredentials;
    mapping(bytes32 => string)      private _credentialIssuers;

    uint256 private _activePACount;
    uint256 private _activeAuditorCount;
    address private _governanceContract;
    address private _deployer;
    bool    private _bootstrapComplete;

    event DIDRegistered(address indexed owner, string did, Role role, string registeredBy, uint256 timestamp);
    event DIDRevoked(address indexed owner, string did, uint256 timestamp);
    event KeyRotated(address indexed owner, string did, uint256 timestamp);
    event CredentialRevoked(bytes32 indexed credentialId, string revokedByDID, uint256 timestamp);
    event BootstrapFinalized(address indexed deployer, uint256 paCount, uint256 auditorCount, uint256 timestamp);
    event GovernanceContractSet(address indexed governance, uint256 timestamp);

    error DIDAlreadyExists(string did);
    error DIDNotFound(string did);
    error DIDNotActive(string did);
    error NotOwner(address caller);
    error NotAuthorized(string reason);
    error BootstrapAlreadyComplete();
    error BootstrapNotComplete();
    error InvalidInput(string reason);
    error CredentialAlreadyRevoked(bytes32 credentialId);
    error OwnerAlreadyRegistered(address owner);
    error InvalidScope(string reason);

    constructor() { _deployer = msg.sender; }

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
            revert NotAuthorized("Solo GovernanceContract");
        _;
    }

    modifier onlyActiveDID(string calldata did) {
        if (_dids[did].owner == address(0)) revert DIDNotFound(did);
        if (!_dids[did].active)             revert DIDNotActive(did);
        if (_dids[did].expiresAt > 0 && block.timestamp > _dids[did].expiresAt)
            revert DIDNotActive(did);
        _;
    }

    // =========================================================================
    // BOOTSTRAP
    // =========================================================================

    function setGovernanceContract(address governance) external onlyBootstrap {
        if (governance == address(0)) revert InvalidInput("Indirizzo non valido");
        _governanceContract = governance;
        emit GovernanceContractSet(governance, block.timestamp);
    }

    function registerPA(string calldata did, bytes calldata publicKey, address owner)
        external onlyBootstrap
    {
        _registerPA(did, publicKey, owner, "genesis");
    }

    /**
     * @notice Registra un Auditor durante il bootstrap.
     * @param credentialId ID della PersistentVC emessa dalla PA all'Auditor — traccia
     *                     formalmente la nomina on-chain. Passare bytes32(0) se non disponibile.
     */
    function registerAuditor(
        string calldata did,
        bytes  calldata publicKey,
        address         owner,
        bytes32         credentialId
    ) external onlyBootstrap {
        _registerAuditor(did, publicKey, owner, "genesis");
        if (credentialId != bytes32(0))
            _credentialIssuers[credentialId] = "genesis";
    }

    function finalizeBootstrap() external onlyBootstrap {
        if (_activePACount < 4)
            revert InvalidInput("Minimo 4 PA richieste");
        if (_activeAuditorCount < 2)
            revert InvalidInput("Minimo 2 Auditor richiesti");
        if (_governanceContract == address(0))
            revert InvalidInput("GovernanceContract non impostato");
        _bootstrapComplete = true;
        emit BootstrapFinalized(_deployer, _activePACount, _activeAuditorCount, block.timestamp);
    }

    // =========================================================================
    // REGISTRAZIONE DELEGATA
    // =========================================================================

    function registerDelegated(
        string   calldata did,
        bytes    calldata publicKey,
        address           owner,
        Role              role,
        uint256           expiresAt,
        Domain[] calldata scope,
        bytes32           credentialId
    ) external onlyPostBootstrap {
        if (bytes(did).length == 0)               revert InvalidInput("DID vuoto");
        if (publicKey.length == 0)                revert InvalidInput("Chiave pubblica vuota");
        if (owner == address(0))                  revert InvalidInput("Owner non valido");
        if (_dids[did].owner != address(0))       revert DIDAlreadyExists(did);
        if (bytes(_ownerToDID[owner]).length > 0) revert OwnerAlreadyRegistered(owner);
        if (credentialId == bytes32(0))           revert InvalidInput("credentialId zero non ammesso");
        if (bytes(_credentialIssuers[credentialId]).length != 0)
            revert InvalidInput("credentialId gia registrato");

        string memory callerDID = _ownerToDID[msg.sender];
        if (bytes(callerDID).length == 0) revert NotAuthorized("Chiamante non registrato");

        DIDDocument storage caller = _dids[callerDID];
        if (!caller.active || (caller.expiresAt > 0 && block.timestamp > caller.expiresAt))
            revert DIDNotActive(callerDID);

        _checkDelegationAuthorization(caller.role, role, scope);

        DIDType dtype;
        if (role == Role.AA || role == Role.EV) {
            dtype = DIDType.PAIRWISE;
            if (expiresAt == 0 || expiresAt <= block.timestamp)
                revert InvalidInput("AA e EV richiedono scadenza futura");
        } else {
            dtype = DIDType.ANYWISE;
            if (expiresAt != 0) revert InvalidInput("PP e DEG non possono avere scadenza");
        }

        _dids[did] = DIDDocument({
            owner:        owner,
            publicKey:    publicKey,
            active:       true,
            didType:      dtype,
            role:         role,
            scope:        scope,
            registeredAt: block.timestamp,
            updatedAt:    block.timestamp,
            registeredBy: callerDID,
            expiresAt:    expiresAt
        });

        _ownerToDID[owner]               = did;
        _credentialIssuers[credentialId] = callerDID;
        emit DIDRegistered(owner, did, role, callerDID, block.timestamp);
    }

    function registerNewPA(string calldata did, bytes calldata publicKey, address owner)
        external onlyPostBootstrap onlyGovernance
    {
        _registerPA(did, publicKey, owner, "governance");
    }

    function registerNewAuditor(string calldata did, bytes calldata publicKey, address owner)
        external onlyPostBootstrap onlyGovernance
    {
        _registerAuditor(did, publicKey, owner, "governance");
    }

    // =========================================================================
    // ROTAZIONE CHIAVE
    // =========================================================================

    function rotateKey(string calldata did, bytes calldata newPublicKey)
        external onlyPostBootstrap onlyActiveDID(did)
    {
        if (_dids[did].owner != msg.sender) revert NotOwner(msg.sender);
        if (newPublicKey.length == 0)       revert InvalidInput("Chiave vuota");
        if (keccak256(_dids[did].publicKey) == keccak256(newPublicKey))
            revert InvalidInput("Chiave identica alla precedente");
        _dids[did].publicKey = newPublicKey;
        _dids[did].updatedAt = block.timestamp;
        emit KeyRotated(msg.sender, did, block.timestamp);
    }

    // =========================================================================
    // REVOCA
    // =========================================================================

    function revokeDID(string calldata did) external onlyPostBootstrap {
        DIDDocument storage doc = _dids[did];
        if (doc.owner == address(0)) revert DIDNotFound(did);
        if (!doc.active)             revert DIDNotActive(did);
        if (doc.role == Role.PA || doc.role == Role.AUDITOR)
            revert NotAuthorized("PA e Auditor richiedono delibera a quorum");

        string memory callerDID = _ownerToDID[msg.sender];
        if (bytes(callerDID).length == 0) revert NotAuthorized("Chiamante non registrato");

        DIDDocument storage caller = _dids[callerDID];
        if (!caller.active || (caller.expiresAt > 0 && block.timestamp > caller.expiresAt))
            revert DIDNotActive(callerDID);
        if (keccak256(bytes(doc.registeredBy)) != keccak256(bytes(callerDID)))
            revert NotAuthorized("Solo il registrante puo revocare questo DID");

        doc.active = false;
        if (doc.didType == DIDType.PAIRWISE) delete _ownerToDID[doc.owner];
        emit DIDRevoked(doc.owner, did, block.timestamp);
    }

    function revokeByGovernance(string calldata did)
        external onlyPostBootstrap onlyGovernance onlyActiveDID(did)
    {
        DIDDocument storage doc = _dids[did];
        if (doc.role != Role.PA && doc.role != Role.AUDITOR)
            revert NotAuthorized("Funzione riservata a PA e Auditor");
        if (doc.role == Role.PA && _activePACount <= 4)
            revert NotAuthorized("Impossibile scendere sotto 4 PA attive: usare replacePAByGovernance");
        if (doc.role == Role.AUDITOR && _activeAuditorCount <= 2)
            revert NotAuthorized("Impossibile scendere sotto 2 Auditor attivi");

        doc.active = false;
        if (doc.role == Role.PA)      _activePACount--;
        if (doc.role == Role.AUDITOR) _activeAuditorCount--;
        emit DIDRevoked(doc.owner, did, block.timestamp);
    }

    /**
     * @notice Sostituisce atomicamente una PA compromessa con una nuova PA fidata.
     *         Previene il deadlock mantenendo _activePACount stabile.
     */
    function replacePAByGovernance(
        string calldata oldPADID,
        string calldata newPADID,
        bytes  calldata newPublicKey,
        address         newOwner
    ) external onlyPostBootstrap onlyGovernance onlyActiveDID(oldPADID) {
        DIDDocument storage doc = _dids[oldPADID];
        if (doc.role != Role.PA)
            revert NotAuthorized("Il DID da sostituire deve essere una PA");

        doc.active = false;
        delete _ownerToDID[doc.owner];
        emit DIDRevoked(doc.owner, oldPADID, block.timestamp);

        _validateRegistrationInputs(newPADID, newPublicKey, newOwner);
        Domain[] memory emptyScope = new Domain[](0);
        _dids[newPADID] = DIDDocument({
            owner:        newOwner,
            publicKey:    newPublicKey,
            active:       true,
            didType:      DIDType.ANYWISE,
            role:         Role.PA,
            scope:        emptyScope,
            registeredAt: block.timestamp,
            updatedAt:    block.timestamp,
            registeredBy: "governance",
            expiresAt:    0
        });
        _ownerToDID[newOwner] = newPADID;
        emit DIDRegistered(newOwner, newPADID, Role.PA, "governance", block.timestamp);
    }

    function revokeCredential(bytes32 credentialId) external onlyPostBootstrap {
        if (_revokedCredentials[credentialId])
            revert CredentialAlreadyRevoked(credentialId);
        if (bytes(_credentialIssuers[credentialId]).length == 0)
            revert InvalidInput("credentialId non registrato");

        string memory callerDID = _ownerToDID[msg.sender];
        if (bytes(callerDID).length == 0) revert NotAuthorized("Chiamante non registrato");

        DIDDocument storage caller = _dids[callerDID];
        if (!caller.active || (caller.expiresAt > 0 && block.timestamp > caller.expiresAt))
            revert DIDNotActive(callerDID);
        if (keccak256(bytes(_credentialIssuers[credentialId])) != keccak256(bytes(callerDID)))
            revert NotAuthorized("Solo l'issuer puo revocare questa credenziale");

        _revokedCredentials[credentialId] = true;
        emit CredentialRevoked(credentialId, callerDID, block.timestamp);
    }

    // =========================================================================
    // VIEW
    // =========================================================================

    function resolve(string calldata did) external view returns (DIDDocument memory) {
        if (_dids[did].owner == address(0)) revert DIDNotFound(did);
        return _dids[did];
    }

    function isActive(string calldata did) external view returns (bool) {
        DIDDocument storage doc = _dids[did];
        if (doc.owner == address(0))                               return false;
        if (!doc.active)                                           return false;
        if (doc.expiresAt > 0 && block.timestamp > doc.expiresAt) return false;
        return true;
    }

    function isCredentialRevoked(bytes32 credentialId) external view returns (bool) {
        return _revokedCredentials[credentialId];
    }

    function activePACount()       external view returns (uint256) { return _activePACount; }
    function activeAuditorCount()  external view returns (uint256) { return _activeAuditorCount; }
    function isBootstrapComplete() external view returns (bool)    { return _bootstrapComplete; }

    function getDIDByAddress(address owner) external view returns (string memory) {
        return _ownerToDID[owner];
    }

    function getCredentialIssuer(bytes32 credentialId) external view returns (string memory) {
        return _credentialIssuers[credentialId];
    }

    // =========================================================================
    // INTERNE
    // =========================================================================

    function _registerPA(
        string calldata did, bytes calldata publicKey,
        address owner, string memory registeredBy
    ) internal {
        _validateRegistrationInputs(did, publicKey, owner);
        Domain[] memory emptyScope = new Domain[](0);
        _dids[did] = DIDDocument({
            owner: owner, publicKey: publicKey, active: true,
            didType: DIDType.ANYWISE, role: Role.PA, scope: emptyScope,
            registeredAt: block.timestamp, updatedAt: block.timestamp,
            registeredBy: registeredBy, expiresAt: 0
        });
        _ownerToDID[owner] = did;
        _activePACount++;
        emit DIDRegistered(owner, did, Role.PA, registeredBy, block.timestamp);
    }

    function _registerAuditor(
        string calldata did, bytes calldata publicKey,
        address owner, string memory registeredBy
    ) internal {
        _validateRegistrationInputs(did, publicKey, owner);
        Domain[] memory globalScope = new Domain[](3);
        globalScope[0] = Domain.NETWORK;
        globalScope[1] = Domain.SYSTEM;
        globalScope[2] = Domain.APPLICATION;
        _dids[did] = DIDDocument({
            owner: owner, publicKey: publicKey, active: true,
            didType: DIDType.ANYWISE, role: Role.AUDITOR, scope: globalScope,
            registeredAt: block.timestamp, updatedAt: block.timestamp,
            registeredBy: registeredBy, expiresAt: 0
        });
        _ownerToDID[owner] = did;
        _activeAuditorCount++;
        emit DIDRegistered(owner, did, Role.AUDITOR, registeredBy, block.timestamp);
    }

    function _validateRegistrationInputs(
        string calldata did, bytes calldata publicKey, address owner
    ) internal view {
        if (bytes(did).length == 0)               revert InvalidInput("DID vuoto");
        if (publicKey.length == 0)                revert InvalidInput("Chiave pubblica vuota");
        if (owner == address(0))                  revert InvalidInput("Owner non valido");
        if (_dids[did].owner != address(0))       revert DIDAlreadyExists(did);
        if (bytes(_ownerToDID[owner]).length > 0) revert OwnerAlreadyRegistered(owner);
    }

    function _checkDelegationAuthorization(
        Role parentRole, Role childRole, Domain[] calldata scope
    ) internal pure {
        if (parentRole == Role.PA) {
            if (childRole != Role.PP && childRole != Role.AA && childRole != Role.EV)
                revert NotAuthorized("PA puo delegare solo PP, AA, EV");
            if (childRole == Role.PP) {
                if (scope.length != 3) revert InvalidScope("PP deve ricevere 3 domini");
                bool hasNetwork; bool hasSystem; bool hasApp;
                for (uint256 i = 0; i < 3; i++) {
                    if      (scope[i] == Domain.NETWORK)     hasNetwork = true;
                    else if (scope[i] == Domain.SYSTEM)      hasSystem  = true;
                    else if (scope[i] == Domain.APPLICATION) hasApp     = true;
                }
                if (!hasNetwork || !hasSystem || !hasApp)
                    revert InvalidScope("PP deve coprire tutti e 3 i domini senza ripetizioni");
            }
            if ((childRole == Role.AA || childRole == Role.EV) && scope.length != 1)
                revert InvalidScope("AA e EV devono ricevere esattamente un dominio");
        } else if (parentRole == Role.PP) {
            if (childRole != Role.DEG) revert NotAuthorized("PP puo delegare solo DEG");
            if (scope.length != 1)     revert InvalidScope("DEG deve ricevere esattamente un dominio");
        } else {
            revert NotAuthorized("Ruolo non autorizzato a delegare");
        }
    }
}
