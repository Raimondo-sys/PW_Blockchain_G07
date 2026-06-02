// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title  GovernanceContract
 * @notice Gestisce il ciclo vita delle proposte policy e la governance del consorzio.
 *
 * @dev    Operazioni privilegiate per PP, DEG, AA, EV richiedono un validationId
 *         registrato nel CVC prima della chiamata (VP verificata off-chain con JWT RS256).
 *         Le PA si autenticano direttamente tramite msg.sender.
 *         Quorum: ceil(3/4 * N) = (N * 3 + 3) / 4. Con N=4: 3 voti su 4.
 */

// =========================================================================
    // INTERFACCE
    // =========================================================================

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

        function resolve(string calldata did) external view returns (DIDDocument memory);
        function isActive(string calldata did) external view returns (bool);
        function getDIDByAddress(address owner) external view returns (string memory);
        function activePACount() external view returns (uint256);
        function revokeByGovernance(string calldata did) external;
        function registerNewPA(string calldata did, bytes calldata publicKey, address owner) external;
        function registerNewAuditor(string calldata did, bytes calldata publicKey, address owner) external;
    }

    interface IPolicyRegistry {
        function certifyPolicy(bytes32 proposalId, string calldata cid, string calldata cidKeyDistrib, uint8 domain, uint32 version, string calldata safeDefaultCid) external;
        function retirePolicy(bytes32 proposalId) external;
        function updateSafeDefault(uint8 domain, string calldata newSafeDefaultCid) external;
        function getCurrentVersion(uint8 domain) external view returns (uint32);
        function hasSafeDefault(uint8 domain) external view returns (bool);
        function getActivePolicy(uint8 domain) external view returns (bytes32);
    }

    interface ICredentialValidationContract {
        function consumeValidation(
            bytes32 validationId,
            string  calldata expectedDID,
            uint8   expectedRole,
            uint8   expectedDomain
        ) external returns (bool);
    }


contract GovernanceContract {


    // =========================================================================
    // TIPI
    // =========================================================================

    enum ProposalStatus         { Proposed, Forwarded, Endorsed, Certified, Rejected }
    enum GovernanceActionType   { RevokePA, RevokeAuditor, AdmitPA, AdmitAuditor, RetirePolicy, UpdateSafeDefault }
    enum GovernanceActionStatus { Pending, Executed }

    struct PolicyProposal {
        bytes32        proposalId;
        string         submitterDID;
        string         ppDID;
        string         endorserDID;
        string         cid;
        string         cidKeyDistrib;
        uint8          domain;
        ProposalStatus status;
        uint256        quorumSnapshot;
        uint256        quorumRequired;
        uint256        votesFor;
        uint256        submittedAt;
        uint256        forwardedAt;
        uint256        endorsedAt;
        uint256        certifiedAt;
        bytes32        replacesId;
        string         safeDefaultCid;
    }

    struct GovernanceAction {
        bytes32                actionId;
        string                 proposerDID;
        GovernanceActionType   actionType;
        bytes                  payload;
        GovernanceActionStatus status;
        uint256                quorumSnapshot;
        uint256                quorumRequired;
        uint256                votesFor;
        uint256                createdAt;
        uint256                executedAt;
    }

    // =========================================================================
    // STORAGE
    // =========================================================================

    IIdentityRegistry           private _identityRegistry;
    IPolicyRegistry             private _policyRegistry;
    ICredentialValidationContract private _cvc;

    mapping(bytes32 => PolicyProposal)          private _proposals;
    mapping(bytes32 => mapping(string => bool)) private _proposalVotes;
    mapping(uint8   => bytes32)                 private _endorsedByDomain;

    mapping(bytes32 => GovernanceAction)        private _governanceActions;
    mapping(bytes32 => mapping(string => bool)) private _actionVotes;

    uint256 private _auditWindowDuration;
    uint256 private _auditWindowEnd;

    address private _deployer;
    bool    private _bootstrapComplete;

    // =========================================================================
    // EVENTI
    // =========================================================================

    event ProposalSubmitted(bytes32 indexed proposalId, string submitterDID, uint8 domain, string cid, uint256 timestamp);
    event ProposalRejected(bytes32 indexed proposalId, string ppDID, string reason, uint256 timestamp);
    event ProposalForwarded(bytes32 indexed proposalId, string ppDID, uint256 timestamp);
    event ProposalEndorsed(bytes32 indexed proposalId, string endorserDID, uint256 quorumSnapshot, uint256 quorumRequired, uint256 timestamp);
    event VoteCast(bytes32 indexed proposalId, string voterDID, bool support, uint256 votesFor, uint256 quorumRequired, uint256 timestamp);
    event PolicyCertified(bytes32 indexed proposalId, uint8 domain, uint32 version, string cid, uint256 timestamp);
    event AuditWindowOpened(bytes32 indexed proposalId, uint256 endsAt, uint256 timestamp);
    event GovernanceActionProposed(bytes32 indexed actionId, string proposerDID, GovernanceActionType actionType, uint256 quorumSnapshot, uint256 timestamp);
    event GovernanceActionVoteCast(bytes32 indexed actionId, string voterDID, bool support, uint256 votesFor, uint256 timestamp);
    event GovernanceActionExecuted(bytes32 indexed actionId, GovernanceActionType actionType, uint256 timestamp);
    event BootstrapFinalized(address indexed deployer, uint256 timestamp);
    event IdentityRegistrySet(address indexed registry, uint256 timestamp);
    event PolicyRegistrySet(address indexed registry, uint256 timestamp);
    event CVCSet(address indexed cvc, uint256 timestamp);

    // =========================================================================
    // ERRORI
    // =========================================================================

    error BootstrapAlreadyComplete();
    error BootstrapNotComplete();
    error NotAuthorized(string reason);
    error InvalidInput(string reason);
    error ProposalNotFound(bytes32 proposalId);
    error InvalidProposalStatus(bytes32 proposalId, ProposalStatus current, ProposalStatus expected);
    error AlreadyVoted(bytes32 id, string voterDID);
    error DomainAlreadyEndorsed(uint8 domain, bytes32 activeProposalId);
    error ActionNotFound(bytes32 actionId);
    error ActionNotPending(bytes32 actionId);
    error SafeDefaultRequired(uint8 domain);
    error ReplacesIdMismatch(bytes32 replacesId, bytes32 activePolicy);

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

    modifier onlyActivePA() {
        _requireCallerRole(IIdentityRegistry.Role.PA);
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

    function setPolicyRegistry(address registry) external onlyBootstrap {
        if (registry == address(0)) revert InvalidInput("Indirizzo non valido");
        _policyRegistry = IPolicyRegistry(registry);
        emit PolicyRegistrySet(registry, block.timestamp);
    }

    function setCVC(address cvc) external onlyBootstrap {
        if (cvc == address(0)) revert InvalidInput("Indirizzo non valido");
        _cvc = ICredentialValidationContract(cvc);
        emit CVCSet(cvc, block.timestamp);
    }

    function setAuditWindowDuration(uint256 durationSeconds) external onlyBootstrap {
        if (durationSeconds == 0) revert InvalidInput("Durata non valida");
        _auditWindowDuration = durationSeconds;
    }

    function finalizeBootstrap() external onlyBootstrap {
        if (address(_identityRegistry) == address(0)) revert InvalidInput("IdentityRegistry non impostato");
        if (address(_policyRegistry) == address(0))   revert InvalidInput("PolicyRegistry non impostato");
        if (address(_cvc) == address(0))              revert InvalidInput("CVC non impostato");
        if (_auditWindowDuration == 0)                revert InvalidInput("Durata audit window non configurata");
        _bootstrapComplete = true;
        emit BootstrapFinalized(_deployer, block.timestamp);
    }

    // =========================================================================
    // CICLO VITA PROPOSTE — richiedono validationId dal CVC
    // =========================================================================

    /**
     * @notice Il DEG sottomette una proposta.
     * @param validationId  ID registrato nel CVC dopo verifica VP off-chain.
     */
    function submitProposal(
        string  calldata cid,
        string  calldata cidKeyDistrib,
        uint8            domain,
        bytes32          replacesId,
        string  calldata safeDefaultCid,
        bytes32          validationId
    ) external onlyPostBootstrap {
        if (bytes(cid).length == 0)           revert InvalidInput("CID non valido");
        if (bytes(cidKeyDistrib).length == 0) revert InvalidInput("CID key distribution non valido");
        if (domain > 2)                       revert InvalidInput("Dominio non valido");

        string memory submitterDID = _identityRegistry.getDIDByAddress(msg.sender);

        // Verifica e consuma il validationId del DEG
        bool valid = _cvc.consumeValidation(
            validationId,
            submitterDID,
            uint8(IIdentityRegistry.Role.DEG),
            domain
        );
        if (!valid) revert NotAuthorized("Validazione non riuscita");

        _checkDEGDomainScope(submitterDID, domain);
        _checkReplacesId(replacesId, domain);

        bytes32 proposalId = keccak256(abi.encode(submitterDID, cid, domain, block.timestamp));
        if (_proposals[proposalId].proposalId != bytes32(0))
            revert InvalidInput("ProposalId gia esistente");

        _proposals[proposalId] = PolicyProposal({
            proposalId:     proposalId,
            submitterDID:   submitterDID,
            ppDID:          "",
            endorserDID:    "",
            cid:            cid,
            cidKeyDistrib:  cidKeyDistrib,
            domain:         domain,
            status:         ProposalStatus.Proposed,
            quorumSnapshot: 0,
            quorumRequired: 0,
            votesFor:       0,
            submittedAt:    block.timestamp,
            forwardedAt:    0,
            endorsedAt:     0,
            certifiedAt:    0,
            replacesId:     replacesId,
            safeDefaultCid: safeDefaultCid
        });

        emit ProposalSubmitted(proposalId, submitterDID, domain, cid, block.timestamp);
    }

    /**
     * @notice Il PP rigetta una proposta con motivazione tracciata on-chain.
     */
    function rejectProposal(
        bytes32          proposalId,
        string  calldata reason,
        bytes32          validationId
    ) external onlyPostBootstrap {
        if (bytes(reason).length == 0) revert InvalidInput("Motivazione obbligatoria");

        PolicyProposal storage p = _proposals[proposalId];
        if (p.proposalId == bytes32(0)) revert ProposalNotFound(proposalId);
        if (p.status != ProposalStatus.Proposed && p.status != ProposalStatus.Forwarded)
            revert InvalidProposalStatus(proposalId, p.status, ProposalStatus.Proposed);

        string memory ppDID = _identityRegistry.getDIDByAddress(msg.sender);

        bool valid = _cvc.consumeValidation(
            validationId,
            ppDID,
            uint8(IIdentityRegistry.Role.PP),
            p.domain
        );
        if (!valid) revert NotAuthorized("Validazione non riuscita");

        _requirePPisSupervisor(ppDID, p.submitterDID);

        p.status = ProposalStatus.Rejected;
        emit ProposalRejected(proposalId, ppDID, reason, block.timestamp);
    }

    /**
     * @notice Il PP inoltra la proposta alla PA delegante.
     */
    function forwardProposal(
        bytes32 proposalId,
        bytes32 validationId
    ) external onlyPostBootstrap {
        PolicyProposal storage p = _proposals[proposalId];
        if (p.proposalId == bytes32(0)) revert ProposalNotFound(proposalId);
        if (p.status != ProposalStatus.Proposed)
            revert InvalidProposalStatus(proposalId, p.status, ProposalStatus.Proposed);

        string memory ppDID = _identityRegistry.getDIDByAddress(msg.sender);

        bool valid = _cvc.consumeValidation(
            validationId,
            ppDID,
            uint8(IIdentityRegistry.Role.PP),
            p.domain
        );
        if (!valid) revert NotAuthorized("Validazione non riuscita");

        _requirePPisSupervisor(ppDID, p.submitterDID);

        p.status      = ProposalStatus.Forwarded;
        p.ppDID       = ppDID;
        p.forwardedAt = block.timestamp;
        emit ProposalForwarded(proposalId, ppDID, block.timestamp);
    }

    /**
     * @notice La PA endorse la proposta, acquisendo il quorum snapshot.
     *         Le PA si autenticano tramite msg.sender — nessuna VP necessaria.
     */
    function endorseProposal(bytes32 proposalId)
        external onlyPostBootstrap onlyActivePA
    {
        PolicyProposal storage p = _proposals[proposalId];
        if (p.proposalId == bytes32(0)) revert ProposalNotFound(proposalId);
        if (p.status != ProposalStatus.Forwarded)
            revert InvalidProposalStatus(proposalId, p.status, ProposalStatus.Forwarded);
        if (_endorsedByDomain[p.domain] != bytes32(0))
            revert DomainAlreadyEndorsed(p.domain, _endorsedByDomain[p.domain]);

        string memory paDID = _identityRegistry.getDIDByAddress(msg.sender);

        if (bytes(p.ppDID).length > 0) {
            IIdentityRegistry.DIDDocument memory ppDoc = _identityRegistry.resolve(p.ppDID);
            if (keccak256(bytes(ppDoc.registeredBy)) != keccak256(bytes(paDID)))
                revert NotAuthorized("Solo la PA delegante del PP puo endorsare");
        }

        uint256 snapshot = _identityRegistry.activePACount();
        if (snapshot < 4) revert InvalidInput("Minimo 4 PA attive richieste");
        uint256 required = (snapshot * 3 + 3) / 4;

        p.status         = ProposalStatus.Endorsed;
        p.endorserDID    = paDID;
        p.quorumSnapshot = snapshot;
        p.quorumRequired = required;
        p.endorsedAt     = block.timestamp;

        _endorsedByDomain[p.domain] = proposalId;
        emit ProposalEndorsed(proposalId, paDID, snapshot, required, block.timestamp);
    }

    /**
     * @notice La PA vota la proposta. Le PA si autenticano tramite msg.sender.
     */
    function voteProposal(bytes32 proposalId, bool support)
        external onlyPostBootstrap onlyActivePA
    {
        PolicyProposal storage p = _proposals[proposalId];
        if (p.proposalId == bytes32(0)) revert ProposalNotFound(proposalId);
        if (p.status != ProposalStatus.Endorsed)
            revert InvalidProposalStatus(proposalId, p.status, ProposalStatus.Endorsed);

        string memory voterDID = _identityRegistry.getDIDByAddress(msg.sender);
        if (_proposalVotes[proposalId][voterDID]) revert AlreadyVoted(proposalId, voterDID);

        _proposalVotes[proposalId][voterDID] = true;
        if (support) p.votesFor++;

        emit VoteCast(proposalId, voterDID, support, p.votesFor, p.quorumRequired, block.timestamp);

        if (p.votesFor >= p.quorumRequired) {
            _certifyProposal(proposalId);
        }
    }

    // =========================================================================
    // GOVERNANCE CONSORZIO — solo PA
    // =========================================================================

    function proposeGovernanceAction(GovernanceActionType actionType, bytes calldata payload)
        external onlyPostBootstrap onlyActivePA
    {
        if (payload.length == 0) revert InvalidInput("Payload non valido");

        string memory proposerDID = _identityRegistry.getDIDByAddress(msg.sender);
        bytes32 actionId = keccak256(abi.encodePacked(proposerDID, uint8(actionType), payload, block.timestamp));

        uint256 snapshot = _identityRegistry.activePACount();
        if (snapshot < 4) revert InvalidInput("Minimo 4 PA attive richieste");
        uint256 required = (snapshot * 3 + 3) / 4;

        _governanceActions[actionId] = GovernanceAction({
            actionId:       actionId,
            proposerDID:    proposerDID,
            actionType:     actionType,
            payload:        payload,
            status:         GovernanceActionStatus.Pending,
            quorumSnapshot: snapshot,
            quorumRequired: required,
            votesFor:       0,
            createdAt:      block.timestamp,
            executedAt:     0
        });

        emit GovernanceActionProposed(actionId, proposerDID, actionType, snapshot, block.timestamp);
    }

    function voteGovernanceAction(bytes32 actionId, bool support)
        external onlyPostBootstrap onlyActivePA
    {
        GovernanceAction storage action = _governanceActions[actionId];
        if (action.actionId == bytes32(0))                   revert ActionNotFound(actionId);
        if (action.status != GovernanceActionStatus.Pending) revert ActionNotPending(actionId);

        string memory voterDID = _identityRegistry.getDIDByAddress(msg.sender);
        if (_actionVotes[actionId][voterDID]) revert AlreadyVoted(actionId, voterDID);

        _actionVotes[actionId][voterDID] = true;
        if (support) action.votesFor++;

        emit GovernanceActionVoteCast(actionId, voterDID, support, action.votesFor, block.timestamp);

        if (action.votesFor >= action.quorumRequired) {
            _executeGovernanceAction(actionId);
        }
    }

    // =========================================================================
    // INTERNE
    // =========================================================================

    function _certifyProposal(bytes32 proposalId) internal {
        PolicyProposal storage p = _proposals[proposalId];

        if (p.replacesId != bytes32(0)) {
            bytes32 activeId = _policyRegistry.getActivePolicy(p.domain);
            if (activeId != p.replacesId)
                revert ReplacesIdMismatch(p.replacesId, activeId);
        }

        if (!_policyRegistry.hasSafeDefault(p.domain) && bytes(p.safeDefaultCid).length == 0)
            revert SafeDefaultRequired(p.domain);

        p.status      = ProposalStatus.Certified;
        p.certifiedAt = block.timestamp;
        delete _endorsedByDomain[p.domain];

        uint32 newVersion = _policyRegistry.getCurrentVersion(p.domain) + 1;
        _policyRegistry.certifyPolicy(proposalId, p.cid, p.cidKeyDistrib, p.domain, newVersion, p.safeDefaultCid);

        emit PolicyCertified(proposalId, p.domain, newVersion, p.cid, block.timestamp);

        uint256 windowEnd = block.timestamp + _auditWindowDuration;
        if (windowEnd > _auditWindowEnd) _auditWindowEnd = windowEnd;
        emit AuditWindowOpened(proposalId, _auditWindowEnd, block.timestamp);
    }

    function _executeGovernanceAction(bytes32 actionId) internal {
        GovernanceAction storage action = _governanceActions[actionId];
        action.status     = GovernanceActionStatus.Executed;
        action.executedAt = block.timestamp;

        GovernanceActionType t = action.actionType;

        if (t == GovernanceActionType.RevokePA || t == GovernanceActionType.RevokeAuditor) {
            string memory did = abi.decode(action.payload, (string));
            _identityRegistry.revokeByGovernance(did);
        } else if (t == GovernanceActionType.AdmitPA) {
            (string memory did, bytes memory pubkey, address owner) =
                abi.decode(action.payload, (string, bytes, address));
            _identityRegistry.registerNewPA(did, pubkey, owner);
        } else if (t == GovernanceActionType.AdmitAuditor) {
            (string memory did, bytes memory pubkey, address owner) =
                abi.decode(action.payload, (string, bytes, address));
            _identityRegistry.registerNewAuditor(did, pubkey, owner);
        } else if (t == GovernanceActionType.RetirePolicy) {
            bytes32 pid = abi.decode(action.payload, (bytes32));
            _policyRegistry.retirePolicy(pid);
        } else if (t == GovernanceActionType.UpdateSafeDefault) {
            (uint8 domain, string memory newCid) = abi.decode(action.payload, (uint8, string));
            _policyRegistry.updateSafeDefault(domain, newCid);
        }

        emit GovernanceActionExecuted(actionId, action.actionType, block.timestamp);
    }

    function _requireCallerRole(IIdentityRegistry.Role expectedRole) internal view {
        string memory callerDID = _identityRegistry.getDIDByAddress(msg.sender);
        if (bytes(callerDID).length == 0) revert NotAuthorized("Chiamante non registrato");
        IIdentityRegistry.DIDDocument memory doc = _identityRegistry.resolve(callerDID);
        if (doc.role != expectedRole) revert NotAuthorized("Ruolo non autorizzato");
        if (!doc.active || (doc.expiresAt > 0 && block.timestamp > doc.expiresAt))
            revert NotAuthorized("DID revocato o scaduto");
    }

    function _checkDEGDomainScope(string memory degDID, uint8 domain) internal view {
        IIdentityRegistry.DIDDocument memory doc = _identityRegistry.resolve(degDID);
        for (uint256 i = 0; i < doc.scope.length; i++) {
            if (uint8(doc.scope[i]) == domain) return;
        }
        revert NotAuthorized("DEG non ha scope sul dominio dichiarato");
    }

    function _checkReplacesId(bytes32 replacesId, uint8 domain) internal view {
        if (replacesId == bytes32(0)) return;
        PolicyProposal storage replaced = _proposals[replacesId];
        if (replaced.proposalId == bytes32(0))
            revert InvalidInput("replacesId non corrisponde a nessuna proposta");
        if (replaced.domain != domain)
            revert InvalidInput("Dominio della proposta referenziata non corrisponde");
    }

    function _requirePPisSupervisor(string memory ppDID, string memory degDID) internal view {
        IIdentityRegistry.DIDDocument memory degDoc = _identityRegistry.resolve(degDID);
        if (keccak256(bytes(degDoc.registeredBy)) != keccak256(bytes(ppDID)))
            revert NotAuthorized("PP non e il supervisore del DEG sottomittente");
    }

    // =========================================================================
    // VIEW
    // =========================================================================

    function isAuditWindowOpen() external view returns (bool) {
        return block.timestamp <= _auditWindowEnd;
    }

    function getProposal(bytes32 proposalId) external view returns (PolicyProposal memory) {
        if (_proposals[proposalId].proposalId == bytes32(0)) revert ProposalNotFound(proposalId);
        return _proposals[proposalId];
    }

    function getGovernanceAction(bytes32 actionId) external view returns (GovernanceAction memory) {
        if (_governanceActions[actionId].actionId == bytes32(0)) revert ActionNotFound(actionId);
        return _governanceActions[actionId];
    }

    function getEndorsedProposalByDomain(uint8 domain) external view returns (bytes32) {
        return _endorsedByDomain[domain];
    }

    function hasVotedProposal(bytes32 proposalId, string calldata paDID) external view returns (bool) {
        return _proposalVotes[proposalId][paDID];
    }

    function hasVotedAction(bytes32 actionId, string calldata paDID) external view returns (bool) {
        return _actionVotes[actionId][paDID];
    }

    function auditWindowEnd()      external view returns (uint256) { return _auditWindowEnd; }
    function auditWindowDuration() external view returns (uint256) { return _auditWindowDuration; }
    function isBootstrapComplete() external view returns (bool)    { return _bootstrapComplete; }
    function getIdentityRegistry() external view returns (address) { return address(_identityRegistry); }
    function getPolicyRegistry()   external view returns (address) { return address(_policyRegistry); }
    function getCVC()              external view returns (address) { return address(_cvc); }
}
