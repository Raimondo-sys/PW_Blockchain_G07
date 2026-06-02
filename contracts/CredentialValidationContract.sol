// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title  CredentialValidationContract
 * @notice Registra on-chain le validazioni di VP effettuate off-chain.
 *
 * @dev    La verifica della firma JWT RS256 avviene off-chain (non supportata dall'EVM).
 *         Il CVC riceve il risultato della verifica come validationId = keccak256(vpJwt)
 *         e lo registra on-chain con DID, ruolo, scope e timestamp.
 *         Il GovernanceContract verifica che un validationId valido esista prima
 *         di accettare operazioni privilegiate da PP, DEG, AA, EV.
 *
 *         Le PA si autenticano direttamente tramite msg.sender (nessuna VP necessaria).
 *         L'Auditor può accedere solo durante la finestra di audit aperta dal GC.
 *
 *         Giustificazione architetturale (WP4): RSA non è supportato nativamente
 *         dall'EVM; la verifica on-chain richiederebbe precompilazioni custom
 *         non disponibili in PoA consortium. Il pattern off-chain + registrazione
 *         on-chain mantiene la tracciabilità senza sacrificare la fattibilità.
 */

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

    interface IGovernanceContract {
        function isAuditWindowOpen() external view returns (bool);
    }

    

contract CredentialValidationContract {


    // Risultato di una validazione VP registrata on-chain
    struct ValidationRecord {
        string  holderDID;
        uint8   role;
        uint8   domain;
        uint256 validatedAt;
        uint256 expiresAt;   // 0 = nessuna scadenza (PP, DEG, Auditor)
        bool    used;        // true = già consumato da un'operazione GC
    }

    IIdentityRegistry   private _identityRegistry;
    IGovernanceContract private _governanceContract;
    address private _policyRegistry;

    // validationId → record
    mapping(bytes32 => ValidationRecord) private _validations;

    address private _deployer;
    bool    private _bootstrapComplete;

    // Durata massima di validità di un validationId (anti-replay window)
    uint256 public constant VALIDATION_TTL = 5 minutes;

    event ValidationRegistered(
        bytes32 indexed validationId,
        string  holderDID,
        uint8   role,
        uint8   domain,
        uint256 expiresAt,
        uint256 timestamp
    );
    event ValidationConsumed(bytes32 indexed validationId, address consumer, uint256 timestamp);
    event BootstrapFinalized(address indexed deployer, uint256 timestamp);
    event IdentityRegistrySet(address indexed registry, uint256 timestamp);
    event GovernanceContractSet(address indexed governance, uint256 timestamp);

    error BootstrapAlreadyComplete();
    error BootstrapNotComplete();
    error NotAuthorized(string reason);
    error InvalidInput(string reason);
    error ValidationNotFound(bytes32 validationId);
    error ValidationExpired(bytes32 validationId);
    error ValidationAlreadyUsed(bytes32 validationId);
    error AuditWindowClosed();
    error HolderMismatch(string expected, string provided);

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

    modifier onlyCoreContracts() {
    if (msg.sender != address(_governanceContract) && msg.sender != _policyRegistry)
        revert NotAuthorized("Solo GovernanceContract o PolicyRegistry");
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
        _governanceContract = IGovernanceContract(governance);
        emit GovernanceContractSet(governance, block.timestamp);
    }

    function setPolicyRegistry(address registry) external onlyBootstrap {
    if (registry == address(0)) revert InvalidInput("Indirizzo non valido");
    _policyRegistry = registry;
}

    function finalizeBootstrap() external onlyBootstrap {
    if (address(_identityRegistry) == address(0))   revert InvalidInput("IdentityRegistry non impostato"); // 
    if (address(_governanceContract) == address(0)) revert InvalidInput("GovernanceContract non impostato"); // [cite: 34]
    if (_policyRegistry == address(0))              revert InvalidInput("PolicyRegistry non impostato"); // <--- AGGIUNGI QUESTO
    _bootstrapComplete = true; // [cite: 34]
    emit BootstrapFinalized(_deployer, block.timestamp);
}

    // =========================================================================
    // REGISTRAZIONE VALIDAZIONE
    // Chiamata dall'entità stessa dopo aver verificato la VP off-chain.
    // validationId = keccak256(abi.encodePacked(vpJwt)) — legame con il JWT.
    // =========================================================================

    function registerValidation(
        bytes32 validationId,
        string  calldata holderDID,
        uint8   role,
        uint8   domain,
        uint256 vcExpiresAt
    ) external onlyPostBootstrap {
        if (validationId == bytes32(0))       revert InvalidInput("validationId non valido");
        if (bytes(holderDID).length == 0)     revert InvalidInput("holderDID vuoto");
        if (_validations[validationId].validatedAt != 0)
            revert InvalidInput("validationId gia registrato");

        // Verifica che msg.sender sia il titolare del DID
        string memory callerDID = _identityRegistry.getDIDByAddress(msg.sender);
        if (keccak256(bytes(callerDID)) != keccak256(bytes(holderDID)))
            revert HolderMismatch(holderDID, callerDID);

        // Verifica che il DID sia attivo nell'IR
        if (!_identityRegistry.isActive(holderDID))
            revert NotAuthorized("DID non attivo");

        // Per l'Auditor verifica che la finestra di audit sia aperta
        if (role == uint8(IIdentityRegistry.Role.AUDITOR)) {
            if (!_governanceContract.isAuditWindowOpen()) revert AuditWindowClosed();
        }

        // Il validationId scade dopo VALIDATION_TTL (anti-replay)
        uint256 ttlExpiry = block.timestamp + VALIDATION_TTL;

        _validations[validationId] = ValidationRecord({
            holderDID:   holderDID,
            role:        role,
            domain:      domain,
            validatedAt: block.timestamp,
            expiresAt:   ttlExpiry,
            used:        false
        });

        emit ValidationRegistered(validationId, holderDID, role, domain, ttlExpiry, block.timestamp);
    }

    // =========================================================================
    // CONSUMO VALIDAZIONE
    // Chiamato dal GovernanceContract per verificare e consumare un validationId.
    // Il consumo è monouso — previene il riuso dello stesso validationId.
    // =========================================================================

    function consumeValidation(
        bytes32 validationId,
        string  calldata expectedDID,
        uint8   expectedRole,
        uint8   expectedDomain
    ) external onlyPostBootstrap onlyCoreContracts returns (bool) {
        ValidationRecord storage rec = _validations[validationId];

        if (rec.validatedAt == 0)            revert ValidationNotFound(validationId);
        if (block.timestamp > rec.expiresAt) revert ValidationExpired(validationId);
        if (rec.used)                        revert ValidationAlreadyUsed(validationId);

        // Verifica corrispondenza DID, ruolo e dominio
        if (keccak256(bytes(rec.holderDID)) != keccak256(bytes(expectedDID)))
            revert NotAuthorized("DID non corrisponde");
        if (rec.role != expectedRole)
            revert NotAuthorized("Ruolo non corrisponde");
        if (rec.domain != expectedDomain)
            revert NotAuthorized("Dominio non corrisponde");

        rec.used = true;
        emit ValidationConsumed(validationId, msg.sender, block.timestamp);
        return true;
    }

    // =========================================================================
    // VIEW
    // =========================================================================

    function getValidation(bytes32 validationId)
        external view returns (ValidationRecord memory)
    {
        if (_validations[validationId].validatedAt == 0)
            revert ValidationNotFound(validationId);
        return _validations[validationId];
    }

    function isValidationUsable(bytes32 validationId) external view returns (bool) {
        ValidationRecord storage rec = _validations[validationId];
        return rec.validatedAt != 0
            && !rec.used
            && block.timestamp <= rec.expiresAt;
    }

    function isBootstrapComplete() external view returns (bool)    { return _bootstrapComplete; }
    function getIdentityRegistry() external view returns (address) { return address(_identityRegistry); }
    function getGovernanceContract() external view returns (address){ return address(_governanceContract); }
}
