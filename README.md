# WP4 — Sistema di Governance Decentralizzata per Logging Security Policy

Università di Salerno — Corso Blockchain e Cybersecurity 2025/2026  
Progetto: Governance decentralizzata delle Logging Security Policy su blockchain consortium EVM + IPFS

---

## Architettura

Quattro smart contract su blockchain EVM (PoA consortium) + IPFS per lo storage off-chain:

```
IdentityRegistry (IR)
  └─ gestisce DID lifecycle, ruoli, deleghe, chiavi RSA pubbliche on-chain

CredentialValidationContract (CVC)
  └─ registra on-chain le validazioni VP eseguite off-chain (JWT RS256)

GovernanceContract (GC)
  └─ ciclo vita proposte policy + governance consorzio (quorum 3/4 PA)

PolicyRegistry (PR)
  └─ registro permanente delle policy: Active → Archived → Retired
```

**Flusso principale** (WP2 §2.2):
1. DEG costruisce VP JWT RS256, la verifica off-chain, registra `validationId` nel CVC
2. DEG chiama `submitProposal(cid, cidKeyDistrib, domain, replacesId, safeDefaultCid, validationId)`
3. PP verifica, ottiene `validationId`, chiama `forwardProposal`
4. PA endorse e votano (autenticazione diretta via `msg.sender`)
5. Al raggiungimento del quorum (3/4) la policy viene certificata atomicamente nel PR
6. AA scarica da IPFS, verifica integrità CID, applica configurazione, chiama `confirmEnforcement`

---

## Stack tecnologico

- **Hardhat 3.7.0** con `hardhat-toolbox-viem` (ESM obbligatorio)
- **TypeScript 6.0.3** + **Viem 2.x**
- **JWT RS256** (`jsonwebtoken`) per VC e VP
- **AES-256-GCM + ECDH P-256** (`crypto` nativo Node) per cifratura ibrida
- **Helia** per IPFS reale (solo `ipfs-demo.ts`), IPFS simulato per gli script Hardhat

---

## Installazione

```bash
npm install
npx hardhat compile
```

---

## Esecuzione

### Deploy su rete locale

```bash
# Terminale 1
npx hardhat node

# Terminale 2
npx hardhat run scripts/deploy.ts --network localhost
```

### Deploy su hardhatMainnet (autonomo, no nodo esterno)

```bash
npx hardhat run scripts/deploy-mainnet.ts --network hardhatMainnet
```

### Script dimostrativi

```bash
# Flusso end-to-end completo (v1 → v2 → RetirePolicy)
npx hardhat run scripts/full_flow.ts --network hardhatMainnet

# Dimostrazione VC/VP JWT RS256 e integrazione CVC
npx hardhat run scripts/credential_flow.ts --network hardhatMainnet

# Auditor: verificabilità indipendente
npx hardhat run scripts/auditor.ts --network hardhatMainnet

# External Verifier: accesso temporaneo pairwise DID
npx hardhat run scripts/external_verifier.ts --network hardhatMainnet

# Benchmark: latency, gas, storage overhead
npx hardhat run scripts/benchmark.ts --network hardhatMainnet

# IPFS reale con Helia (node diretto, non Hardhat)
node --loader ts-node/esm scripts/ipfs-demo.ts
```

### Test

```bash
npx hardhat test
```

---

## Struttura del progetto

```
contracts/
  IdentityRegistry.sol               DID lifecycle, RSA pubkey on-chain
  CredentialValidationContract.sol   Registrazione validationId on-chain
  GovernanceContract.sol             Ciclo vita proposte + governance
  PolicyRegistry.sol                 Registro permanente policy

crypto/
  keys.ts       Generazione RSA 2048 + ECDH P-256
  vc.ts         Emissione e verifica VC come JWT RS256
  vp.ts         Costruzione VP JWT RS256 con selective disclosure
  hybrid.ts     Cifratura ibrida AES-256-GCM + ECDH P-256

ipfs/
  helia-node.ts      IPFS reale Helia in-memory (ipfs-demo.ts)
  ipfs-simulated.ts  IPFS simulato SHA-256 (script Hardhat)

policies/
  safe-default-network.json    Configurazione minima dominio NETWORK
  LSP-NETWORK-001-v1.json      Policy NETWORK versione 1.0
  LSP-NETWORK-001-v2.json      Policy NETWORK versione 2.0

scripts/
  deploy.ts              Bootstrap localhost
  deploy-mainnet.ts      Bootstrap hardhatMainnet
  full_flow.ts           Flusso end-to-end completo
  credential_flow.ts     Dimostrazione VC/VP + CVC
  auditor.ts             Verificabilità indipendente
  external_verifier.ts   Accesso temporaneo EV
  benchmark.ts           Performance evaluation
  ipfs-demo.ts           IPFS reale Helia

test/
  IdentityRegistry.test.ts
  CredentialValidationContract.test.ts
  GovernanceContract.test.ts
  PolicyRegistry.test.ts
  integration.test.ts
```

---

## Semplificazioni del prototipo (documentate nel WP4)

| Componente | Produzione | Prototipo |
|---|---|---|
| IPFS | Cluster reale con full-coverage replication tra 4 PA | Helia in-memory (demo) + SHA-256 simulato (script) |
| Verifica VP | On-chain nell'EVM | Off-chain + registrazione `validationId` on-chain nel CVC |
| Selective disclosure | SD-JWT completo | Hash claim con salt, disclosure parziale nella VP |
| Wallet | Persistente su disco con chiave RSA + ECDH | In-memory per sessione |
| Chiave P-256 | Registrata on-chain nell'IR | Solo off-chain (IR contiene solo chiave RSA) |

**Giustificazione architetturale CVC**: RSA 2048 non è verificabile on-chain nell'EVM senza precompilazioni custom non disponibili in PoA consortium. Il pattern off-chain + `validationId = keccak256-like(vpJwt)` registrato on-chain mantiene la tracciabilità senza sacrificare la fattibilità.
