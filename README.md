# 🔐 Decentralized Governance for Logging Security Policy

<div align="center">

![Solidity](https://img.shields.io/badge/Solidity-0.8.28-363636?style=for-the-badge&logo=solidity)
![Hardhat](https://img.shields.io/badge/Hardhat-3.7.0-f7dc6f?style=for-the-badge&logo=hardhat)
![TypeScript](https://img.shields.io/badge/TypeScript-6.x-3178c6?style=for-the-badge&logo=typescript)
![Tests](https://img.shields.io/badge/Tests-52%2F52%20passing-2ecc71?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

**Sistema di governance decentralizzata per la gestione delle Logging Security Policy su blockchain EVM PoA**

*Università di Salerno — Blockchain & Cybersecurity 2025/2026*

</div>

---

## 📋 Panoramica

Il sistema implementa un meccanismo di governance decentralizzata per la gestione del ciclo di vita delle **Logging Security Policy** in un consorzio enterprise. Nessun attore singolo ha autorità unilaterale — ogni decisione richiede una delibera a **quorum 3/4** delle Policy Authority attive.

```
DEG sottomette proposta  →  PP verifica e inoltra  →  PA endorse  →  PA votano (3/4)  →  Policy certificata
                                                                                              ↓
                                                                              AA scarica, verifica CID, applica
```

---

## 🏗️ Architettura

```
┌─────────────────────────────────────────────────────────────────┐
│                         EVM PoA Consortium                      │
│                                                                 │
│  ┌──────────────────┐         ┌────────────────────────────┐    │
│  │ IdentityRegistry │◄────────│    GovernanceContract      │    │
│  │                  │         │                            │    │
│  │  DID lifecycle   │         │  Proposte + Votazione      │    │
│  │  Ruoli e deleghe │         │  Governance consorzio      │    │
│  │  Chiavi RSA      │         │  Quorum 3/4                │    │
│  └──────────────────┘         └────────────────────────────┘    │
│                                          │                      │
│  ┌───────────────────────────┐           │                      │
│  │ CredentialValidationContr.│◄──────────┤                      │
│  │                           │           │                      │
│  │  validationId on-chain    │           │                      │
│  │  Anti-replay TTL 5 min    │           ▼                      │
│  │  Adattatore crittografico │   ┌─────────────────┐            │
│  └───────────────────────────┘   │  PolicyRegistry │            │
│                                  │                 │            │
│                                  │  Active         │            │
│                                  │  → Archived     │            │
│                                  │  → Retired      │            │
│                                  └─────────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

---

## ⚙️ Stack Tecnologico

| Layer | Tecnologia | Versione |
|---|---|---|
| Framework blockchain | Hardhat | 3.7.0 |
| Client EVM | Viem | 2.x |
| Linguaggio | TypeScript | 6.x |
| Identità (VC/VP) | JWT RS256 — jsonwebtoken | 9.x |
| Cifratura payload | AES-256-GCM + ECDH P-256 | Node crypto |
| Storage | IPFS simulato SHA-256 + Helia PoC | — |
| Analisi statica | Slither | 0.11.5 |

---

## 🚀 Installazione

```bash
# Clona la repository
git clone https://github.com/TUO_USERNAME/NOME_REPO.git
cd NOME_REPO

# Installa le dipendenze
npm install

# Compila i contratti
npx hardhat compile
```

---

## 🧪 Test

```bash
npx hardhat test
```

```
  CredentialValidationContract   8 passing
  GovernanceContract            11 passing
  IdentityRegistry              16 passing
  Integration                    5 passing
  PolicyRegistry                12 passing
  ─────────────────────────────────────────
  52 passing — 0 failing
```

---

## ▶️ Esecuzione

```bash
# Deploy su rete simulata autonoma
npx hardhat run scripts/deploy-mainnet.ts --network hardhatMainnet

# Flusso end-to-end completo (v1 → v2 → RetirePolicy)
npx hardhat run scripts/full_flow.ts --network hardhatMainnet

# Dimostrazione VC/VP JWT RS256 + selective disclosure
npx hardhat run scripts/credential_flow.ts --network hardhatMainnet

# Auditor — verifica indipendente con finestra di audit
npx hardhat run scripts/auditor.ts --network hardhatMainnet

# External Verifier — accesso temporaneo con pairwise DID
npx hardhat run scripts/external_verifier.ts --network hardhatMainnet

# Benchmark — gas, latency, storage overhead
npx hardhat run scripts/benchmark.ts --network hardhatMainnet
```

---

## 🔒 Proprietà di Sicurezza

| Proprietà | Meccanismo | THA coperta |
|---|---|---|
| Anti-double voting | `_proposalVotes` mapping per DID | THA-4 |
| Policy injection | `onlyGovernance` nel PolicyRegistry | THA-1 |
| Revoca lazy cascade | Flag `active = false`, costo O(1) | THA-5 |
| Anti-replay | `validationId` monouso con TTL 5 min | THA-6, THA-7 |
| Storia immutabile | Append-only nel PolicyRegistry | THA-11 |
| Quorum snapshot | Acquisito all'endorsement, immutabile | THA-3 |
| Deadlock PA | `replacePAByGovernance` atomico | THA-2 |

---

## 📊 Risultati

```
✅  52 / 52  test automatici passing
🔍   0 / 58  finding di severità High (Slither 0.11.5)
⛽  2.617.904 gas — ciclo vita completo policy
⚡    < 20 ms — flusso off-chain (VC + VP + validationId)
📦  423 SLOC  — contratto più grande (GovernanceContract)
```

---

## 📁 Struttura del Progetto

```
contracts/
  IdentityRegistry.sol               DID lifecycle, RSA pubkey on-chain
  CredentialValidationContract.sol   Registrazione validationId on-chain
  GovernanceContract.sol             Ciclo vita proposte + governance
  PolicyRegistry.sol                 Registro permanente policy

crypto/
  keys.ts      Generazione RSA 2048 + ECDH P-256
  vc.ts        Emissione e verifica VC — JWT RS256
  vp.ts        Costruzione VP con selective disclosure
  hybrid.ts    Cifratura ibrida AES-256-GCM + ECDH P-256

ipfs/
  ipfs-simulated.ts   IPFS simulato SHA-256 (script e test)
  helia-node.ts       IPFS reale Helia in-memory (PoC)

scripts/
  deploy-mainnet.ts      Bootstrap autonomo su hardhatMainnet
  full_flow.ts           Flusso end-to-end completo
  credential_flow.ts     Dimostrazione VC/VP + CVC
  auditor.ts             Verifica indipendente Auditor
  external_verifier.ts   Accesso temporaneo EV
  benchmark.ts           Performance evaluation

test/
  IdentityRegistry.test.ts
  CredentialValidationContract.test.ts
  GovernanceContract.test.ts
  PolicyRegistry.test.ts
  integration.test.ts

policies/
  safe-default-network.json
  LSP-NETWORK-001-v1.json
  LSP-NETWORK-001-v2.json
```

---

## 👥 Autori

Progetto di gruppo — Università di Salerno
Corso: Blockchain e Cybersecurity — A.A. 2025/2026

---

<div align="center">
  <sub>Built with ❤️ on Hardhat · Solidity · TypeScript</sub>
</div>
