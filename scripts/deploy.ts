/**
 * deploy.ts
 * Bootstrap completo su rete locale (localhost).
 * Richiede: npx hardhat node in un terminale separato.
 *
 * ESEGUI:
 * npx hardhat run scripts/deploy.ts --network localhost
 */

import { createPublicClient, createWalletClient, http } from "viem";
import { hardhat }             from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync, writeFileSync } from "fs";
import { resolve }             from "path";
import { generateEntityKeys }  from "../crypto/keys.js";
import { generateCredentialId } from "../crypto/vc.js"; // <--- IMPORT AGGIUNTO

// Account Hardhat default
const ACCOUNTS = [
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
  "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
  "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
  "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
];

const chain     = { ...hardhat, rpcUrls: { default: { http: ["http://127.0.0.1:8545"] } } };
const transport = http("http://127.0.0.1:8545");
const pubClient = createPublicClient({ chain, transport });

function getWallet(index: number) {
  const account = privateKeyToAccount(ACCOUNTS[index] as `0x${string}`);
  return createWalletClient({ account, chain, transport });
}

function loadArtifact(name: string) {
  const path = resolve(`artifacts/contracts/${name}.sol/${name}.json`);
  return JSON.parse(readFileSync(path, "utf8"));
}

async function deploy(wallet: any, name: string) {
  const artifact = loadArtifact(name);
  const hash     = await wallet.deployContract({ abi: artifact.abi, bytecode: artifact.bytecode, args: [] });
  const receipt  = await pubClient.waitForTransactionReceipt({ hash });
  return { address: receipt.contractAddress as `0x${string}`, abi: artifact.abi };
}

async function write(wallet: any, contract: any, functionName: string, args: any[] = []) {
  const hash = await wallet.writeContract({ address: contract.address, abi: contract.abi, functionName, args });
  await pubClient.waitForTransactionReceipt({ hash });
}

async function main() {
  const deployer = getWallet(0);
  const [pa1, pa2, pa3, pa4, aud1, aud2] = [1,2,3,4,5,6].map(getWallet);

  console.log("Deployer:", deployer.account.address);
  console.log("─────────────────────────────────────");

  // Genera chiavi RSA per PA e Auditor (registrate on-chain nell'IR)
  const PA1  = generateEntityKeys("did:ethr:pa1");
  const PA2  = generateEntityKeys("did:ethr:pa2");
  const PA3  = generateEntityKeys("did:ethr:pa3");
  const PA4  = generateEntityKeys("did:ethr:pa4");
  const AUD1 = generateEntityKeys("did:ethr:aud1");
  const AUD2 = generateEntityKeys("did:ethr:aud2");

  // 1. Deploy
  const IR  = await deploy(deployer, "IdentityRegistry");
  console.log("✓ IdentityRegistry:            ", IR.address);
  const GC  = await deploy(deployer, "GovernanceContract");
  console.log("✓ GovernanceContract:          ", GC.address);
  const CVC = await deploy(deployer, "CredentialValidationContract");
  console.log("✓ CredentialValidationContract:", CVC.address);
  const PR  = await deploy(deployer, "PolicyRegistry");
  console.log("✓ PolicyRegistry:              ", PR.address);

  console.log("─────────────────────────────────────");

  // 2. Wiring
  await write(deployer, IR,  "setGovernanceContract",  [GC.address]);
  await write(deployer, GC,  "setIdentityRegistry",    [IR.address]);
  await write(deployer, GC,  "setPolicyRegistry",      [PR.address]);
  await write(deployer, GC,  "setCVC",                 [CVC.address]);
  await write(deployer, GC,  "setAuditWindowDuration", [BigInt(30 * 24 * 60 * 60)]);
  
  await write(deployer, CVC, "setIdentityRegistry",     [IR.address]);
  await write(deployer, CVC, "setGovernanceContract",   [GC.address]);
  await write(deployer, CVC, "setPolicyRegistry",       [PR.address]); // <--- FIX 1: Impostazione PolicyRegistry nel CVC
  
  await write(deployer, PR,  "setIdentityRegistry",    [IR.address]);
  await write(deployer, PR,  "setGovernanceContract",  [GC.address]);
  await write(deployer, PR,  "setCVC",                 [CVC.address]); // <--- FIX 2: Impostazione CVC nel PolicyRegistry
  console.log("✓ Wiring completato");

  console.log("─────────────────────────────────────");

  // 4. Registrazione PA e Auditor (chiave RSA pubblica in hex on-chain)
  // Nota: Spostato PRIMA dei finalize perché l'IdentityRegistry richiede la presenza dei PA e degli Auditor per finalizzarsi
  await write(deployer, IR, "registerPA", ["did:ethr:pa1", PA1.rsaPublicKeyHex, pa1.account.address]);
  await write(deployer, IR, "registerPA", ["did:ethr:pa2", PA2.rsaPublicKeyHex, pa2.account.address]);
  await write(deployer, IR, "registerPA", ["did:ethr:pa3", PA3.rsaPublicKeyHex, pa3.account.address]);
  await write(deployer, IR, "registerPA", ["did:ethr:pa4", PA4.rsaPublicKeyHex, pa4.account.address]);

  // FIX 3: Generazione dei CredentialID per soddisfare la firma a 4 parametri dei contratti aggiornati
  const credIdAUD1 = generateCredentialId("did:ethr:pa1", "did:ethr:aud1", 3) as `0x${string}`;
  const credIdAUD2 = generateCredentialId("did:ethr:pa1", "did:ethr:aud2", 3) as `0x${string}`;

  await write(deployer, IR, "registerAuditor", ["did:ethr:aud1", AUD1.rsaPublicKeyHex, aud1.account.address, credIdAUD1]);
  await write(deployer, IR, "registerAuditor", ["did:ethr:aud2", AUD2.rsaPublicKeyHex, aud2.account.address, credIdAUD2]);
  console.log("✓ PA e Auditor registrati con Credential ID");

  // 3. Finalize di tutti i moduli di core
  await write(deployer, PR,  "finalizeBootstrap", []);
  await write(deployer, CVC, "finalizeBootstrap", []);
  await write(deployer, GC,  "finalizeBootstrap", []);
  await write(deployer, IR,  "finalizeBootstrap", []);
  console.log("✓ Tutti i contratti finalizzati (Stato PostBootstrap)");

  console.log("─────────────────────────────────────");

  const deployment = {
    network:   "localhost",
    timestamp: new Date().toISOString(),
    contracts: {
      IdentityRegistry:             IR.address,
      GovernanceContract:           GC.address,
      CredentialValidationContract: CVC.address,
      PolicyRegistry:               PR.address,
    },
    accounts: {
      deployer: deployer.account.address,
      pa1: pa1.account.address,
      pa2: pa2.account.address,
      pa3: pa3.account.address,
      pa4: pa4.account.address,
      aud1: aud1.account.address,
      aud2: aud2.account.address,
    },
    dids: {
      pa1: "did:ethr:pa1", pa2: "did:ethr:pa2",
      pa3: "did:ethr:pa3", pa4: "did:ethr:pa4",
      aud1: "did:ethr:aud1", aud2: "did:ethr:aud2",
    }
  };

  writeFileSync("deployment.json", JSON.stringify(deployment, null, 2));
  console.log("✓ deployment.json salvato");
  console.log("Bootstrap completato locale eseguito con successo.");
  console.log(deployment.contracts);
}

main().catch((err) => { console.error(err); process.exit(1); });