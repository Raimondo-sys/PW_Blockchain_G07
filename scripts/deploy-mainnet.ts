/**
 * deploy-mainnet.ts
 * Script di deployment e cablaggio iniziale (Bootstrap) dei contratti sulla rete.
 *
 * ESEGUI:
 * npx hardhat run scripts/deploy-mainnet.ts --network hardhatMainnet
 */

import { network }            from "hardhat";
import { generateEntityKeys } from "../crypto/keys.js";
import { generateCredentialId } from "../crypto/vc.js";

const Role = { PA: 0, PP: 1, DEG: 2, AUDITOR: 3, AA: 4, EV: 5 };

async function main() {
  const { viem } = await network.connect("hardhatMainnet");
  const wallets  = await viem.getWalletClients();
  const [deployer, w_pa1, w_pa2, w_pa3, w_pa4, w_aud1, w_aud2] = wallets;

  console.log(`Deployer: ${deployer.account.address}`);
  console.log("─────────────────────────────────────");

  // 1. DEPLOY DEI CONTRATTI
  const ir  = await viem.deployContract("IdentityRegistry",             []);
  const gc  = await viem.deployContract("GovernanceContract",           []);
  const cvc = await viem.deployContract("CredentialValidationContract", []);
  const pr  = await viem.deployContract("PolicyRegistry",               []);

  console.log(`✓ IdentityRegistry:             ${ir.address}`);
  console.log(`✓ GovernanceContract:           ${gc.address}`);
  console.log(`✓ CredentialValidationContract: ${cvc.address}`);
  console.log(`✓ PolicyRegistry:               ${pr.address}`);
  console.log("─────────────────────────────────────");

  // 2. WIRING DEI CONTRATTI (Collegamenti reciproci)
  await ir.write.setGovernanceContract([gc.address],    { account: deployer.account });
  
  await gc.write.setIdentityRegistry([ir.address],      { account: deployer.account });
  await gc.write.setPolicyRegistry([pr.address],        { account: deployer.account });
  await gc.write.setCVC([cvc.address],                  { account: deployer.account });
  await gc.write.setAuditWindowDuration([86400n],       { account: deployer.account }); // 24 ore di finestra
  
  await cvc.write.setIdentityRegistry([ir.address],     { account: deployer.account });
  await cvc.write.setGovernanceContract([gc.address],   { account: deployer.account });
  await cvc.write.setPolicyRegistry([pr.address],       { account: deployer.account }); // <--- FIX INSERITO QUI!
  
  await pr.write.setIdentityRegistry([ir.address],      { account: deployer.account });
  await pr.write.setGovernanceContract([gc.address],    { account: deployer.account });
  await pr.write.setCVC([cvc.address],                  { account: deployer.account });

  console.log("✓ Wiring completato");
  console.log("─────────────────────────────────────");

  // 3. REGISTRAZIONI OBBLIGATORIE DI GENESIS (Richieste dall'IdentityRegistry per chiudere il bootstrap)
  // Generiamo al volo dei DID/Chiavi di test per PA e Auditor iniziali per soddisfare i requisiti dei contratti
  const PA1 = generateEntityKeys("did:ethr:pa1");
  const PA2 = generateEntityKeys("did:ethr:pa2");
  const PA3 = generateEntityKeys("did:ethr:pa3");
  const PA4 = generateEntityKeys("did:ethr:pa4");
  const AUD1 = generateEntityKeys("did:ethr:aud1");
  const AUD2 = generateEntityKeys("did:ethr:aud2");

  await ir.write.registerPA([PA1.did, PA1.rsaPublicKeyHex, w_pa1.account.address], { account: deployer.account });
  await ir.write.registerPA([PA2.did, PA2.rsaPublicKeyHex, w_pa2.account.address], { account: deployer.account });
  await ir.write.registerPA([PA3.did, PA3.rsaPublicKeyHex, w_pa3.account.address], { account: deployer.account });
  await ir.write.registerPA([PA4.did, PA4.rsaPublicKeyHex, w_pa4.account.address], { account: deployer.account });

  const credIdAUD1 = generateCredentialId(PA1.did, AUD1.did, Role.AUDITOR) as `0x${string}`;
  const credIdAUD2 = generateCredentialId(PA1.did, AUD2.did, Role.AUDITOR) as `0x${string}`;
  
  await ir.write.registerAuditor([AUD1.did, AUD1.rsaPublicKeyHex, w_aud1.account.address, credIdAUD1], { account: deployer.account });
  await ir.write.registerAuditor([AUD2.did, AUD2.rsaPublicKeyHex, w_aud2.account.address, credIdAUD2], { account: deployer.account });

  console.log("✓ Entità di Genesis registrate (4 PA + 2 Auditor)");
  console.log("─────────────────────────────────────");

  // 4. FINALIZZAZIONE DEL BOOTSTRAP (Chiusura dello stato di configurazione)
  await pr.write.finalizeBootstrap({ account: deployer.account });
  await cvc.write.finalizeBootstrap({ account: deployer.account }); // <--- RIGA 57 (Ora passerà senza revert!)
  await gc.write.finalizeBootstrap({ account: deployer.account });
  await ir.write.finalizeBootstrap({ account: deployer.account });

  console.log("✓ Bootstrap finalizzato con successo! Rete pronta per la produzione.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});