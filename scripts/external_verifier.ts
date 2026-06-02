/**
 * external_verifier.ts
 * Dimostra l'accesso temporaneo dell'External Verifier — WP2 §4.3.4, §6.4.
 * Scenario: PA autorizza EV (ente certificazione NIS2), EV ispeziona policy NETWORK.
 *
 * ESEGUI:
 * npx hardhat run scripts/external_verifier.ts --network hardhatMainnet
 */

import { network }            from "hardhat";
import { generateEntityKeys } from "../crypto/keys.js";
import { issuePersistentVC, issueTemporaryVC, generateCredentialId } from "../crypto/vc.js";
import { encryptDocument, buildKDDoc, decryptDocument } from "../crypto/hybrid.js";
import { ipfsUpload, ipfsDownload }                      from "../ipfs/ipfs-simulated.js";
import { readFileSync }        from "fs";

const SCOPE_NETWORK = [0] as const;
const ZERO_ID       = `0x${"00".repeat(32)}` as `0x${string}`;
const FUTURE        = 9_999_999_999n;
const Role = { PA: 0, PP: 1, DEG: 2, AUDITOR: 3, AA: 4, EV: 5 };

function separator(title: string) {
  console.log(`\n── ${title} ${"─".repeat(Math.max(0, 60 - title.length))}`);
}

async function main() {
  const { viem } = await network.connect("hardhatMainnet");
  const wallets  = await viem.getWalletClients();
  const [deployer, w_pa1, w_pa2, w_pa3, w_pa4,
         w_aud1, w_aud2, w_pp1, w_deg1, w_aa1, w_ev1] = wallets;

  console.log("\n================================================================");
  console.log("  EXTERNAL VERIFIER — Accesso temporaneo e mirato");
  console.log("  Scenario: ente NIS2 ispeziona policy NETWORK attiva");
  console.log("================================================================");

  // ==========================================================================
  // FASE 0 — SETUP E BOOTSTRAP
  // ==========================================================================
  separator("Fase 0: Setup e bootstrap");

  const PA1  = generateEntityKeys("did:ethr:pa1");
  const PA2  = generateEntityKeys("did:ethr:pa2");
  const PA3  = generateEntityKeys("did:ethr:pa3");
  const PA4  = generateEntityKeys("did:ethr:pa4");
  const AUD1 = generateEntityKeys("did:ethr:aud1");
  const AUD2 = generateEntityKeys("did:ethr:aud2");
  const PP1  = generateEntityKeys("did:ethr:pp1");
  const DEG1 = generateEntityKeys("did:ethr:deg1");
  const AA1  = generateEntityKeys("did:ethr:aa1");
  const EV1  = generateEntityKeys("did:ethr:ev1"); // pairwise DID

  const ir  = await viem.deployContract("IdentityRegistry",             []);
  const gc  = await viem.deployContract("GovernanceContract",           []);
  const cvc = await viem.deployContract("CredentialValidationContract", []);
  const pr  = await viem.deployContract("PolicyRegistry",               []);

  await ir.write.setGovernanceContract([gc.address],    { account: deployer.account });
  await gc.write.setIdentityRegistry([ir.address],      { account: deployer.account });
  await gc.write.setPolicyRegistry([pr.address],        { account: deployer.account });
  await gc.write.setCVC([cvc.address],                  { account: deployer.account });
  await gc.write.setAuditWindowDuration([86400n],       { account: deployer.account });
  
  await cvc.write.setIdentityRegistry([ir.address],     { account: deployer.account });
  await cvc.write.setGovernanceContract([gc.address],   { account: deployer.account });
  await cvc.write.setPolicyRegistry([pr.address],       { account: deployer.account }); // <--- FIX 1: Impostazione PolicyRegistry nel CVC

  await pr.write.setIdentityRegistry([ir.address],      { account: deployer.account });
  await pr.write.setGovernanceContract([gc.address],    { account: deployer.account });
  await pr.write.setCVC([cvc.address],                  { account: deployer.account });

  await ir.write.registerPA([PA1.did, PA1.rsaPublicKeyHex, w_pa1.account.address], { account: deployer.account });
  await ir.write.registerPA([PA2.did, PA2.rsaPublicKeyHex, w_pa2.account.address], { account: deployer.account });
  await ir.write.registerPA([PA3.did, PA3.rsaPublicKeyHex, w_pa3.account.address], { account: deployer.account });
  await ir.write.registerPA([PA4.did, PA4.rsaPublicKeyHex, w_pa4.account.address], { account: deployer.account });
  
  // <--- FIX 2: Generazione Credential IDs e passaggio del 4° parametro obbligatorio per registerAuditor
  const credIdAUD1 = generateCredentialId(PA1.did, AUD1.did, Role.AUDITOR) as `0x${string}`;
  const credIdAUD2 = generateCredentialId(PA1.did, AUD2.did, Role.AUDITOR) as `0x${string}`;
  await ir.write.registerAuditor([AUD1.did, AUD1.rsaPublicKeyHex, w_aud1.account.address, credIdAUD1], { account: deployer.account });
  await ir.write.registerAuditor([AUD2.did, AUD2.rsaPublicKeyHex, w_aud2.account.address, credIdAUD2], { account: deployer.account });

  await pr.write.finalizeBootstrap({ account: deployer.account });
  await cvc.write.finalizeBootstrap({ account: deployer.account });
  await gc.write.finalizeBootstrap({ account: deployer.account });
  await ir.write.finalizeBootstrap({ account: deployer.account });

  const credIdPP1  = generateCredentialId(PA1.did, PP1.did,  Role.PP)  as `0x${string}`;
  const credIdDEG1 = generateCredentialId(PP1.did, DEG1.did, Role.DEG) as `0x${string}`;
  const credIdAA1  = generateCredentialId(PA1.did, AA1.did,  Role.AA)  as `0x${string}`;

  await ir.write.registerDelegated([PP1.did,  PP1.rsaPublicKeyHex,  w_pp1.account.address,  1, 0n,    [0,1,2], credIdPP1],  { account: w_pa1.account });
  await ir.write.registerDelegated([DEG1.did, DEG1.rsaPublicKeyHex, w_deg1.account.address, 2, 0n,    [0],     credIdDEG1], { account: w_pp1.account });
  await ir.write.registerDelegated([AA1.did,  AA1.rsaPublicKeyHex,  w_aa1.account.address,  4, FUTURE, [0],    credIdAA1],  { account: w_pa1.account });

  console.log("  Bootstrap completato");

  // ==========================================================================
  // FASE 1 — CERTIFICAZIONE POLICY NETWORK V1
  // ==========================================================================
  separator("Fase 1: Certificazione policy NETWORK v1");

  const policyJson   = readFileSync("policies/LSP-NETWORK-001-v1.json", "utf8");
  const policy       = JSON.parse(policyJson);
  const safeDefJson  = readFileSync("policies/safe-default-network.json", "utf8");
  const safeDefCid   = ipfsUpload(Buffer.from(safeDefJson));
  const { symmetricKey, encrypted } = encryptDocument(Buffer.from(policyJson));
  const cidPayload   = ipfsUpload(encrypted.ciphertext);
  const deliberativeRecipients = [PA1, PA2, PA3, PA4, PP1];
  const kdDocDelib   = buildKDDoc(symmetricKey, deliberativeRecipients, policy.id);
  const cidKDDelib   = ipfsUpload(Buffer.from(JSON.stringify(kdDocDelib)));

  const { buildVP, generateNonce, computeValidationId } = await import("../crypto/vp.js");
  const vcPP  = issuePersistentVC(PA1.did, PA1.rsaPrivateKeyPem, PP1.did,  Role.PP,  [0,1,2], credIdPP1);
  const vcDEG = issuePersistentVC(PP1.did, PP1.rsaPrivateKeyPem, DEG1.did, Role.DEG, [0],     credIdDEG1);
  const vcAA  = issueTemporaryVC(PA1.did, PA1.rsaPrivateKeyPem, AA1.did, Role.AA, [0], credIdAA1, 365 * 24 * 3600);
  const cvcAddress = cvc.address as string;

  const vpDEG  = buildVP(DEG1.did, DEG1.rsaPrivateKeyPem, cvcAddress, generateNonce(), [vcPP, vcDEG], {});
  const vidDEG = computeValidationId(vpDEG);
  await cvc.write.registerValidation([vidDEG, DEG1.did, Role.DEG, 0, 0n], { account: w_deg1.account });
  await gc.write.submitProposal([cidPayload, cidKDDelib, 0, ZERO_ID, safeDefCid, vidDEG], { account: w_deg1.account });

  const events     = await gc.getEvents.ProposalSubmitted();
  const proposalId = events[events.length - 1].args.proposalId as `0x${string}`;

  const vpPP  = buildVP(PP1.did, PP1.rsaPrivateKeyPem, cvcAddress, generateNonce(), [vcPP], {});
  const vidPP = computeValidationId(vpPP);
  await cvc.write.registerValidation([vidPP, PP1.did, Role.PP, 0, 0n], { account: w_pp1.account });
  await gc.write.forwardProposal([proposalId, vidPP], { account: w_pp1.account });
  await gc.write.endorseProposal([proposalId], { account: w_pa1.account });
  await gc.write.voteProposal([proposalId, true], { account: w_pa1.account });
  await gc.write.voteProposal([proposalId, true], { account: w_pa2.account });
  await gc.write.voteProposal([proposalId, true], { account: w_pa3.account });

  const fullRecipients = [PA1, PA2, PA3, PA4, PP1, AUD1, AUD2, AA1];
  const kdDocFull      = buildKDDoc(symmetricKey, fullRecipients, policy.id);
  const cidKDFull      = ipfsUpload(Buffer.from(JSON.stringify(kdDocFull)));
  await pr.write.updateKeyDistrib([proposalId, cidKDFull], { account: w_pa1.account });

  // <--- FIX 3: Generazione, firma e registrazione validationId temporaneo per l'Application Agent prima di confirmEnforcement
  const nonceAA = generateNonce();
  const vpAA    = buildVP(AA1.did, AA1.rsaPrivateKeyPem, cvcAddress, nonceAA, [vcAA], {});
  const vidAA   = computeValidationId(vpAA);
  await cvc.write.registerValidation([vidAA, AA1.did, Role.AA, 0, 0n], { account: w_aa1.account });

  const record = await pr.read.getPolicy([proposalId]);
  
  // <--- FIX 4: Passaggio del 3° parametro (vidAA) richiesto per la firma a 3 parametri di confirmEnforcement
  await pr.write.confirmEnforcement([proposalId, record.cid, vidAA], { account: w_aa1.account });

  console.log(`  Policy v1 certificata: ${proposalId.substring(0, 18)}...`);

  // ==========================================================================
  // FASE 2 — PA AUTORIZZA EXTERNAL VERIFIER
  // ==========================================================================
  separator("Fase 2: PA autorizza External Verifier (pairwise DID)");

  const pub        = await viem.getPublicClient();
  const block      = await pub.getBlock({ blockTag: "latest" });
  const expiresAt  = block.timestamp + 15n; // 15 secondi per la demo
  const credIdEV1  = generateCredentialId(PA1.did, EV1.did, Role.EV) as `0x${string}`;

  const vcEV1 = issueTemporaryVC(
    PA1.did, PA1.rsaPrivateKeyPem, EV1.did,
    Role.EV, [0], credIdEV1, 15
  );

  await ir.write.registerDelegated(
    [EV1.did, EV1.rsaPublicKeyHex, w_ev1.account.address, 5, expiresAt, [0], credIdEV1],
    { account: w_pa1.account }
  );

  console.log(`  EV registrato: DID=${EV1.did} (pairwise, monouso)`);
  console.log(`  TemporaryVC emessa: scadenza 15 secondi`);
  console.log(`  isActive(EV): ${await ir.read.isActive([EV1.did]) ? "✓ true" : "✗ false"}`);

  // ==========================================================================
  // FASE 3 — PA AGGIORNA KD DOC
  // ==========================================================================
  separator("Fase 3: PA aggiorna KD doc includendo EV");

  const recipientsWithEV = [PA1, PA2, PA3, PA4, PP1, AUD1, AUD2, AA1, EV1];
  const kdDocWithEV      = buildKDDoc(symmetricKey, recipientsWithEV, policy.id);
  const cidKDWithEV      = ipfsUpload(Buffer.from(JSON.stringify(kdDocWithEV)));
  await pr.write.updateKeyDistrib([proposalId, cidKDWithEV], { account: w_pa1.account });

  console.log(`  KD doc aggiornato con EV (${recipientsWithEV.length} destinatari)`);

  // ==========================================================================
  // FASE 4 — EV ACCEDE AL DOCUMENTO
  // ==========================================================================
  separator("Fase 4: EV accede al documento durante la validità");

  const isActiveBefore = await ir.read.isActive([EV1.did]);
  console.log(`  isActive(EV) prima della scadenza: ${isActiveBefore ? "✓ true" : "✗ false"}`);

  const activeRecord   = await pr.read.getActivePolicyRecord([0]);
  const kdDocCurrent   = JSON.parse(ipfsDownload(activeRecord.cidKeyDistrib).toString());
  const payloadCurrent = ipfsDownload(activeRecord.cid);

  try {
    const decrypted  = decryptDocument(EV1, kdDocCurrent, { ciphertext: payloadCurrent, iv: encrypted.iv, authTag: encrypted.authTag });
    const inspected  = JSON.parse(decrypted.toString());
    console.log(`  EV ha decifrato il documento: ✓`);
    console.log(`  Policy: ${inspected.id} v${inspected.version} — ${inspected.rules.length} regole`);
    inspected.rules.forEach((r: any) => {
      console.log(`    → ${r.eventType.padEnd(28)} retention: ${r.retention}`);
    });
  } catch (e: any) {
    console.log(`  ✗ Errore decifratura: ${e.message}`);
  }

  // ==========================================================================
  // FASE 5 — SCADENZA TEMPORARYVC
  // ==========================================================================
  separator("Fase 5: Scadenza TemporaryVC → accesso bloccato");

  const testClient = await viem.getTestClient();
  await testClient.increaseTime({ seconds: 16 });
  await testClient.mine({ blocks: 1 });

  const isActiveAfter = await ir.read.isActive([EV1.did]);
  console.log(`  isActive(EV) dopo la scadenza: ${isActiveAfter ? "✗ true (ERRORE)" : "✓ false (scaduto)"}`);

  try {
    if (!isActiveAfter) throw new Error("DID scaduto: TemporaryVC non più valida");
    decryptDocument(EV1, kdDocCurrent, { ciphertext: payloadCurrent, iv: encrypted.iv, authTag: encrypted.authTag });
    console.log("  ✗ ERRORE: accesso consentito dopo scadenza");
  } catch (e: any) {
    console.log(`  ✓ Accesso bloccato: ${e.message}`);
  }

  // ==========================================================================
  // FASE 6 — REVOCA ANTICIPATA E SOSTITUZIONE
  // ==========================================================================
  separator("Fase 6: Revoca anticipata e sostituzione EV");

  await ir.write.revokeDID([EV1.did], { account: w_pa1.account });
  console.log(`  PA ha revocato EV1. Indirizzo ${w_ev1.account.address.substring(0,10)}... liberato`);

  const EV2       = generateEntityKeys("did:ethr:ev2");
  const credIdEV2 = generateCredentialId(PA1.did, EV2.did, Role.EV) as `0x${string}`;
  const block2    = await pub.getBlock({ blockTag: "latest" });

  await ir.write.registerDelegated(
    [EV2.did, EV2.rsaPublicKeyHex, w_ev1.account.address, 5, block2.timestamp + 86400n, [0], credIdEV2],
    { account: w_pa1.account }
  );

  console.log(`  EV2 registrato sullo stesso indirizzo con nuovo DID: ${EV2.did}`);
  console.log(`  isActive(EV2): ${await ir.read.isActive([EV2.did]) ? "✓ true" : "✗ false"}`);

  // ==========================================================================
  // RIEPILOGO
  // ==========================================================================
  separator("RIEPILOGO");
  console.log(`
  1. TEMPORARYVC E PAIRWISE DID (WP2 §4.1.2, §4.3.4)
     PA ha emesso TemporaryVC con scadenza esplicita a EV (pairwise DID).

  2. AGGIORNAMENTO KD DOC (WP2 §3.3)
     PA ha aggiornato il KD doc includendo EV senza nuova deliberazione.

  3. ACCESSO DURANTE VALIDITÀ (WP2 §4.7)
     EV ha decifrato il documento policy nel periodo autorizzato.

  4. BLOCCO AUTOMATICO ALLA SCADENZA (WP2 §4.3.4)
     isActive(EV.did) == false dopo la scadenza. Nessuna manutenzione richiesta.

  5. REVOCA E SOSTITUZIONE (WP2 §4.5.2)
     Revoca formale libera l'indirizzo PAIRWISE per la sostituzione con EV2.
  `);
}

main().catch((err) => { console.error(err); process.exit(1); });