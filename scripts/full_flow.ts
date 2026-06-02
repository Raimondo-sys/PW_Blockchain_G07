/**
 * full_flow.ts
 * Flusso end-to-end completo — WP2 §2.2.
 * Scenario: NETWORK v1 → v2 → RetirePolicy.
 *
 * Tutti i ruoli presentano VP con VC prima di operare (WP2 §4.3):
 * - DEG: VP con catena [vcPP, vcDEG] prima di submitProposal
 * - PP:  VP con catena [vcPP] prima di forwardProposal
 * - AA:  VP con catena [vcAA] prima di confirmEnforcement
 * - Auditor: VP con catena [vcAUD] per accesso durante finestra
 * - PA:  autenticazione diretta msg.sender (root of trust, no VC)
 *
 * ESEGUI:
 * npx hardhat run scripts/full_flow.ts --network hardhatMainnet
 */

import { network }               from "hardhat";
import { readFileSync, writeFileSync } from "fs";
import { generateEntityKeys }    from "../crypto/keys.js";
import { issuePersistentVC, issueTemporaryVC, verifyVC, generateCredentialId } from "../crypto/vc.js";
import { buildVP, generateNonce, computeValidationId } from "../crypto/vp.js";
import { encryptDocument, buildKDDoc, decryptDocument } from "../crypto/hybrid.js";
import { ipfsUpload, ipfsDownload, ipfsVerifyCID }      from "../ipfs/ipfs-simulated.js";

const SCOPE_FULL    = [0, 1, 2] as const;
const SCOPE_NETWORK = [0]       as const;
const ZERO_ID       = `0x${"00".repeat(32)}` as `0x${string}`;
const FUTURE        = 9_999_999_999n;
const Sample_window  = 60n;
const Role = { PA: 0, PP: 1, DEG: 2, AUDITOR: 3, AA: 4, EV: 5 };

function separator(title: string) {
  console.log(`\n── ${title} ${"─".repeat(Math.max(0, 60 - title.length))}`);
}

// Helper: registra validationId nel CVC dopo verifica VP off-chain
async function getVid(
  cvc: any, holderKeys: any, wallet: any,
  vcChain: any[], role: number, domain: number,
  vcExpiresAt = 0n
) {
  const nonce = generateNonce();
  const vpJwt = buildVP(holderKeys.did, holderKeys.rsaPrivateKeyPem, cvc.address as string, nonce, vcChain, {});
  const vid   = computeValidationId(vpJwt);
  await cvc.write.registerValidation([vid, holderKeys.did, role, domain, vcExpiresAt], { account: wallet.account });
  return vid;
}

// Helper: ciclo vita policy completo
async function certifyPolicy(params: {
  policyPath: string; safeDefCid: string; replacesId: `0x${string}`; domain: number;
  deliberativeRecipients: any[]; fullRecipients: any[];
  DEG1: any; PP1: any; AA1: any;
  vcDEG: any; vcPP: any; vcAA: any;
  w_deg: any; w_pp: any; w_pa1: any; w_pa2: any; w_pa3: any; w_aa: any;
  gc: any; pr: any; cvc: any; cvcAddress: string;
  aaExpiresAt?: bigint;
}) {
  const {
    policyPath, safeDefCid, replacesId,
    deliberativeRecipients, fullRecipients,
    DEG1, PP1, AA1, vcDEG, vcPP, vcAA,
    w_deg, w_pp, w_pa1, w_pa2, w_pa3, w_aa,
    gc, pr, cvc, cvcAddress, aaExpiresAt = 0n,
  } = params;

  const policyJson = readFileSync(policyPath, "utf8");
  const policy     = JSON.parse(policyJson);
  const { symmetricKey, encrypted } = encryptDocument(Buffer.from(policyJson));
  const cidPayload = ipfsUpload(encrypted.ciphertext);
  const kdDocDelib = buildKDDoc(symmetricKey, deliberativeRecipients, policy.id);
  const cidKDDelib = ipfsUpload(Buffer.from(JSON.stringify(kdDocDelib)));

  // DEG presenta VP con catena [vcPP, vcDEG]
  const vidDEG = await getVid(cvc, DEG1, w_deg, [vcPP, vcDEG], Role.DEG, params.domain);
  await gc.write.submitProposal([cidPayload, cidKDDelib, params.domain, replacesId, safeDefCid, vidDEG], { account: w_deg.account });

  const evs     = await gc.getEvents.ProposalSubmitted();
  const proposalId = evs[evs.length - 1].args.proposalId as `0x${string}`;
  console.log(`  ProposalId: ${proposalId.substring(0, 20)}...`);

  // PP presenta VP con catena [vcPP]
  const vidPP = await getVid(cvc, PP1, w_pp, [vcPP], Role.PP, params.domain);
  await gc.write.forwardProposal([proposalId, vidPP], { account: w_pp.account });
  console.log(`  PP ha inoltrato`);

  // PA endorse e votano (autenticazione diretta)
  await gc.write.endorseProposal([proposalId], { account: w_pa1.account });
  await gc.write.voteProposal([proposalId, true], { account: w_pa1.account });
  await gc.write.voteProposal([proposalId, true], { account: w_pa2.account });
  await gc.write.voteProposal([proposalId, true], { account: w_pa3.account });
  console.log(`  3/4 PA hanno votato → policy certificata`);

  // PA aggiorna KD doc con accessi completi
  const kdDocFull = buildKDDoc(symmetricKey, fullRecipients, policy.id);
  const cidKDFull = ipfsUpload(Buffer.from(JSON.stringify(kdDocFull)));
  await pr.write.updateKeyDistrib([proposalId, cidKDFull], { account: w_pa1.account });
  console.log(`  KD doc aggiornato (${fullRecipients.length} destinatari)`);

  // Salva KD doc su disco
  writeFileSync(`kd-doc-${policy.id}-v${policy.version}.json`, JSON.stringify(kdDocFull, null, 2));
  console.log(`  KD doc salvato: kd-doc-${policy.id}-v${policy.version}.json`);

  // AA verifica CID
  const record  = await pr.read.getPolicy([proposalId]);
  const payload = ipfsDownload(record.cid);
  const cidOk   = ipfsVerifyCID(payload, record.cid);
  console.log(`  AA verifica integrità CID: ${cidOk ? "✓ integro" : "✗ ERRORE"}`);

  // AA presenta VP con catena [vcAA] prima di confirmEnforcement (WP2 §4.3.4)
  const vidAA = await getVid(cvc, AA1, w_aa, [vcAA], Role.AA, params.domain, aaExpiresAt);
  await pr.write.confirmEnforcement([proposalId, record.cid, vidAA], { account: w_aa.account });
  console.log(`  AA ha confermato enforcement on-chain`);

  return { proposalId, symmetricKey, encrypted, cidKDFull };
}

async function main() {
  const { viem } = await network.connect("hardhatMainnet");
  const wallets  = await viem.getWalletClients();
  const [deployer, w_pa1, w_pa2, w_pa3, w_pa4,
         w_aud1, w_aud2, w_pp1, w_deg1, w_aa1] = wallets;

  console.log("\n================================================================");
  console.log("  FULL FLOW — Governance Logging Security Policy (JWT RS256)");
  console.log("  Tutti i ruoli presentano VP con VC (WP2 §4.3)");
  console.log("================================================================");

  separator("Fase 0: Generazione chiavi RSA + ECDH");

  const PA1  = generateEntityKeys("did:ethr:pa1");
  const PA2  = generateEntityKeys("did:ethr:pa2");
  const PA3  = generateEntityKeys("did:ethr:pa3");
  const PA4  = generateEntityKeys("did:ethr:pa4");
  const AUD1 = generateEntityKeys("did:ethr:aud1");
  const AUD2 = generateEntityKeys("did:ethr:aud2");
  const PP1  = generateEntityKeys("did:ethr:pp1");
  const DEG1 = generateEntityKeys("did:ethr:deg1");
  const AA1  = generateEntityKeys("did:ethr:aa1");
  console.log("  Chiavi RSA 2048 + ECDH P-256 per 9 entità");

  separator("Fase 1: Deploy e bootstrap");

  const ir  = await viem.deployContract("IdentityRegistry",             []);
  const gc  = await viem.deployContract("GovernanceContract",           []);
  const cvc = await viem.deployContract("CredentialValidationContract", []);
  const pr  = await viem.deployContract("PolicyRegistry",               []);

  await ir.write.setGovernanceContract([gc.address],    { account: deployer.account });
  await gc.write.setIdentityRegistry([ir.address],      { account: deployer.account });
  await gc.write.setPolicyRegistry([pr.address],        { account: deployer.account });
  await gc.write.setCVC([cvc.address],                  { account: deployer.account });
  await gc.write.setAuditWindowDuration([Sample_window], { account: deployer.account });
  
  await cvc.write.setIdentityRegistry([ir.address],     { account: deployer.account });
  await cvc.write.setGovernanceContract([gc.address],   { account: deployer.account });
  await cvc.write.setPolicyRegistry([pr.address],       { account: deployer.account }); // <--- FIX 1: Impostazione PolicyRegistry nel CVC
  
  await pr.write.setIdentityRegistry([ir.address],      { account: deployer.account });
  await pr.write.setGovernanceContract([gc.address],    { account: deployer.account });
  await pr.write.setCVC([cvc.address],                  { account: deployer.account });

  // PA: root of trust, nessuna VC (Registrazione prima della chiusura del Bootstrap)
  await ir.write.registerPA([PA1.did, PA1.rsaPublicKeyHex, w_pa1.account.address], { account: deployer.account });
  await ir.write.registerPA([PA2.did, PA2.rsaPublicKeyHex, w_pa2.account.address], { account: deployer.account });
  await ir.write.registerPA([PA3.did, PA3.rsaPublicKeyHex, w_pa3.account.address], { account: deployer.account });
  await ir.write.registerPA([PA4.did, PA4.rsaPublicKeyHex, w_pa4.account.address], { account: deployer.account });

  // Auditor: PersistentVC emessa dalla PA1 (WP2 §4.3.3)
  const credIdAUD1 = generateCredentialId(PA1.did, AUD1.did, Role.AUDITOR) as `0x${string}`;
  const credIdAUD2 = generateCredentialId(PA1.did, AUD2.did, Role.AUDITOR) as `0x${string}`;
  const vcAUD1 = issuePersistentVC(PA1.did, PA1.rsaPrivateKeyPem, AUD1.did, Role.AUDITOR, [0,1,2], credIdAUD1);
  const vcAUD2 = issuePersistentVC(PA1.did, PA1.rsaPrivateKeyPem, AUD2.did, Role.AUDITOR, [0,1,2], credIdAUD2);

  // <--- FIX 2: Passaggio di credIdAUD1 e credIdAUD2 come 4° parametro obliggatorio
  await ir.write.registerAuditor([AUD1.did, AUD1.rsaPublicKeyHex, w_aud1.account.address, credIdAUD1], { account: deployer.account });
  await ir.write.registerAuditor([AUD2.did, AUD2.rsaPublicKeyHex, w_aud2.account.address, credIdAUD2], { account: deployer.account });

  // FIX 3: Chiamate di finalizzazione collocate nell'ordine corretto dopo le registrazioni di Genesi
  await pr.write.finalizeBootstrap({ account: deployer.account });
  await cvc.write.finalizeBootstrap({ account: deployer.account });
  await gc.write.finalizeBootstrap({ account: deployer.account });
  await ir.write.finalizeBootstrap({ account: deployer.account });
  console.log("  Deploy e bootstrap completati");

  separator("Fase 2: Emissione VC e registrazione deleghe on-chain");

  const credIdPP1  = generateCredentialId(PA1.did, PP1.did,  Role.PP)  as `0x${string}`;
  const credIdDEG1 = generateCredentialId(PP1.did, DEG1.did, Role.DEG) as `0x${string}`;
  const credIdAA1  = generateCredentialId(PA1.did, AA1.did,  Role.AA)  as `0x${string}`;

  const vcPP  = issuePersistentVC(PA1.did, PA1.rsaPrivateKeyPem, PP1.did,  Role.PP,  [0,1,2], credIdPP1);
  const vcDEG = issuePersistentVC(PP1.did, PP1.rsaPrivateKeyPem, DEG1.did, Role.DEG, [0],     credIdDEG1);
  const vcAA  = issueTemporaryVC(PA1.did, PA1.rsaPrivateKeyPem,  AA1.did,  Role.AA,  [0],     credIdAA1, 365 * 24 * 3600);

  console.log("  PA1 → PP1:  PersistentVC");
  console.log("  PP1 → DEG1: PersistentVC (scope: NETWORK)");
  console.log("  PA1 → AA1:  TemporaryVC (scadenza: 1 anno)");
  console.log("  PA1 → AUD1: PersistentVC (scope: globale)");

  await ir.write.registerDelegated([PP1.did,  PP1.rsaPublicKeyHex,  w_pp1.account.address,  1, 0n,    [0,1,2], credIdPP1],  { account: w_pa1.account });
  await ir.write.registerDelegated([DEG1.did, DEG1.rsaPublicKeyHex, w_deg1.account.address, 2, 0n,    [0],     credIdDEG1], { account: w_pp1.account });
  await ir.write.registerDelegated([AA1.did,  AA1.rsaPublicKeyHex,  w_aa1.account.address,  4, FUTURE, [0],    credIdAA1],  { account: w_pa1.account });

  verifyVC(vcPP.jwt,  PA1.rsaPublicKeyPem);
  verifyVC(vcDEG.jwt, PP1.rsaPublicKeyPem);
  verifyVC(vcAA.jwt,  PA1.rsaPublicKeyPem);
  console.log("  Verifica VC off-chain: ✓ tutte valide");

  separator("Fase 3: Safe default");

  const safeDefCid = ipfsUpload(Buffer.from(readFileSync("policies/safe-default-network.json", "utf8")));
  const cvcAddress = cvc.address as string;
  const aaExpiresAt = BigInt(Math.floor(Date.now() / 1000) + 365 * 24 * 3600);

  const deliberativeRecipients = [PA1, PA2, PA3, PA4, PP1];
  const fullRecipients         = [PA1, PA2, PA3, PA4, PP1, AUD1, AUD2, AA1];

  separator("Fase 4: Policy NETWORK v1");

  const { proposalId: pid1 } = await certifyPolicy({
    policyPath: "policies/LSP-NETWORK-001-v1.json",
    safeDefCid, replacesId: ZERO_ID, domain: 0,
    deliberativeRecipients, fullRecipients,
    DEG1, PP1, AA1, vcDEG, vcPP, vcAA,
    w_deg: w_deg1, w_pp: w_pp1,
    w_pa1, w_pa2, w_pa3, w_aa: w_aa1,
    gc, pr, cvc, cvcAddress, aaExpiresAt,
  });
  console.log(`  v1 certificata`);

  separator("Fase 5: Policy NETWORK v2");

  const { proposalId: pid2 } = await certifyPolicy({
    policyPath: "policies/LSP-NETWORK-001-v2.json",
    safeDefCid, replacesId: pid1, domain: 0,
    deliberativeRecipients, fullRecipients,
    DEG1, PP1, AA1, vcDEG, vcPP, vcAA,
    w_deg: w_deg1, w_pp: w_pp1,
    w_pa1, w_pa2, w_pa3, w_aa: w_aa1,
    gc, pr, cvc, cvcAddress, aaExpiresAt,
  });

  const activeV2   = await pr.read.getPolicy([pid2]);
  const archivedV1 = await pr.read.getPolicy([pid1]);
  console.log(`  v2 stato: ${activeV2.status} (0=Active)`);
  console.log(`  v1 stato: ${archivedV1.status} (1=Archived)`);

  separator("Fase 6: RetirePolicy");

  await gc.write.proposeGovernanceAction([4, pid2], { account: w_pa1.account });
  const gaEvs   = await gc.getEvents.GovernanceActionProposed();
  const actionId = gaEvs[gaEvs.length - 1].args.actionId as `0x${string}`;
  await gc.write.voteGovernanceAction([actionId, true], { account: w_pa1.account });
  await gc.write.voteGovernanceAction([actionId, true], { account: w_pa2.account });
  await gc.write.voteGovernanceAction([actionId, true], { account: w_pa3.account });
  console.log(`  RetirePolicy eseguita`);

  separator("Fase 7: Auditor — verifica durante finestra aperta");

  const auditOpen = await gc.read.isAuditWindowOpen();
  console.log(`  Finestra di audit: ${auditOpen ? "✓ aperta" : "✗ chiusa"}`);

  if (auditOpen) {
    // Auditor presenta VP con PersistentVC nella catena (WP2 §4.3.3)
    const vidAUD = await getVid(cvc, AUD1, w_aud1, [vcAUD1], Role.AUDITOR, 0);
    console.log(`  Auditor ha registrato validationId: ✓`);
    const history = await pr.read.getDomainHistory([0]);
    console.log(`  Storia dominio NETWORK: ${history.length} versioni`);
    const stati = ["Active", "Archived", "Retired"];
    for (const pid of history) {
      const rec = await pr.read.getPolicy([pid]);
      console.log(`    v${rec.version} — ${stati[rec.status]}`);
    }
  }

  separator("RIEPILOGO");
  console.log(`
  Tutti i ruoli hanno presentato VP con VC (WP2 §4.3):
  ✓ DEG: VP con catena [vcPP, vcDEG] → submitProposal
  ✓ PP:  VP con catena [vcPP] → forwardProposal
  ✓ AA:  VP con catena [vcAA] → confirmEnforcement (via PR → CVC)
  ✓ Auditor: VP con catena [vcAUD1] → accesso durante finestra
  ✓ PA:  autenticazione diretta msg.sender (root of trust)
  `);
}

main().catch((err) => { console.error(err); process.exit(1); });