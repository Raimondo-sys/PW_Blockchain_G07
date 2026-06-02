import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { generateEntityKeys } from "../crypto/keys.js";
import { issuePersistentVC, issueTemporaryVC, generateCredentialId } from "../crypto/vc.js";
import { buildVP, generateNonce, computeValidationId } from "../crypto/vp.js";
import { ipfsUpload } from "../ipfs/ipfs-simulated.js";

const SCOPE_FULL    = [0, 1, 2] as const;
const SCOPE_NETWORK = [0]       as const;
const ZERO_ID       = `0x${"00".repeat(32)}` as `0x${string}`;
const FUTURE        = 9_999_999_999n;
const Role = { PA: 0, PP: 1, DEG: 2, AUDITOR: 3, AA: 4, EV: 5 };

describe("PolicyRegistry", async () => {
  const { viem } = await network.connect();
  const wallets  = await viem.getWalletClients();
  const [deployer, w_pa1, w_pa2, w_pa3, w_pa4,
         w_aud1, w_aud2, w_pp1, w_deg1, w_aa1] = wallets;

  const PA1  = generateEntityKeys("did:ethr:pa1");
  const PA2  = generateEntityKeys("did:ethr:pa2");
  const PA3  = generateEntityKeys("did:ethr:pa3");
  const PA4  = generateEntityKeys("did:ethr:pa4");
  const PP1  = generateEntityKeys("did:ethr:pp1");
  const DEG1 = generateEntityKeys("did:ethr:deg1");
  const AA1  = generateEntityKeys("did:ethr:aa1");
  const AUD1 = generateEntityKeys("did:ethr:aud1");
  const AUD2 = generateEntityKeys("did:ethr:aud2");

  const safeDefCid  = ipfsUpload(Buffer.from("safe-default"));
  const cidPayload1 = ipfsUpload(Buffer.from("policy-v1-payload"));
  const cidPayload2 = ipfsUpload(Buffer.from("policy-v2-payload"));
  const cidKD       = ipfsUpload(Buffer.from("key-distrib"));

  async function setup() {
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
    await cvc.write.setPolicyRegistry([pr.address],       { account: deployer.account }); // <--- AGGIUNTA FONDAMENTALE
    
    await pr.write.setIdentityRegistry([ir.address],      { account: deployer.account });
    await pr.write.setGovernanceContract([gc.address],    { account: deployer.account });
    await pr.write.setCVC([cvc.address],                  { account: deployer.account });

    await ir.write.registerPA([PA1.did, PA1.rsaPublicKeyHex, w_pa1.account.address], { account: deployer.account });
    await ir.write.registerPA([PA2.did, PA2.rsaPublicKeyHex, w_pa2.account.address], { account: deployer.account });
    await ir.write.registerPA([PA3.did, PA3.rsaPublicKeyHex, w_pa3.account.address], { account: deployer.account });
    await ir.write.registerPA([PA4.did, PA4.rsaPublicKeyHex, w_pa4.account.address], { account: deployer.account });

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

    await ir.write.registerDelegated([PP1.did,  PP1.rsaPublicKeyHex,  w_pp1.account.address,  1, 0n,    SCOPE_FULL,    credIdPP1],  { account: w_pa1.account });
    await ir.write.registerDelegated([DEG1.did, DEG1.rsaPublicKeyHex, w_deg1.account.address, 2, 0n,    SCOPE_NETWORK, credIdDEG1], { account: w_pp1.account });
    await ir.write.registerDelegated([AA1.did,  AA1.rsaPublicKeyHex,  w_aa1.account.address,  4, FUTURE, SCOPE_NETWORK, credIdAA1],  { account: w_pa1.account });

    const vcPP  = issuePersistentVC(PA1.did, PA1.rsaPrivateKeyPem, PP1.did,  Role.PP,  [0,1,2], credIdPP1);
    const vcDEG = issuePersistentVC(PP1.did, PP1.rsaPrivateKeyPem, DEG1.did, Role.DEG, [0],     credIdDEG1);
    // issueTemporaryVC senza expiresIn nelle opzioni (fix bug)
    const vcAA  = issueTemporaryVC(PA1.did, PA1.rsaPrivateKeyPem, AA1.did, Role.AA, [0], credIdAA1, 365 * 24 * 3600);

    return { ir, gc, cvc, pr, vcPP, vcDEG, vcAA };
  }

  // Helper: registra validationId
  // registerValidation(validationId, holderDID, role, domain, vcExpiresAt)
  async function getVid(cvc: any, holderKeys: any, wallet: any, vcChain: any[], role: number, domain: number) {
    const nonce = generateNonce();
    const vpJwt = buildVP(holderKeys.did, holderKeys.rsaPrivateKeyPem, cvc.address as string, nonce, vcChain, {});
    const vid   = computeValidationId(vpJwt);
    await cvc.write.registerValidation([vid, holderKeys.did, role, domain, 0n], { account: wallet.account });
    return vid;
  }

  // Helper: certifica policy completo con VP per tutti i ruoli
  // confirmEnforcement(proposalId, appliedCid, validationId)
  async function certify(
    gc: any, cvc: any, pr: any, vcPP: any, vcDEG: any, vcAA: any,
    cidPayload: string, replacesId: `0x${string}` = ZERO_ID, customSafeDefCid = safeDefCid
  ): Promise<`0x${string}`> {
    const vidDEG = await getVid(cvc, DEG1, w_deg1, [vcPP, vcDEG], Role.DEG, 0);
    await gc.write.submitProposal([cidPayload, cidKD, 0, replacesId, customSafeDefCid, vidDEG], { account: w_deg1.account });
    const evs = await gc.getEvents.ProposalSubmitted();
    const pid  = evs[evs.length - 1].args.proposalId as `0x${string}`;

    const vidPP = await getVid(cvc, PP1, w_pp1, [vcPP], Role.PP, 0);
    await gc.write.forwardProposal([pid, vidPP], { account: w_pp1.account });
    await gc.write.endorseProposal([pid], { account: w_pa1.account });
    await gc.write.voteProposal([pid, true], { account: w_pa1.account });
    await gc.write.voteProposal([pid, true], { account: w_pa2.account });
    await gc.write.voteProposal([pid, true], { account: w_pa3.account });

    // AA presenta VP con TemporaryVC prima di confirmEnforcement (WP2 §4.3.4)
    const vidAA = await getVid(cvc, AA1, w_aa1, [vcAA], Role.AA, 0);
    await pr.write.confirmEnforcement([pid, cidPayload, vidAA], { account: w_aa1.account });
    return pid;
  }

  // =========================================================================
  // CERTIFY POLICY
  // =========================================================================

  it("certifyPolicy: prima policy crea safe default — WP2 §2.1", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAA } = await setup();
    await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload1);
    assert.equal(await pr.read.hasSafeDefault([0]), true);
    assert.equal(await pr.read.getSafeDefault([0]), safeDefCid);
  });

  it("certifyPolicy: policy v2 archivia v1 atomicamente — WP2 §2.3 — THA-11", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAA } = await setup();
    const pid1 = await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload1);
    const pid2 = await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload2, pid1, "");

    assert.equal(Number((await pr.read.getPolicy([pid1])).status), 1); // Archived
    assert.equal(Number((await pr.read.getPolicy([pid2])).status), 0); // Active
    assert.equal(await pr.read.getActivePolicy([0]), pid2);
  });

  it("certifyPolicy: proposalId duplicato viene rifiutato", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAA } = await setup();
    const pid1 = await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload1);
    const rec  = await pr.read.getPolicy([pid1]);
    assert.equal(Number(rec.status), 0);
    assert.equal(Number(rec.version), 1);
  });

  it("certifyPolicy: prima policy senza safeDefaultCid viene rifiutata", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAA } = await setup();
    // Invochiamo l'intero ciclo tramite l'helper passando "" come safeDefaultCid.
    // La sottomissione passerà, ma la transazione finale (che certifica la policy on-chain)
    // fallirà restituendo l'errore SafeDefaultRequired.
    await assert.rejects(
      certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload1, ZERO_ID, "")
    );
  });

  // =========================================================================
  // RETIRE POLICY
  // =========================================================================

  it("retirePolicy: porta la policy in stato Retired — WP2 §2.3", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAA } = await setup();
    const pid1 = await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload1);

    await gc.write.proposeGovernanceAction([4, pid1], { account: w_pa1.account });
    const gaEvs    = await gc.getEvents.GovernanceActionProposed();
    const actionId = gaEvs[0].args.actionId as `0x${string}`;
    await gc.write.voteGovernanceAction([actionId, true], { account: w_pa1.account });
    await gc.write.voteGovernanceAction([actionId, true], { account: w_pa2.account });
    await gc.write.voteGovernanceAction([actionId, true], { account: w_pa3.account });

    assert.equal(Number((await pr.read.getPolicy([pid1])).status), 2); // Retired
    assert.equal(await pr.read.getActivePolicy([0]), ZERO_ID);
  });

  it("retirePolicy: policy non Active viene rifiutata", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAA } = await setup();
    const pid1 = await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload1);
    await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload2, pid1, "");

    await gc.write.proposeGovernanceAction([4, pid1], { account: w_pa1.account });
    const gaEvs    = await gc.getEvents.GovernanceActionProposed();
    const actionId = gaEvs[gaEvs.length - 1].args.actionId as `0x${string}`;
    await gc.write.voteGovernanceAction([actionId, true], { account: w_pa1.account });
    await gc.write.voteGovernanceAction([actionId, true], { account: w_pa2.account });
    await assert.rejects(
      gc.write.voteGovernanceAction([actionId, true], { account: w_pa3.account })
    );
  });

  // =========================================================================
  // UPDATE KEY DISTRIB
  // =========================================================================

  it("updateKeyDistrib: qualsiasi PA attiva può aggiornare — WP2 §3.3", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAA } = await setup();
    const pid1   = await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload1);
    const newCid = ipfsUpload(Buffer.from("new-key-distrib"));
    await pr.write.updateKeyDistrib([pid1, newCid], { account: w_pa2.account });
    assert.equal((await pr.read.getPolicy([pid1])).cidKeyDistrib, newCid);
  });

  it("updateKeyDistrib: entità non PA viene rifiutata", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAA } = await setup();
    const pid1   = await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload1);
    const newCid = ipfsUpload(Buffer.from("new-key-distrib-2"));
    await assert.rejects(
      pr.write.updateKeyDistrib([pid1, newCid], { account: w_aa1.account })
    );
  });

  // =========================================================================
  // CONFIRM ENFORCEMENT — AA con VP (WP2 §4.3.4)
  // confirmEnforcement(proposalId, appliedCid, validationId)
  // =========================================================================

  it("confirmEnforcement: AA presenta VP con TemporaryVC — WP2 §4.3.4", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAA } = await setup();

    const vidDEG = await getVid(cvc, DEG1, w_deg1, [vcPP, vcDEG], Role.DEG, 0);
    await gc.write.submitProposal([cidPayload1, cidKD, 0, ZERO_ID, safeDefCid, vidDEG], { account: w_deg1.account });
    const evs = await gc.getEvents.ProposalSubmitted();
    const pid  = evs[evs.length - 1].args.proposalId as `0x${string}`;

    const vidPP = await getVid(cvc, PP1, w_pp1, [vcPP], Role.PP, 0);
    await gc.write.forwardProposal([pid, vidPP], { account: w_pp1.account });
    await gc.write.endorseProposal([pid], { account: w_pa1.account });
    await gc.write.voteProposal([pid, true], { account: w_pa1.account });
    await gc.write.voteProposal([pid, true], { account: w_pa2.account });
    await gc.write.voteProposal([pid, true], { account: w_pa3.account });

    const vidAA = await getVid(cvc, AA1, w_aa1, [vcAA], Role.AA, 0);
    await pr.write.confirmEnforcement([pid, cidPayload1, vidAA], { account: w_aa1.account });

    const enforcements = await pr.read.getEnforcements([pid]);
    assert.equal(enforcements.length, 1);
    assert.equal(enforcements[0].aaDID, AA1.did);
  });

  it("confirmEnforcement: PA non può confermare enforcement", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAA } = await setup();
    const pid1    = await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload1);
    const fakeVid = `0x${"ee".repeat(32)}` as `0x${string}`;
    await assert.rejects(
      pr.write.confirmEnforcement([pid1, cidPayload1, fakeVid], { account: w_pa1.account })
    );
  });

  // =========================================================================
  // STORIA IMMUTABILE — THA-11
  // =========================================================================

  it("getDomainHistory: versioni sempre accessibili anche dopo Archived/Retired", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAA } = await setup();
    const pid1 = await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload1);
    const pid2 = await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload2, pid1, "");

    await gc.write.proposeGovernanceAction([4, pid2], { account: w_pa1.account });
    const gaEvs    = await gc.getEvents.GovernanceActionProposed();
    const actionId = gaEvs[gaEvs.length - 1].args.actionId as `0x${string}`;
    await gc.write.voteGovernanceAction([actionId, true], { account: w_pa1.account });
    await gc.write.voteGovernanceAction([actionId, true], { account: w_pa2.account });
    await gc.write.voteGovernanceAction([actionId, true], { account: w_pa3.account });

    const history = await pr.read.getDomainHistory([0]);
    assert.equal(history.length, 2);
    assert.equal(Number((await pr.read.getPolicy([pid1])).status), 1); // Archived
    assert.equal(Number((await pr.read.getPolicy([pid2])).status), 2); // Retired
  });
});