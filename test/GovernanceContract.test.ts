import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { generateEntityKeys } from "../crypto/keys.js";
import { issuePersistentVC, generateCredentialId } from "../crypto/vc.js";
import { buildVP, generateNonce, computeValidationId } from "../crypto/vp.js";
import { ipfsUpload } from "../ipfs/ipfs-simulated.js";

const SCOPE_FULL    = [0, 1, 2] as const;
const SCOPE_NETWORK = [0]       as const;
const ZERO_ID       = `0x${"00".repeat(32)}` as `0x${string}`;
const FUTURE        = 9_999_999_999n;
const Role = { PA: 0, PP: 1, DEG: 2, AUDITOR: 3, AA: 4, EV: 5 };

describe("GovernanceContract", async () => {
  const { viem } = await network.connect();
  const wallets  = await viem.getWalletClients();
  const [deployer, w_pa1, w_pa2, w_pa3, w_pa4,
         w_aud1, w_aud2, w_pp1, w_deg1, w_aa1,
         w_extra1] = wallets;

  const PA1  = generateEntityKeys("did:ethr:pa1");
  const PA2  = generateEntityKeys("did:ethr:pa2");
  const PA3  = generateEntityKeys("did:ethr:pa3");
  const PA4  = generateEntityKeys("did:ethr:pa4");
  const PP1  = generateEntityKeys("did:ethr:pp1");
  const PP2  = generateEntityKeys("did:ethr:pp2");
  const DEG1 = generateEntityKeys("did:ethr:deg1");
  const AA1  = generateEntityKeys("did:ethr:aa1");
  const AUD1 = generateEntityKeys("did:ethr:aud1");
  const AUD2 = generateEntityKeys("did:ethr:aud2");

  const safeDefCid = ipfsUpload(Buffer.from("safe-default"));
  const cidPayload = ipfsUpload(Buffer.from("policy-payload"));
  const cidKD      = ipfsUpload(Buffer.from("key-distrib"));

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
    await cvc.write.setPolicyRegistry([pr.address],       { account: deployer.account }); // <--- RIGA INSERITA
    
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
    const credIdPP2  = generateCredentialId(PA2.did, PP2.did,  Role.PP)  as `0x${string}`;

    await ir.write.registerDelegated([PP1.did,  PP1.rsaPublicKeyHex,  w_pp1.account.address,    1, 0n,    SCOPE_FULL,    credIdPP1],  { account: w_pa1.account });
    await ir.write.registerDelegated([DEG1.did, DEG1.rsaPublicKeyHex, w_deg1.account.address,   2, 0n,    SCOPE_NETWORK, credIdDEG1], { account: w_pp1.account });
    await ir.write.registerDelegated([AA1.did,  AA1.rsaPublicKeyHex,  w_aa1.account.address,    4, FUTURE, SCOPE_NETWORK, credIdAA1],  { account: w_pa1.account });
    await ir.write.registerDelegated([PP2.did,  PP2.rsaPublicKeyHex,  w_extra1.account.address, 1, 0n,    SCOPE_FULL,    credIdPP2],  { account: w_pa2.account });

    const vcPP1 = issuePersistentVC(PA1.did, PA1.rsaPrivateKeyPem, PP1.did,  Role.PP,  [0,1,2], credIdPP1);
    const vcPP2 = issuePersistentVC(PA2.did, PA2.rsaPrivateKeyPem, PP2.did,  Role.PP,  [0,1,2], credIdPP2);
    const vcDEG = issuePersistentVC(PP1.did, PP1.rsaPrivateKeyPem, DEG1.did, Role.DEG, [0],     credIdDEG1);

    return { ir, gc, cvc, pr, vcPP1, vcPP2, vcDEG };
  }

  // Helper: registra validationId nel CVC
  // registerValidation(validationId, holderDID, role, domain, vcExpiresAt)
  async function getVid(cvc: any, holderKeys: any, wallet: any, vcChain: any[], role: number, domain: number) {
    const nonce = generateNonce();
    const vpJwt = buildVP(holderKeys.did, holderKeys.rsaPrivateKeyPem, cvc.address as string, nonce, vcChain, {});
    const vid   = computeValidationId(vpJwt);
    await cvc.write.registerValidation([vid, holderKeys.did, role, domain, 0n], { account: wallet.account });
    return vid;
  }

  // Helper: ciclo completo submit → forward → endorse → vota×3
  // confirmEnforcement(proposalId, appliedCid, validationId)
  async function certifyHelper(gc: any, cvc: any, pr: any, vcPP1: any, vcDEG: any, replacesId: `0x${string}` = ZERO_ID) {
    const vidDEG = await getVid(cvc, DEG1, w_deg1, [vcPP1, vcDEG], Role.DEG, 0);
    await gc.write.submitProposal([cidPayload, cidKD, 0, replacesId, safeDefCid, vidDEG], { account: w_deg1.account });
    const evs = await gc.getEvents.ProposalSubmitted();
    const pid  = evs[evs.length - 1].args.proposalId as `0x${string}`;

    const vidPP = await getVid(cvc, PP1, w_pp1, [vcPP1], Role.PP, 0);
    await gc.write.forwardProposal([pid, vidPP], { account: w_pp1.account });
    await gc.write.endorseProposal([pid], { account: w_pa1.account });
    await gc.write.voteProposal([pid, true], { account: w_pa1.account });
    await gc.write.voteProposal([pid, true], { account: w_pa2.account });
    await gc.write.voteProposal([pid, true], { account: w_pa3.account });

    // AA presenta VP prima di confirmEnforcement
    const vidAA = await getVid(cvc, AA1, w_aa1, [], Role.AA, 0);
    await pr.write.confirmEnforcement([pid, cidPayload, vidAA], { account: w_aa1.account });
    return pid;
  }

  // =========================================================================
  // SUBMIT PROPOSAL
  // =========================================================================

  it("submitProposal: DEG con validationId valido riesce", async () => {
    const { gc, cvc, vcPP1, vcDEG } = await setup();
    const vidDEG = await getVid(cvc, DEG1, w_deg1, [vcPP1, vcDEG], Role.DEG, 0);
    await gc.write.submitProposal([cidPayload, cidKD, 0, ZERO_ID, safeDefCid, vidDEG], { account: w_deg1.account });
    const evs = await gc.getEvents.ProposalSubmitted();
    assert.equal(evs.length, 1);
  });

  it("submitProposal: PA non può sottomettere (ruolo sbagliato) — THA-2", async () => {
    const { gc } = await setup();
    const fakeVid = `0x${"aa".repeat(32)}` as `0x${string}`;
    await assert.rejects(
      gc.write.submitProposal([cidPayload, cidKD, 0, ZERO_ID, safeDefCid, fakeVid], { account: w_pa1.account })
    );
  });

  it("submitProposal: validationId non registrato viene rifiutato", async () => {
    const { gc } = await setup();
    const fakeVid = `0x${"dd".repeat(32)}` as `0x${string}`;
    await assert.rejects(
      gc.write.submitProposal([cidPayload, cidKD, 0, ZERO_ID, safeDefCid, fakeVid], { account: w_deg1.account })
    );
  });

  it("forwardProposal: solo il PP supervisore del DEG può inoltrare — THA-2", async () => {
    const { gc, cvc, vcPP1, vcPP2, vcDEG } = await setup();

    const vidDEG = await getVid(cvc, DEG1, w_deg1, [vcPP1, vcDEG], Role.DEG, 0);
    await gc.write.submitProposal([cidPayload, cidKD, 0, ZERO_ID, safeDefCid, vidDEG], { account: w_deg1.account });
    const evs = await gc.getEvents.ProposalSubmitted();
    const pid  = evs[0].args.proposalId as `0x${string}`;

    const vidPP2 = await getVid(cvc, PP2, w_extra1, [vcPP2], Role.PP, 0);
    await assert.rejects(
      gc.write.forwardProposal([pid, vidPP2], { account: w_extra1.account })
    );
  });

  it("rejectProposal: PP può rigettare con motivazione", async () => {
    const { gc, cvc, vcPP1, vcDEG } = await setup();
    const vidDEG = await getVid(cvc, DEG1, w_deg1, [vcPP1, vcDEG], Role.DEG, 0);
    await gc.write.submitProposal([cidPayload, cidKD, 0, ZERO_ID, safeDefCid, vidDEG], { account: w_deg1.account });
    const evs = await gc.getEvents.ProposalSubmitted();
    const pid  = evs[0].args.proposalId as `0x${string}`;

    const vidPP = await getVid(cvc, PP1, w_pp1, [vcPP1], Role.PP, 0);
    await gc.write.rejectProposal([pid, "Non conforme NIS2", vidPP], { account: w_pp1.account });
    const proposal = await gc.read.getProposal([pid]);
    assert.equal(Number(proposal.status), 4); // Rejected
  });

  it("endorseProposal: solo la PA delegante del PP può endorsare", async () => {
    const { gc, cvc, vcPP1, vcDEG } = await setup();
    const vidDEG = await getVid(cvc, DEG1, w_deg1, [vcPP1, vcDEG], Role.DEG, 0);
    await gc.write.submitProposal([cidPayload, cidKD, 0, ZERO_ID, safeDefCid, vidDEG], { account: w_deg1.account });
    const evs = await gc.getEvents.ProposalSubmitted();
    const pid  = evs[0].args.proposalId as `0x${string}`;

    const vidPP = await getVid(cvc, PP1, w_pp1, [vcPP1], Role.PP, 0);
    await gc.write.forwardProposal([pid, vidPP], { account: w_pp1.account });

    await assert.rejects(
      gc.write.endorseProposal([pid], { account: w_pa2.account })
    );
  });

  it("voteProposal: PA non può votare due volte — THA-4", async () => {
    const { gc, cvc, vcPP1, vcDEG } = await setup();
    const vidDEG = await getVid(cvc, DEG1, w_deg1, [vcPP1, vcDEG], Role.DEG, 0);
    await gc.write.submitProposal([cidPayload, cidKD, 0, ZERO_ID, safeDefCid, vidDEG], { account: w_deg1.account });
    const evs = await gc.getEvents.ProposalSubmitted();
    const pid  = evs[0].args.proposalId as `0x${string}`;

    const vidPP = await getVid(cvc, PP1, w_pp1, [vcPP1], Role.PP, 0);
    await gc.write.forwardProposal([pid, vidPP], { account: w_pp1.account });
    await gc.write.endorseProposal([pid], { account: w_pa1.account });
    await gc.write.voteProposal([pid, true], { account: w_pa1.account });

    await assert.rejects(
      gc.write.voteProposal([pid, true], { account: w_pa1.account })
    );
  });

  it("voteProposal: 3/4 voti certifica la policy", async () => {
    const { gc, cvc, pr, vcPP1, vcDEG } = await setup();
    const pid = await certifyHelper(gc, cvc, pr, vcPP1, vcDEG);
    const proposal = await gc.read.getProposal([pid]);
    assert.equal(Number(proposal.status), 3); // Certified
  });

  it("DomainAlreadyEndorsed: due proposte sullo stesso dominio contemporaneamente — THA-5", async () => {
    const { gc, cvc, vcPP1, vcDEG } = await setup();

    const vidDEG1 = await getVid(cvc, DEG1, w_deg1, [vcPP1, vcDEG], Role.DEG, 0);
    await gc.write.submitProposal([cidPayload, cidKD, 0, ZERO_ID, safeDefCid, vidDEG1], { account: w_deg1.account });
    const evs1 = await gc.getEvents.ProposalSubmitted();
    const pid1  = evs1[0].args.proposalId as `0x${string}`;

    const vidPP1 = await getVid(cvc, PP1, w_pp1, [vcPP1], Role.PP, 0);
    await gc.write.forwardProposal([pid1, vidPP1], { account: w_pp1.account });
    await gc.write.endorseProposal([pid1], { account: w_pa1.account });

    const cidPayload2 = `Qm${"bb".repeat(22)}`;
    const vidDEG2 = await getVid(cvc, DEG1, w_deg1, [vcPP1, vcDEG], Role.DEG, 0);
    await gc.write.submitProposal([cidPayload2, cidKD, 0, ZERO_ID, safeDefCid, vidDEG2], { account: w_deg1.account });
    const evs2 = await gc.getEvents.ProposalSubmitted();
    const pid2  = evs2[evs2.length - 1].args.proposalId as `0x${string}`;

    const vidPP2 = await getVid(cvc, PP1, w_pp1, [vcPP1], Role.PP, 0);
    await gc.write.forwardProposal([pid2, vidPP2], { account: w_pp1.account });

    await assert.rejects(
      gc.write.endorseProposal([pid2], { account: w_pa1.account })
    );
  });

  it("proposeGovernanceAction: solo PA può proporre", async () => {
    const { gc } = await setup();
    const payload = `0x${"aa".repeat(32)}`;
    await assert.rejects(
      gc.write.proposeGovernanceAction([0, payload], { account: w_pp1.account })
    );
  });

  it("voteGovernanceAction: PA non può votare due volte", async () => {
    const { gc } = await setup();
    const payload = `0x${"aa".repeat(32)}`;
    await gc.write.proposeGovernanceAction([0, payload], { account: w_pa1.account });
    const evs      = await gc.getEvents.GovernanceActionProposed();
    const actionId = evs[0].args.actionId as `0x${string}`;

    await gc.write.voteGovernanceAction([actionId, true], { account: w_pa1.account });
    await assert.rejects(
      gc.write.voteGovernanceAction([actionId, true], { account: w_pa1.account })
    );
  });

  it("isAuditWindowOpen: aperta dopo certificazione — WP2 §6.3", async () => {
    const { gc, cvc, pr, vcPP1, vcDEG } = await setup();
    assert.equal(await gc.read.isAuditWindowOpen(), false);
    await certifyHelper(gc, cvc, pr, vcPP1, vcDEG);
    assert.equal(await gc.read.isAuditWindowOpen(), true);
  });
});