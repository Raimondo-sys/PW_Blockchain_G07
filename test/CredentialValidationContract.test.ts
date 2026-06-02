import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { generateEntityKeys } from "../crypto/keys.js";
import { issuePersistentVC, generateCredentialId } from "../crypto/vc.js";
import { buildVP, generateNonce, computeValidationId } from "../crypto/vp.js";
import { ipfsUpload } from "../ipfs/ipfs-simulated.js";

const SCOPE_FULL    = [0, 1, 2] as const;
const SCOPE_NETWORK = [0]       as const;
const ZERO_BYTES32  = `0x${"00".repeat(32)}` as `0x${string}`;
const FUTURE        = 9_999_999_999n;
const Role = { PA: 0, PP: 1, DEG: 2, AUDITOR: 3, AA: 4, EV: 5 };

describe("CredentialValidationContract", async () => {
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
    await cvc.write.setPolicyRegistry([pr.address],       { account: deployer.account }); // <--- NUOVA RIGA INSERITA QUI
    
    await pr.write.setIdentityRegistry([ir.address],      { account: deployer.account });
    await pr.write.setGovernanceContract([gc.address],    { account: deployer.account });
    await pr.write.setCVC([cvc.address],                  { account: deployer.account });

    await ir.write.registerPA([PA1.did, PA1.rsaPublicKeyHex, w_pa1.account.address], { account: deployer.account });
    await ir.write.registerPA([PA2.did, PA2.rsaPublicKeyHex, w_pa2.account.address], { account: deployer.account });
    await ir.write.registerPA([PA3.did, PA3.rsaPublicKeyHex, w_pa3.account.address], { account: deployer.account });
    await ir.write.registerPA([PA4.did, PA4.rsaPublicKeyHex, w_pa4.account.address], { account: deployer.account });

    const credIdAUD1 = generateCredentialId(PA1.did, AUD1.did, Role.AUDITOR) as `0x${string}`;
    const credIdAUD2 = generateCredentialId(PA1.did, AUD2.did, Role.AUDITOR) as `0x${string}`;
    const vcAUD1 = issuePersistentVC(PA1.did, PA1.rsaPrivateKeyPem, AUD1.did, Role.AUDITOR, [0,1,2], credIdAUD1);

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

    return { ir, gc, cvc, pr, vcPP, vcDEG, vcAUD1, credIdAUD1 };
  }

  // Helper: certifica policy per aprire finestra audit
  async function certifyHelper(gc: any, cvc: any, pr: any, vcPP: any, vcDEG: any, vcAUD1: any) {
    const safeDefCid = `Qm${"aa".repeat(22)}`;
    const cidPayload = `Qm${"bb".repeat(22)}`;
    const cidKD      = `Qm${"cc".repeat(22)}`;

    const nonceDEG = generateNonce();
    const vpDEG    = buildVP(DEG1.did, DEG1.rsaPrivateKeyPem, cvc.address as string, nonceDEG, [vcPP, vcDEG], {});
    const vidDEG   = computeValidationId(vpDEG);
    // registerValidation: (validationId, holderDID, role, domain, vcExpiresAt)
    await cvc.write.registerValidation([vidDEG, DEG1.did, Role.DEG, 0, 0n], { account: w_deg1.account });
    await gc.write.submitProposal([cidPayload, cidKD, 0, ZERO_BYTES32, safeDefCid, vidDEG], { account: w_deg1.account });

    const evs = await gc.getEvents.ProposalSubmitted();
    const pid  = evs[evs.length - 1].args.proposalId as `0x${string}`;

    const noncePP = generateNonce();
    const vpPP    = buildVP(PP1.did, PP1.rsaPrivateKeyPem, cvc.address as string, noncePP, [vcPP], {});
    const vidPP   = computeValidationId(vpPP);
    await cvc.write.registerValidation([vidPP, PP1.did, Role.PP, 0, 0n], { account: w_pp1.account });
    await gc.write.forwardProposal([pid, vidPP], { account: w_pp1.account });
    await gc.write.endorseProposal([pid], { account: w_pa1.account });
    await gc.write.voteProposal([pid, true], { account: w_pa1.account });
    await gc.write.voteProposal([pid, true], { account: w_pa2.account });
    await gc.write.voteProposal([pid, true], { account: w_pa3.account });

    // AA presenta VP prima di confirmEnforcement
    const nonceAA = generateNonce();
    const vpAA    = buildVP(AA1.did, AA1.rsaPrivateKeyPem, cvc.address as string, nonceAA, [], {});
    const vidAA   = computeValidationId(vpAA);
    await cvc.write.registerValidation([vidAA, AA1.did, Role.AA, 0, 0n], { account: w_aa1.account });
    await pr.write.confirmEnforcement([pid, cidPayload, vidAA], { account: w_aa1.account });

    return pid;
  }

  // =========================================================================
  // REGISTRAZIONE VALIDATIONID
  // registerValidation(validationId, holderDID, role, domain, vcExpiresAt)
  // =========================================================================

  it("registerValidation: DEG registra validationId correttamente", async () => {
    const { cvc, vcPP, vcDEG } = await setup();
    const nonce = generateNonce();
    const vpJwt = buildVP(DEG1.did, DEG1.rsaPrivateKeyPem, cvc.address as string, nonce, [vcPP, vcDEG], {});
    const vid   = computeValidationId(vpJwt);

    await cvc.write.registerValidation([vid, DEG1.did, Role.DEG, 0, 0n], { account: w_deg1.account });

    const rec = await cvc.read.getValidation([vid]);
    assert.equal(rec.holderDID, DEG1.did);
    assert.equal(Number(rec.role), Role.DEG);
    assert.equal(Number(rec.domain), 0);
    assert.equal(rec.used, false);
  });

  it("registerValidation: validationId già registrato viene rifiutato (anti-replay) — THA-6", async () => {
    const { cvc, vcPP, vcDEG } = await setup();
    const nonce = generateNonce();
    const vpJwt = buildVP(DEG1.did, DEG1.rsaPrivateKeyPem, cvc.address as string, nonce, [vcPP, vcDEG], {});
    const vid   = computeValidationId(vpJwt);

    await cvc.write.registerValidation([vid, DEG1.did, Role.DEG, 0, 0n], { account: w_deg1.account });
    await assert.rejects(
      cvc.write.registerValidation([vid, DEG1.did, Role.DEG, 0, 0n], { account: w_deg1.account })
    );
  });

  it("registerValidation: caller diverso dal holderDID viene rifiutato", async () => {
    const { cvc, vcPP, vcDEG } = await setup();
    const nonce = generateNonce();
    const vpJwt = buildVP(DEG1.did, DEG1.rsaPrivateKeyPem, cvc.address as string, nonce, [vcPP, vcDEG], {});
    const vid   = computeValidationId(vpJwt);

    await assert.rejects(
      cvc.write.registerValidation([vid, DEG1.did, Role.DEG, 0, 0n], { account: w_pa2.account })
    );
  });

  it("registerValidation: DID non attivo viene rifiutato", async () => {
    const { ir, cvc, vcPP, vcDEG } = await setup();
    await ir.write.revokeDID([DEG1.did], { account: w_pp1.account });

    const nonce = generateNonce();
    const vpJwt = buildVP(DEG1.did, DEG1.rsaPrivateKeyPem, cvc.address as string, nonce, [vcPP, vcDEG], {});
    const vid   = computeValidationId(vpJwt);

    await assert.rejects(
      cvc.write.registerValidation([vid, DEG1.did, Role.DEG, 0, 0n], { account: w_deg1.account })
    );
  });

  it("isValidationUsable: true dopo registrazione, false dopo consumo via GC", async () => {
    const { gc, cvc, vcPP, vcDEG } = await setup();

    const nonce = generateNonce();
    const vpJwt = buildVP(DEG1.did, DEG1.rsaPrivateKeyPem, cvc.address as string, nonce, [vcPP, vcDEG], {});
    const vid   = computeValidationId(vpJwt);

    await cvc.write.registerValidation([vid, DEG1.did, Role.DEG, 0, 0n], { account: w_deg1.account });
    assert.equal(await cvc.read.isValidationUsable([vid]), true);

    // submitProposal consuma il validationId tramite GC → CVC
    const safeDefCid = `Qm${"aa".repeat(22)}`;
    const cidPayload = `Qm${"bb".repeat(22)}`;
    const cidKD      = `Qm${"cc".repeat(22)}`;
    await gc.write.submitProposal(
      [cidPayload, cidKD, 0, ZERO_BYTES32, safeDefCid, vid],
      { account: w_deg1.account }
    );

    assert.equal(await cvc.read.isValidationUsable([vid]), false);
  });

  // =========================================================================
  // AUDITOR — VP con PersistentVC (WP2 §4.3.3)
  // =========================================================================

  it("Auditor: VP con PersistentVC e finestra aperta — successo — WP2 §4.3.3", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAUD1 } = await setup();

    await certifyHelper(gc, cvc, pr, vcPP, vcDEG, vcAUD1);
    assert.equal(await gc.read.isAuditWindowOpen(), true);

    const nonce = generateNonce();
    const vpJwt = buildVP(AUD1.did, AUD1.rsaPrivateKeyPem, cvc.address as string, nonce, [vcAUD1], {});
    const vid   = computeValidationId(vpJwt);

    await cvc.write.registerValidation([vid, AUD1.did, Role.AUDITOR, 0, 0n], { account: w_aud1.account });
    assert.equal(await cvc.read.isValidationUsable([vid]), true);
  });

  it("Auditor: registrazione bloccata se finestra chiusa — THA-9", async () => {
    const { cvc, vcAUD1 } = await setup();
    const nonce = generateNonce();
    const vpJwt = buildVP(AUD1.did, AUD1.rsaPrivateKeyPem, cvc.address as string, nonce, [vcAUD1], {});
    const vid   = computeValidationId(vpJwt);

    await assert.rejects(
      cvc.write.registerValidation([vid, AUD1.did, Role.AUDITOR, 0, 0n], { account: w_aud1.account })
    );
  });

  // =========================================================================
  // VALIDATIONID ZERO
  // =========================================================================

  it("validationId zero viene rifiutato", async () => {
    const { cvc } = await setup();
    await assert.rejects(
      cvc.write.registerValidation([ZERO_BYTES32, DEG1.did, Role.DEG, 0, 0n], { account: w_deg1.account })
    );
  });
});