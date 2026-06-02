import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { generateEntityKeys } from "../crypto/keys.js";
import { issuePersistentVC, issueTemporaryVC, generateCredentialId } from "../crypto/vc.js";
import { buildVP, generateNonce, computeValidationId } from "../crypto/vp.js";
import { encryptDocument } from "../crypto/hybrid.js";
import { ipfsUpload, ipfsDownload, ipfsVerifyCID } from "../ipfs/ipfs-simulated.js";
import { readFileSync } from "fs";

const SCOPE_FULL    = [0, 1, 2] as const;
const SCOPE_NETWORK = [0]       as const;
const ZERO_ID       = `0x${"00".repeat(32)}` as `0x${string}`;
const FUTURE        = 9_999_999_999n;
const Role = { PA: 0, PP: 1, DEG: 2, AUDITOR: 3, AA: 4, EV: 5 };

describe("Integration — Flusso end-to-end multi-contratto", async () => {
  const { viem } = await network.connect();
  const wallets  = await viem.getWalletClients();
  const [deployer, w_pa1, w_pa2, w_pa3, w_pa4,
         w_aud1, w_aud2, w_pp1, w_deg1, w_aa1] = wallets;

  const PA1  = generateEntityKeys("did:ethr:pa1");
  const PA2  = generateEntityKeys("did:ethr:pa2");
  const PA3  = generateEntityKeys("did:ethr:pa3");
  const PA4  = generateEntityKeys("did:ethr:pa4");
  const AUD1 = generateEntityKeys("did:ethr:aud1");
  const AUD2 = generateEntityKeys("did:ethr:aud2");
  const PP1  = generateEntityKeys("did:ethr:pp1");
  const DEG1 = generateEntityKeys("did:ethr:deg1");
  const AA1  = generateEntityKeys("did:ethr:aa1");

  async function fullSetup() {
    const ir  = await viem.deployContract("IdentityRegistry",             []);
    const gc  = await viem.deployContract("GovernanceContract",           []);
    const cvc = await viem.deployContract("CredentialValidationContract", []);
    const pr  = await viem.deployContract("PolicyRegistry",               []);

    await ir.write.setGovernanceContract([gc.address],    { account: deployer.account });
    await gc.write.setIdentityRegistry([ir.address],      { account: deployer.account });
    await gc.write.setPolicyRegistry([pr.address],        { account: deployer.account });
    await gc.write.setCVC([cvc.address],                  { account: deployer.account });
    await gc.write.setAuditWindowDuration([60n],          { account: deployer.account });
    await cvc.write.setIdentityRegistry([ir.address],     { account: deployer.account });
    await cvc.write.setGovernanceContract([gc.address],   { account: deployer.account });
    await cvc.write.setPolicyRegistry([pr.address],       { account: deployer.account });
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
    const vcAA  = issueTemporaryVC(PA1.did, PA1.rsaPrivateKeyPem,  AA1.did,  Role.AA,  [0],     credIdAA1, 365 * 24 * 3600);

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

  // Helper: certifica policy con VP per tutti i ruoli
  // confirmEnforcement(proposalId, appliedCid, validationId)
  async function certify(
    gc: any, cvc: any, pr: any, vcPP: any, vcDEG: any, vcAA: any,
    cidPayload: string, replacesId: `0x${string}` = ZERO_ID, safeDefCid = ""
  ): Promise<`0x${string}`> {
    const sd     = safeDefCid || ipfsUpload(Buffer.from("safe-default"));
    const vidDEG = await getVid(cvc, DEG1, w_deg1, [vcPP, vcDEG], Role.DEG, 0);
    await gc.write.submitProposal([cidPayload, `Qm${"cc".repeat(22)}`, 0, replacesId, sd, vidDEG], { account: w_deg1.account });
    const evs = await gc.getEvents.ProposalSubmitted();
    const pid  = evs[evs.length - 1].args.proposalId as `0x${string}`;

    const vidPP = await getVid(cvc, PP1, w_pp1, [vcPP], Role.PP, 0);
    await gc.write.forwardProposal([pid, vidPP], { account: w_pp1.account });
    await gc.write.endorseProposal([pid], { account: w_pa1.account });
    await gc.write.voteProposal([pid, true], { account: w_pa1.account });
    await gc.write.voteProposal([pid, true], { account: w_pa2.account });
    await gc.write.voteProposal([pid, true], { account: w_pa3.account });

    const vidAA = await getVid(cvc, AA1, w_aa1, [vcAA], Role.AA, 0);
    await pr.write.confirmEnforcement([pid, cidPayload, vidAA], { account: w_aa1.account });
    return pid;
  }

  // =========================================================================
  // THA-1 — Policy injection
  // =========================================================================

  it("THA-1 — Nessuno può scrivere direttamente nel PR senza passare per il GC", async () => {
    const { pr } = await fullSetup();
    const cidFake = ipfsUpload(Buffer.from("malicious-policy"));
    const pidFake = `0x${"ff".repeat(32)}` as `0x${string}`;
    await assert.rejects(
      pr.write.certifyPolicy([pidFake, cidFake, cidFake, 0, 1, cidFake], { account: w_pa1.account })
    );
    await assert.rejects(
      pr.write.certifyPolicy([pidFake, cidFake, cidFake, 0, 1, cidFake], { account: w_deg1.account })
    );
  });

  // =========================================================================
  // Ciclo vita completo v1 → v2
  // =========================================================================

  it("Ciclo completo: v1 → v2 con JWT RS256, cifratura ibrida e verifica CID", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAA } = await fullSetup();

    const policyV1   = readFileSync("policies/LSP-NETWORK-001-v1.json", "utf8");
    const { encrypted: enc1 } = encryptDocument(Buffer.from(policyV1));
    const cidP1      = ipfsUpload(enc1.ciphertext);
    const safeDefCid = ipfsUpload(Buffer.from(readFileSync("policies/safe-default-network.json", "utf8")));

    const pid1 = await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidP1, ZERO_ID, safeDefCid);

    // Verifica CID
    const recV1 = await pr.read.getPolicy([pid1]);
    assert.equal(ipfsVerifyCID(ipfsDownload(recV1.cid), recV1.cid), true);

    const policyV2 = readFileSync("policies/LSP-NETWORK-001-v2.json", "utf8");
    const { encrypted: enc2 } = encryptDocument(Buffer.from(policyV2));
    const cidP2 = ipfsUpload(enc2.ciphertext);
    const pid2  = await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidP2, pid1);

    assert.equal(Number((await pr.read.getPolicy([pid1])).status), 1); // Archived
    assert.equal(Number((await pr.read.getPolicy([pid2])).status), 0); // Active
    assert.equal(await pr.read.getActivePolicy([0]), pid2);
    assert.equal((await pr.read.getDomainHistory([0])).length, 2);
  });

  // =========================================================================
  // THA-4 — Cascade revoca
  // =========================================================================

  it("THA-4 — Revoca PP1 blocca forward e il flusso della sua gerarchia", async () => {
    const { ir, gc, cvc, vcPP, vcDEG } = await fullSetup();

    assert.equal(await ir.read.isActive([PP1.did]), true);
    await ir.write.revokeDID([PP1.did], { account: w_pa1.account });
    assert.equal(await ir.read.isActive([PP1.did]), false);

    const cidFake    = ipfsUpload(Buffer.from("policy-test"));
    const safeDefCid = ipfsUpload(Buffer.from("safe-default"));
    const vidDEG     = await getVid(cvc, DEG1, w_deg1, [vcPP, vcDEG], Role.DEG, 0);
    await gc.write.submitProposal([cidFake, `Qm${"cc".repeat(22)}`, 0, ZERO_ID, safeDefCid, vidDEG], { account: w_deg1.account });
    const evs = await gc.getEvents.ProposalSubmitted();
    const pid  = evs[evs.length - 1].args.proposalId as `0x${string}`;

    // PP1 revocato — registerValidation fallisce per DID non attivo
    await assert.rejects(getVid(cvc, PP1, w_pp1, [vcPP], Role.PP, 0));

    const fakeVid = `0x${"ee".repeat(32)}` as `0x${string}`;
    await assert.rejects(
      gc.write.forwardProposal([pid, fakeVid], { account: w_pp1.account })
    );
  });

  // =========================================================================
  // Audit window
  // =========================================================================

  it("Audit window: aperta dopo certificazione, chiude dopo scadenza — WP2 §6.3", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAA } = await fullSetup();
    assert.equal(await gc.read.isAuditWindowOpen(), false);

    const cidPayload = ipfsUpload(Buffer.from("policy"));
    const safeDefCid = ipfsUpload(Buffer.from("safe-default"));
    await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload, ZERO_ID, safeDefCid);
    assert.equal(await gc.read.isAuditWindowOpen(), true);

    const testClient = await viem.getTestClient();
    await testClient.increaseTime({ seconds: 61 });
    await testClient.mine({ blocks: 1 });
    assert.equal(await gc.read.isAuditWindowOpen(), false);
  });

  // =========================================================================
  // Integrità CID
  // =========================================================================

  it("Integrità CID: CID alterato rilevato dalla verifica ipfsVerifyCID", async () => {
    const { gc, cvc, pr, vcPP, vcDEG, vcAA } = await fullSetup();

    const policyJson = readFileSync("policies/LSP-NETWORK-001-v1.json", "utf8");
    const { encrypted } = encryptDocument(Buffer.from(policyJson));
    const cidPayload = ipfsUpload(encrypted.ciphertext);
    const safeDefCid = ipfsUpload(Buffer.from("safe-default"));

    const pid = await certify(gc, cvc, pr, vcPP, vcDEG, vcAA, cidPayload, ZERO_ID, safeDefCid);
    const rec = await pr.read.getPolicy([pid]);

    assert.equal(ipfsVerifyCID(ipfsDownload(rec.cid), rec.cid), true);
    assert.equal(ipfsVerifyCID(Buffer.from("MALICIOUS CONTENT"), rec.cid), false);
  });
});
