import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { generateEntityKeys } from "../crypto/keys.js";

const SCOPE_FULL    = [0, 1, 2] as const;
const SCOPE_NETWORK = [0]       as const;
const ZERO_CRED     = `0x${"aa".repeat(32)}` as `0x${string}`;
const ZERO_CRED2    = `0x${"bb".repeat(32)}` as `0x${string}`;
const ZERO_CRED3    = `0x${"cc".repeat(32)}` as `0x${string}`;
const ZERO_BYTES32  = `0x${"00".repeat(32)}` as `0x${string}`;
const FUTURE        = 9_999_999_999n;
const Role = { PA: 0, PP: 1, DEG: 2, AUDITOR: 3, AA: 4, EV: 5 };

describe("IdentityRegistry", async () => {
  const { viem } = await network.connect();
  const wallets  = await viem.getWalletClients();
  const [deployer, w_pa1, w_pa2, w_pa3, w_pa4, w_aud1, w_aud2, w_pp1, w_deg1, w_aa1] = wallets;

  const PA1 = generateEntityKeys("did:ethr:pa1");
  const PA2 = generateEntityKeys("did:ethr:pa2");
  const PA3 = generateEntityKeys("did:ethr:pa3");
  const PA4 = generateEntityKeys("did:ethr:pa4");
  const PP1 = generateEntityKeys("did:ethr:pp1");
  const DEG1 = generateEntityKeys("did:ethr:deg1");
  const AA1  = generateEntityKeys("did:ethr:aa1");

  // registerAuditor ora richiede 4 parametri: did, publicKey, owner, credentialId
  async function setup() {
    const ir = await viem.deployContract("IdentityRegistry", []);
    const gc = await viem.deployContract("GovernanceContract", []);
    await ir.write.setGovernanceContract([gc.address], { account: deployer.account });
    await ir.write.registerPA([PA1.did, PA1.rsaPublicKeyHex, w_pa1.account.address], { account: deployer.account });
    await ir.write.registerPA([PA2.did, PA2.rsaPublicKeyHex, w_pa2.account.address], { account: deployer.account });
    await ir.write.registerPA([PA3.did, PA3.rsaPublicKeyHex, w_pa3.account.address], { account: deployer.account });
    await ir.write.registerPA([PA4.did, PA4.rsaPublicKeyHex, w_pa4.account.address], { account: deployer.account });
    await ir.write.registerAuditor([`did:ethr:aud1`, `0x${"01".repeat(64)}`, w_aud1.account.address, ZERO_BYTES32], { account: deployer.account });
    await ir.write.registerAuditor([`did:ethr:aud2`, `0x${"02".repeat(64)}`, w_aud2.account.address, ZERO_BYTES32], { account: deployer.account });
    await ir.write.finalizeBootstrap({ account: deployer.account });
    return ir;
  }

  // =========================================================================
  // BOOTSTRAP
  // =========================================================================

  it("finalizeBootstrap fallisce senza GovernanceContract", async () => {
    const ir = await viem.deployContract("IdentityRegistry", []);
    await ir.write.registerPA([PA1.did, PA1.rsaPublicKeyHex, w_pa1.account.address], { account: deployer.account });
    await ir.write.registerPA([PA2.did, PA2.rsaPublicKeyHex, w_pa2.account.address], { account: deployer.account });
    await ir.write.registerPA([PA3.did, PA3.rsaPublicKeyHex, w_pa3.account.address], { account: deployer.account });
    await ir.write.registerPA([PA4.did, PA4.rsaPublicKeyHex, w_pa4.account.address], { account: deployer.account });
    await ir.write.registerAuditor([`did:ethr:aud1`, `0x${"01".repeat(64)}`, w_aud1.account.address, ZERO_BYTES32], { account: deployer.account });
    await ir.write.registerAuditor([`did:ethr:aud2`, `0x${"02".repeat(64)}`, w_aud2.account.address, ZERO_BYTES32], { account: deployer.account });
    await assert.rejects(ir.write.finalizeBootstrap({ account: deployer.account }));
  });

  it("finalizeBootstrap fallisce con meno di 4 PA", async () => {
    const ir = await viem.deployContract("IdentityRegistry", []);
    const gc = await viem.deployContract("GovernanceContract", []);
    await ir.write.setGovernanceContract([gc.address], { account: deployer.account });
    await ir.write.registerPA([PA1.did, PA1.rsaPublicKeyHex, w_pa1.account.address], { account: deployer.account });
    await ir.write.registerPA([PA2.did, PA2.rsaPublicKeyHex, w_pa2.account.address], { account: deployer.account });
    await ir.write.registerPA([PA3.did, PA3.rsaPublicKeyHex, w_pa3.account.address], { account: deployer.account });
    await ir.write.registerAuditor([`did:ethr:aud1`, `0x${"01".repeat(64)}`, w_aud1.account.address, ZERO_BYTES32], { account: deployer.account });
    await ir.write.registerAuditor([`did:ethr:aud2`, `0x${"02".repeat(64)}`, w_aud2.account.address, ZERO_BYTES32], { account: deployer.account });
    await assert.rejects(ir.write.finalizeBootstrap({ account: deployer.account }));
  });

  it("bootstrap completo: isBootstrapComplete() == true", async () => {
    const ir = await setup();
    assert.equal(await ir.read.isBootstrapComplete(), true);
  });

  // =========================================================================
  // REGISTRAZIONE E RISOLUZIONE
  // =========================================================================

  it("registerDelegated: PA registra PP con scope [0,1,2]", async () => {
    const ir = await setup();
    await ir.write.registerDelegated(
      [PP1.did, PP1.rsaPublicKeyHex, w_pp1.account.address, 1, 0n, SCOPE_FULL, ZERO_CRED],
      { account: w_pa1.account }
    );
    const doc = await ir.read.resolve([PP1.did]);
    assert.equal(doc.active, true);
    assert.equal(Number(doc.role), Role.PP);
    assert.equal(doc.scope.length, 3);
  });

  it("registerDelegated: PP registra DEG con scope [0]", async () => {
    const ir = await setup();
    await ir.write.registerDelegated(
      [PP1.did, PP1.rsaPublicKeyHex, w_pp1.account.address, 1, 0n, SCOPE_FULL, ZERO_CRED],
      { account: w_pa1.account }
    );
    await ir.write.registerDelegated(
      [DEG1.did, DEG1.rsaPublicKeyHex, w_deg1.account.address, 2, 0n, SCOPE_NETWORK, ZERO_CRED2],
      { account: w_pp1.account }
    );
    const doc = await ir.read.resolve([DEG1.did]);
    assert.equal(Number(doc.role), Role.DEG);
    assert.equal(doc.scope.length, 1);
  });

  it("registerDelegated: PA registra AA con scadenza FUTURE", async () => {
    const ir = await setup();
    await ir.write.registerDelegated(
      [AA1.did, AA1.rsaPublicKeyHex, w_aa1.account.address, 4, FUTURE, SCOPE_NETWORK, ZERO_CRED],
      { account: w_pa1.account }
    );
    const doc = await ir.read.resolve([AA1.did]);
    assert.equal(Number(doc.role), Role.AA);
    assert.equal(Number(doc.didType), 1);
    assert.equal(doc.expiresAt, FUTURE);
  });

  it("registerDelegated: DEG non può sub-delegare — THA-2", async () => {
    const ir = await setup();
    await ir.write.registerDelegated(
      [PP1.did, PP1.rsaPublicKeyHex, w_pp1.account.address, 1, 0n, SCOPE_FULL, ZERO_CRED],
      { account: w_pa1.account }
    );
    await ir.write.registerDelegated(
      [DEG1.did, DEG1.rsaPublicKeyHex, w_deg1.account.address, 2, 0n, SCOPE_NETWORK, ZERO_CRED2],
      { account: w_pp1.account }
    );
    await assert.rejects(
      ir.write.registerDelegated(
        ["did:ethr:unknown", `0x${"ff".repeat(64)}`, w_aa1.account.address, 2, 0n, SCOPE_NETWORK, ZERO_CRED3],
        { account: w_deg1.account }
      )
    );
  });

  it("DID duplicato viene rifiutato", async () => {
    const ir = await setup();
    await ir.write.registerDelegated(
      [PP1.did, PP1.rsaPublicKeyHex, w_pp1.account.address, 1, 0n, SCOPE_FULL, ZERO_CRED],
      { account: w_pa1.account }
    );
    await assert.rejects(
      ir.write.registerDelegated(
        [PP1.did, PP1.rsaPublicKeyHex, w_pp1.account.address, 1, 0n, SCOPE_FULL, ZERO_CRED2],
        { account: w_pa1.account }
      )
    );
  });

  // =========================================================================
  // ISACTIVE E REVOCA
  // =========================================================================

  it("isActive: DID non registrato → false (no revert)", async () => {
    const ir = await setup();
    assert.equal(await ir.read.isActive(["did:ethr:nonexistent"]), false);
  });

  it("revokeDID: solo il registrante può revocare", async () => {
    const ir = await setup();
    await ir.write.registerDelegated(
      [PP1.did, PP1.rsaPublicKeyHex, w_pp1.account.address, 1, 0n, SCOPE_FULL, ZERO_CRED],
      { account: w_pa1.account }
    );
    await assert.rejects(
      ir.write.revokeDID([PP1.did], { account: w_pa2.account })
    );
  });

  it("revokeDID: DID revocato → isActive() == false (lazy cascade)", async () => {
    const ir = await setup();
    await ir.write.registerDelegated(
      [PP1.did, PP1.rsaPublicKeyHex, w_pp1.account.address, 1, 0n, SCOPE_FULL, ZERO_CRED],
      { account: w_pa1.account }
    );
    await ir.write.revokeDID([PP1.did], { account: w_pa1.account });
    assert.equal(await ir.read.isActive([PP1.did]), false);
  });

  it("PA e Auditor non possono essere revocati con revokeDID — richiedono quorum", async () => {
    const ir = await setup();
    await assert.rejects(
      ir.write.revokeDID([PA1.did], { account: w_pa1.account })
    );
  });

  // =========================================================================
  // ROTAZIONE CHIAVE
  // =========================================================================

  it("rotateKey: aggiorna chiave pubblica correttamente", async () => {
    const ir = await setup();
    await ir.write.registerDelegated(
      [PP1.did, PP1.rsaPublicKeyHex, w_pp1.account.address, 1, 0n, SCOPE_FULL, ZERO_CRED],
      { account: w_pa1.account }
    );
    const NEW_KEY = generateEntityKeys("did:ethr:pp1-new");
    await ir.write.rotateKey([PP1.did, NEW_KEY.rsaPublicKeyHex], { account: w_pp1.account });
    const doc = await ir.read.resolve([PP1.did]);
    assert.equal(doc.publicKey, NEW_KEY.rsaPublicKeyHex);
  });

  it("rotateKey: chiave identica viene rifiutata", async () => {
    const ir = await setup();
    await ir.write.registerDelegated(
      [PP1.did, PP1.rsaPublicKeyHex, w_pp1.account.address, 1, 0n, SCOPE_FULL, ZERO_CRED],
      { account: w_pa1.account }
    );
    await assert.rejects(
      ir.write.rotateKey([PP1.did, PP1.rsaPublicKeyHex], { account: w_pp1.account })
    );
  });

  // =========================================================================
  // REVOCA CREDENZIALI
  // =========================================================================

  it("revokeCredential: solo l'issuer può revocare — THA-2", async () => {
    const ir = await setup();
    await ir.write.registerDelegated(
      [PP1.did, PP1.rsaPublicKeyHex, w_pp1.account.address, 1, 0n, SCOPE_FULL, ZERO_CRED],
      { account: w_pa1.account }
    );
    await assert.rejects(
      ir.write.revokeCredential([ZERO_CRED], { account: w_pa2.account })
    );
  });

  it("revokeCredential: credentialId inesistente viene rifiutato", async () => {
    const ir = await setup();
    const NON_EXISTENT = `0x${"ff".repeat(32)}` as `0x${string}`;
    await assert.rejects(
      ir.write.revokeCredential([NON_EXISTENT], { account: w_pa1.account })
    );
  });
});
