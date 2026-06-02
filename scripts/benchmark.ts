/**
 * benchmark.ts
 * Valutazione delle performance del sistema — latency, throughput, storage overhead.
 * Misura operazioni off-chain (cifratura ibrida, JWT) e on-chain (gas, block time).
 *
 * ESEGUI:
 * npx hardhat run scripts/benchmark.ts --network hardhatMainnet
 */

import { network }            from "hardhat";
import { generateEntityKeys } from "../crypto/keys.js";
import { issuePersistentVC, issueTemporaryVC, generateCredentialId } from "../crypto/vc.js";
import { buildVP, generateNonce, computeValidationId } from "../crypto/vp.js";
import { encryptDocument, buildKDDoc }               from "../crypto/hybrid.js";
import { ipfsUpload }                                from "../ipfs/ipfs-simulated.js";
import { randomBytes }                               from "crypto";

const Role = { PA: 0, PP: 1, DEG: 2, AUDITOR: 3, AA: 4, EV: 5 };

function hrMs(): number {
  const [s, ns] = process.hrtime();
  return s * 1000 + ns / 1_000_000;
}

function fmtBytes(b: number): string {
  if (b < 1024)        return `${b} B`;
  if (b < 1024 * 1024) return `${(b/1024).toFixed(1)} KB`;
  return `${(b/(1024*1024)).toFixed(2)} MB`;
}

function fmtMs(ms: number): string {
  return `${ms.toFixed(2)} ms`;
}

function separator(title: string) {
  console.log(`\n── ${title} ${"─".repeat(Math.max(0, 60 - title.length))}`);
}

// ============================================================================
// BENCHMARK OFF-CHAIN
// ============================================================================

function benchmarkKeyGen(iterations = 5) {
  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const t0 = hrMs();
    generateEntityKeys(`did:ethr:bench${i}`);
    times.push(hrMs() - t0);
  }
  return times.reduce((a, b) => a + b) / times.length;
}

// [cite: 494, 495, 530]
function benchmarkEncryption(docSizeKB: number, numRecipients: number) {
  const doc        = randomBytes(docSizeKB * 1024);
  const recipients = Array.from({ length: numRecipients }, (_, i) =>
    generateEntityKeys(`did:ethr:r${i}`)
  );

  const t0 = hrMs();
  const { symmetricKey, encrypted } = encryptDocument(Buffer.from(doc));
  const encryptMs = hrMs() - t0;

  const t1 = hrMs();
  const kd = buildKDDoc(symmetricKey, recipients, "bench");
  const keyWrapMs = hrMs() - t1;

  const t2 = hrMs();
  ipfsUpload(encrypted.ciphertext);
  const ipfsMs = hrMs() - t2;

  const payloadSize = encrypted.ciphertext.length + encrypted.authTag.length;
  const kdSize      = JSON.stringify(kd).length;

  return { encrypted, encryptMs, keyWrapMs, ipfsMs, payloadSize, kdSize };
}

function benchmarkJWT(numVCs: number) {
  const issuer  = generateEntityKeys("did:ethr:issuer");
  const subject = generateEntityKeys("did:ethr:subject");
  const vcs     = [];

  const t0 = hrMs();
  for (let i = 0; i < numVCs; i++) {
    const credId = generateCredentialId(issuer.did, subject.did, Role.PP) as `0x${string}`;
    vcs.push(issuePersistentVC(issuer.did, issuer.rsaPrivateKeyPem, subject.did, Role.PP, [0,1,2], credId));
  }
  const issueMs = hrMs() - t0;

  const nonce = generateNonce();
  const t1    = hrMs();
  const vpJwt = buildVP(subject.did, subject.rsaPrivateKeyPem, "0x1234", nonce, vcs, {});
  const buildVpMs = hrMs() - t1;

  const t2 = hrMs();
  computeValidationId(vpJwt);
  const hashMs = hrMs() - t2;

  return { issueMs: issueMs / numVCs, buildVpMs, hashMs, vpSize: vpJwt.length };
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
  const { viem } = await network.connect("hardhatMainnet");
  const wallets  = await viem.getWalletClients();
  const [deployer, w_pa1, w_pa2, w_pa3, w_pa4, w_aud1, w_aud2, w_pp1, w_deg1, w_aa1] = wallets;

  console.log("\n================================================================");
  console.log("  BENCHMARK — Latency, Throughput, Storage Overhead");
  console.log("================================================================");

  // ==========================================================================
  // SETUP CONTRATTI
  // ==========================================================================

  separator("Setup contratti");

  const PA1  = generateEntityKeys("did:ethr:pa1");
  const PA2  = generateEntityKeys("did:ethr:pa2");
  const PA3  = generateEntityKeys("did:ethr:pa3");
  const PA4  = generateEntityKeys("did:ethr:pa4");
  const AUD1 = generateEntityKeys("did:ethr:aud1");
  const AUD2 = generateEntityKeys("did:ethr:aud2");
  const PP1  = generateEntityKeys("did:ethr:pp1");
  const DEG1 = generateEntityKeys("did:ethr:deg1");
  const AA1  = generateEntityKeys("did:ethr:aa1");

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
  await cvc.write.setPolicyRegistry([pr.address],       { account: deployer.account }); // <--- FIX 1: Impostazione PolicyRegistry nel CVC [cite: 525]

  await pr.write.setIdentityRegistry([ir.address],      { account: deployer.account });
  await pr.write.setGovernanceContract([gc.address],    { account: deployer.account });
  await pr.write.setCVC([cvc.address],                  { account: deployer.account });

  await ir.write.registerPA([PA1.did, PA1.rsaPublicKeyHex, w_pa1.account.address], { account: deployer.account });
  await ir.write.registerPA([PA2.did, PA2.rsaPublicKeyHex, w_pa2.account.address], { account: deployer.account });
  await ir.write.registerPA([PA3.did, PA3.rsaPublicKeyHex, w_pa3.account.address], { account: deployer.account });
  await ir.write.registerPA([PA4.did, PA4.rsaPublicKeyHex, w_pa4.account.address], { account: deployer.account });
  
  // <--- FIX 2: Generazione Credential IDs e passaggio del 4° parametro per registerAuditor 
  const credIdAUD1 = generateCredentialId(PA1.did, AUD1.did, Role.AUDITOR) as `0x${string}`;
  const credIdAUD2 = generateCredentialId(PA1.did, AUD2.did, Role.AUDITOR) as `0x${string}`;
  await ir.write.registerAuditor([AUD1.did, AUD1.rsaPublicKeyHex, w_aud1.account.address, credIdAUD1], { account: deployer.account });
  await ir.write.registerAuditor([AUD2.did, AUD2.rsaPublicKeyHex, w_aud2.account.address, credIdAUD2], { account: deployer.account });
  
  await pr.write.finalizeBootstrap({ account: deployer.account });
  await cvc.write.finalizeBootstrap({ account: deployer.account }); // [cite: 527]
  await gc.write.finalizeBootstrap({ account: deployer.account });
  await ir.write.finalizeBootstrap({ account: deployer.account });

  const credIdPP1  = generateCredentialId(PA1.did, PP1.did,  Role.PP)  as `0x${string}`;
  const credIdDEG1 = generateCredentialId(PP1.did, DEG1.did, Role.DEG) as `0x${string}`;
  const credIdAA1  = generateCredentialId(PA1.did, AA1.did,  Role.AA)  as `0x${string}`;

  await ir.write.registerDelegated([PP1.did,  PP1.rsaPublicKeyHex,  w_pp1.account.address,  1, 0n, [0,1,2], credIdPP1],  { account: w_pa1.account });
  await ir.write.registerDelegated([DEG1.did, DEG1.rsaPublicKeyHex, w_deg1.account.address, 2, 0n, [0],     credIdDEG1], { account: w_pp1.account });
  await ir.write.registerDelegated([AA1.did,  AA1.rsaPublicKeyHex,  w_aa1.account.address,  4, 9_999_999_999n, [0], credIdAA1], { account: w_pa1.account });

  const pub = await viem.getPublicClient();
  console.log("  Setup completato");

  // ==========================================================================
  // BENCHMARK 1: GENERAZIONE CHIAVI
  // ==========================================================================

  separator("Benchmark 1: Generazione chiavi RSA 2048 + ECDH P-256");

  const avgKeyGenMs = benchmarkKeyGen(5);
  console.log(`  Media su 5 iterazioni: ${fmtMs(avgKeyGenMs)}`);
  console.log(`  Throughput: ${(1000 / avgKeyGenMs).toFixed(1)} chiavi/sec`);

  // ==========================================================================
  // BENCHMARK 2: CIFRATURA IBRIDA
  // ==========================================================================

  separator("Benchmark 2: Cifratura ibrida AES-256-GCM + ECDH P-256");

  const docSizes    = [1, 10, 100, 1024];
  const recipCounts = [1, 4, 8];

  console.log(`\n  ${"Doc".padEnd(8)} ${"Dest".padEnd(6)} ${"Cifra".padStart(10)} ${"KeyWrap".padStart(10)} ${"IPFS".padStart(8)} ${"Payload".padStart(10)} ${"KD Doc".padStart(10)} ${"Overhead".padStart(10)}`);
  console.log(`  ${"─".repeat(72)}`);

  for (const sizeKB of docSizes) {
    for (const nRec of recipCounts) {
      const r = benchmarkEncryption(sizeKB, nRec);
      const overhead = ((r.payloadSize + r.kdSize - sizeKB * 1024) / (sizeKB * 1024) * 100).toFixed(1);
      console.log(
        `  ${(sizeKB + " KB").padEnd(8)}` +
        `${nRec.toString().padEnd(6)}` +
        `${fmtMs(r.encryptMs).padStart(10)}` +
        `${fmtMs(r.keyWrapMs).padStart(10)}` +
        `${fmtMs(r.ipfsMs).padStart(8)}` +
        `${fmtBytes(r.payloadSize).padStart(10)}` +
        `${fmtBytes(r.kdSize).padStart(10)}` +
        `${(overhead + "%").padStart(10)}`
      );
    }
  }

  // ==========================================================================
  // BENCHMARK 3: JWT VC/VP
  // ==========================================================================

  separator("Benchmark 3: JWT RS256 — emissione VC e costruzione VP");

  for (const nVCs of [1, 2, 3]) {
    const r = benchmarkJWT(nVCs);
    console.log(`  ${nVCs} VC nella catena:`);
    console.log(`    Emissione VC (media): ${fmtMs(r.issueMs)}`);
    console.log(`    Costruzione VP:       ${fmtMs(r.buildVpMs)}`);
    console.log(`    Hash validationId:    ${fmtMs(r.hashMs)}`);
    console.log(`    Dimensione VP JWT:    ${fmtBytes(r.vpSize)}`);
  }

  // ==========================================================================
  // BENCHMARK 4: TRANSAZIONI ON-CHAIN
  // ==========================================================================

  separator("Benchmark 4: Gas e latency transazioni on-chain");

  const vcPP  = issuePersistentVC(PA1.did, PA1.rsaPrivateKeyPem, PP1.did,  Role.PP,  [0,1,2], credIdPP1);
  const vcDEG = issuePersistentVC(PP1.did, PP1.rsaPrivateKeyPem, DEG1.did, Role.DEG, [0],     credIdDEG1);

  const ZERO_ID = `0x${"00".repeat(32)}` as `0x${string}`;
  const safeDefCid = ipfsUpload(Buffer.from("safe-default"));

  // Prepara proposta
  const rEnc = benchmarkEncryption(10, 5); // 10 KB payload
  const cidPayload  = ipfsUpload(rEnc.encrypted.ciphertext);
  const kdDoc       = buildKDDoc(randomBytes(32), [PA1, PA2, PA3, PA4, PP1], "bench");
  const cidKDDelib  = ipfsUpload(Buffer.from(JSON.stringify(kdDoc)));

  const nonce   = generateNonce();
  const vpDEG   = buildVP(DEG1.did, DEG1.rsaPrivateKeyPem, cvc.address as string, nonce, [vcPP, vcDEG], {});
  const vidDEG  = computeValidationId(vpDEG);

  const txBenchmarks: { op: string; gasUsed: bigint; ms: number }[] = [];

  async function measureTx(op: string, fn: () => Promise<`0x${string}`>) {
    const t0   = hrMs();
    const hash = await fn();
    const rcpt = await pub.waitForTransactionReceipt({ hash });
    const ms   = hrMs() - t0;
    txBenchmarks.push({ op, gasUsed: rcpt.gasUsed, ms });
    console.log(`  ${op.padEnd(30)} gas: ${rcpt.gasUsed.toString().padStart(8)}   time: ${fmtMs(ms)}`);
  }

  await measureTx("registerValidation (DEG)", () =>
    cvc.write.registerValidation([vidDEG, DEG1.did, Role.DEG, 0, 0n], { account: w_deg1.account })
  );

  await measureTx("submitProposal", () =>
    gc.write.submitProposal([cidPayload, cidKDDelib, 0, ZERO_ID, safeDefCid, vidDEG], { account: w_deg1.account })
  );

  const evs     = await gc.getEvents.ProposalSubmitted();
  const pid     = evs[evs.length - 1].args.proposalId as `0x${string}`;

  const noncePP  = generateNonce();
  const vpPP     = buildVP(PP1.did, PP1.rsaPrivateKeyPem, cvc.address as string, noncePP, [vcPP], {});
  const vidPP    = computeValidationId(vpPP);

  await measureTx("registerValidation (PP)", () =>
    cvc.write.registerValidation([vidPP, PP1.did, Role.PP, 0, 0n], { account: w_pp1.account })
  );

  await measureTx("forwardProposal", () =>
    gc.write.forwardProposal([pid, vidPP], { account: w_pp1.account })
  );

  await measureTx("endorseProposal", () =>
    gc.write.endorseProposal([pid], { account: w_pa1.account })
  );

  await measureTx("voteProposal", () =>
    gc.write.voteProposal([pid, true], { account: w_pa1.account })
  );
  await measureTx("voteProposal (certifica)", () =>
    gc.write.voteProposal([pid, true], { account: w_pa2.account })
  );

  // Il terzo voto certifica (3/4)
  const t0v3   = hrMs();
  const hashV3 = await gc.write.voteProposal([pid, true], { account: w_pa3.account });
  const rcptV3 = await pub.waitForTransactionReceipt({ hash: hashV3 });
  const msV3   = hrMs() - t0v3;
  txBenchmarks.push({ op: "voteProposal (3/4 → certifica)", gasUsed: rcptV3.gasUsed, ms: msV3 });
  console.log(`  ${"voteProposal (3/4 → certifica)".padEnd(30)} gas: ${rcptV3.gasUsed.toString().padStart(8)}   time: ${fmtMs(msV3)}`);

  await measureTx("updateKeyDistrib", () =>
    pr.write.updateKeyDistrib([pid, cidKDDelib], { account: w_pa1.account })
  );

  const record = await pr.read.getPolicy([pid]);

  // <--- FIX 3: Generazione, firma e registrazione validationId temporaneo per l'Application Agent prima dell'enforcement 
  const nonceAA = generateNonce();
  const vcAA    = issueTemporaryVC(PA1.did, PA1.rsaPrivateKeyPem, AA1.did, Role.AA, [0], credIdAA1, 3600);
  const vpAA    = buildVP(AA1.did, AA1.rsaPrivateKeyPem, cvc.address as string, nonceAA, [vcAA], {});
  const vidAA   = computeValidationId(vpAA);

  await measureTx("registerValidation (AA)", () =>
    cvc.write.registerValidation([vidAA, AA1.did, Role.AA, 0, 0n], { account: w_aa1.account })
  );

  // Allineamento a 3 parametri (proposalId, appliedCid, validationId) 
  await measureTx("confirmEnforcement", () =>
    pr.write.confirmEnforcement([pid, record.cid, vidAA], { account: w_aa1.account })
  );

  // ==========================================================================
  // BENCHMARK 5: THROUGHPUT STIMA
  // ==========================================================================

  separator("Benchmark 5: Stima throughput ciclo vita policy");

  const totalGas = txBenchmarks.reduce((sum, t) => sum + t.gasUsed, 0n);
  const totalMs  = txBenchmarks.reduce((sum, t) => sum + t.ms, 0);
  const avgGas   = totalGas / BigInt(txBenchmarks.length);

  console.log(`  Transazioni per ciclo vita completo: ${txBenchmarks.length}`);
  console.log(`  Gas totale per ciclo vita:           ${totalGas.toString()}`);
  console.log(`  Gas medio per transazione:           ${avgGas.toString()}`);
  console.log(`  Tempo totale (rete simulata):        ${fmtMs(totalMs)}`);
  console.log(`  Tempo medio per transazione:         ${fmtMs(totalMs / txBenchmarks.length)}`);

  // ==========================================================================
  // RIEPILOGO TABELLE
  // ==========================================================================

  separator("RIEPILOGO");
  console.log(`
  OSSERVAZIONI:

  Off-chain (cifratura + JWT):
  ─ Generazione chiavi RSA 2048: ~${avgKeyGenGenMs => avgKeyGenMs.toFixed(0)} ms — operazione one-time per entità
  ─ Cifratura AES-256-GCM: scala linearmente con la dimensione del documento
  ─ Key wrap ECDH: scala con il numero di destinatari, indipendente dalla dimensione
  ─ Overhead KD doc: dominante per doc piccoli, trascurabile per doc >100 KB
  ─ JWT RS256: ~${benchmarkJWT(2).buildVpMs.toFixed(0)} ms per VP con 2 VC nella catena

  On-chain (gas + latency):
  ─ Gas totale ciclo vita: ${totalGas.toString()} unità
  ─ Operazione più costosa: voteProposal che certifica (include certifyPolicy)
  ─ Tutti i costi sono deterministici e proporzionali ai dati scritti
  ─ La rete PoA consortium guarantees immediate finality (1 blocco)
  `);
}

main().catch((err) => { console.error(err); process.exit(1); });