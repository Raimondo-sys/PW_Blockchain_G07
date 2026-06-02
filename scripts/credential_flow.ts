/**
 * credential_flow.ts
 * Dimostrazione completa del flusso VC/VP con JWT RS256 e selective disclosure.
 * Mostra l'integrazione CVC: validationId registrato on-chain dopo verifica off-chain.
 *
 * ESEGUI:
 * npx hardhat run scripts/credential_flow.ts --network hardhatMainnet
 */

import { network }            from "hardhat";
import { generateEntityKeys } from "../crypto/keys.js";
import { issuePersistentVC, issueTemporaryVC, verifyVC, generateCredentialId } from "../crypto/vc.js";
import { buildVP, verifyVP, verifyDisclosures, generateNonce, computeValidationId } from "../crypto/vp.js";
import { createHash }         from "crypto";

const Role = { PA: 0, PP: 1, DEG: 2, AUDITOR: 3, AA: 4, EV: 5 };

function separator(title: string) {
  console.log(`\n── ${title} ${"─".repeat(Math.max(0, 60 - title.length))}`);
}

async function main() {
  const { viem } = await network.connect("hardhatMainnet");
  const wallets  = await viem.getWalletClients();
  const [deployer, w_pa1, w_pa2, w_pa3, w_pa4,
         w_aud1, w_aud2, w_pp1, w_deg1, w_aa1] = wallets;

  console.log("\n================================================================");
  console.log("  CREDENTIAL FLOW — VC/VP JWT RS256 + Selective Disclosure");
  console.log("  Integrazione CVC: validationId on-chain dopo verifica off-chain");
  console.log("================================================================");

  // ==========================================================================
  // FASE 0 — SETUP
  // ==========================================================================

  separator("Fase 0: Deploy e bootstrap");

  const PA1  = generateEntityKeys("did:ethr:pa1");
  const PP1  = generateEntityKeys("did:ethr:pp1");
  const DEG1 = generateEntityKeys("did:ethr:deg1");
  const PA2  = generateEntityKeys("did:ethr:pa2");
  const PA3  = generateEntityKeys("did:ethr:pa3");
  const PA4  = generateEntityKeys("did:ethr:pa4");
  const AUD1 = generateEntityKeys("did:ethr:aud1");
  const AUD2 = generateEntityKeys("did:ethr:aud2");

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
  await cvc.write.setPolicyRegistry([pr.address],       { account: deployer.account }); // <--- FIX: PolicyRegistry nel CVC

  await pr.write.setIdentityRegistry([ir.address],      { account: deployer.account });
  await pr.write.setGovernanceContract([gc.address],    { account: deployer.account });
  await pr.write.setCVC([cvc.address],                  { account: deployer.account });

  await ir.write.registerPA([PA1.did, PA1.rsaPublicKeyHex, w_pa1.account.address], { account: deployer.account });
  await ir.write.registerPA([PA2.did, PA2.rsaPublicKeyHex, w_pa2.account.address], { account: deployer.account });
  await ir.write.registerPA([PA3.did, PA3.rsaPublicKeyHex, w_pa3.account.address], { account: deployer.account });
  await ir.write.registerPA([PA4.did, PA4.rsaPublicKeyHex, w_pa4.account.address], { account: deployer.account });

  // FIX: Generazione Credential IDs per gli Auditor
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

  await ir.write.registerDelegated(
    [PP1.did, PP1.rsaPublicKeyHex, w_pp1.account.address, 1, 0n, [0,1,2], credIdPP1],
    { account: w_pa1.account }
  );
  await ir.write.registerDelegated(
    [DEG1.did, DEG1.rsaPublicKeyHex, w_deg1.account.address, 2, 0n, [0], credIdDEG1],
    { account: w_pp1.account }
  );

  console.log("  Setup completato");

  // ==========================================================================
  // FASE 1 — EMISSIONE VC
  // ==========================================================================

  separator("Fase 1: Emissione VC (JWT RS256)");

  // PA1 → PP1: PersistentVC con scope completo
  const vcPP1 = issuePersistentVC(
    PA1.did, PA1.rsaPrivateKeyPem, PP1.did,
    Role.PP, [0, 1, 2], credIdPP1
  );
  console.log("  PA1 ha emesso PersistentVC a PP1");
  console.log(`  JWT (header.payload): ${vcPP1.jwt.split(".").slice(0,2).join(".").substring(0,60)}...`);

  // PP1 → DEG1: PersistentVC con scope NETWORK
  const vcDEG1 = issuePersistentVC(
    PP1.did, PP1.rsaPrivateKeyPem, DEG1.did,
    Role.DEG, [0], credIdDEG1
  );
  console.log("  PP1 ha emesso PersistentVC a DEG1 (scope: NETWORK)");

  // ==========================================================================
  // FASE 2 — VERIFICA VC OFF-CHAIN
  // ==========================================================================

  separator("Fase 2: Verifica VC off-chain");

  // Risolve chiave pubblica dell'issuer dall'IR on-chain
  const pa1Doc  = await ir.read.resolve([PA1.did]);
  const pp1Doc  = await ir.read.resolve([PP1.did]);
  const pa1PubKey = Buffer.from((pa1Doc.publicKey as string).slice(2), "hex").toString("utf8");
  const pp1PubKey = Buffer.from((pp1Doc.publicKey as string).slice(2), "hex").toString("utf8");

  const decodedVCPP1  = verifyVC(vcPP1.jwt,  pa1PubKey);
  const decodedVCDEG1 = verifyVC(vcDEG1.jwt, pp1PubKey);

  console.log(`  VC PP1  verificata: iss=${decodedVCPP1.iss} sub=${decodedVCPP1.sub} role=${decodedVCPP1.role}`);
  console.log(`  VC DEG1 verificata: iss=${decodedVCDEG1.iss} sub=${decodedVCDEG1.sub} scope=${decodedVCDEG1.scope}`);

  // Verifica holder binding: sub(VC_PA→PP) == iss(VC_PP→DEG)
  const holderBinding = decodedVCPP1.sub === decodedVCDEG1.iss;
  console.log(`  Holder binding (sub PA→PP == iss PP→DEG): ${holderBinding ? "✓" : "✗"}`);

  // ==========================================================================
  // FASE 3 — SELECTIVE DISCLOSURE
  // ==========================================================================

  separator("Fase 3: Selective disclosure nella VP");

  // Claim del DEG con salt per selective disclosure
  const claims = {
    did:    DEG1.did,
    domain: "NETWORK",
    role:   "DEG",
  };
  const salts: Record<string, string> = {};
  const commitments: Record<string, string> = {};
  for (const [k, v] of Object.entries(claims)) {
    salts[k] = createHash("sha256").update(DEG1.did + k).digest("hex").slice(0, 16);
    commitments[k] = createHash("sha256").update(`${k}:${v}:${salts[k]}`).digest("hex");
  }

  // DEG rivela solo il claim "domain" (necessario per submitProposal)
  const disclosures = {
    domain: { value: claims.domain, salt: salts.domain },
  };

  console.log(`  Claim totali: ${Object.keys(claims).length}`);
  console.log(`  Claim rivelati nella VP: ${Object.keys(disclosures).length} (solo "domain")`);
  console.log(`  Claim nascosti: did, role`);

  // ==========================================================================
  // FASE 4 — COSTRUZIONE E VERIFICA VP
  // ==========================================================================

  separator("Fase 4: Costruzione VP e verifica off-chain");

  const nonce      = generateNonce();
  const cvcAddress = cvc.address as string;

  const vpJwt = buildVP(
    DEG1.did,
    DEG1.rsaPrivateKeyPem,
    cvcAddress,
    nonce,
    [vcPP1, vcDEG1],
    disclosures
  );

  console.log("  VP costruita e firmata dal DEG");
  console.log(`  Nonce anti-replay: ${nonce.substring(0, 16)}...`);

  // Verifica VP off-chain
  const deg1Doc    = await ir.read.resolve([DEG1.did]);
  const deg1PubKey = Buffer.from((deg1Doc.publicKey as string).slice(2), "hex").toString("utf8");
  const decodedVP  = verifyVP(vpJwt, deg1PubKey, nonce, cvcAddress);

  console.log(`  VP verificata: iss=${decodedVP.iss} aud=${decodedVP.aud}`);
  console.log(`  Nonce corrisponde: ✓`);

  // Verifica disclosures contro commitments
  const disclosuresOk = verifyDisclosures(decodedVP.vp.disclosures, commitments);
  console.log(`  Disclosures verificate contro commitments: ${disclosuresOk ? "✓" : "✗"}`);
  console.log(`  Claim nascosti (did, role) non presenti nella VP: ✓`);

  // ==========================================================================
  // FASE 5 — REGISTRAZIONE VALIDATIONID ON-CHAIN NEL CVC
  // ==========================================================================

  separator("Fase 5: Registrazione validationId on-chain nel CVC");

  const validationId = computeValidationId(vpJwt);
  console.log(`  validationId = keccak256-like(vpJwt): ${validationId.substring(0, 20)}...`);

  await cvc.write.registerValidation(
    [validationId, DEG1.did, Role.DEG, 0, 0n],
    { account: w_deg1.account }
  );

  const record = await cvc.read.getValidation([validationId]);
  console.log(`  Registrazione on-chain: ✓`);
  console.log(`  holderDID: ${record.holderDID}`);
  console.log(`  role:      ${record.role} (DEG=2)`);
  console.log(`  domain:    ${record.domain} (NETWORK=0)`);
  console.log(`  usable:    ${await cvc.read.isValidationUsable([validationId]) ? "✓ sì" : "✗ no"}`);

  // ==========================================================================
  // FASE 6 — ANTI-REPLAY
  // ==========================================================================

  separator("Fase 6: Test anti-replay");

  // Tentativo di riuso dello stesso validationId
  try {
    await cvc.write.registerValidation(
      [validationId, DEG1.did, Role.DEG, 0, 0n],
      { account: w_deg1.account }
    );
    console.log("  ✗ ERRORE: riuso validationId non bloccato");
  } catch {
    console.log("  ✓ Riuso validationId bloccato correttamente (già registrato)");
  }

  // Tentativo con VP falsificata (firma non valida)
  const tamperedVP = vpJwt.slice(0, -5) + "XXXXX";
  try {
    verifyVP(tamperedVP, deg1PubKey, nonce, cvcAddress);
    console.log("  ✗ ERRORE: VP falsificata non rilevata");
  } catch {
    console.log("  ✓ VP con firma falsificata rigettata correttamente");
  }

  // ==========================================================================
  // FASE 7 — TEMPORARYVC (AA e EV)
  // ==========================================================================

  separator("Fase 7: TemporaryVC per AA (scadenza obbligatoria)");

  const credIdAA = generateCredentialId(PA1.did, "did:ethr:aa-demo", Role.AA) as `0x${string}`;
  const vcAA     = issueTemporaryVC(
    PA1.did, PA1.rsaPrivateKeyPem,
    "did:ethr:aa-demo",
    Role.AA, [0], credIdAA,
    3600 // 1 ora
  );

  const decodedAA = verifyVC(vcAA.jwt, pa1PubKey);
  console.log(`  TemporaryVC AA emessa: exp=${new Date((decodedAA.exp ?? 0) * 1000).toISOString()}`);
  console.log(`  Scadenza esplicita obbligatoria: ${decodedAA.exp ? "✓ presente" : "✗ assente"}`);

  // ==========================================================================
  // RIEPILOGO
  // ==========================================================================

  separator("RIEPILOGO");
  console.log(`
  1. EMISSIONE VC JWT RS256 (WP2 §4.2)
     PA emette PersistentVC a PP, PP emette PersistentVC a DEG.
     Ogni VC è un JWT firmato con chiave RSA 2048 dell'issuer.

  2. VERIFICA VC OFF-CHAIN (WP2 §4.3.2)
     Il verifier risolve la chiave pubblica dell'issuer dall'IR on-chain
     e verifica la firma JWT. Holder binding verificato (sub == iss catena).

  3. SELECTIVE DISCLOSURE (WP2 §4.3.2)
     Il DEG rivela solo il claim "domain" nella VP, nascondendo did e role.
     I disclosures sono verificati contro i commitments hash+salt dell'issuer.

  4. VP JWT RS256 CON NONCE ANTI-REPLAY (WP2 §4.3.5)
     VP firmata dal holder con catena VC, nonce, audience (CVC address).
     VP falsificata rigettata dalla verifica della firma.

  5. VALIDATIONID ON-CHAIN NEL CVC (WP4 — giustificazione architetturale)
     RSA non verificabile on-chain nell'EVM.
     Pattern: verifica off-chain → validationId = hash(vpJwt) registrato on-chain.
     Il GC consuma il validationId prima di accettare l'operazione privilegiata.

  6. TEMPORARYVC (WP2 §4.3.4)
     AA e EV ricevono TemporaryVC con scadenza obbligatoria.
     Scadenza automatica senza transazioni di manutenzione.
  `);
}

main().catch((err) => { console.error(err); process.exit(1); });