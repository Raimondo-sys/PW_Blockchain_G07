/**
 * vp.ts
 * Costruisce e verifica Verifiable Presentations come JWT RS256.
 * Selective disclosure: solo i claim necessari vengono rivelati (scope del dominio).
 *
 * Struttura VP JWT:
 *   payload: {
 *     iss:   holderDID,
 *     aud:   cvcAddress,
 *     nonce: challenge on-chain (anti-replay),
 *     vp: {
 *       chain:       VC JWT chain (PA→PP→DEG ecc.),
 *       disclosures: claim rivelati selettivamente
 *     }
 *   }
 *
 * Selective disclosure (semplificata, ispirata a SD-JWT):
 *   - L'issuer include nella VC gli hash dei claim (commitments)
 *   - Il holder rivela solo i claim necessari con il loro salt
 *   - Il verifier ricalcola l'hash e lo confronta con il commitment
 */

import jwt      from "jsonwebtoken";
import { createHash, randomBytes } from "crypto";
import type { VerifiableCredential } from "./vc.js";

export interface Disclosure {
  value: string;
  salt:  string;
}

export interface VPPayload {
  iss:   string;   // holderDID
  aud:   string;   // indirizzo CVC on-chain
  nonce: string;   // challenge anti-replay
  iat:   number;
  exp:   number;
  vp: {
    chain:       string[];                     // JWT di ogni VC nella catena
    disclosures: Record<string, Disclosure>;   // claim rivelati
  };
}

/**
 * Costruisce e firma una VP che include la catena di VC e i claim selettivamente divulgati.
 * @param holderDID     DID di chi presenta
 * @param holderPrivKey chiave privata RSA del holder
 * @param cvcAddress    indirizzo del CVC (audience)
 * @param nonce         challenge generato off-chain (anti-replay)
 * @param vcChain       array di VC JWT nella catena di delega
 * @param disclosures   claim da rivelare (solo quelli necessari per l'operazione)
 * @param ttlSeconds    durata della VP (default 5 minuti)
 */
export function buildVP(
  holderDID:     string,
  holderPrivKey: string,
  cvcAddress:    string,
  nonce:         string,
  vcChain:       VerifiableCredential[],
  disclosures:   Record<string, Disclosure>,
  ttlSeconds     = 300
): string {
  const now = Math.floor(Date.now() / 1000);

  const payload: VPPayload = {
    iss:   holderDID,
    aud:   cvcAddress,
    nonce,
    iat:   now,
    exp:   now + ttlSeconds,
    vp: {
      chain:       vcChain.map((vc) => vc.jwt),
      disclosures,
    },
  };

  return jwt.sign(payload, holderPrivKey, { algorithm: "RS256" });
}

/**
 * Verifica la VP e restituisce il payload decodificato.
 * Lancia eccezione se la firma non è valida, la VP è scaduta o il nonce non corrisponde.
 */
export function verifyVP(
  vpJwt:          string,
  holderPublicKey: string,
  expectedNonce:   string,
  cvcAddress:      string
): VPPayload {
  const decoded = jwt.verify(vpJwt, holderPublicKey, {
    algorithms: ["RS256"],
    audience:   cvcAddress,
  }) as VPPayload;

  if (decoded.nonce !== expectedNonce)
    throw new Error(`Nonce non corrisponde: atteso ${expectedNonce}, ricevuto ${decoded.nonce}`);

  return decoded;
}

/**
 * Verifica i claim rivelati contro i commitment nella VC.
 * @param disclosures  claim rivelati dal holder
 * @param commitments  hash dei claim registrati nella VC dall'issuer
 */
export function verifyDisclosures(
  disclosures: Record<string, Disclosure>,
  commitments: Record<string, string>
): boolean {
  for (const [key, { value, salt }] of Object.entries(disclosures)) {
    const recomputed = createHash("sha256")
      .update(`${key}:${value}:${salt}`)
      .digest("hex");
    if (recomputed !== commitments[key]) return false;
  }
  return true;
}

/**
 * Genera un nonce casuale per il challenge anti-replay.
 */
export function generateNonce(): string {
  return randomBytes(16).toString("hex");
}

/**
 * Calcola il validationId da registrare on-chain nel CVC.
 * validationId = keccak256-like(vpJwt) — lega il record on-chain al JWT specifico.
 */
export function computeValidationId(vpJwt: string): `0x${string}` {
  return `0x${createHash("sha256").update(vpJwt).digest("hex")}` as `0x${string}`;
}
