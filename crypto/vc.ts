/**
 * vc.ts
 * Costruisce e verifica Verifiable Credentials come JWT RS256.
 * Supporta PersistentVC (senza scadenza) e TemporaryVC (con scadenza).
 *
 * Struttura JWT:
 *   header: { alg: "RS256", typ: "JWT" }
 *   payload: { iss, sub, credentialId, role, scope, iat, [exp] }
 */

import jwt from "jsonwebtoken";
import { createHash, randomBytes } from "crypto";

export interface VCPayload {
  iss:          string;   // DID dell'issuer
  sub:          string;   // DID del subject (holder)
  credentialId: string;   // keccak256-like ID per revoca on-chain
  role:         number;   // Role enum: PA=0, PP=1, DEG=2, AUDITOR=3, AA=4, EV=5
  scope:        number[]; // Domain enum: NETWORK=0, SYSTEM=1, APPLICATION=2
  iat:          number;
  exp?:         number;   // assente per PersistentVC
}

export interface VerifiableCredential {
  jwt:     string;
  payload: VCPayload;
}

/**
 * Emette una PersistentVC (PP, DEG, Auditor) — senza scadenza.
 */
export function issuePersistentVC(
  issuerDID:      string,
  issuerPrivKey:  string,
  subjectDID:     string,
  role:           number,
  scope:          number[],
  credentialId:   string
): VerifiableCredential {
  const payload: VCPayload = {
    iss:          issuerDID,
    sub:          subjectDID,
    credentialId,
    role,
    scope,
    iat:          Math.floor(Date.now() / 1000),
  };

  const token = jwt.sign(payload, issuerPrivKey, { algorithm: "RS256" });
  return { jwt: token, payload };
}

/**
 * Emette una TemporaryVC (AA, EV) — con scadenza obbligatoria.
 */
export function issueTemporaryVC(
  issuerDID:      string,
  issuerPrivKey:  string,
  subjectDID:     string,
  role:           number,
  scope:          number[],
  credentialId:   string,
  expiresInSec:   number
): VerifiableCredential {
  const payload: VCPayload = {
    iss:          issuerDID,
    sub:          subjectDID,
    credentialId,
    role,
    scope,
    iat:          Math.floor(Date.now() / 1000),
    exp:          Math.floor(Date.now() / 1000) + expiresInSec,
  };

  const token = jwt.sign(payload, issuerPrivKey, { algorithm: "RS256" });
  return { jwt: token, payload };
}

/**
 * Verifica una VC usando la chiave pubblica RSA dell'issuer.
 * Lancia eccezione se la firma non è valida o la VC è scaduta.
 */
export function verifyVC(vcJwt: string, issuerPublicKeyPem: string): VCPayload {
  return jwt.verify(vcJwt, issuerPublicKeyPem, { algorithms: ["RS256"] }) as VCPayload;
}

/**
 * Genera un credentialId deterministico da issuer + subject + role + timestamp.
 */
export function generateCredentialId(issuerDID: string, subjectDID: string, role: number): string {
  const data = `${issuerDID}:${subjectDID}:${role}:${Date.now()}:${randomBytes(8).toString("hex")}`;
  return "0x" + createHash("sha256").update(data).digest("hex");
}
