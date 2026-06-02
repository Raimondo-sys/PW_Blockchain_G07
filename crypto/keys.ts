/**
 * keys.ts
 * Generazione chiavi per ogni entità del sistema:
 *   - RSA 2048 (PEM) → firma/verifica VC e VP (JWT RS256), registrata on-chain nell'IR
 *   - ECDH P-256     → cifratura ibrida del payload policy (off-chain)
 */

import { generateKeyPairSync, createECDH } from "crypto";

export interface EntityKeys {
  did:            string;
  // RSA — per JWT RS256
  rsaPublicKeyPem:  string;
  rsaPrivateKeyPem: string;
  rsaPublicKeyHex:  `0x${string}`; // PEM codificato hex per on-chain
  // ECDH P-256 — per cifratura ibrida
  ecdhPrivateKey: Buffer;
  ecdhPublicKey:  Buffer;
}

export function generateEntityKeys(did: string): EntityKeys {
  // RSA 2048 per JWT
  const { publicKey: rsaPublicKeyPem, privateKey: rsaPrivateKeyPem } =
    generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding:  { type: "spki",  format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

  // ECDH P-256 per cifratura ibrida
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();

  return {
    did,
    rsaPublicKeyPem,
    rsaPrivateKeyPem,
    rsaPublicKeyHex: `0x${Buffer.from(rsaPublicKeyPem).toString("hex")}` as `0x${string}`,
    ecdhPrivateKey:  ecdh.getPrivateKey(),
    ecdhPublicKey:   ecdh.getPublicKey(),
  };
}
