/**
 * hybrid.ts
 * Cifratura ibrida per il payload delle policy su IPFS — WP2 §3.3.
 * Schema: AES-256-GCM (payload) + ECDH P-256 + AES-256-GCM (key wrap).
 */

import { createCipheriv, createDecipheriv, createECDH, createHash, randomBytes } from "crypto";

export interface EncryptedKeyEntry {
  recipientDID:    string;
  ephemeralPubKey: string; // hex
  encryptedKey:    string; // hex
  iv:              string; // hex
  authTag:         string; // hex
}

export interface KeyDistributionDocument {
  policyId:  string;
  entries:   EncryptedKeyEntry[];
  updatedAt: number;
}

export interface EncryptedPayload {
  ciphertext: Buffer;
  iv:         Buffer;
  authTag:    Buffer;
}

export interface ECDHKeys {
  ecdhPrivateKey: Buffer;
  ecdhPublicKey:  Buffer;
}

/**
 * Cifra un documento con AES-256-GCM usando una chiave simmetrica usa e getta.
 */
export function encryptDocument(document: Buffer): {
  symmetricKey: Buffer;
  encrypted:    EncryptedPayload;
} {
  const symmetricKey = randomBytes(32);
  const iv           = randomBytes(12);
  const cipher       = createCipheriv("aes-256-gcm", symmetricKey, iv);
  const ciphertext   = Buffer.concat([cipher.update(document), cipher.final()]);
  const authTag      = cipher.getAuthTag();
  return { symmetricKey, encrypted: { ciphertext, iv, authTag } };
}

/**
 * Cifra la chiave simmetrica con la chiave pubblica ECDH P-256 del destinatario.
 */
export function encryptKeyForRecipient(
  symmetricKey:       Buffer,
  recipientPublicKey: Buffer,
  recipientDID:       string
): EncryptedKeyEntry {
  const ephemeralECDH = createECDH("prime256v1");
  ephemeralECDH.generateKeys();
  const ephemeralPubKey = ephemeralECDH.getPublicKey();
  const sharedSecret    = ephemeralECDH.computeSecret(recipientPublicKey);
  const derivedKey      = createHash("sha256").update(sharedSecret).digest();
  const iv              = randomBytes(12);
  const cipher          = createCipheriv("aes-256-gcm", derivedKey, iv);
  const encKey          = Buffer.concat([cipher.update(symmetricKey), cipher.final()]);
  const authTag         = cipher.getAuthTag();
  return {
    recipientDID,
    ephemeralPubKey: ephemeralPubKey.toString("hex"),
    encryptedKey:    encKey.toString("hex"),
    iv:              iv.toString("hex"),
    authTag:         authTag.toString("hex"),
  };
}

/**
 * Costruisce il key distribution document per un insieme di destinatari.
 */
export function buildKDDoc(
  symmetricKey: Buffer,
  recipients:   ECDHKeys & { did: string }[],
  policyId:     string
): KeyDistributionDocument {
  return {
    policyId,
    entries:   recipients.map((r) =>
      encryptKeyForRecipient(symmetricKey, r.ecdhPublicKey, r.did)
    ),
    updatedAt: Date.now(),
  };
}

/**
 * Decifra il documento come destinatario usando la propria chiave privata ECDH.
 */
export function decryptDocument(
  recipient: ECDHKeys & { did: string },
  kdDoc:     KeyDistributionDocument,
  encrypted: EncryptedPayload
): Buffer {
  const entry = kdDoc.entries.find((e) => e.recipientDID === recipient.did);
  if (!entry) throw new Error(`Entry non trovata per ${recipient.did}`);

  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(recipient.ecdhPrivateKey);
  const sharedSecret = ecdh.computeSecret(Buffer.from(entry.ephemeralPubKey, "hex"));
  const derivedKey   = createHash("sha256").update(sharedSecret).digest();

  const decipher = createDecipheriv("aes-256-gcm", derivedKey, Buffer.from(entry.iv, "hex"));
  decipher.setAuthTag(Buffer.from(entry.authTag, "hex"));
  const symKey = Buffer.concat([
    decipher.update(Buffer.from(entry.encryptedKey, "hex")),
    decipher.final(),
  ]);

  const docDecipher = createDecipheriv("aes-256-gcm", symKey, encrypted.iv);
  docDecipher.setAuthTag(encrypted.authTag);
  return Buffer.concat([docDecipher.update(encrypted.ciphertext), docDecipher.final()]);
}
