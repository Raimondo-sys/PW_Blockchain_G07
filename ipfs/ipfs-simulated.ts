/**
 * ipfs-simulated.ts
 * IPFS simulato in-memory per gli script Hardhat.
 * CID = SHA-256 del contenuto — stesso algoritmo usato da IPFS per file piccoli.
 * In produzione: sostituire con chiamate al cluster IPFS reale (WP2 §3.2).
 */

import { createHash } from "crypto";

const store = new Map<string, Buffer>();

export function ipfsUpload(content: Buffer | string): string {
  const buf  = typeof content === "string" ? Buffer.from(content) : content;
  const hash = createHash("sha256").update(buf).digest("hex");
  const cid  = `Qm${hash.substring(0, 44)}`;
  store.set(cid, buf);
  return cid;
}

export function ipfsDownload(cid: string): Buffer {
  const data = store.get(cid);
  if (!data) throw new Error(`CID non trovato: ${cid}`);
  return data;
}

export function ipfsVerifyCID(content: Buffer, cid: string): boolean {
  const hash     = createHash("sha256").update(content).digest("hex");
  const expected = `Qm${hash.substring(0, 44)}`;
  return expected === cid;
}
