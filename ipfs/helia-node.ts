/**
 * helia-node.ts
 * Non compatibile con il contesto di esecuzione di Hardhat (conflitto @libp2p/tls).
 */

import { createHelia, type Helia } from "helia";
import { unixfs, type UnixFS }     from "@helia/unixfs";
import { MemoryBlockstore }        from "blockstore-core";
import { MemoryDatastore }         from "datastore-core";

let _helia: Helia | null = null;
let _fs:    UnixFS | null = null;

export async function getNode(): Promise<{ helia: Helia; fs: UnixFS }> {
  if (_helia && _fs) return { helia: _helia, fs: _fs };
  const blockstore = new MemoryBlockstore();
  const datastore  = new MemoryDatastore();
  _helia = await createHelia({ blockstore, datastore, start: false });
  _fs    = unixfs(_helia);
  return { helia: _helia, fs: _fs };
}

export async function stopNode(): Promise<void> {
  if (_helia) { await _helia.stop(); _helia = null; _fs = null; }
}

export async function addFile(content: string | Uint8Array | Buffer): Promise<string> {
  const { fs } = await getNode();
  const bytes =
    typeof content === "string"
      ? new TextEncoder().encode(content)
      : content instanceof Buffer
      ? new Uint8Array(content.buffer, content.byteOffset, content.byteLength)
      : content;
  const cid = await fs.addBytes(bytes);
  return cid.toString();
}

export async function getFile(cidStr: string): Promise<Uint8Array> {
  const { fs } = await getNode();
  const chunks: Uint8Array[] = [];
  for await (const chunk of fs.cat(cidStr)) chunks.push(chunk);
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out   = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

export async function getFileAsString(cidStr: string): Promise<string> {
  return new TextDecoder().decode(await getFile(cidStr));
}

export async function verifyCID(cidStr: string, content: string | Uint8Array | Buffer): Promise<boolean> {
  return (await addFile(content)) === cidStr;
}
