/**
 * 官方 6edf14bb bundle 深层诊断：AssetBundle(142) 容器 / 类型树 / 全量资产名
 *
 * 打印：
 * 1. 全部 345 个 TextAsset 资产名（裸名）及明文长度、DefinedFix/entry 明文首部
 * 2. AssetBundle(142) 对象的 m_Container（资产名 → pathId 映射）
 * 3. 两个类型树 blob 的 hex（重建 SF 时需字节级复用）
 *
 * 用法：npx tsx scripts/dump-api-container.ts
 */
import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { lz4BlockDecompress, decompressLz4ak } from "./vendor/lz4";
import { decryptLuaScript, isLuaEncrypted } from "./vendor/lua-crypt";

function u32be(b: Uint8Array, o: number): number {
  return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
}
function i64be(b: Uint8Array, o: number): number {
  return u32be(b, o) * 4294967296 + u32be(b, o + 4);
}
function i32le(b: Uint8Array, o: number): number {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) | 0;
}
function u32le(b: Uint8Array, o: number): number {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
}
function cstr(b: Uint8Array, o: number): { s: string; off: number } {
  let e = o;
  while (b[e] !== 0) e++;
  return { s: new TextDecoder().decode(b.subarray(o, e)), off: e + 1 };
}
function concat(p: Uint8Array[]): Uint8Array {
  const t = p.reduce((a, x) => a + x.length, 0);
  const out = new Uint8Array(t);
  let o = 0;
  for (const x of p) out.set(x, o), (o += x.length);
  return out;
}
function hex(b: Uint8Array, max = 64): string {
  const arr = Array.from(b.subarray(0, max).slice()).map((x) => x.toString(16).padStart(2, "0"));
  return arr.join(" ");
}
function readI64(b: Uint8Array, o: number): bigint {
  return (BigInt(u32le(b, o + 4)) << 32n) | BigInt(u32le(b, o));
}

async function readBundleBytes(file: string): Promise<Uint8Array> {
  const ext = path.extname(file).toLowerCase();
  if (ext === ".dat") {
    const zip = await JSZip.loadAsync(fs.readFileSync(file));
    const entries = Object.keys(zip.files).find((n) => !zip.files[n].dir);
    if (entries === undefined) throw new Error(`.dat bundle 内无文件条目: ${file}`);
    const inner = await zip.files[entries].async("uint8array");
    return new Uint8Array(inner);
  }
  return new Uint8Array(fs.readFileSync(file));
}

/** 解析 UnityFS → 返回 CAB 与块信息 */
function toCab(uf: Uint8Array): Uint8Array {
  let off = 0;
  let e = 0;
  while (uf[e] !== 0) e++;
  off = e + 1;
  const version = u32be(uf, off);
  off += 4;
  while (uf[off] !== 0) off++;
  off += 1;
  while (uf[off] !== 0) off++;
  off += 1;
  off += 8;
  const cSize = u32be(uf, off);
  off += 4;
  const uSize = u32be(uf, off);
  off += 4;
  const flags = u32be(uf, off);
  off += 4;
  if (version >= 7) while (off % 16 !== 0) off++;
  const biBytes = flags & 0x80 ? uf.subarray(uf.length - cSize) : uf.subarray(off, off + cSize);
  const infoMode = flags & 0x3f;
  let bi: Uint8Array;
  if (infoMode === 0) bi = biBytes;
  else if (infoMode === 3 || infoMode === 2) bi = lz4BlockDecompress(biBytes, uSize);
  else if (infoMode === 4) bi = decompressLz4ak(biBytes, uSize);
  else throw new Error(`infoMode ${infoMode}`);
  let o = 16;
  const blockCount = u32be(bi, o);
  o += 4;
  const blocks: { u: number; c: number; mode: number }[] = [];
  for (let i = 0; i < blockCount; i++) {
    const u = u32be(bi, o);
    const c = u32be(bi, o + 4);
    const fl = (bi[o + 8] << 8) | bi[o + 9];
    o += 10;
    blocks.push({ u, c, mode: fl & 0x3f });
  }
  const nodeCount = u32be(bi, o);
  o += 4;
  const nodes: { offset: number; size: number }[] = [];
  for (let i = 0; i < nodeCount; i++) {
    const no = i64be(bi, o);
    const ns = i64be(bi, o + 8);
    o += 20;
    while (bi[o] !== 0) o++;
    o += 1;
    nodes.push({ offset: no, size: ns });
  }
  let dataOff = off + cSize;
  if (flags & 0x200) while (dataOff % 16 !== 0) dataOff++;
  let bstart = dataOff;
  const parts: Uint8Array[] = [];
  for (const b of blocks) {
    const raw = uf.subarray(bstart, bstart + b.c);
    bstart += b.c;
    if (b.mode === 0) parts.push(raw);
    else if (b.mode === 3 || b.mode === 2) parts.push(lz4BlockDecompress(raw, b.u));
    else if (b.mode === 4) parts.push(decompressLz4ak(raw, b.u));
    else throw new Error(`block mode ${b.mode}`);
  }
  const cab = concat(parts);
  const node = nodes[0];
  return cab.subarray(node.offset, node.offset + node.size);
}

/** 解析 SF 返回 { classIds, objects, typeTreeBlobs, textAssets, assetBundleObj } */
function parseSF(sf: Uint8Array) {
  let o = 0;
  const version = u32be(sf, 8);
  o += 16;
  o += 4;
  let dataOffset = 0;
  if (version >= 22) {
    o += 4;
    o += 8;
    dataOffset = i64be(sf, o);
    o += 8;
    o += 8;
  }
  cstr(sf, o);
  o = (() => { let e = o; while (sf[e] !== 0) e++; return e + 1; })();
  o += 4; // targetPlatform
  const enableTypeTree = sf[o] !== 0;
  o += 1;
  const typeCount = i32le(sf, o);
  o += 4;
  const classIds: number[] = [];
  const typeTreeBlobs: Uint8Array[] = [];
  for (let i = 0; i < typeCount; i++) {
    const classId = i32le(sf, o);
    o += 4;
    classIds.push(classId);
    if (version >= 16) o += 1;
    if (version >= 17) o += 2;
    if (version >= 13) {
      if (version >= 16 ? classId === 114 : classId < 0) o += 16;
      o += 16;
    }
    if (enableTypeTree && version >= 12) {
      const nodeCount = i32le(sf, o);
      o += 4;
      const sbSize = i32le(sf, o);
      o += 4;
      const len = 32 * nodeCount + sbSize;
      typeTreeBlobs.push(sf.slice(o, o + len));
      o += len;
    }
    if (version >= 21) {
      const depCount = i32le(sf, o);
      o += 4;
      o += 4 * depCount;
    }
  }
  if (version >= 7 && version < 14) o += 4;
  const objectCount = i32le(sf, o);
  o += 4;
  while (o % 4 !== 0) o++;
  const objects: any[] = [];
  for (let i = 0; i < objectCount; i++) {
    const pathId = readI64(sf, o);
    o += 8;
    const start = Number(readI64(sf, o)) + dataOffset;
    o += 8;
    const size = i32le(sf, o);
    o += 4;
    const typeId = i32le(sf, o);
    o += 4;
    objects.push({ pathId, start, size, typeId });
  }
  // TextAsset 与 AssetBundle 对象
  const taIdx = classIds.indexOf(49);
  const abIdx = classIds.indexOf(142);
  const textAssets: { pathId: bigint; name: string; script: Uint8Array }[] = [];
  for (const obj of objects.filter((x) => x.typeId === taIdx)) {
    let p = obj.start;
    const nameLen = i32le(sf, p);
    p += 4;
    const name = new TextDecoder().decode(sf.subarray(p, p + nameLen));
    p += nameLen;
    while ((p - obj.start) % 4 !== 0) p++;
    const scriptLen = i32le(sf, p);
    p += 4;
    textAssets.push({ pathId: obj.pathId, name, script: sf.slice(p, p + scriptLen) });
  }
  const abObj = abIdx >= 0 ? objects.find((x) => x.typeId === abIdx) : undefined;
  const assetBundleBytes = abObj ? sf.slice(abObj.start, abObj.start + abObj.size) : undefined;
  return { classIds, objects, typeTreeBlobs, textAssets, assetBundleBytes, dataOffset };
}

/** 解析 AssetBundle(142) 对象的 m_Container */
function parseAssetBundleContainer(obj: Uint8Array): void {
  console.log(`\n==== AssetBundle(142) 对象原始字节 (${obj.length}B) ====`);
  console.log(`hex[0..80]: ${hex(obj, 80)}`);
  let o = 0;
  // m_Name
  const nameLen = i32le(obj, o);
  o += 4;
  const name = new TextDecoder().decode(obj.subarray(o, o + nameLen));
  o += nameLen;
  while (o % 4 !== 0) o++;
  console.log(`m_Name="${name}"`);
  // m_Container : vector<Pair<string, AssetBundleInfo>>
  const pairCount = i32le(obj, o);
  o += 4;
  console.log(`m_Container 条目数=${pairCount}`);
  let entries: any[] = [];
  // 每条 Pair<first, second>；second = AssetBundleInfo{m_PreloadTable:vector<pair<PPtr<Object>,Guid>>, m_Container(vector<pair<string,ObjectInfo>>)}
  // 但先按序读取期：m_PreloadTable count + 每项(assetFileID i32 + pathID i64 + guid 16B)
  // m_Container(" nested) count + 每项(string assetPath + PPtr(assetFileID i32, pathID i64))
  const preloadCount = i32le(obj, o);
  o += 4;
  console.log(`  m_PreloadTable 条数=${preloadCount}`);
  for (let i = 0; i < preloadCount; i++) {
    const fileId = i32le(obj, o);
    const pathId = readI64(obj, o + 4);
    o += 12;
    o += 16; // guid
    void fileId;
    void pathId;
  }
  const internalCount = i32le(obj, o);
  o += 4;
  console.log(`  m_Container 内部条数=${internalCount}`);
  for (let i = 0; i < internalCount; i++) {
    const sLen = i32le(obj, o);
    o += 4;
    const assetPath = new TextDecoder().decode(obj.subarray(o, o + sLen));
    o += sLen;
    const fileId = i32le(obj, o);
    o += 4;
    const pId = readI64(obj, o);
    o += 8;
    entries.push({ assetPath, fileId, pathId: String(pId) });
  }
  console.log(`内部 m_Container 条目（前 20 条）:`);
  for (const e of entries.slice(0, 20)) console.log(`  "${e.assetPath}" → fileId=${e.fileId} pathId=${e.pathId}`);
  if (entries.length > 20) console.log(`  … 共 ${entries.length} 条`);
  // 剩余字节（m_ObjectHideFlags / m_AutoLoadFromDisk 等）
  if (o < obj.length) {
    console.log(`剩余 ${obj.length - o}B (尾部字段): hex=${hex(obj.subarray(o), 48)}`);
  }
}

async function main(): Promise<void> {
  const file = path.resolve(process.argv[2] ?? "reference/hotupdate/downloads-min/anon_6edf14bbd79243eb61e288ff28e446c3.dat");
  console.log(`读取: ${file}`);
  const cab = toCab(await readBundleBytes(file));
  const r = parseSF(cab);
  console.log(`\n==== 全量资产名(${r.textAssets.length}) 与明文长度 ====`);
  for (const ta of r.textAssets) {
    let first = "";
    let plain: Uint8Array | null = null;
    if (isLuaEncrypted(ta.script)) {
      try {
        plain = decryptLuaScript(ta.script);
        first = new TextDecoder().decode(plain.subarray(0, 40)).replace(/\n/g, "\\n");
      } catch {
        first = "(解密失败)";
      }
    } else {
      plain = ta.script;
      first = new TextDecoder().decode(plain.subarray(0, 40)).replace(/\n/g, "\\n");
    }
    const lname = ta.name.toLowerCase();
    const mark = lname.includes("definedfix") || lname === "entry.lua" || lname.includes("main") || lname.includes("init")
      ? "  <=== B00T_CANDIDATE"
      : "";
    console.log(`  ${String(ta.pathId).padStart(3)}. "${ta.name}"  enc=${ta.script.length}B plain=${plain ? plain.length : 0}B${plain ? `  | ${first}` : ""}${mark}`);
  }
  if (r.assetBundleBytes) parseAssetBundleContainer(r.assetBundleBytes);
  console.log(`\n==== 类型树 blobs (${r.typeTreeBlobs.length}) ====`);
  for (const [i, t] of r.typeTreeBlobs.entries()) {
    console.log(`type[${i}] classId=${r.classIds[i]} len=${t.length}`);
    console.log(`  hex[0..96]: ${hex(t, 96)}`);
  }
  // 打印 DefinedFix / HotfixProcesser 明文
  for (const key of ["definedfix", "hotfixprocesser", "arkventh", "teststub", "hotfixbase"]) {
    const ta = r.textAssets.find((x) => x.name.toLowerCase().includes(key));
    if (!ta) continue;
    console.log(`\n==== ${ta.name} 明文 (${ta.script.length}B) ====`);
    let plain: Uint8Array = ta.script;
    try {
      if (isLuaEncrypted(ta.script)) plain = decryptLuaScript(ta.script);
    } catch { /* keep raw */ }
    console.log(new TextDecoder().decode(plain));
  }
}

if (require.main === module) {
  main().catch((e) => {
    console.error("诊断失败:", e instanceof Error ? e.message : e);
    process.exit(1);
  });
}