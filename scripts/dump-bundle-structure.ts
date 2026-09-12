/**
 * 官方 6edf14bb Lua bundle 结构诊断器
 *
 * 逐层拆解官方热更 Lua bundle（.dat zip → UnityFS → 块/SF → 序列化文件），
 * 打印对重打包保真度至关重要的全部细节：
 *   - UnityFS 头（version / flags / block info 与数据块压缩模式）
 *   - 块信息（blocks：uncompressed/compressed/mode；nodes：offset/size/name）
 *   - SerializedFile v22（version / dataOffset / unityVersion / targetPlatform /
 *     enableTypeTree / typeCount → 每个类型的 classId + typeTree 大小 / objectCount → 每个对象）
 *   - 各 classId 分布（TextAsset=49 / AssetBundle=142 …）
 *   - 每个 TextAsset 的名称与是否 CRYPTIC_A 加密
 *
 * 用法：npx tsx scripts/dump-bundle-structure.ts <bundle.dat|.bin> [--sf <hex offset>]
 */
import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { lz4BlockDecompress, decompressLz4ak } from "./vendor/lz4";
import { isLuaEncrypted, decryptLuaScript } from "./vendor/lua-crypt";

/** u32 大端 */
function u32be(b: Uint8Array, o: number): number {
  return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
}
/** u64 大端 → number（2^53 内安全） */
function i64be(b: Uint8Array, o: number): number {
  return u32be(b, o) * 4294967296 + u32be(b, o + 4);
}
/** i32 小端 */
function i32le(b: Uint8Array, o: number): number {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) | 0;
}
/** u32 小端 */
function u32le(b: Uint8Array, o: number): number {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
}
/** C 字符串 */
function cstr(b: Uint8Array, o: number): { s: string; off: number } {
  let e = o;
  while (b[e] !== 0) e++;
  return { s: new TextDecoder().decode(b.subarray(o, e)), off: e + 1 };
}

/** 读取 bundle 字节（.dat 取 zip 单条目 / .bin 直读） */
async function readBundleBytes(file: string): Promise<Uint8Array> {
  const ext = path.extname(file).toLowerCase();
  if (ext === ".dat") {
    const zip = await JSZip.loadAsync(fs.readFileSync(file));
    const entries = Object.keys(zip.files).find((n) => !zip.files[n].dir);
    if (!entries) throw new Error(`.dat 内无条目`);
    const inner = await zip.files[entries].async("uint8array");
    return new Uint8Array(inner);
  }
  return new Uint8Array(fs.readFileSync(file));
}

/** 拼接字节 */
function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) out.set(p, o), (o += p.length);
  return out;
}

/** 打印 UnityFS 层级结构 */
function dumpUnityFS(uf: Uint8Array): { sf: Uint8Array; sfOffset: number } {
  let off = 0;
  const sig = cstr(uf, off);
  off = sig.off;
  const version = u32be(uf, off);
  off += 4;
  const vp = cstr(uf, off);
  off = vp.off;
  const ve = cstr(uf, off);
  off = ve.off;
  const size = i64be(uf, off);
  off += 8;
  const cSize = u32be(uf, off);
  off += 4;
  const uSize = u32be(uf, off);
  off += 4;
  const flags = u32be(uf, off);
  off += 4;
  console.log("\n==== UnityFS 头 ====");
  console.log(`sig=${sig.s} version=${version} player=${vp.s} engine=${ve.s}`);
  console.log(`headerSize(u64 字段)=${size} actualFileSize=${uf.length}`);
  console.log(`blockInfo: cSize=${cSize} uSize=${uSize} flags=0x${flags.toString(16)}`);
  console.log(`  infoMode=${flags & 0x3f} |0x40=${!!(flags & 0x40)} |0x80(inline/eof)=${!!(flags & 0x80)} |0x200=${!!(flags & 0x200)}`);
  if (version >= 7) while (off % 16 !== 0) off++;
  console.log(`blockInfo offset=${off}`);

  // 块信息字节
  let biBytes: Uint8Array;
  if (flags & 0x80) biBytes = uf.subarray(uf.length - cSize);
  else biBytes = uf.subarray(off, off + cSize);
  const infoMode = flags & 0x3f;
  let bi: Uint8Array;
  if (infoMode === 0) bi = biBytes;
  else if (infoMode === 3 || infoMode === 2) bi = lz4BlockDecompress(biBytes, uSize);
  else if (infoMode === 4) bi = decompressLz4ak(biBytes, uSize);
  else throw new Error(`块信息压缩模式不支持: ${infoMode}`);

  let o = 16;
  const blockCount = u32be(bi, o);
  o += 4;
  console.log(`\n块信息: hash=16B blockCount=${blockCount}`);
  const blocks: { u: number; c: number; mode: number }[] = [];
  let totalC = 0;
  for (let i = 0; i < blockCount; i++) {
    const u = u32be(bi, o);
    o += 4;
    const c = u32be(bi, o);
    o += 4;
    const fl = (bi[o] << 8) | bi[o + 1];
    o += 2;
    blocks.push({ u, c, mode: fl & 0x3f });
    totalC += c;
    console.log(`  block[${i}] u=${u} c=${c} mode=${fl & 0x3f} (flags16=0x${fl.toString(16)})`);
  }
  const nodeCount = u32be(bi, o);
  o += 4;
  console.log(`nodeCount=${nodeCount}`);
  const nodes: { offset: number; size: number; flags: number; path: string }[] = [];
  for (let i = 0; i < nodeCount; i++) {
    const nOffset = i64be(bi, o);
    o += 8;
    const nSize = i64be(bi, o);
    o += 8;
    const nFlags = u32be(bi, o);
    o += 4;
    const name = cstr(bi, o);
    o = name.off;
    nodes.push({ offset: nOffset, size: nSize, flags: nFlags, path: name.s });
    console.log(`  node[${i}] offset=${nOffset} size=${nSize} flags=0x${nFlags.toString(16)} path=${name.s}`);
  }

  // 数据块
  let dataOff = off + cSize;
  if (flags & 0x200) while (dataOff % 16 !== 0) dataOff++;
  console.log(`\n数据区 offset=${dataOff} (块信息末尾偏移 ${off + cSize})`);
  let blocksStart = dataOff;
  const parts: Uint8Array[] = [];
  for (const blk of blocks) {
    const raw = uf.subarray(blocksStart, blocksStart + blk.c);
    blocksStart += blk.c;
    if (blk.mode === 0) parts.push(raw);
    else if (blk.mode === 2 || blk.mode === 3) parts.push(lz4BlockDecompress(raw, blk.u));
    else if (blk.mode === 4) parts.push(decompressLz4ak(raw, blk.u));
    else throw new Error(`数据块压缩模式不支持: ${blk.mode}`);
  }
  const cab = concat(parts);
  console.log(`CAB 总长=${cab.length} (还原后)`);

  const node = nodes[0];
  const sf = cab.subarray(node.offset, node.offset + node.size);
  console.log(`node[0] 即 SerializedFile: offset=${node.offset} size=${node.size} → SF 绝对偏移=${dataOff + node.offset}`);
  return { sf, sfOffset: dataOff + node.offset };
}

/** SerializedFile 中反序列化出的对象记录（pathId 以十进制字符串呈现，避免 BigInt 打印差异） */
interface SfObjectRecord {
  pathId: string;
  start: number;
  size: number;
  typeId: number;
}

/** 打印 SerializedFile 结构 */
function dumpSerializedFile(sf: Uint8Array): { classIds: number[]; textAssets: { name: string; script: Uint8Array }[]; objects: SfObjectRecord[] } {
  let o = 0;
  const metadataSize = u32be(sf, 0);
  const sfFileSize = u32be(sf, 4);
  const version = u32be(sf, 8);
  const hdrDataOffset = u32be(sf, 12);
  const endian = sf[16];
  o += 16;
  o += 4; // endian u8 + reserved
  let dataOffset = 0;
  if (version >= 22) {
    o += 4; // metadataSize 重读
    o += 8; // fileSize i64
    dataOffset = i64be(sf, o);
    o += 8;
    o += 8; // unknown
  }
  console.log("\n==== SerializedFile ====");
  console.log(
    `hdr: metadataSize=${metadataSize} fileSize=${sfFileSize} version=${version} hdrDataOffset=${hdrDataOffset} endian=${endian} sfActualLen=${sf.length}`,
  );
  console.log(`v22: dataOffset=${dataOffset} metadataStart=${o}`);
  const uv = cstr(sf, o);
  o = uv.off;
  const targetPlatform = i32le(sf, o);
  o += 4;
  const enableTypeTree = sf[o] !== 0;
  o += 1;
  const typeCount = i32le(sf, o);
  o += 4;
  console.log(`unityVersion=${uv.s} targetPlatform=${targetPlatform} enableTypeTree=${enableTypeTree} typeCount=${typeCount}`);

  const classIds: number[] = [];
  const typeTreeSizes: number[] = [];
  for (let i = 0; i < typeCount; i++) {
    const classId = i32le(sf, o);
    o += 4;
    classIds.push(classId);
    let typeTreeSize = 0;
    if (version >= 16) o += 1; // isStrippedType
    if (version >= 17) o += 2; // scriptTypeIndex i16
    if (version >= 13) {
      if (version >= 16 ? classId === 114 : classId < 0) o += 16; // scriptId
      o += 16; // oldTypeHash
    }
    if (enableTypeTree && version >= 12) {
      const nodeCount = i32le(sf, o);
      o += 4;
      const sbSize = i32le(sf, o);
      o += 4;
      typeTreeSize = 32 * nodeCount + sbSize;
      const blob = sf.subarray(o, o + typeTreeSize);
      // 打印类型树根节点（校验完整性）
      const rootName = cstr(blob, 4); // 每条节点 32B：version u16+level u8+flags u8+nameLen i32+name...
      o += typeTreeSize;
      void rootName;
    }
    if (version >= 21) {
      const depCount = i32le(sf, o);
      o += 4;
      o += 4 * depCount;
    }
    console.log(`  type[${i}] classId=${classId} typeTree=${enableTypeTree && typeTreeSize > 0 ? typeTreeSize + "B" : "none"}`);
  }
  if (version >= 7 && version < 14) o += 4;
  const objectCount = i32le(sf, o);
  o += 4;
  while (o % 4 !== 0) o++;
  console.log(`objectCount=${objectCount}`);

  type Counts = { [k: number]: number };
  const classCounts: Counts = {};
  const objects: SfObjectRecord[] = [];
  for (let i = 0; i < objectCount; i++) {
    const pathId = version >= 14 ? readI64(sf, o) : BigInt(i32le(sf, o));
    o += version >= 14 ? 8 : 4;
    let start: number;
    if (version >= 22) {
      start = Number(readI64(sf, o)) + dataOffset;
      o += 8;
    } else {
      start = i32le(sf, o) + dataOffset;
      o += 4;
    }
    const size = i32le(sf, o);
    o += 4;
    const typeId = i32le(sf, o);
    o += 4;
    objects.push({ pathId: String(pathId), start, size, typeId });
    const cid = classIds[typeId];
    classCounts[cid] = (classCounts[cid] ?? 0) + 1;
  }
  console.log(`对象按 classId 分布:`);
  for (const [cid, n] of Object.entries(classCounts)) console.log(`  classId=${cid}: ${n} 个`);

  // 提取 TextAsset
  const taTypeIdx = classIds.indexOf(49);
  const textAssets: { name: string; script: Uint8Array }[] = [];
  if (taTypeIdx >= 0) {
    for (const obj of objects.filter((x) => x.typeId === taTypeIdx)) {
      const taObj = sf.subarray(obj.start, obj.start + obj.size);
      const { name, script } = parseTextAsset(taObj);
      textAssets.push({ name, script });
    }
    console.log(`\nTextAsset 采样（前 6 条 + DefinedFix）:`);
    let shown = 0;
    for (const ta of textAssets) {
      const isDf = nameLc(ta.name).includes("definedfix");
      if (shown < 6 || isDf) {
        console.log(`  name=${ta.name}  bytes=${ta.script.length}  encrypted=${isLuaEncrypted(ta.script)}`);
        shown++;
      }
    }
    console.log(`TextAsset 总数=${textAssets.length}`);
  }
  return { classIds, textAssets, objects };
}

function readI64(b: Uint8Array, o: number): bigint {
  const lo = BigInt(u32le(b, o));
  const hi = BigInt(u32le(b, o + 4));
  return (hi << 32n) | lo;
}
function parseTextAsset(obj: Uint8Array): { name: string; script: Uint8Array } {
  let o = 0;
  const nameLen = i32le(obj, o);
  o += 4;
  const name = new TextDecoder().decode(obj.subarray(o, o + nameLen));
  o += nameLen;
  while (o % 4 !== 0) o++;
  const scriptLen = i32le(obj, o);
  o += 4;
  const script = obj.subarray(o, o + scriptLen).slice();
  return { name, script };
}
function nameLc(s: string): string {
  return s.toLowerCase();
}

/** 主流程 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const file = path.resolve(args[0] ?? "reference/hotupdate/downloads-min/anon_6edf14bbd79243eb61e288ff28e446c3.dat");
  console.log(`读取: ${file}`);
  const bytes = await readBundleBytes(file);
  if (bytes.length < 8 || String.fromCharCode(...bytes.subarray(0, 7)) !== "UnityFS") {
    throw new Error("非 UnityFS bundle");
  }
  const { sf } = dumpUnityFS(bytes);
  dumpSerializedFile(sf);
}

if (require.main === module) {
  main().catch((e) => {
    console.error("诊断失败:", e instanceof Error ? e.message : e);
    process.exit(1);
  });
}