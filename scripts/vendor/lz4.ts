/**
 * LZ4 原始块解压（UnityFS 块信息用，Arknights excel bundle 的块信息均为 Lz4hc 模式）。
 * 标准 LZ4 block 格式（非 frame）：token → 字面量 → 匹配(offset+length)。
 */

export function lz4BlockDecompress(src: Uint8Array, uncompressedSize: number): Uint8Array {
  const out = new Uint8Array(uncompressedSize);
  let s = 0;
  let d = 0;
  while (s < src.length) {
    const token = src[s++];
    // 字面量长度
    let litLen = token >> 4;
    if (litLen === 15) {
      let b: number;
      do {
        b = src[s++];
        litLen += b;
      } while (b === 255);
    }
    // 拷贝字面量
    if (litLen > 0) {
      out.set(src.subarray(s, s + litLen), d);
      s += litLen;
      d += litLen;
    }
    if (s >= src.length) break; // 块结束（最后一段仅字面量）
    // 匹配
    const offset = src[s] | (src[s + 1] << 8);
    s += 2;
    let matchLen = (token & 0x0f) + 4;
    if ((token & 0x0f) === 15) {
      let b: number;
      do {
        b = src[s++];
        matchLen += b;
      } while (b === 255);
    }
    // 拷贝匹配（允许重叠——LZ4 语义）
    for (let i = 0; i < matchLen; i++) {
      out[d] = out[d - offset];
      d++;
    }
  }
  return out;
}

/**
 * LZ4AK（Arknights 自定义 LZ4 变体）解压。
 * 算法：先"修复"流——token 的高低半字节对调、offset 字节序对调（同时跟踪输出长度，
 * 输出填满即止），再按标准 LZ4 block 解压。
 */
export function decompressLz4ak(compressed: Uint8Array, uncompressedSize: number): Uint8Array {
  const data = new Uint8Array(compressed); // 拷贝以便修改
  let ip = 0;
  let op = 0;
  const cSize = data.length;
  while (ip < cSize) {
    // 序列 token：字面量长度在低半字节，匹配长度在高半字节（与标准 LZ4 相反）
    const literalLength = data[ip] & 0x0f;
    const matchLength = (data[ip] >> 4) & 0x0f;
    data[ip] = (literalLength << 4) | matchLength;
    ip += 1;

    // 字面量
    let lit = literalLength;
    if (literalLength === 0x0f) {
      let b: number;
      do {
        b = data[ip++];
        lit += b;
      } while (b === 0xff);
    }
    ip += lit;
    op += lit;
    if (op >= uncompressedSize) break; // 块结束

    // 匹配
    const offset = (data[ip] << 8) | data[ip + 1];
    data[ip] = offset & 0xff;
    data[ip + 1] = (offset >> 8) & 0xff;
    ip += 2;
    let match = matchLength;
    if (matchLength === 0x0f) {
      let b: number;
      do {
        b = data[ip++];
        match += b;
      } while (b === 0xff);
    }
    match += 4; // 最小匹配
    op += match;
  }
  return lz4BlockDecompress(data, uncompressedSize);
}

