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

/**
 * 标准 LZ4 block 压缩（贪心，4 字节哈希表找最长匹配）。
 * 输出标准 LZ4 block 格式：token(高半字节=字面量长/低半字节=匹配长) → 字面量 → offset(LE u16) → 匹配长扩展。
 * @param src - 待压缩数据
 * @returns 标准 LZ4 压缩块字节
 */
export function lz4BlockCompress(src: Uint8Array): Uint8Array {
  const out: number[] = [];
  const MIN_MATCH = 4;
  const MAX_DIST = 0xffff;
  const hashBits = 16;
  const hashSize = 1 << hashBits;
  const ht = new Int32Array(hashSize).fill(-1);
  const hashOf = (i: number): number => {
    const v = (src[i] << 24) | (src[i + 1] << 16) | (src[i + 2] << 8) | src[i + 3];
    return (Math.imul(v, 2654435761) >>> (32 - hashBits)) & (hashSize - 1);
  };
  const emitLit = (from: number, to: number): number => {
    let lit = to - from;
    const tokenPos = out.length;
    out.push(0); // token 占位
    if (lit >= 15) {
      out[tokenPos] = 0xf0;
      let v = lit - 15;
      while (v >= 255) {
        out.push(255);
        v -= 255;
      }
      out.push(v);
    } else {
      out[tokenPos] = lit << 4;
    }
    for (let i = from; i < to; i++) out.push(src[i]);
    return tokenPos; // token 的确切索引（供匹配回填）
  };
  const emitMatch = (tokenPos: number, litLen: number, offset: number, matchLen: number): void => {
    // 回填 token：高半字节=字面量长，低半字节=匹配长(截断，扩展)
    let mlPart = matchLen - MIN_MATCH;
    const low = mlPart >= 15 ? 15 : mlPart;
    out[tokenPos] = (litLen >= 15 ? 0x0f : litLen) << 4 | low;
    out.push(offset & 0xff, (offset >> 8) & 0xff);
    if (mlPart >= 15) {
      let v = mlPart - 15;
      while (v >= 255) {
        out.push(255);
        v -= 255;
      }
      out.push(v);
    }
  };
  if (src.length === 0) return Uint8Array.from([0]);
  let anchor = 0;
  let pos = 0;
  while (pos + MIN_MATCH <= src.length) {
    const h = hashOf(pos);
    let candidate = ht[h];
    ht[h] = pos;
    let matchLen = 0;
    if (candidate >= 0 && pos - candidate <= MAX_DIST) {
      // 扩展匹配长度（前提：哈希命中且首 4 字节一致）
      if (
        src[candidate] === src[pos] &&
        src[candidate + 1] === src[pos + 1] &&
        src[candidate + 2] === src[pos + 2] &&
        src[candidate + 3] === src[pos + 3]
      ) {
        matchLen = MIN_MATCH;
        while (
          matchLen + pos < src.length &&
          candidate + matchLen < src.length &&
          src[candidate + matchLen] === src[pos + matchLen]
        ) {
          matchLen++;
        }
      }
    }
    if (matchLen >= MIN_MATCH && pos - anchor > 0) {
      const tokenPos = emitLit(anchor, pos);
      emitMatch(tokenPos, pos - anchor, pos - candidate, matchLen);
      anchor = pos + matchLen;
      pos = anchor;
    } else {
      pos++;
    }
  }
  if (anchor < src.length) {
    emitLit(anchor, src.length);
  } else if (src.length > 0 && out.length === 0) {
    emitLit(0, src.length);
  }
  return Uint8Array.from(out);
}

/**
 * LZ4AK（Arknights 变体）压缩：先标准 LZ4 block 压缩，再把每个序列改为 AK 存储：
 *   token 高低半字节对调（字面量长入低半字节、匹配长入高半字节），offset 改为大端。
 * 输出序列顺序（与解压一致）：AK token → 字面量扩展 → 字面量 → offset(BE) → 匹配扩展。
 * @param src - 待压缩数据
 * @returns LZ4AK 压缩块字节
 */
export function compressLz4ak(src: Uint8Array): Uint8Array {
  const std = lz4BlockCompress(src);
  const out: number[] = [];
  // 把 n 编码为 255-分组扩展字节（LZ4 语义）
  const extBytes = (n: number): number[] => {
    const arr: number[] = [];
    let x = n;
    while (x >= 255) {
      arr.push(255);
      x -= 255;
    }
    arr.push(x);
    return arr;
  };
  let s = 0;
  while (s < std.length) {
    const tok = std[s++];
    const litNib = tok >> 4;
    let lit = litNib;
    if (litNib === 15) {
      let b: number;
      do {
        b = std[s++];
        lit += b;
      } while (b === 255 && s < std.length);
    }
    const matchNib = tok & 0x0f;
    // AK token：字面量长入低半字节、匹配长入高半字节
    const akTok = (lit >= 15 ? 0x0f : lit) | (matchNib << 4);
    out.push(akTok);
    // 字面量扩展（AK 低半字节==0x0f 时解压器会读后续字节补足）
    if (lit >= 15) {
      for (const b of extBytes(lit - 15)) out.push(b);
    }
    for (let i = 0; i < lit; i++) out.push(std[s + i]);
    s += lit;
    if (s >= std.length) break; // 末段仅字面量（匹配 nibble 为 0）
    // 匹配：offset 反向为大端；匹配扩展字节原样重发
    out.push(std[s + 1], std[s]); // 大端 offset
    s += 2;
    if (matchNib === 15) {
      let b: number;
      do {
        b = std[s++];
        out.push(b);
      } while (b === 255 && s < std.length);
    }
  }
  return Uint8Array.from(out);
}

