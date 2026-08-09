/**
 * arkhub 像素画工具（管理后台像素画生成 / 上传官服用）
 *
 * 官服 arkhub 像素画数据格式（自抓包逆向确认）：
 *   - 画布 24×24，每像素 3 字节 RGB（共 1728 字节）
 *   - 空白像素为 (255,255,255)，上传时原样传输；md5 即像素数据字节的 md5
 *   - 调色板：官方热更下发（display_meta_table.pixelMapData.paramMap.<id>.htmlColors），
 *     本地数据为空，先用内置默认 40 色（PIXEL_PALETTE 可替换）
 */
import { createHash } from "crypto";
import { deflateSync } from "zlib";

/** 画布宽 */
export const PIXEL_CANVAS_W = 24;
/** 画布高 */
export const PIXEL_CANVAS_H = 24;
/** 像素数据字节数（24×24×3 RGB） */
export const PIXEL_DATA_LEN = PIXEL_CANVAS_W * PIXEL_CANVAS_H * 3;

/** 空白像素 RGB（透明/背景） */
export const PIXEL_EMPTY: readonly [number, number, number] = [255, 255, 255];

/** 默认 40 色调色板（HTML 颜色，编辑器选色用；官方热更数据可后续替换） */
export const PIXEL_PALETTE: readonly string[] = [
  "#ffffff", "#cccccc", "#888888", "#444444", "#000000",
  "#ff8888", "#ff4444", "#cc0000", "#880000", "#440000",
  "#ffcc88", "#ff8800", "#cc6600", "#884400", "#442200",
  "#ffee88", "#ffcc00", "#cc9900", "#886600", "#443300",
  "#ccff88", "#88ff00", "#66cc00", "#448800", "#224400",
  "#88ffcc", "#00ff88", "#00cc66", "#008844", "#004422",
  "#88ffff", "#00cccc", "#009999", "#006666", "#003333",
  "#8888ff", "#4444ff", "#0000cc", "#000088", "#4400cc",
];

/**
 * 校验并归一化像素数据为 24×24×3 RGB Buffer
 *
 * 接受：
 *  - Buffer/Uint8Array（长度 1728，RGB 栅格）
 *  - number[]（长度 1728）
 *  - { r,g,b }[]（长度 576）或 { red,green,blue }[]
 *  - 字符串（base64 或 16 进制）
 * 非法输入抛 Error。
 *
 * @param input - 像素数据
 * @returns 1728 字节 RGB Buffer
 */
export function validatePixelData(input: unknown): Buffer {
  let buf: Buffer;
  if (Buffer.isBuffer(input)) {
    buf = input;
  } else if (input instanceof Uint8Array) {
    buf = Buffer.from(input);
  } else if (typeof input === "string") {
    // 兼容 base64 / hex 输入
    try {
      buf = Buffer.from(input, "base64");
      if (buf.length !== PIXEL_DATA_LEN) buf = Buffer.from(input, "hex");
    } catch {
      buf = Buffer.alloc(0);
    }
  } else if (Array.isArray(input)) {
    if (input.length === PIXEL_DATA_LEN) {
      buf = Buffer.from(input as number[]);
    } else if (input.length === PIXEL_CANVAS_W * PIXEL_CANVAS_H) {
      // 对象数组 {r,g,b}
      const arr = Buffer.alloc(PIXEL_DATA_LEN);
      input.forEach((px: unknown, i: number) => {
        const o = px as { r?: number; g?: number; b?: number; red?: number; green?: number; blue?: number };
        arr[i * 3] = o.r ?? o.red ?? PIXEL_EMPTY[0];
        arr[i * 3 + 1] = o.g ?? o.green ?? PIXEL_EMPTY[1];
        arr[i * 3 + 2] = o.b ?? o.blue ?? PIXEL_EMPTY[2];
      });
      buf = arr;
    } else {
      throw new Error(`像素数据长度非法：${input.length}（应为 ${PIXEL_DATA_LEN} 字节 RGB 或 ${PIXEL_CANVAS_W * PIXEL_CANVAS_H} 像素）`);
    }
  } else {
    throw new Error("像素数据格式不支持");
  }
  if (buf.length !== PIXEL_DATA_LEN) {
    throw new Error(`像素数据长度非法：${buf.length}（应为 ${PIXEL_DATA_LEN} 字节 = ${PIXEL_CANVAS_W}×${PIXEL_CANVAS_H}×3）`);
  }
  return buf;
}

/** 像素数据 md5（hex 小写）——RequestPixelArtUploadTokenReq 的 Md5 字段 */
export function pixelDataMd5(pixels: Buffer): string {
  return createHash("md5").update(pixels).digest("hex");
}

/* ---------- PNG 编码（无第三方依赖，RGBA + 可选网格线 + 空白透明） ---------- */

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type: string, data: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const typeBuf = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])));
  return Buffer.concat([len, typeBuf, data, crc]);
}

/**
 * 24×24 RGB 像素数据 → 放大 PNG
 *
 * 空白像素 (255,255,255) 渲染为透明；非空白像素放大为实心色块，边缘画浅灰网格线。
 *
 * @param pixels - 1728 字节 RGB
 * @param scale - 每像素放大倍数（缺省 10）
 * @param grid - 是否画网格线（缺省 true）
 * @returns PNG Buffer
 */
export function pixelDataToPng(pixels: Buffer, scale = 10, grid = true): Buffer {
  const buf = validatePixelData(pixels);
  const W = PIXEL_CANVAS_W * scale;
  const H = PIXEL_CANVAS_H * scale;
  const raw = Buffer.alloc(H * (1 + W * 4));
  for (let y = 0; y < H; y++) {
    const rowStart = y * (1 + W * 4);
    raw[rowStart] = 0; // filter: none
    const py = Math.floor(y / scale);
    for (let x = 0; x < W; x++) {
      const px = Math.floor(x / scale);
      const i = (py * PIXEL_CANVAS_W + px) * 3;
      const r = buf[i];
      const g = buf[i + 1];
      const b = buf[i + 2];
      const empty = r === PIXEL_EMPTY[0] && g === PIXEL_EMPTY[1] && b === PIXEL_EMPTY[2];
      const off = rowStart + 1 + x * 4;
      const isGrid = grid && (x % scale === 0 || y % scale === 0);
      if (empty) {
        raw[off] = 255;
        raw[off + 1] = 255;
        raw[off + 2] = 255;
        raw[off + 3] = 0; // 透明
      } else {
        raw[off] = isGrid ? 180 : r;
        raw[off + 1] = isGrid ? 180 : g;
        raw[off + 2] = isGrid ? 180 : b;
        raw[off + 3] = 255;
      }
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(W, 0);
  ihdr.writeUInt32BE(H, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type: RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", deflateSync(raw)),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}
