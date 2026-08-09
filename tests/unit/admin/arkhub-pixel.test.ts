import { describe, it, expect } from "vitest";
import {
  PIXEL_CANVAS_W,
  PIXEL_CANVAS_H,
  PIXEL_DATA_LEN,
  PIXEL_PALETTE,
  validatePixelData,
  pixelDataToPng,
  pixelDataMd5,
} from "../../../app/admin/arkhub-pixel";

/** 生成合法像素数据：全部 (34,34,34)，中间 3×3 用 (255,0,0) */
function samplePixels(): Buffer {
  const buf = Buffer.alloc(PIXEL_DATA_LEN, 34);
  for (let y = 10; y < 13; y++) {
    for (let x = 10; x < 13; x++) {
      const i = (y * PIXEL_CANVAS_W + x) * 3;
      buf[i] = 255;
      buf[i + 1] = 0;
      buf[i + 2] = 0;
    }
  }
  return buf;
}

describe("PIXEL_PALETTE（默认 40 色调色板）", () => {
  it("恰好 40 色，均为 #RRGGBB", () => {
    expect(PIXEL_PALETTE.length).toBe(40);
    for (const c of PIXEL_PALETTE) expect(c).toMatch(/^#[0-9a-f]{6}$/);
  });
});

describe("validatePixelData（24×24×3 RGB 校验）", () => {
  it("接受 1728 长度 Buffer", () => {
    const buf = samplePixels();
    expect(validatePixelData(buf).equals(buf)).toBe(true);
  });

  it("接受 1728 长度 number[]", () => {
    const arr = Array.from(samplePixels());
    const out = validatePixelData(arr);
    expect(out.length).toBe(PIXEL_DATA_LEN);
    expect(out[0]).toBe(34);
  });

  it("接受 576 长度 {r,g,b} 对象数组", () => {
    const buf = samplePixels();
    const objs = [];
    for (let i = 0; i < buf.length; i += 3) objs.push({ r: buf[i], g: buf[i + 1], b: buf[i + 2] });
    const out = validatePixelData(objs);
    expect(out.equals(buf)).toBe(true);
  });

  it("非法长度抛错", () => {
    expect(() => validatePixelData(Buffer.alloc(100))).toThrow(/长度非法/);
    expect(() => validatePixelData([1, 2, 3])).toThrow(/长度非法/);
    expect(() => validatePixelData(null)).toThrow();
  });
});

describe("pixelDataToPng（放大 PNG 渲染）", () => {
  it("生成合法 PNG（魔数 + 尺寸 = 24*scale × 24*scale）", () => {
    const png = pixelDataToPng(samplePixels(), 10);
    expect(png.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))).toBe(true);
    expect(png.readUInt32BE(16)).toBe(240);
    expect(png.readUInt32BE(20)).toBe(240);
    // 缩放 1（不放大）
    const png1 = pixelDataToPng(samplePixels(), 1);
    expect(png1.readUInt32BE(16)).toBe(24);
    expect(png1.readUInt32BE(20)).toBe(24);
  });

  it("非法输入抛错", () => {
    expect(() => pixelDataToPng(Buffer.alloc(10))).toThrow();
  });
});

describe("pixelDataMd5", () => {
  it("md5 与官服 token 请求一致（抓包 golden：1728B 心形像素 → b0f433...）", () => {
    // 用抓包提取的 06-23 真实像素数据校验（若存在）
    const { existsSync, readFileSync } = require("fs");
    const capture = "tmp/_pixeldata.bin";
    if (existsSync(capture)) {
      const buf = readFileSync(capture);
      expect(buf.length).toBe(PIXEL_DATA_LEN);
      expect(pixelDataMd5(buf)).toBe("b0f433255e8d282ebe6ebcadd0f3e1ae");
    }
  });

  it("确定性：相同输入同 md5，不同输入不同", () => {
    const a = pixelDataMd5(Buffer.alloc(PIXEL_DATA_LEN, 1));
    const b = pixelDataMd5(Buffer.alloc(PIXEL_DATA_LEN, 1));
    const c = pixelDataMd5(Buffer.alloc(PIXEL_DATA_LEN, 2));
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });
});
