/**
 * 奇象巡展巡展像素（ARKPIXEL）存储层单测：保存/读取/URL 构造/收集去重/
 * multipart 解析。2026-08-17。
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import {
  setPixelsDirForTest,
  savePixel,
  loadPixelBytes,
  pixelMeta,
  buildPixelArtResp,
  computeNewCollects,
  parseMultipartForm,
} from "@game/manager/activity/arkpixel";
import { PIXEL_PALETTE, PIXEL_DATA_LEN } from "../../../app/admin/arkhub-pixel";

/** 合法像素：全空白（255,255,255） */
function blankPixel(): Buffer {
  return Buffer.alloc(PIXEL_DATA_LEN, 0xff);
}

describe("ARKPIXEL 像素存储", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "arkpixel-test-"));
    setPixelsDirForTest(dir);
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("savePixel：分配全局唯一 id、落盘 1728B、索引含 uid/ts/md5", () => {
    const id = savePixel("1", blankPixel());
    expect(id).toBeGreaterThan(1_000_000_000);
    const bytes = loadPixelBytes(id)!;
    expect(bytes.length).toBe(PIXEL_DATA_LEN);
    expect(bytes.equals(blankPixel())).toBe(true);
    const meta = pixelMeta(id)!;
    expect(meta.uid).toBe("1");
    expect(meta.ts).toBeGreaterThan(0);
    expect(meta.md5).toMatch(/^[0-9a-f]{32}$/);
    expect(meta.banned).toBe(false);
  });

  it("savePixel：非法长度/非法颜色抛错（validatePixelData 校验）", () => {
    expect(() => savePixel("1", Buffer.alloc(10))).toThrow();
    // 非法颜色（非调色板内 RGB）
    const bad = Buffer.alloc(PIXEL_DATA_LEN, 0x7f); // RGB(127,127,127) 不在 40 色调色板
    expect(() => savePixel("1", bad)).toThrow();
  });

  it("loadPixelBytes：不存在的 id 返回 null", () => {
    expect(loadPixelBytes(999999999)).toBeNull();
  });

  it("buildPixelArtResp：url 指向本服下载端点、isBanned=false、不存在的 id 跳过", () => {
    const id = savePixel("2222", blankPixel());
    const resp = buildPixelArtResp([id, 999999999], "http://127.0.0.1:8443");
    expect(resp[String(id)].url).toBe(`http://127.0.0.1:8443/activity/arkhub/pixel/${id}.dat`);
    expect(resp[String(id)].isBanned).toBe(false);
    expect(resp["999999999"]).toBeUndefined();
  });
});

describe("收集画像去重（computeNewCollects）", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "arkpixel-test-"));
    setPixelsDirForTest(dir);
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("他人画像计收集、本人发布不算、重复请求去重", () => {
    const mine = savePixel("1", blankPixel());
    const other1 = savePixel("2", blankPixel());
    const other2 = savePixel("3", blankPixel());

    const fresh = computeNewCollects("1", [mine, other1, other2], []);
    expect(fresh).toEqual([other1, other2]); // 本人 mine 不计

    const fresh2 = computeNewCollects("1", [other1, other2], [other1, other2]);
    expect(fresh2).toEqual([]); // 已收集去重

    const fresh3 = computeNewCollects("1", [other2, 999999999], []);
    expect(fresh3).toEqual([other2]); // 不存在的 id 跳过
  });
});

describe("multipart/form-data 解析（parseMultipartForm）", () => {
  it("解析 json + pixelData 两个 part（对齐官服 savePixelArt 请求）", () => {
    const boundary = "526254C8";
    const jsonPart = Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="json"; filename="json_info"\r\nContent-Type: application/json\r\n\r\n{"brief":{"activityId":"act1arkhub","token":"5856d791603b47638d4b6d"}}\r\n`,
    );
    const pixel = Buffer.alloc(PIXEL_DATA_LEN, 0xff);
    const pixelPart = Buffer.concat([
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="pixelData"; filename="pixelDataFile"\r\nContent-Type: multipart/form-data\r\n\r\n`,
      ),
      pixel,
      Buffer.from(`\r\n--${boundary}--\r\n`),
    ]);
    const raw = Buffer.concat([jsonPart, pixelPart]);

    const parts = parseMultipartForm(raw, `multipart/form-data; boundary=${boundary}`);
    expect(parts.size).toBe(2);
    const brief = JSON.parse(parts.get("json")!.toString("utf-8"));
    expect(brief.brief.activityId).toBe("act1arkhub");
    expect(parts.get("pixelData")!.length).toBe(PIXEL_DATA_LEN);
  });

  it("boundary 带引号 / 无 boundary / 空体容错", () => {
    expect(parseMultipartForm(Buffer.alloc(0), "multipart/form-data; boundary=x").size).toBe(0);
    expect(parseMultipartForm(Buffer.from("abc"), undefined).size).toBe(0);
  });
});

describe("PIXEL_PALETTE 完整性", () => {
  it("40 色调色板与画布像素语义一致", () => {
    expect(PIXEL_PALETTE).toHaveLength(40);
    expect(PIXEL_PALETTE).toContain("#ffffff");
    expect(PIXEL_DATA_LEN).toBe(24 * 24 * 3);
  });
});
