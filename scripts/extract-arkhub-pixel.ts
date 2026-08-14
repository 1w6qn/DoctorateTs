/**
 * arkhub 像素画提取工具：从抓包的 savePixelArt 请求里还原上传的 file 字节
 *
 * 从统一抓包存储（captureManager）读取最近一条 savePixelArt 请求记录
 * （multipart 原始字节以 req.bin 落盘），提取 file part。
 *
 * 用法：pnpm exec tsx scripts/extract-arkhub-pixel.ts [rid]
 * 缺省取最新一条 path=/activity/arkhub/savePixelArt 的记录。
 * 输出：
 *   - tmp/pixel-art-extracted.<ext> —— 提取的 file part 原始字节
 *   - 控制台打印 part 清单与魔数/尺寸识别，帮助判断图像格式
 *
 * 前置：capture 模式 + traffic-recorder（rawBody 以 req.bin 落盘），
 * 客户端在游戏内重新保存一次像素画即可产生含原始字节的请求记录。
 */
import fs from "fs";
import { pixelDataToPng } from "../app/admin/arkhub-pixel";
import path from "path";
import { captureManager } from "../app/capture/capture-manager";

/** 解析 multipart/form-data 原始字节，返回各 part（name → Buffer 或字符串） */
function parseMultipart(raw: Buffer, boundary: string): Map<string, Buffer> {
  const parts = new Map<string, Buffer>();
  // 按 boundary 分隔（首行 --boundary，末尾 --boundary--）
  const delimiter = Buffer.from(`--${boundary}`);
  const bodyStart = raw.indexOf(delimiter);
  if (bodyStart === -1) throw new Error(`boundary "${boundary}" 未在 body 中找到`);
  let pos = bodyStart;
  for (;;) {
    const next = raw.indexOf(delimiter, pos + delimiter.length);
    if (next === -1) break;
    const chunk = raw.subarray(pos + delimiter.length, next);
    pos = next;
    const afterCrlf = chunk[0] === 0x0d && chunk[1] === 0x0a ? 2 : 0;
    const headerEnd = chunk.indexOf(Buffer.from("\r\n\r\n"), afterCrlf);
    if (headerEnd === -1) continue;
    const header = chunk.subarray(afterCrlf, headerEnd).toString("utf8");
    const content = chunk.subarray(headerEnd + 4);
    // 去掉 part 尾部 \r\n（Buffer 无 endsWith，手动比较末两字节）
    const data =
      content.length >= 2 &&
      content[content.length - 2] === 0x0d &&
      content[content.length - 1] === 0x0a
        ? content.subarray(0, content.length - 2)
        : content;
    const nameMatch = /name="([^"]+)"/.exec(header);
    if (nameMatch) parts.set(nameMatch[1], data);
  }
  return parts;
}

function detectFormat(buf: Buffer): string {
  if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    const w = buf.readUInt32BE(16);
    const h = buf.readUInt32BE(20);
    return `PNG 图片（${w}x${h}）`;
  }
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xd8) return "JPEG 图片";
  if (buf.length >= 6 && buf.subarray(0, 6).toString("ascii") === "GIF89a") return "GIF 图片";
  // 常见自有格式：前 4 字节可能是尺寸
  const hex = buf.subarray(0, 16).toString("hex");
  return `未知格式（前 16 字节 hex: ${hex}）`;
}

async function main(): Promise<void> {
  await captureManager.init();
  const arg = process.argv[2];
  let rec = arg ? await captureManager.getRecord(arg) : null;
  if (!rec) {
    const { items } = await captureManager.query({ path: "/activity/arkhub/savePixelArt", limit: 1 });
    rec = items[0] ?? null;
  }
  if (!rec) {
    console.error("未找到 savePixelArt 抓包记录——请先在 capture 模式下让客户端保存一次像素画（记录存入 tmp/capture/）");
    process.exit(1);
  }
  const detail = await captureManager.getRecordDetail(rec.id);
  if (!detail || detail.reqBodyType !== "bin" || !detail.reqBody || typeof detail.reqBody !== "object" || !("base64" in detail.reqBody)) {
    console.error("该记录没有原始请求体（req.bin / multipart 字节）——需要 capture 模式重启后重新保存像素画。");
    process.exit(1);
  }
  const raw = Buffer.from((detail.reqBody as { base64: string }).base64, "base64");
  const reqHeaders =
    typeof detail.reqHeaders === "string" ? (JSON.parse(detail.reqHeaders) as Record<string, string>) : {};
  const contentType = reqHeaders["content-type"] || "";
  const boundary = /boundary="?([^";]+)"?/.exec(contentType)?.[1] || "C880D0B0";
  console.log("记录:", rec.rid, "| 时间:", new Date(rec.ts).toISOString(), "| URL:", rec.path);
  console.log(`content-length: ${raw.length}B, boundary: ${boundary}`);

  const parts = parseMultipart(raw, boundary);
  console.log("multipart parts:");
  for (const [name, data] of parts) {
    const text = data.length <= 300 && data.every((b) => b === 0x09 || b === 0x0a || b === 0x0d || (b >= 0x20 && b < 0x7f));
    console.log(`  - ${name}: ${data.length}B ${text ? "→ " + data.toString("utf8") : ""}`);
  }

  const file = parts.get("pixelData") || parts.get("file") || parts.get("pixel");
  if (!file) {
    console.error("未找到 pixelData/file/pixel part");
    process.exit(1);
  }
  console.log("\npixelData 格式识别:", detectFormat(file));

  const out = path.join(__dirname, "..", "tmp", `pixel-art-extracted.dat`);
  fs.writeFileSync(out, file);
  console.log("已保存:", out, `(${file.length}B)`);

  // arkhub 像素画格式：24x24 画布，每像素 3 字节 RGB（1728 = 24*24*3），
  // 空白像素 (255,255,255) 视为透明背景。解析后放大输出 PNG（复用 app/admin/arkhub-pixel）。
  const scale = Number(process.env.PIXEL_SCALE || 10);
  if (file.length === 24 * 24 * 3) {
    const pngOut = path.join(__dirname, "..", "tmp", "pixel-art.png");
    fs.writeFileSync(pngOut, pixelDataToPng(file, scale));
    console.log(`已转 PNG（24x24 放大 ${scale} 倍，空白为透明）:`, pngOut);
  } else {
    console.log(`pixelData 不是 24x24 RGB 栅格（${file.length}B）——跳过 PNG 生成`);
  }
}

main().catch((e) => {
  console.error("提取失败:", (e as Error).message);
  process.exit(1);
});
