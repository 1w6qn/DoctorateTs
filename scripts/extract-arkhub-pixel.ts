/**
 * arkhub 像素画提取工具：从抓包的 savePixelArt 请求里还原上传的 file 字节
 *
 * 用法：npx tsx scripts/extract-arkhub-pixel.ts [请求文件路径]
 * 缺省取 tmp/request_activity/arkhub/savePixelArt/ 下最新的一个。
 * 输出：
 *   - tmp/pixel-art-extracted.<ext> —— 提取的 file part 原始字节
 *   - 控制台打印 part 清单与魔数/尺寸识别，帮助判断图像格式
 *
 * 前置：capture 模式 + traffic-recorder（已支持 rawBody base64 落盘），
 * 客户端在游戏内重新保存一次像素画即可产生含 rawBody 的请求记录。
 */
import fs from "fs";
import path from "path";

interface CapturedRequest {
  headers?: Record<string, string>;
  rawBody?: string;
  body?: unknown;
  url?: string;
  timestamp?: string;
}

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

function main(): void {
  const argFile = process.argv[2];
  const reqDir = path.join(__dirname, "..", "tmp", "request_activity", "arkhub", "savePixelArt");
  let reqPath: string;
  if (argFile) {
    reqPath = argFile;
  } else {
    if (!fs.existsSync(reqDir)) {
      console.error(`无抓包目录 ${reqDir}——请先在 capture 模式下让客户端保存一次像素画`);
      process.exit(1);
    }
    const files = fs.readdirSync(reqDir)
      .filter((f) => f.endsWith(".json"))
      .sort();
    if (!files.length) {
      console.error("savePixelArt 请求目录为空");
      process.exit(1);
    }
    reqPath = path.join(reqDir, files[files.length - 1]);
  }

  const req = JSON.parse(fs.readFileSync(reqPath, "utf8")) as CapturedRequest;
  console.log("请求文件:", reqPath);
  console.log("时间:", req.timestamp, "URL:", req.url);

  if (!req.rawBody) {
    console.error("该记录没有 rawBody（multipart 原始字节）——需要 capture 模式重启后重新保存像素画。");
    console.error("旧记录只存了 body={}（express.json 不解析 multipart），字节已丢失。");
    process.exit(1);
  }

  const raw = Buffer.from(req.rawBody, "base64");
  const contentType = req.headers?.["content-type"] || "";
  const boundary = /boundary="?([^";]+)"?/.exec(contentType)?.[1] || "C880D0B0";
  console.log(`content-length: ${raw.length}B, boundary: ${boundary}`);

  const parts = parseMultipart(raw, boundary);
  console.log("multipart parts:");
  for (const [name, data] of parts) {
    const text = data.length <= 300 && data.every((b) => b === 0x09 || b === 0x0a || b === 0x0d || (b >= 0x20 && b < 0x7f));
    console.log(`  - ${name}: ${data.length}B ${text ? "→ " + data.toString("utf8") : ""}`);
  }

  const file = parts.get("file") || parts.get("pixel");
  if (!file) {
    console.error("未找到 file/pixel part");
    process.exit(1);
  }
  console.log("\nfile 格式识别:", detectFormat(file));

  const out = path.join(__dirname, "..", "tmp", `pixel-art-extracted.dat`);
  fs.writeFileSync(out, file);
  console.log("已保存:", out, `(${file.length}B)`);
}

main();
