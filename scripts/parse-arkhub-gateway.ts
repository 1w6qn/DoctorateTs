/**
 * 离线解析已抓取的 arkhub 网关 TCP 流量（arkodc 帧）
 *
 * 对 tmp/arkhub-gateway/{connectionId}/ 的 up.bin/down.bin 按网关帧格式
 * （4B 大端长度 + 4B 消息 ID + 8B 头 + protobuf）解析，输出 parsed.json；
 * 未按长度前缀切分的余量（登录后 down 流等）以 hex 记录。
 *
 * 用法：
 *   npx tsx scripts/parse-arkhub-gateway.ts                 # 解析全部连接目录
 *   npx tsx scripts/parse-arkhub-gateway.ts 2026-08-12T10-01-12-289Z   # 单个连接
 */
import fs from "fs";
import path from "path";
import {
  parseGatewayStream,
  framesToJson,
  fieldsToJson,
  gatewayTranscript,
} from "../app/proxy/arkodc";

const ROOT = path.join(process.cwd(), "tmp", "arkhub-gateway");

function parseConnection(dir: string): void {
  const upPath = path.join(dir, "up.bin");
  const downPath = path.join(dir, "down.bin");
  if (!fs.existsSync(upPath) && !fs.existsSync(downPath)) return;
  const up = fs.existsSync(upPath) ? fs.readFileSync(upPath) : Buffer.alloc(0);
  const down = fs.existsSync(downPath) ? fs.readFileSync(downPath) : Buffer.alloc(0);
  const upResult = parseGatewayStream(up, "up");
  const downResult = parseGatewayStream(down, "down");
  // 真实可读的 request/response 记录
  fs.writeFileSync(
    path.join(dir, "messages.json"),
    JSON.stringify(gatewayTranscript(upResult, downResult), null, 2),
  );
  fs.writeFileSync(
    path.join(dir, "parsed.json"),
    JSON.stringify(
      {
        up: framesToJson(upResult.frames),
        down: framesToJson(downResult.frames),
        upRemainderHex: upResult.remainder.toString("hex"),
        downRemainderHex: downResult.remainder.toString("hex"),
        upRemainderLen: upResult.remainder.length,
        downRemainderLen: downResult.remainder.length,
        downWrappers: upResult.wrappers
          ? upResult.wrappers.map((w) => ({
              start: w.start,
              end: w.end,
              len: w.bytes.length,
              fields: fieldsToJson(w.fields),
            }))
          : undefined,
        downRecovered: downResult.recovered
          ? {
              start: downResult.recovered.start,
              end: downResult.recovered.end,
              fields: fieldsToJson(downResult.recovered.fields),
            }
          : undefined,
      },
      null,
      2,
    ),
  );
  const summary = {
    id: path.basename(dir),
    upFrames: upResult.frames.length,
    downFrames: downResult.frames.length,
    upRemainder: upResult.remainder.length,
    downRemainder: downResult.remainder.length,
    downWrappers: upResult.wrappers ? upResult.wrappers.map((w) => `${w.bytes.length}B`) : undefined,
    downRecovered: downResult.recovered ? `${downResult.recovered.fields.length}字段@${downResult.recovered.start}` : undefined,
    upBytes: up.length,
    downBytes: down.length,
  };
  console.log(JSON.stringify(summary));
}

const args = process.argv.slice(2);
if (args[0]) {
  parseConnection(path.join(ROOT, args[0]));
} else {
  for (const name of fs.readdirSync(ROOT)) {
    parseConnection(path.join(ROOT, name));
  }
}
