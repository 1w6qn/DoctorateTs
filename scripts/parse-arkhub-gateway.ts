/**
 * 离线解析已抓取的 奇象巡展（arkhub）网关 TCP 流量（网关帧）
 *
 * 从统一抓包存储（captureManager，tmp/capture/）读取 gateway-bidi 记录的
 * up.bin/down.bin，按网关帧格式（4B 大端长度 + 4B 消息 ID + 8B 头 + protobuf）
 * 解析输出 parsed.json；未按长度前缀切分的余量（登录后 down 流等）以 hex 记录。
 *
 * 用法：
 *   pnpm exec tsx scripts/parse-arkhub-gateway.ts          # 解析全部网关记录
 *   pnpm exec tsx scripts/parse-arkhub-gateway.ts <rid>    # 单条记录（rid 或数字 id）
 */
import fs from "fs";
import path from "path";
import { captureManager } from "@capture/capture-manager";
import {
  parseGatewayStream,
  framesToJson,
  fieldsToJson,
  gatewayTranscript,
} from "@game/modules/activities/arkhub/public";

function parseConnection(dir: string, id: string): void {
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
    id,
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

export async function main(argv: string[] = []): Promise<void> {
  await captureManager.init();
  const arg = argv[0];
  if (arg) {
    const rec = await captureManager.getRecord(arg);
    if (!rec) {
      console.error(`抓包记录不存在: ${arg}`);
      process.exit(1);
    }
    parseConnection(path.join(captureManager.recordsDir(), rec.rid), rec.rid);
    return;
  }
  const { items } = await captureManager.query({ direction: "gateway-bidi", limit: 1000 });
  if (!items.length) {
    console.log("无网关抓包记录（tmp/capture/records/ 下无 gateway-bidi 记录）");
    return;
  }
  for (const rec of items) {
    parseConnection(path.join(captureManager.recordsDir(), rec.rid), rec.rid);
  }
}

// 直连执行入口（被 admin-cli tools 导入时不自动运行）
if (typeof require !== "undefined" && require.main === module) {
  main().catch((e) => {
    console.error("解析失败:", (e as Error).message);
    process.exit(1);
  });
}
