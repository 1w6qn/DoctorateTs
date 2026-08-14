/**
 * 网关协议字典：扫描全部抓包，按 (msgId, 方向, payload 结构) 汇总消息形态
 *
 * 从统一抓包存储（captureManager）读取 gateway-bidi 记录的 up.bin/down.bin，
 * 输出每个 msgId 在各方向的帧数、payload 形态数与样例、解码字段——
 * 用于逆向确认 msgId→消息类型映射（MSG_NAMES/MSG_SCHEMAS 的观测依据）。
 *
 * 用法：npx tsx scripts/dump-gateway-dict.ts [rid]
 */
import fs from "fs";
import path from "path";
import { captureManager } from "../app/capture/capture-manager";
import { splitGatewayFrames, MSG_NAMES, decodeProtobuf } from "../app/proxy/arkodc";

interface DictEntry {
  msgId: number;
  dir: string;
  n: number;
  sample: string;
  fields: string;
}

function buildDict(dirs: string[]): Map<string, DictEntry> {
  const dict = new Map<string, DictEntry>();
  for (const dir of dirs) {
    for (const d of ["up", "down"]) {
      const f = path.join(dir, d + ".bin");
      if (!fs.existsSync(f)) continue;
      const frames = splitGatewayFrames(fs.readFileSync(f), d === "up" ? "up" : "down");
      for (const fr of frames) {
        const key = `${fr.msgId}:${d}:${fr.fields.length}:${fr.payloadHex.slice(0, 8)}`;
        const e = dict.get(key) ?? {
          msgId: fr.msgId,
          dir: d,
          n: 0,
          sample: fr.payloadHex.slice(0, 40),
          fields: "",
        };
        e.n++;
        if (!e.fields && fr.fields.length > 0) {
          e.fields = fr.fields
            .slice(0, 4)
            .map((x) =>
              `${x.field}(${x.wireName}${x.str ? ":" + x.str.slice(0, 12) : x.varint !== undefined ? "=" + x.varint : ""})`,
            )
            .join(" ");
        }
        dict.set(key, e);
      }
    }
  }
  return dict;
}

async function main(): Promise<void> {
  await captureManager.init();
  const arg = process.argv[2];
  let dirs: string[];
  if (arg) {
    const rec = await captureManager.getRecord(arg);
    if (!rec) {
      console.error(`抓包记录不存在: ${arg}`);
      process.exit(1);
    }
    dirs = [path.join(captureManager.recordsDir(), rec.rid)];
  } else {
    const { items } = await captureManager.query({ direction: "gateway-bidi", limit: 1000 });
    dirs = items.map((r) => path.join(captureManager.recordsDir(), r.rid));
  }
  const dict = buildDict(dirs);

  const byMsg = new Map<string, DictEntry[]>();
  for (const e of dict.values()) {
    const k = `${e.msgId}:${e.dir}`;
    if (!byMsg.has(k)) byMsg.set(k, []);
    byMsg.get(k)!.push(e);
  }
  for (const [k, entries] of [...byMsg.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const [msgId, dir] = k.split(":");
    const total = entries.reduce((s, e) => s + e.n, 0);
    console.log(`msgId=${msgId} ${dir} ${MSG_NAMES[+msgId] ?? ""} 共${total}帧 ${entries.length}种形态`);
    entries
      .sort((a, b) => b.n - a.n)
      .slice(0, 5)
      .forEach((e, i) => {
        console.log(`   [${i}] x${e.n} ${e.sample} ${e.fields}`);
      });
  }
}

main().catch((e) => {
  console.error("字典生成失败:", (e as Error).message);
  process.exit(1);
});
