/**
 * 网关协议字典：扫描全部抓包，按 (msgId, 方向, payload 结构) 汇总消息形态
 *
 * 输出每个 msgId 在各方向的帧数、payload 形态数与样例、解码字段——
 * 用于逆向确认 msgId→消息类型映射（MSG_NAMES/MSG_SCHEMAS 的观测依据）。
 *
 * 用法：npx tsx scripts/dump-gateway-dict.ts [连接目录]
 */
import fs from "fs";
import path from "path";
import { splitGatewayFrames, MSG_NAMES, decodeProtobuf } from "../app/proxy/arkodc";

const ROOT = path.join(process.cwd(), "tmp", "arkhub-gateway");

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
      const f = path.join(ROOT, dir, d + ".bin");
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

const args = process.argv.slice(2);
const dirs = args[0] ? [args[0]] : fs.readdirSync(ROOT);
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
