/* eslint-disable */
// 一次性完整扫描：抓包索引库中所有请求产生的 422（source=private，HTTP 请求）
// 运行：pnpm exec tsx scripts/scan-422.ts
import { DatabaseSync } from "node:sqlite";
import path from "node:path";

const db = new DatabaseSync(path.join(process.cwd(), "tmp", "capture", "index.db"), { readOnly: true });

// 先打印 records 表列名，便于定位字段
const cols = db.prepare("PRAGMA table_info(records)").all() as any[];
console.log("records 列:", cols.map((c) => c.name).join(", "), "\n");

// 仅 HTTP 请求方向（排除 arkhub 网关双向流 gateway-bidi）
const rows = db
  .prepare(
    `SELECT * FROM records
     WHERE status = 422
     ORDER BY ts ASC`,
  )
  .all() as any[];

console.log(`共 ${rows.length} 条 HTTP 422 记录：\n`);
for (const r of rows) {
  console.log(
    `${r.method ?? "-"} ${r.path} → 422  source=${r.source} dir=${r.direction} rid=${r.rid} ts=${r.ts}`,
  );
  console.log(`    reqBody=${r.reqBodyFile ?? ""} resBody=${r.resBodyFile ?? ""} note=${r.note ?? ""}`);
}
db.close();