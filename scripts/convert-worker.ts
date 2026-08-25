/**
 * 转换 worker（worker_threads）：并行执行 excel 转换（raw excel_json → 服务端格式 → data/excel）。
 * 每个 worker 独立处理一批表（读文件→转换→写回），主线程按表分发。
 */
import { parentPort, workerData } from "worker_threads";
import * as fs from "fs";
import * as path from "path";
import { convertTable, buildCompletion, isUpToDate } from "./excel-convert";

interface WorkerJob {
  tables: string[]; // 表名（不含 .json）
  outDir: string;
  dataDir: string;
  schemaDir: string;
}

const job: WorkerJob = workerData;
const { tables, outDir, dataDir, schemaDir } = job;

for (const name of tables) {
  const f = `${name}.json`;
  const out = path.join(dataDir, f);
  const schemaPath = path.join(schemaDir, f);
  try {
    // 增量：原始解码 + schema 均未变 → 跳过
    if (isUpToDate(path.join(outDir, f), out, schemaPath)) {
      parentPort?.postMessage({ name, status: "skipped" });
      continue;
    }
    const dec = JSON.parse(fs.readFileSync(path.join(outDir, f), "utf-8"));
    const loc = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, "utf-8")) : null;
    const completion = buildCompletion(schemaPath);
    const result = convertTable(dec, loc, name, completion);
    fs.writeFileSync(out, JSON.stringify(result));
    parentPort?.postMessage({ name, status: "ok" });
  } catch (e) {
    parentPort?.postMessage({ name, status: "fail", error: (e as Error).message.slice(0, 60) });
  }
}
parentPort?.postMessage({ done: true });
