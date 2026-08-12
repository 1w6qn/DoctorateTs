/**
 * 转换 worker（worker_threads）：并行执行 excel 转换（raw excel_json → 服务端格式 → data/excel）。
 * 每个 worker 独立处理一批表（读文件→转换→写回），主线程按表分发。
 */
import { parentPort, workerData } from "worker_threads";
import * as fs from "fs";
import * as path from "path";
import { convertTable } from "./excel-convert";

interface WorkerJob {
  tables: string[]; // 表名（不含 .json）
  outDir: string;
  dataDir: string;
  schemaDir: string;
}

const job: WorkerJob = workerData;
const { tables, outDir, dataDir, schemaDir } = job;

function buildCompletion(schemaPath: string): any {
  if (!fs.existsSync(schemaPath)) return undefined;
  let schema: any;
  try {
    schema = JSON.parse(fs.readFileSync(schemaPath, "utf-8"));
  } catch {
    return undefined;
  }
  const root: string = schema.root || "";
  let recordType = root;
  let applyTo: "root" | "values" = "root";
  if (root.startsWith("clz_Torappu_SimpleKVTable_")) {
    recordType = root.slice("clz_Torappu_SimpleKVTable_".length);
    applyTo = "values";
  }
  const fields = (schema.tables?.[recordType] || []).map((x: any) => x.name);
  if (!fields.length) return undefined;
  return { fields, applyTo, schema, recordType };
}

for (const name of tables) {
  const f = `${name}.json`;
  const out = path.join(dataDir, f);
  const schemaPath = path.join(schemaDir, f);
  try {
    // 增量：原始解码 + schema 均未变 → 跳过
    const decStat = fs.statSync(path.join(outDir, f));
    const outStat = fs.existsSync(out) ? fs.statSync(out) : null;
    const schemaStat = fs.existsSync(schemaPath) ? fs.statSync(schemaPath) : null;
    if (
      outStat &&
      decStat.mtimeMs <= outStat.mtimeMs &&
      (!schemaStat || schemaStat.mtimeMs <= outStat.mtimeMs)
    ) {
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
