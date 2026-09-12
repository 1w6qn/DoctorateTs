/**
 * 转换 worker（worker_threads）：并行执行 excel 转换（raw excel_json → 服务端格式 → data/excel）。
 * 每个 worker 独立处理一批表（读文件→转换→写回），主线程按表分发。
 *
 * 注意：本文件**不能**被直接 spawn 为 worker——worker_threads 以普通 Node 进程
 * 启动，不继承主进程 tsx 的转译上下文，`.ts` 在 `"type": "commonjs"` 的包里会被
 * 按 CJS 解析并执行源码，`import` 直接抛
 * `Cannot use import statement outside a module`。
 *
 * 正确入口是 `scripts/convert-worker-boot.cjs`：它先 `require("tsx/cjs")` 注册
 * 转译钩子，再 require 本文件。主线程 spawn 该 .cjs 引导文件。
 *
 * 历史缺陷：这条链路此前完全不可用（63/63 全败），错误被主线程
 * `on("error", () => resolve())` 吞掉，管线仍报「转换完成 N ok」，
 * 导致 28/63 张表长期停留在旧批次而不被发现（2026-09-11 修复）。
 */
import { parentPort, workerData } from "worker_threads";
import * as fs from "fs";
import * as path from "path";
import { convertTable, buildCompletion, buildMeta, writeMeta } from "./excel-convert";

interface WorkerJob {
  tables: string[]; // 表名（不含 .json）
  outDir: string;
  dataDir: string;
  schemaDir: string;
}

const job: WorkerJob = workerData;
const { tables, outDir, dataDir, schemaDir } = job;

/** 上报单表失败（保证主线程 fail 计数与实际失败一致） */
function reportFail(name: string, e: unknown): void {
  const msg = e instanceof Error ? e.message : String(e);
  parentPort?.postMessage({ name, status: "fail", error: msg.slice(0, 200) });
}

for (const name of tables) {
  const f = `${name}.json`;
  const out = path.join(dataDir, f);
  const schemaPath = path.join(schemaDir, f);
  try {
    const rawPath = path.join(outDir, f);
    const dec = JSON.parse(fs.readFileSync(rawPath, "utf-8"));
    const loc = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, "utf-8")) : null;
    const completion = buildCompletion(schemaPath);
    const result = convertTable(dec, loc, name, completion);
    fs.writeFileSync(out, JSON.stringify(result));
    // 溯源指纹旁挂（下次 isUpToDate 的内容级判据）
    const meta = buildMeta(rawPath, schemaPath);
    if (meta) writeMeta(out, meta);
    parentPort?.postMessage({ name, status: "ok" });
  } catch (e) {
    reportFail(name, e);
  }
}

// 历史缺陷：worker 顶层异常（如 workerData 缺失、import 期抛错）原先只让 on("error") 静默
// resolve()，不 post fail 消息 → 主线程 fail 计数偏低、管线误报成功。此处兜底上报，
// 即便循环外抛错也能让主线程感知。
process.on("uncaughtException", (e) => {
  try {
    parentPort?.postMessage({ name: "<worker>", status: "fail", error: (e as Error).message.slice(0, 200) });
  } finally {
    process.exit(1);
  }
});

parentPort?.postMessage({ done: true });
