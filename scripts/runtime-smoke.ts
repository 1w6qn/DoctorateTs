/**
 * 运行时端到端冒烟脚本
 *
 * 遍历 app/game/routes.ts 的路由注册表，动态 import 每个 router 模块，
 * 通过 Express Router 的 .stack 结构枚举其全部已注册端点，统一带有效 secret 请求，
 * 按 HTTP 状态 / 是否 JSON / 业务 result 分类输出，用于系统定位运行时 bug。
 *
 * 用法（服务器需已启动，默认连 9001 端口账号 2222）：
 *   pnpm exec tsx scripts/runtime-smoke.ts
 *   SMOKE_BASE=http://localhost:9001 SMOKE_SECRET=xxx pnpm exec tsx scripts/runtime-smoke.ts
 *   pnpm exec tsx scripts/runtime-smoke.ts --min        # 仅输出异常分类
 */
import { routes } from "../app/game/routes";

/** 服务器基址（环境变量覆盖） */
const BASE = process.env.SMOKE_BASE || "http://localhost:9001";
/** 账号 secret（默认账号 2222 的确定性 secret） */
const SECRET =
  process.env.SMOKE_SECRET || "ac6457289cfb192ccd6dd9830f73881b";
/** 单请求超时（ms）——过短会误伤慢端点，过长会在挂起端点上拖慢全量探测 */
const TIMEOUT = Number(process.env.SMOKE_TIMEOUT || 3000);
/** --min：仅打印异常与汇总 */
const MIN = process.argv.includes("--min");
/**
 * 已知挂起的前缀（URL 重写别名中间件不调用 next()，导致请求永远不响应）：
 * /crisisV2、/sandboxPerm 为客户端别名挂载，实测挂起；其真实前缀 /crisis、/sandbox 正常。
 * 跳过以免阻塞全量探测（已单独确认挂起并计入 bug 报告）。
 */
const SKIP_PREFIXES = new Set(["/crisisV2", "/sandboxPerm"]);

/** 单条探测结果 */
interface ProbeResult {
  module: string;
  prefix: string;
  method: string;
  /** 实际请求的完整路径 */
  path: string;
  httpStatus: number;
  isJson: boolean;
  /** 业务 result（JSON 响应中 result 或 status 字段） */
  result: number | null;
  ms: number;
  category:
    | "ok"
    | "business-error"
    | "404"
    | "5xx"
    | "non-json"
    | "network-error"
    | "other";
  snippet: string;
}

/**
 * 拼接挂载前缀与路由相对路径，规范化斜杠
 * @param prefix - 挂载前缀（"" 或 "/" 表示根级）
 * @param path - 路由内定义的路径
 * @returns 完整请求路径
 */
function joinPath(prefix: string, path: string): string {
  const p = prefix === "/" ? "" : prefix;
  let rp = path;
  if (!rp.startsWith("/")) rp = "/" + rp;
  const full = (p + rp).replace(/\/{2,}/g, "/");
  return full || "/";
}

/**
 * 从 Express Router 的 .stack 提取全部 (method, path)
 * 仅取字符串路径（跳过正则/regexp 类型的复杂路由）
 * @param router - Express Router 实例
 * @returns 端点列表
 */
function extractEndpoints(router: unknown): { method: string; path: string }[] {
  const out: { method: string; path: string }[] = [];
  const stack = (router as { stack?: unknown[] })?.stack ?? [];
  for (const layer of stack) {
    const route = (layer as { route?: { methods?: Record<string, boolean>; path?: unknown } })
      ?.route;
    if (!route) continue;
    if (typeof route.path !== "string") continue;
    const methods = Object.keys(route.methods ?? {}).filter((m) => route.methods?.[m]);
    for (const m of methods) {
      out.push({ method: m.toUpperCase(), path: route.path });
    }
  }
  return out;
}

/**
 * 对单个端点发起探测请求并分类
 * @param fullPath - 完整请求路径
 * @param method - HTTP 方法（GET/POST/...）
 * @returns 分类后的探测结果
 */
async function probe(fullPath: string, method: string): Promise<ProbeResult> {
  const t0 = Date.now();
  try {
    const res = await fetch(BASE + fullPath, {
      method,
      headers: {
        secret: SECRET,
        "content-type": "application/json",
      },
      body: method === "GET" ? undefined : "{}",
      signal: AbortSignal.timeout(TIMEOUT),
    });
    const text = await res.text();
    const ms = Date.now() - t0;
    let isJson = false;
    let result: number | null = null;
    let snippet = text.slice(0, 140).replace(/\s+/g, " ");
    try {
      const j = JSON.parse(text);
      isJson = true;
      result = typeof j.result === "number" ? j.result : typeof j.status === "number" ? j.status : null;
    } catch {
      /* 非 JSON */
    }
    let category: ProbeResult["category"];
    if (res.status === 404) category = "404";
    else if (res.status >= 500) category = "5xx";
    else if (res.status === 200 && isJson && (result === 0 || result === null)) category = "ok";
    else if (res.status === 200 && isJson && result !== 0) category = "business-error";
    else if (res.status === 200 && !isJson) category = "non-json";
    else if (res.status === 401) category = "other"; // 应少见（有效 secret）
    else category = "other";
    return {
      module: "",
      prefix: "",
      method,
      path: fullPath,
      httpStatus: res.status,
      isJson,
      result,
      ms,
      category,
      snippet,
    };
  } catch (e) {
    const isTimeout = (e as { name?: string })?.name === "TimeoutError" || (e as { message?: string })?.message?.includes("timeout");
    return {
      module: "",
      prefix: "",
      method,
      path: fullPath,
      httpStatus: 0,
      isJson: false,
      result: null,
      ms: Date.now() - t0,
      category: isTimeout ? "other" : "network-error",
      snippet: isTimeout ? "[超时 8s 无响应]" : (e as Error).message,
    };
  }
}

/**
 * 将 routes.ts 内相对路径的模块解析为绝对文件 URL
 * （routes.ts 位于 app/game/，其 ./router/x 相对该目录）
 * @param rel - 相对模块路径
 * @returns 可动态 import 的文件 URL
 */
function resolveModuleUrl(rel: string): string {
  const pathMod = require("path") as typeof import("path");
  const { pathToFileURL } = require("url") as typeof import("url");
  const baseDir = pathMod.resolve(__dirname, "../app/game");
  return pathToFileURL(pathMod.resolve(baseDir, rel)).href;
}

/**
 * 主流程：遍历路由表，探测全部端点，汇总分类
 */
async function main(): Promise<void> {
  const results: ProbeResult[] = [];
  let totalEp = 0;
  for (const reg of routes) {
    const mod = (await import(resolveModuleUrl(reg.module))) as Record<string, unknown>;
    const router = reg.exportName === "rootRouter" ? mod.rootRouter : mod.default;
    const endpoints = extractEndpoints(router);
    for (const ep of endpoints) {
      totalEp++;
      const fullPath = joinPath(reg.prefix, ep.path);
      if (SKIP_PREFIXES.has(reg.prefix)) continue;
      const r = await probe(fullPath, ep.method);
      r.module = reg.module;
      r.prefix = reg.prefix;
      results.push(r);
      if (totalEp % 20 === 0) console.log(`  进度: ${totalEp} 端点已探测...`);
    }
  }

  // 汇总统计
  const total = results.length;
  const byCat = new Map<string, number>();
  for (const r of results) byCat.set(r.category, (byCat.get(r.category) ?? 0) + 1);

  console.log(`\n===== 冒烟汇总（${BASE}）=====`);
  console.log(`探测端点总数: ${total}`);
  for (const [cat, n] of [...byCat.entries()].sort()) console.log(`  ${cat}: ${n}`);
  console.log("");

  // 输出异常明细
  const abnormal = results.filter((r) =>
    ["404", "5xx", "non-json", "network-error", "other"].includes(r.category),
  );
  if (abnormal.length) {
    console.log(`===== 异常端点（${abnormal.length}）=====`);
    for (const r of abnormal) {
      console.log(`[${r.category}] ${r.httpStatus} ${r.method} ${r.path} (${r.ms}ms) <- ${r.module}`);
      console.log(`    ${r.snippet}`);
    }
  } else {
    console.log("无 404/5xx/非JSON 端点");
  }

  // 输出到文件（供报告引用）
  const fs = await import("fs");
  const path = await import("path");
  const outFile = path.resolve(__dirname, "../tmp/runtime-smoke-results.json");
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, JSON.stringify(results, null, 2));
  console.log(`\n明细已写入 ${outFile}`);
}

main().catch((e) => {
  console.error("冒烟脚本执行失败:", e);
  process.exit(1);
});