/**
 * 旧格式抓包数据迁移工具（一次性，幂等）
 *
 * 把旧 tmp/ 抓包格式合并进统一抓包存储 tmp/capture/（SQLite 索引 + records/{rid}/）：
 *
 * 1. 记录器目录格式：tmp/{module}/{endpoint...}/{ts}.json（响应）+ tmp/request_{module}/...（请求元数据镜像）
 * 2. 顶层扁平旧格式：{module}_{endpoint}_req|res_{id}.json / {module}_{endpoint}request|response{id}.json / 裸 {module}_{endpoint}.json
 * 3. 官服操作：tmp/official/** + tmp/request_official/**（source=ops）
 * 4. arkhub 网关：tmp/arkhub-gateway/{connectionId}/（up.bin/down.bin/parsed.json/messages.json → 移动为 gateway-bidi 记录）
 *
 * 合并成功的旧文件默认删除（--keep 保留），空目录自动清理。
 * 非抓包产物（tmp/decompile 反编译工作区 / tmp/test-logs / tmp/capture 新存储 /
 * 顶层 _* 临时脚本与 pixel-art 等）一律不触碰；无法识别的顶层文件跳过并在报告列出。
 *
 * 用法：
 *   npx tsx scripts/migrate-capture-legacy.ts [--dry-run] [--keep]
 *   --dry-run   只统计将合并的内容，不写存储不删文件
 *   --keep      合并后保留旧文件（默认合并成功后删除源文件）
 *
 * 说明：旧记录无法可靠区分私服/capture 转发来源——请求文件 headers.host 含 :8444（独立代理）→ harness，
 * 其余 → private；official → ops；网关 → gateway。合并记录归入「旧格式迁移」会话，note 记录源路径。
 */
import fs from "fs";
import path from "path";
import { captureManager, CaptureSource } from "../app/capture/capture-manager";
import { logger } from "../app/utils/logger";

const TMP = path.join(process.cwd(), "tmp");
const CAPTURE_DIR = path.join(TMP, "capture");

/** 不参与迁移/清理的顶层目录（非抓包数据） */
const SKIP_DIRS = new Set(["capture", "test-logs", "decompile", "arkhub-gateway", ".idea", "compare"]);
/** 顶层不迁移的文件名前缀/模式（临时脚本/分析产物） */
const SKIP_TOP_FILES = /^(_|pixel-art|pixel_data|test_topic|\.)/;

interface FlatParse {
  module: string;
  endpoint: string;
  /** "req" | "res" | null（null=裸响应） */
  kind: "req" | "res" | null;
  id: string | null;
  /** 命名风格：A=_req_/_res_（带下划线）；B=request/response 连写；C=裸文件 */
  style: "A" | "B" | "C";
}

/** 解析顶层扁平文件名 */
function parseFlat(name: string): FlatParse | null {
  if (SKIP_TOP_FILES.test(name) || !name.endsWith(".json")) return null;
  const stem = name.slice(0, -5);
  // A 风格：{base}_req_{id} / {base}_res_{id}
  let m = /^(.*?)_(req|res)(?:_(\d+))?$/.exec(stem);
  if (m) {
    const base = m[1];
    if (!base.includes("_")) return null; // 无模块分隔（u8usergettoken 之类）跳过
    const idx = base.indexOf("_");
    return { module: base.slice(0, idx), endpoint: base.slice(idx + 1), kind: m[2] as "req" | "res", id: m[3] ?? null, style: "A" };
  }
  // B 风格：{base}request{id} / {base}response{id}（或 request.{id}）
  m = /^(.*?)(request|response)\.?(\d+)?$/.exec(stem);
  if (m) {
    const base = m[1];
    if (!base.includes("_")) return null;
    const idx = base.indexOf("_");
    return { module: base.slice(0, idx), endpoint: base.slice(idx + 1), kind: m[2] === "request" ? "req" : "res", id: m[3] ?? null, style: "B" };
  }
  // C 风格：裸 {base}.json → 响应（无请求）
  if (!stem.includes("_")) return null;
  const idx = stem.indexOf("_");
  return { module: stem.slice(0, idx), endpoint: stem.slice(idx + 1), kind: null, id: null, style: "C" };
}

interface MergeStats {
  pairs: number;
  resOnly: number;
  reqOnly: number;
  gateway: number;
  bytes: number;
  skipped: number;
  failed: number;
  unrecognized: string[];
}

/** 解析请求元数据文件内容（记录器格式 {method,url,headers,body,rawBody?,query} 或 ops 格式 {cgi,headers,body}） */
function parseReqMeta(text: string): {
  method?: string;
  url?: string;
  cgi?: string;
  headers?: Record<string, unknown>;
  body?: unknown;
  rawBody?: string;
  query?: unknown;
} {
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

/** 从请求元数据推断来源 */
function inferSource(module: string, reqMeta: { headers?: Record<string, unknown> }): CaptureSource {
  if (module === "official") return "ops";
  const host = String((reqMeta.headers as Record<string, string> | undefined)?.host ?? "");
  if (host.includes(":8444")) return "harness";
  return "private";
}

/** 时间戳：ISO 文件名 → Date.parse；否则文件 mtime */
function fileTs(file: string, name: string): number {
  const iso = /^(\d{4}-\d{2}-\d{2}T[^.]+)/.exec(name)?.[1];
  if (iso) {
    const t = Date.parse(iso + "Z");
    if (!Number.isNaN(t)) return t;
  }
  return fs.statSync(file).mtimeMs;
}

/** 合并一条 http 记录（响应文件 + 可选请求镜像） */
async function mergeHttpRecord(
  sessionId: string,
  resFile: string,
  reqFile: string | null,
  source: CaptureSource,
  metaPath: string,
  extra: {
    path?: string;
    method?: string;
    query?: string;
    reqHeaders?: Record<string, unknown>;
    /** 扁平旧格式：req 文件内容即请求体本身（非元数据包装） */
    flatReqBody?: string | null;
  } = {},
): Promise<void> {
  const resText = fs.readFileSync(resFile, "utf-8");
  const bodies: { req?: { kind: "json" | "bin"; data: unknown }; res: { kind: "json"; data: string } } = {
    res: { kind: "json", data: resText },
  };
  let method = extra.method;
  let pathName = extra.path;
  let query = extra.query;
  let reqHeaders = extra.reqHeaders;
  if (reqFile) {
    if (extra.flatReqBody !== undefined) {
      // 扁平格式：请求体原样
      bodies.req = { kind: "json", data: extra.flatReqBody };
    } else {
      const meta = parseReqMeta(fs.readFileSync(reqFile, "utf-8"));
      if (meta.rawBody) {
        bodies.req = { kind: "bin", data: Buffer.from(meta.rawBody, "base64") };
      } else if (meta.body !== undefined) {
        bodies.req = { kind: "json", data: meta.body };
      }
      if (!pathName && meta.url) {
        pathName = meta.url.split("?")[0];
        query = meta.url.includes("?") ? meta.url.split("?")[1] : undefined;
      }
      if (!pathName && meta.cgi) pathName = meta.cgi;
      if (!method && meta.method) method = meta.method;
      if (!reqHeaders && meta.headers) reqHeaders = meta.headers as Record<string, unknown>;
    }
  }
  await captureManager.addRecord(
    {
      sessionId,
      ts: fileTs(resFile, path.basename(resFile)),
      method: method ?? null,
      path: pathName,
      query,
      status: null,
      source,
      reqHeaders,
      note: `旧格式迁移: ${metaPath}`,
    },
    bodies,
  );
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");
  const keep = args.includes("--keep");
  const stats: MergeStats = { pairs: 0, resOnly: 0, reqOnly: 0, gateway: 0, bytes: 0, skipped: 0, failed: 0, unrecognized: [] };

  if (!fs.existsSync(path.join(TMP, "arkhub-gateway")) && !fs.existsSync(TMP)) {
    logger.warn("migrate", "tmp/ 目录不存在，无需迁移");
    return;
  }

  if (!dryRun) {
    await captureManager.init();
  }

  let sessionId: string | null = null;
  if (!dryRun) {
    const s = await captureManager.startSession(
      `旧格式迁移 ${new Date().toISOString().slice(0, 10)}`,
      "private",
      "脚本 scripts/migrate-capture-legacy.ts 合并的旧格式抓包",
    );
    sessionId = s.id;
    logger.info("migrate", `新建迁移会话「${s.name}」(${s.id})`);
  }

  /* ---------- 1+3. 记录器目录格式（含 official） ---------- */
  const consumedMirrors = new Set<string>(); // 已合并的 request_* 镜像文件（防 req-only 二次处理）
  const rootDirs = fs.existsSync(TMP)
    ? fs.readdirSync(TMP, { withFileTypes: true }).filter((d) => d.isDirectory() && !d.name.startsWith("request_") && !SKIP_DIRS.has(d.name))
    : [];

  for (const ent of rootDirs) {
    const module = ent.name;
    const root = path.join(TMP, module);
    const walk = async (dir: string): Promise<void> => {
      let files: fs.Dirent[] = [];
      try {
        files = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const f of files) {
        const fp = path.join(dir, f.name);
        if (f.isDirectory()) {
          await walk(fp);
          continue;
        }
        if (!f.name.endsWith(".json")) continue;
        const rel = path.relative(TMP, fp).split(path.sep).join("/");
        const rest = rel.slice(module.length + 1); // endpoint.../filename
        const mirror = path.join(TMP, `request_${module}`, rest);
        const hasMirror = fs.existsSync(mirror);
        const relMirror = hasMirror ? `request_${module}/${rest}` : null;
        const source = inferSource(module, hasMirror ? parseReqMeta(fs.readFileSync(mirror, "utf-8")) : {});
        try {
          if (dryRun) {
            stats.bytes += fs.statSync(fp).size + (hasMirror ? fs.statSync(mirror).size : 0);
            if (hasMirror) stats.pairs++; else stats.resOnly++;
            if (hasMirror) consumedMirrors.add(relMirror!);
            continue;
          }
          await mergeHttpRecord(sessionId!, fp, hasMirror ? mirror : null, source, rel, {});
          stats.bytes += fs.statSync(fp).size + (hasMirror ? fs.statSync(mirror).size : 0);
          if (hasMirror) {
            stats.pairs++;
            consumedMirrors.add(relMirror!);
          } else {
            stats.resOnly++;
          }
          // 删除源文件（默认）
          if (!keep) {
            fs.rmSync(fp, { force: true });
            if (hasMirror) fs.rmSync(mirror, { force: true });
          }
        } catch (e) {
          stats.failed++;
          logger.warn("migrate", `合并失败 ${rel}: ${(e as Error).message}`);
        }
      }
    };
    await walk(root);
  }

  /* ---------- 2. 顶层扁平旧格式 ---------- */
  const topFiles = fs.existsSync(TMP)
    ? fs.readdirSync(TMP).filter((n) => n.endsWith(".json") && !n.startsWith("request_"))
    : [];
  // 按 base+命名风格 分组，同组内按 id 建档（旧代理 seq 偏移：req{n} ↔ res{n-1}）
  interface FlatGroup {
    req: Map<string, string>;
    res: Map<string, string>;
    bare: string | null;
  }
  const flatGroups = new Map<string, FlatGroup>();
  for (const name of topFiles) {
    const p = parseFlat(name);
    if (!p) continue;
    const key = `${p.module}_${p.endpoint}::${p.style}`;
    const g = flatGroups.get(key) ?? { req: new Map(), res: new Map(), bare: null };
    if (p.kind === "req") g.req.set(p.id ?? "0", name);
    else if (p.kind === "res") g.res.set(p.id ?? "0", name);
    else g.bare = name;
    flatGroups.set(key, g);
  }
  for (const [key, g] of flatGroups) {
    const usedReq = new Set<string>();
    const usedRes = new Set<string>();
    // 成对：req{n} ↔ res{n-1}（旧代理计数偏移），缺省回退同 id
    for (const [id, reqName] of g.req) {
      const resId = String(Number(id) - 1);
      const resName = g.res.get(resId) ?? g.res.get(id);
      if (!resName) continue;
      const p = parseFlat(reqName)!;
      const resPath = path.join(TMP, resName);
      const reqPath = path.join(TMP, reqName);
      try {
        if (dryRun) {
          stats.bytes += fs.statSync(resPath).size + fs.statSync(reqPath).size;
          stats.pairs++;
          continue;
        }
        await mergeHttpRecord(
          sessionId!,
          resPath,
          reqPath,
          "harness",
          `${reqName} / ${resName}`,
          { path: `/${p.module}/${p.endpoint}`, flatReqBody: fs.readFileSync(reqPath, "utf-8") },
        );
        stats.bytes += fs.statSync(resPath).size + fs.statSync(reqPath).size;
        stats.pairs++;
        usedReq.add(id);
        usedRes.add(resId);
        if (!keep) {
          fs.rmSync(resPath, { force: true });
          fs.rmSync(reqPath, { force: true });
        }
      } catch (e) {
        stats.failed++;
        logger.warn("migrate", `合并失败 ${reqName}/${resName}: ${(e as Error).message}`);
      }
    }
    // 剩余响应（含裸文件）
    for (const [id, resName] of g.res) {
      if (usedRes.has(id)) continue;
      const p = parseFlat(resName)!;
      const resPath = path.join(TMP, resName);
      try {
        if (dryRun) {
          stats.bytes += fs.statSync(resPath).size;
          stats.resOnly++;
          continue;
        }
        await mergeHttpRecord(sessionId!, resPath, null, "harness", resName, {
          path: `/${p.module}/${p.endpoint}`,
        });
        stats.bytes += fs.statSync(resPath).size;
        stats.resOnly++;
        if (!keep) fs.rmSync(resPath, { force: true });
      } catch (e) {
        stats.failed++;
        logger.warn("migrate", `合并失败 ${resName}: ${(e as Error).message}`);
      }
    }
    // 剩余请求
    for (const [id, reqName] of g.req) {
      if (usedReq.has(id)) continue;
      const p = parseFlat(reqName)!;
      const reqPath = path.join(TMP, reqName);
      try {
        if (dryRun) {
          stats.bytes += fs.statSync(reqPath).size;
          stats.reqOnly++;
          continue;
        }
        await captureManager.addRecord(
          {
            sessionId,
            ts: fileTs(reqPath, reqName),
            method: null,
            path: `/${p.module}/${p.endpoint}`,
            query: undefined,
            status: null,
            source: "harness",
            note: `旧格式迁移: ${reqName}（仅请求）`,
          },
          { req: { kind: "json", data: fs.readFileSync(reqPath, "utf-8") } },
        );
        stats.bytes += fs.statSync(reqPath).size;
        stats.reqOnly++;
        if (!keep) fs.rmSync(reqPath, { force: true });
      } catch (e) {
        stats.failed++;
        logger.warn("migrate", `合并失败 ${reqName}: ${(e as Error).message}`);
      }
    }
    if (g.bare) {
      const p = parseFlat(g.bare)!;
      const resPath = path.join(TMP, g.bare);
      try {
        if (dryRun) {
          stats.bytes += fs.statSync(resPath).size;
          stats.resOnly++;
          continue;
        }
        await mergeHttpRecord(sessionId!, resPath, null, "harness", g.bare, {
          path: `/${p.module}/${p.endpoint}`,
        });
        stats.bytes += fs.statSync(resPath).size;
        stats.resOnly++;
        if (!keep) fs.rmSync(resPath, { force: true });
      } catch (e) {
        stats.failed++;
        logger.warn("migrate", `合并失败 ${g.bare}: ${(e as Error).message}`);
      }
    }
  }
  // 顶层未识别文件（含无下划线旧格式）
  for (const name of topFiles) {
    if (!parseFlat(name)) {
      if (!SKIP_TOP_FILES.test(name) && !/^request_/.test(name)) {
        stats.unrecognized.push(name);
      }
    }
  }

  /* ---------- 4. arkhub 网关连接 ---------- */
  const gwRoot = path.join(TMP, "arkhub-gateway");
  const gwDirs = new Set<string>();
  if (fs.existsSync(gwRoot)) {
    for (const name of fs.readdirSync(gwRoot)) {
      if (fs.statSync(path.join(gwRoot, name)).isDirectory()) gwDirs.add(name);
    }
  }
  // 已移动但缺索引的记录目录（上次运行移动后 commit 失败的补录）
  const recRoot = path.join(CAPTURE_DIR, "records");
  if (fs.existsSync(recRoot)) {
    for (const name of fs.readdirSync(recRoot)) {
      const dir = path.join(recRoot, name);
      if (!fs.statSync(dir).isDirectory()) continue;
      const hasStream = fs.existsSync(path.join(dir, "up.bin")) || fs.existsSync(path.join(dir, "down.bin"));
      if (hasStream) gwDirs.add(name);
    }
  }
  for (const name of [...gwDirs].sort()) {
    const src = path.join(gwRoot, name);
    const target = path.join(recRoot, name);
    const inPlace = fs.existsSync(src) && fs.statSync(src).isDirectory();
    const dir = inPlace ? src : target;
    const hasStream = fs.existsSync(path.join(dir, "up.bin")) || fs.existsSync(path.join(dir, "down.bin"));
    if (!hasStream) continue;
    try {
      if (dryRun) {
        stats.gateway++;
        stats.bytes += fs.readdirSync(dir).reduce((s, f) => s + fs.statSync(path.join(dir, f)).size, 0);
        continue;
      }
      await captureManager.ensureInit();
      // 已在库（rid 已存在）→ 跳过
      if (await captureManager.getRecord(name)) {
        logger.info("migrate", `网关连接 ${name} 已在索引库（跳过）`);
        continue;
      }
      if (inPlace) {
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.renameSync(src, target); // 移动整个连接目录
      }
      // meta.json 可能缺失（历史中断写入）——容错为 {}
      let meta: Record<string, unknown> = {};
      try {
        meta = JSON.parse(fs.readFileSync(path.join(target, "meta.json"), "utf-8"));
      } catch {
        logger.warn("migrate", `网关连接 ${name} 缺 meta.json（按文件补齐）`);
      }
      const startedAt = Date.parse(String(meta.timestamp ?? "")) || fs.statSync(target).mtimeMs;
      const upSize = fs.existsSync(path.join(target, "up.bin")) ? fs.statSync(path.join(target, "up.bin")).size : 0;
      const downSize = fs.existsSync(path.join(target, "down.bin")) ? fs.statSync(path.join(target, "down.bin")).size : 0;
      await captureManager.commitRecord(
        name,
        {
          sessionId,
          ts: startedAt,
          path: "/arkhub/gateway",
          source: "gateway",
          direction: "gateway-bidi",
          status: null,
          reqSize: (meta.upBytes as number) ?? upSize,
          resSize: (meta.downBytes as number) ?? downSize,
          note: `旧格式迁移: arkhub-gateway/${name}`,
        },
        target,
        {
          targetAddr: meta.targetAddr,
          clientAddr: meta.clientAddr,
          upBytes: meta.upBytes,
          downBytes: meta.downBytes,
          reason: meta.reason,
        },
      );
      stats.gateway++;
      stats.bytes += fs.readdirSync(target).reduce((s, f) => s + fs.statSync(path.join(target, f)).size, 0);
    } catch (e) {
      stats.failed++;
      logger.warn("migrate", `网关连接 ${name} 迁移失败: ${(e as Error).message}`);
    }
  }

  /* ---------- 5. request_* 孤儿请求（无对应响应） ---------- */
  if (!dryRun) {
    for (const ent of fs.readdirSync(TMP, { withFileTypes: true }).filter((d) => d.isDirectory() && d.name.startsWith("request_"))) {
      const module = ent.name.slice("request_".length);
      const walk = async (dir: string): Promise<void> => {
        let files: fs.Dirent[] = [];
        try {
          files = fs.readdirSync(dir, { withFileTypes: true });
        } catch {
          return;
        }
        for (const f of files) {
          const fp = path.join(dir, f.name);
          if (f.isDirectory()) {
            await walk(fp);
            continue;
          }
          if (!f.name.endsWith(".json")) continue;
          const rel = path.relative(TMP, fp).split(path.sep).join("/");
          if (consumedMirrors.has(rel)) continue;
          const meta = parseReqMeta(fs.readFileSync(fp, "utf-8"));
          const source = inferSource(module, meta);
          try {
            const bodies: { req?: { kind: "json" | "bin"; data: unknown } } = {};
            if (meta.rawBody) bodies.req = { kind: "bin", data: Buffer.from(meta.rawBody, "base64") };
            else if (meta.body !== undefined) bodies.req = { kind: "json", data: meta.body };
            await captureManager.addRecord(
              {
                sessionId,
                ts: fileTs(fp, f.name),
                method: meta.method ?? (module === "official" ? "POST" : null),
                path: meta.url ? meta.url.split("?")[0] : meta.cgi,
                query: meta.url && meta.url.includes("?") ? meta.url.split("?")[1] : undefined,
                status: null,
                source,
                reqHeaders: meta.headers as Record<string, unknown> | undefined,
                note: `旧格式迁移: ${rel}（仅请求）`,
              },
              bodies,
            );
            stats.reqOnly++;
            stats.bytes += fs.statSync(fp).size;
            if (!keep) fs.rmSync(fp, { force: true });
          } catch (e) {
            stats.failed++;
            logger.warn("migrate", `孤儿请求合并失败 ${rel}: ${(e as Error).message}`);
          }
        }
      };
      await walk(path.join(TMP, ent.name));
    }
  }

  /* ---------- 6. 清理空目录（默认；仅限抓包相关模块目录） ---------- */
  if (!dryRun && !keep) {
    const dirs: string[] = [];
    for (const ent of rootDirs) {
      const collect = (d: string): void => {
        for (const f of fs.readdirSync(d, { withFileTypes: true })) {
          if (f.isDirectory()) collect(path.join(d, f.name));
        }
        dirs.push(d);
      };
      collect(path.join(TMP, ent.name));
    }
    for (const ent of fs.readdirSync(TMP, { withFileTypes: true }).filter((d) => d.isDirectory() && d.name.startsWith("request_"))) {
      const collect = (d: string): void => {
        for (const f of fs.readdirSync(d, { withFileTypes: true })) {
          if (f.isDirectory()) collect(path.join(d, f.name));
        }
        dirs.push(d);
      };
      collect(path.join(TMP, ent.name));
    }
    dirs.sort((a, b) => b.length - a.length); // 深到浅
    let pruned = 0;
    for (const d of dirs) {
      try {
        fs.rmdirSync(d);
        pruned++;
      } catch {
        /* 非空目录保留 */
      }
    }
    if (fs.existsSync(gwRoot)) {
      try {
        fs.rmdirSync(gwRoot);
      } catch {
        /* 保留 */
      }
    }
    if (pruned > 0) logger.info("migrate", `已清理 ${pruned} 个空目录`);
  }

  /* ---------- 报告 ---------- */
  const mb = (stats.bytes / 1048576).toFixed(1);
  console.log("\n===== 旧抓包迁移报告 =====");
  console.log(`模式: ${dryRun ? "DRY-RUN（仅统计）" : keep ? "合并（保留旧文件）" : "合并 + 清理旧文件"}`);
  console.log(`成对记录: ${stats.pairs} | 仅响应: ${stats.resOnly} | 仅请求: ${stats.reqOnly} | 网关连接: ${stats.gateway}`);
  console.log(`合计记录: ${stats.pairs + stats.resOnly + stats.reqOnly + stats.gateway} | 迁移字节: ${mb} MB | 失败: ${stats.failed}`);
  if (stats.unrecognized.length) {
    console.log(`未识别顶层文件 ${stats.unrecognized.length} 个（保留，可人工处理）: ${stats.unrecognized.slice(0, 10).join(", ")}${stats.unrecognized.length > 10 ? " …" : ""}`);
  }
  if (dryRun) {
    console.log("（dry-run 未写入存储、未删除任何文件）");
  }
  logger.info("migrate", "迁移完成");
}

main().catch((e) => {
  logger.error("migrate", `迁移失败: ${(e as Error).stack ?? (e as Error).message}`);
  process.exit(1);
});
