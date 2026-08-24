/**
 * 资产自动补全模块（自定义活动切换的 asset 补全）
 *
 * 背景：私服 assets/{version}/redirect/ 按需缓存客户端请求的 bundle（downloadLocally=true）。
 * 切到过往活动（含旧危机合约赛季）后，客户端可能请求当前官方版本 CDN 上已下架/修剪的资源
 * （该 bundle 已从当前版本 hot_update_list 移除，当前版本 CDN 404）。本模块：
 *
 * 1. 请求路径补全（backfillFile）：当前版本下载失败 → 本地其它版本目录拷贝 / 官方 CDN
 *    历史 resVersion 探测下载，统一落盘到「官方版本目录」（assets/{官方版本}/redirect/，
 *    mod 签名版本与直连版本共享命中，见 asset.ts 的官方版本目录回退）。
 * 2. 活动预取（prewarmStageFiles / startBackfillTask）：按活动/全部关卡推导 bundle 扁平名，
 *    提前下载缺失文件（活动切换后自动触发，config.activities.autoBackfill）。
 *
 * 官方 CDN 保留历史版本（实测旧 resVersion 下 hot_update_list.json 与旧 bundle 均 200），
 * 故历史版本探测是补全的主要来源；本地其它版本目录拷贝作为离线兜底。
 */

import { readdir, readFile, copyFile, mkdir, writeFile } from "fs/promises";
import { join, dirname } from "path";
import config from "./config";
import excel from "@excel/excel";
import { exists } from "@utils/file";
import { logger } from "@utils/logger";

/** CDN 超时（毫秒）——对齐 asset.ts 的 CDN_TIMEOUT */
const CDN_TIMEOUT = 10000;
/** 单文件下载超时（毫秒）——大 bundle（几十 MB）放宽 */
const DOWNLOAD_TIMEOUT = CDN_TIMEOUT * 8;
/** 历史版本探测并发上限（避免打满连接） */
const PROBE_CONCURRENCY = 4;
/** 预取下载并发上限 */
const DOWNLOAD_CONCURRENCY = 6;
/** 单次预取最多处理文件数（防止后台任务长时间占用） */
const PREWARM_MAX_FILES = 400;

/** assets 根目录 */
const ASSETS_DIR = join(__dirname, "..", "assets");

/** 版本目录识别：形如 YYYY-MM-DD-HH-MM-SS_6hex（可选 -m 后缀的 mod 版本） */
const VERSION_DIR_RE = /^\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}_[0-9a-f]{6}(?:-m[0-9a-f]{6})?$/;

/**
 * 官方（无 mod 签名）资源版本：Windows 用 config.version.windows（对齐 asset.ts officialResVersion）
 * @param platform - 平台键（Windows/Android）
 */
export function officialVersion(platform: string): string {
  const win = (config.version as any).windows;
  return platform === "Windows" && win?.resVersion ? win.resVersion : config.version.resVersion;
}

/**
 * bundle 名 → 客户端扁平下载名（对齐 asset.ts loadMods 的 download 名规则：
 * / → _、# → __、去扩展名、补 .dat）
 * @param name - 官方 bundle 名（如 scenes/obt/rune/level_rune_04-01/level_rune_04-01.ab）
 * @returns 扁平下载名（如 scenes_obt_rune_level_rune_04-01_level_rune_04-01.dat）
 */
export function flattenBundleName(name: string): string {
  return name.replace(/\//g, "_").replace(/#/g, "__").split(".")[0] + ".dat";
}

/**
 * 已知资源版本列表（探测用）：assets/ 目录版本子目录 + config.assets.backfillVersions
 * + 当前官方版本。按版本日期倒序去重（新版本优先——最新有则无需翻旧）。
 * @param platform - 平台键
 * @returns 版本列表（不含 mod 签名版本——CDN 无 mod 版本；本地拷贝探测不受此限）
 */
export async function knownVersions(platform: string): Promise<string[]> {
  const set = new Set<string>();
  try {
    const entries = await readdir(ASSETS_DIR);
    for (const e of entries) {
      // 只收集官方版本（无 -m 后缀），mod 签名版本 CDN 不存在、跳过探测
      if (VERSION_DIR_RE.test(e) && !e.includes("-m")) set.add(e);
    }
  } catch {
    /* 目录不存在跳过 */
  }
  for (const v of config.assets.backfillVersions ?? []) {
    if (v && typeof v === "string" && !v.includes("-m")) set.add(v);
  }
  set.add(officialVersion(platform));
  // 日期部分 YYYY-MM-DD-HH-MM-SS（前 17 字符）倒序，新版本在前；同日期保持字典序稳定
  return [...set].sort((a, b) => {
    const da = a.slice(0, 17);
    const db = b.slice(0, 17);
    return da === db ? (a < b ? 1 : -1) : da < db ? 1 : -1;
  });
}

/** CDN 探测结果缓存（同 平台|版本|文件 只探测一次，避免重复 HEAD） */
const probeCache = new Map<string, boolean>();

/**
 * 探测官方 CDN 上某版本是否存在该文件
 * @param platform - 平台键
 * @param version  - resVersion
 * @param fileName - 文件名（扁平下载名）
 * @returns 是否存在（200）；网络错误视为不存在
 */
async function cdnHas(platform: string, version: string, fileName: string): Promise<boolean> {
  const key = `${platform}|${version}|${fileName}`;
  const cached = probeCache.get(key);
  if (cached !== undefined) return cached;
  try {
    const r = await fetch(
      `https://ak.hycdn.cn/assetbundle/official/${platform}/assets/${version}/${fileName}`,
      { method: "HEAD", signal: AbortSignal.timeout(CDN_TIMEOUT) },
    );
    const ok = r.ok || r.status === 206;
    probeCache.set(key, ok);
    return ok;
  } catch {
    probeCache.set(key, false);
    return false;
  }
}

/**
 * 从 CDN 下载文件并落盘
 * @param platform - 平台键
 * @param version  - resVersion
 * @param fileName - 文件名
 * @param target   - 目标路径（自动建目录）
 * @returns 是否成功
 */
async function downloadCdn(platform: string, version: string, fileName: string, target: string): Promise<boolean> {
  try {
    const r = await fetch(
      `https://ak.hycdn.cn/assetbundle/official/${platform}/assets/${version}/${fileName}`,
      { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT) },
    );
    if (!r.ok) return false;
    const buf = Buffer.from(await r.arrayBuffer());
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, buf);
    return true;
  } catch (err) {
    logger.warn("AssetBackfill", `CDN 下载失败 ${version}/${fileName}: ${(err as Error).message}`);
    return false;
  }
}

/** 单目标路径的单飞队列（并发请求同一文件时合并） */
const inflight = new Map<string, Promise<boolean>>();

/**
 * 补全单个缺失文件（请求路径自动补全入口）
 *
 * 策略：① 本地其它版本目录拷贝（含 redirect 子目录，离线兜底）→
 * ② 官方 CDN 历史版本探测下载（新→旧，HEAD 快查 + GET 下载）→ ③ 失败返回 false。
 *
 * @param platform   - 平台键（Windows/Android）
 * @param fileName   - 客户端请求的文件名（扁平下载名）
 * @param targetPath - 目标落盘路径（建议官方版本目录 assets/{官方版本}/redirect/，供各签名版本共享）
 * @returns 是否补全成功
 */
export async function backfillFile(
  platform: string,
  fileName: string,
  targetPath: string,
): Promise<boolean> {
  const key = `${platform}|${targetPath}`;
  const existing = inflight.get(key);
  if (existing) return existing;
  const p = doBackfill(platform, fileName, targetPath);
  inflight.set(key, p);
  try {
    return await p;
  } finally {
    inflight.delete(key);
  }
}

async function doBackfill(platform: string, fileName: string, targetPath: string): Promise<boolean> {
  // ① 本地其它版本目录拷贝（离线优先，零网络开销）
  const versions = await knownVersions(platform);
  for (const v of versions) {
    for (const sub of ["", "redirect"]) {
      const src = join(ASSETS_DIR, v, sub, fileName);
      if (!(await exists(src))) continue;
      try {
        await mkdir(dirname(targetPath), { recursive: true });
        await copyFile(src, targetPath);
        logger.info("AssetBackfill", `本地拷贝 ${v}/${fileName} → ${targetPath}`);
        return true;
      } catch (err) {
        logger.warn("AssetBackfill", `本地拷贝失败 ${src}: ${(err as Error).message}`);
      }
    }
  }
  // ② 官方 CDN 历史版本探测（新→旧；当前官方版本已在 knownVersions 内）
  const targets = versions.filter((v) => v !== officialVersion(platform));
  const hit: string[] = [];
  // 分批并发探测，命中的版本记录后统一按顺序下载（探测为 HEAD 快查）
  for (let i = 0; i < targets.length; i += PROBE_CONCURRENCY) {
    const batch = targets.slice(i, i + PROBE_CONCURRENCY);
    const results = await Promise.all(batch.map((v) => cdnHas(platform, v, fileName)));
    batch.forEach((v, idx) => {
      if (results[idx]) hit.push(v);
    });
    if (hit.length > 0) break;
  }
  for (const v of hit) {
    if (await downloadCdn(platform, v, fileName, targetPath)) {
      logger.info("AssetBackfill", `CDN 历史版本 ${v} 补全 ${fileName}`);
      return true;
    }
  }
  logger.debug("AssetBackfill", `补全失败 ${fileName}（探测 ${targets.length} 个版本均无）`);
  return false;
}

// ==================== 活动资产预取（关卡 bundle 推导）====================

/**
 * 由关卡 levelId 推导其场景 bundle 扁平下载名列表
 *
 * 官方命名规则（实测）：levelId "Obt/Rune/level_rune_04-01" →
 * bundle "scenes/obt/rune/level_rune_04-01/level_rune_04-01.ab"（小写化 + 最后一段）
 * 与灯光数据 "scenes/{...}/{last}/lightingdata.ab"；客户端下载名 = 扁平化 + .dat。
 * @param levelId - 关卡 levelId（如 "Obt/Rune/level_rune_04-01"）
 * @returns 扁平下载名列表（去重；levelId 非法返回空）
 */
export function levelBundleCandidates(levelId: string): string[] {
  if (!levelId || typeof levelId !== "string" || !levelId.trim()) return [];
  const lower = levelId.toLowerCase().trim();
  const last = lower.split("/").pop() ?? "";
  if (!last) return [];
  const names = new Set<string>([flattenBundleName(`scenes/${lower}/${last}.ab`)]);
  // 灯光数据 bundle（scenes/.../{last}/lightingdata.ab）
  names.add(flattenBundleName(`scenes/${lower}/${last}/lightingdata.ab`));
  return [...names];
}

/**
 * 由关卡 id 推导其场景 bundle 扁平下载名列表（经 StageTable 查 levelId）
 * @param stageId - 关卡 id（StageTable.stages 键；危机关卡不在 StageTable 时返回空）
 * @returns 扁平下载名列表
 */
export async function stageBundleCandidates(stageId: string): Promise<string[]> {
  const stage = excel.StageTable?.stages?.[stageId];
  if (!stage?.levelId) return [];
  return levelBundleCandidates(String(stage.levelId));
}

/** 预取统计 */
export interface BackfillStats {
  /** 目标：all | 活动 id | crisis 赛季 id */
  target: string;
  /** 平台键 */
  platform: string;
  /** 候选文件总数 */
  candidates: number;
  /** 本地已存在（跳过） */
  local: number;
  /** 成功补全（下载/拷贝） */
  downloaded: number;
  /** 补全失败 */
  failed: number;
  /** 成功补全的文件名（扁平下载名） */
  files: string[];
}

/**
 * 预取一组文件的缺失资产（本地已有跳过；缺失走 backfillFile 全套逻辑）
 * @param platform    - 平台键
 * @param files       - 扁平下载名列表（去重后处理）
 * @param max         - 单次最多处理文件数（缺省 PREWARM_MAX_FILES，0=不限制）
 * @param targetLabel - 统计里展示的目标标识（缺省 "prewarm"）
 * @returns 统计结果
 */
export async function prewarmFiles(
  platform: string,
  files: string[],
  max = PREWARM_MAX_FILES,
  targetLabel = "prewarm",
): Promise<BackfillStats> {
  const stats: BackfillStats = {
    target: targetLabel,
    platform,
    candidates: 0,
    local: 0,
    downloaded: 0,
    failed: 0,
    files: [],
  };
  const canonicalDir = join(ASSETS_DIR, officialVersion(platform), "redirect");
  const unique = [...new Set(files.filter(Boolean))];
  const todo = max > 0 ? unique.slice(0, max) : unique;
  stats.candidates = todo.length;
  logger.info("AssetBackfill", `[${platform}] 预取 ${todo.length} 个文件（目标 ${stats.target}）`);

  let idx = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = idx++;
      if (i >= todo.length) return;
      const file = todo[i];
      const target = join(canonicalDir, file);
      if (await exists(target)) {
        stats.local++;
        continue;
      }
      if (await backfillFile(platform, file, target)) {
        stats.downloaded++;
        stats.files.push(file);
      } else {
        stats.failed++;
      }
    }
  };
  await Promise.all(Array.from({ length: DOWNLOAD_CONCURRENCY }, () => worker()));
  logger.info(
    "AssetBackfill",
    `[${platform}] 预取完成：候选 ${stats.candidates}、已有 ${stats.local}、补全 ${stats.downloaded}、失败 ${stats.failed}`,
  );
  return stats;
}

// ==================== 活动 → 关卡收集 ====================

/** 活动关卡引用（危机关卡不在 StageTable，levelId 直接来自赛季数据） */
export interface ActivityLevelRef {
  /** 关卡 id */
  stageId: string;
  /** 关卡 levelId（如 Obt/Rune/level_rune_04-01） */
  levelId: string;
}

/**
 * 从危机合约赛季数据文件提取关卡引用（合约关卡是活动专属，配置在 data/crisis*.json）
 * @param seasonId - 赛季 id（data/crisis 或 data/crisisV2 下文件名）
 * @param v2       - 是否 V2 赛季
 * @returns 关卡引用列表
 */
export async function crisisSeasonLevelRefs(seasonId: string, v2: boolean): Promise<ActivityLevelRef[]> {
  try {
    const data = JSON.parse(
      await readFile(
        join(process.cwd(), "data", v2 ? "crisisV2" : "crisis", `${seasonId}.json`),
        "utf-8",
      ),
    ) as Record<string, any>;
    const out: ActivityLevelRef[] = [];
    const push = (stage: any): void => {
      if (stage?.stageId) {
        out.push({ stageId: stage.stageId, levelId: String(stage?.levelId ?? "") });
      }
    };
    if (v2) {
      for (const stage of Object.values(data?.info?.mapStageDataMap ?? {}) as any[]) push(stage);
    } else {
      for (const season of data?.data?.seasonInfo ?? []) {
        for (const stage of Object.values(season?.stages ?? {}) as any[]) push(stage);
      }
    }
    return out;
  } catch (err) {
    logger.warn("AssetBackfill", `读取危机赛季 ${seasonId} 失败: ${(err as Error).message}`);
    return [];
  }
}

/**
 * 递归扫描活动详情对象，提取形如 level_* / stage_* 的字符串（活动关卡引用）
 * @param obj - 活动详情对象（excel.ActivityTable.activity[type][actId]）
 * @returns 疑似关卡 id 集合
 */
function scanStageIds(obj: unknown, out: Set<string>): void {
  if (!obj || typeof obj !== "object") return;
  if (Array.isArray(obj)) {
    for (const item of obj) scanStageIds(item, out);
    return;
  }
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === "string") {
      if (/^(level_|stage_)/.test(v)) out.add(v);
    } else if (typeof v === "object" && v !== null) {
      // zone 键（如 act11d7_zone1）→ zoneId 字段；zone 引用由调用方经 StageTable 扩展
      if (k === "zoneId" && typeof v === "string" && /_zone/.test(v)) {
        out.add(`zone:${v}`);
      }
      scanStageIds(v, out);
    }
  }
}

/** activity 字典键：首字母小写（与 unlockActivity 对齐；大小写/下划线不敏感匹配） */
function activityDictKey(type: string): string | undefined {
  const norm = type.replace(/_/g, "").toLowerCase();
  const dict = (excel.ActivityTable?.activity ?? {}) as Record<string, unknown>;
  return Object.keys(dict).find((k) => k.replace(/_/g, "").toLowerCase() === norm);
}

/** 经 StageTable 按 zoneId 反查关卡 id */
function stageIdsByZone(zoneId: string, out: Set<string>): void {
  for (const stage of Object.values(excel.StageTable?.stages ?? {}) as any[]) {
    if (stage?.zoneId === zoneId && stage?.stageId) out.add(stage.stageId);
  }
}

/**
 * 收集某活动的关卡引用（stageId + levelId）
 *
 * 来源：
 * 1. 危机合约赛季（ccN / data/crisisV2 文件名）：直接读赛季数据（含 levelId）；
 * 2. 通用活动：zoneToActivity 反查活动 zone → StageTable 关卡，叠加活动详情递归扫描
 *    （`level_*` / `stage_*` 直接引用与 zoneId 字段），经 StageTable 解析 levelId。
 * @param activityId - 活动 id（basicInfo.id 或危机赛季 id）
 * @returns 关卡引用列表（去重；无 levelId 的引用剔除）
 */
export async function collectActivityLevelRefs(activityId: string): Promise<ActivityLevelRef[]> {
  // 1) 危机合约赛季（data/crisis/ccN.json / data/crisisV2/*.json 文件名直查）
  const seasons = await (await import("./game/crisis-seasons")).listCrisisSeasons();
  if (seasons.v1.includes(activityId)) {
    return crisisSeasonLevelRefs(activityId, false);
  }
  if (seasons.v2.includes(activityId)) {
    return crisisSeasonLevelRefs(activityId, true);
  }

  // 2) 通用活动：zoneToActivity 反查（{ zoneId: activityId }）+ 详情递归扫描
  const stageIds = new Set<string>();
  const zta = (excel.ActivityTable?.zoneToActivity ?? {}) as Record<string, string>;
  for (const [zoneId, act] of Object.entries(zta)) {
    if (act === activityId) stageIdsByZone(zoneId, stageIds);
  }
  const info = (excel.ActivityTable?.basicInfo ?? {})[activityId];
  if (info) {
    const dict = (excel.ActivityTable?.activity ?? {}) as Record<string, any>;
    const detail = dict[activityDictKey(info.type) ?? info.type]?.[activityId];
    if (detail) {
      const refs = new Set<string>();
      scanStageIds(detail, refs);
      for (const ref of refs) {
        if (ref.startsWith("zone:")) stageIdsByZone(ref.slice(5), stageIds);
        else stageIds.add(ref);
      }
    }
  }
  // 3) 解析 levelId（无 levelId 的引用剔除）
  const out: ActivityLevelRef[] = [];
  for (const stageId of stageIds) {
    const levelId = (excel.StageTable?.stages as Record<string, any>)?.[stageId]?.levelId;
    if (levelId) out.push({ stageId, levelId: String(levelId) });
  }
  return out;
}

// ==================== 后台任务 ====================

/** 后台补全任务 */
export interface BackfillTask {
  /** 任务 id */
  id: string;
  /** 目标：all | 活动 id | crisis 赛季 id */
  target: string;
  /** 平台键 */
  platform: string;
  /** running | done | error */
  status: "running" | "done" | "error";
  /** 统计（运行中为部分结果） */
  stats: BackfillStats | null;
  /** 错误信息 */
  error?: string;
  /** 开始时间（秒） */
  startedAt: number;
  /** 结束时间（秒） */
  finishedAt?: number;
}

const tasks = new Map<string, BackfillTask>();
let taskSeq = 0;

/**
 * 启动后台补全任务（不阻塞调用方；进度经 getBackfillTask/listBackfillTasks 查询）
 * @param target   - all（全部关卡）| 活动 id | 危机赛季 id
 * @param platform - 平台键（缺省 Android）
 * @returns 任务对象（status=running）
 */
export async function startBackfillTask(target: string, platform = "Android"): Promise<BackfillTask> {
  const id = `bf-${Date.now()}-${taskSeq++}`;
  const task: BackfillTask = {
    id,
    target,
    platform,
    status: "running",
    stats: null,
    startedAt: Math.floor(Date.now() / 1000),
  };
  tasks.set(id, task);
  void (async () => {
    try {
      // 收集活动关卡引用（含 levelId；危机关卡不在 StageTable）
      const refs =
        target === "all"
          ? Object.keys(excel.StageTable?.stages ?? {}).map((stageId) => ({
              stageId,
              levelId: String(
                (excel.StageTable?.stages as Record<string, any>)?.[stageId]?.levelId ?? "",
              ),
            }))
          : await collectActivityLevelRefs(target);
      // 关卡 levelId → bundle 扁平下载名（去重）
      const files = new Set<string>();
      for (const ref of refs) {
        if (ref.levelId) {
          for (const name of levelBundleCandidates(ref.levelId)) files.add(name);
        }
      }
      const stats = await prewarmFiles(platform, [...files], PREWARM_MAX_FILES, target);
      task.stats = stats;
      task.status = "done";
      task.finishedAt = Math.floor(Date.now() / 1000);
    } catch (err) {
      task.status = "error";
      task.error = (err as Error).message;
      task.finishedAt = Math.floor(Date.now() / 1000);
      logger.error("AssetBackfill", `后台补全任务 ${id} 失败: ${task.error}`);
    }
  })();
  return task;
}

/** 查询后台补全任务 */
export function getBackfillTask(id: string): BackfillTask | undefined {
  return tasks.get(id);
}

/** 最近后台补全任务列表（新→旧，最多 20 条） */
export function listBackfillTasks(): BackfillTask[] {
  return [...tasks.values()].sort((a, b) => b.startedAt - a.startedAt).slice(0, 20);
}

/**
 * 活动切换后自动补全入口（config.activities.autoBackfill !== false 且本地下载模式时生效）
 * @param target   - 活动 id / 危机赛季 id / all
 * @param platform - 平台键
 * @returns 任务或 null（未启用时）
 */
export async function autoBackfillAfterSwitch(target: string, platform: string): Promise<BackfillTask | null> {
  if (config.activities?.autoBackfill === false) {
    logger.info("AssetBackfill", `活动切换自动补全已关闭（activities.autoBackfill=false），跳过 ${target}`);
    return null;
  }
  if (!config.assets?.downloadLocally) {
    logger.info("AssetBackfill", `非本地下载模式（downloadLocally=false），跳过自动补全 ${target}`);
    return null;
  }
  if (config.assets?.downloadPeoxy) {
    logger.info("AssetBackfill", `代理转发模式（downloadPeoxy=true），无需本地补全，跳过 ${target}`);
    return null;
  }
  return startBackfillTask(target, platform);
}
