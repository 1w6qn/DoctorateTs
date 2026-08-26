/**
 * 危机合约赛季服务（Crisis Seasons）
 *
 * 从 router 层剥离出的数据查询服务：仅负责读取 data/crisis/ 与 data/crisisV2/
 * 目录下的赛季文件列表（纯数据访问，不依赖 express / 请求上下文）。
 *
 * 解耦目的（见解耦方案 admin→game 网关）：
 * - admin 后台曾直接 `import { listCrisisSeasons } from "@game/router/crisis"`，
 *   形成「admin → game/router」跨层依赖；本服务将数据查询下沉到独立文件后，
 *   admin 与 game/router 均导入本服务，去除 admin 对 router 层的依赖。
 */
import { readdir } from "fs/promises";

/** 危机合约V1数据文件基础路径 */
export const CRISIS_JSON_BASE_PATH = "./data/crisis/";
/** 危机合约V2数据文件基础路径 */
export const CRISIS_V2_JSON_BASE_PATH = "./data/crisisV2/";

/** 可用赛季文件列表缓存（静态资源，进程生命周期内不变） */
let crisisSeasonsCache: { v1: string[]; v2: string[] } | null = null;

/**
 * 列出某目录下可用赛季文件名（去 .json 后缀；目录不存在返回空）
 * @param dir - 数据目录
 * @returns 赛季 id 列表
 */
async function listCrisisFiles(dir: string): Promise<string[]> {
  try {
    const names = await readdir(dir);
    return names.filter((n) => n.endsWith(".json")).map((n) => n.replace(/\.json$/, ""));
  } catch {
    return [];
  }
}

/**
 * 可用危机合约赛季列表
 * @returns { v1: data/crisis/*.json 文件列表, v2: data/crisisV2/*.json 文件列表 }
 */
export async function listCrisisSeasons(): Promise<{ v1: string[]; v2: string[] }> {
  if (!crisisSeasonsCache) {
    const [v1, v2] = await Promise.all([
      listCrisisFiles(CRISIS_JSON_BASE_PATH),
      listCrisisFiles(CRISIS_V2_JSON_BASE_PATH),
    ]);
    crisisSeasonsCache = { v1, v2 };
  }
  return crisisSeasonsCache;
}