import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";
import { getResVersion, CONF_API } from "./official-api";

const EXCEL_TARGET_DIR = path.join(__dirname, "../data/excel");

/**
 * 完全离线模式启动所需的本地数据文件（相对项目根目录）。
 * 覆盖 excel.init()、ShopData.init()、AccountManager.init() 及 auth 模块加载的全部文件。
 */
const REQUIRED_DATA_FILES: string[] = [
  // 配置文件
  "data/config.json",
  "data/appConfig.json",
  // 用户数据
  "data/user/users.json",
  // Excel 数据表（excel.init() 加载）
  "data/excel/mission_table.json",
  "data/excel/battle_equip_table.json",
  "data/excel/building_data.json",
  "data/excel/character_table.json",
  "data/excel/gamedata_const.json",
  "data/excel/item_table.json",
  "data/excel/stage_table.json",
  "data/excel/handbook_info_table.json",
  "data/excel/checkin_table.json",
  "data/excel/story_review_meta_table.json",
  "data/excel/gacha_table.json",
  "data/excel/roguelike_topic_table.json",
  "data/excel/uniequip_table.json",
  "data/excel/favor_table.json",
  "data/excel/story_review_table.json",
  "data/excel/medal_table.json",
  "data/excel/char_meta_table.json",
  "data/excel/skin_table.json",
  "data/excel/open_server_table.json",
  "data/excel/retro_table.json",
  "data/excel/activity_table.json",
  // 修复：excel.init() 加载 ArkventTable 但离线校验遗漏该文件——缺失时 --offline 误报通过后启动即崩
  "data/excel/arkvent_table.json",
  "data/excel/campaign_table.json",
  "data/excel/chapter_table.json",
  "data/excel/char_master_table.json",
  "data/excel/char_patch_table.json",
  "data/excel/charword_table.json",
  "data/excel/charm_table.json",
  "data/excel/climb_tower_table.json",
  "data/excel/crisis_table.json",
  "data/excel/crisis_v2_table.json",
  "data/excel/display_meta_table.json",
  "data/excel/enemy_database.json",
  "data/excel/enemy_handbook_table.json",
  "data/excel/ep_breakbuff_table.json",
  "data/excel/extra_battlelog_table.json",
  "data/excel/handbook_team_table.json",
  "data/excel/hotupdate_meta_table.json",
  "data/excel/meta_ui_table.json",
  "data/excel/player_avatar_table.json",
  "data/excel/range_table.json",
  "data/excel/replicate_table.json",
  "data/excel/roguelike_table.json",
  "data/excel/sandbox_table.json",
  "data/excel/sandbox_perm_table.json",
  "data/excel/shop_client_table.json",
  "data/excel/skill_table.json",
  "data/excel/special_operator_table.json",
  "data/excel/story_table.json",
  "data/excel/uniequip_data.json",
  "data/excel/zone_table.json",
  "data/rlv2.json",
  "data/gacha_detail_table.json",
  // 商店数据（ShopData.init() 加载）
  "data/shop/LowGoodList.json",
  "data/shop/SkinGoodList.json",
  "data/shop/CashGoodList.json",
  "data/shop/HighGoodList.json",
  "data/shop/REPGoodList.json",
  "data/shop/LMTGSGoodList.json",
  "data/shop/EPGSGoodList.json",
  "data/shop/ClassicGoodList.json",
  "data/shop/ExtraGoodList.json",
  "data/shop/GPGoodList.json",
  "data/shop/FurniGoodList.json",
];

function log(message: string): void {
  console.log(`[update-data] ${message}`);
}

function logError(message: string): void {
  console.error(`[update-data][ERROR] ${message}`);
}

/**
 * 校验本地数据文件完整性（纯文件系统操作，不进行任何网络访问）。
 *
 * @param baseDir - 项目根目录，默认取当前工作目录
 * @returns 缺失文件的相对路径列表，空数组表示数据完整
 */
export function verifyLocalData(baseDir: string = process.cwd()): string[] {
  const missing = REQUIRED_DATA_FILES.filter(
    (file) => !fs.existsSync(path.join(baseDir, file)),
  );
  return missing;
}

function executeCommand(command: string, cwd: string): boolean {
  try {
    log(`执行命令: ${command}`);
    execSync(command, { cwd, stdio: "inherit" });
    return true;
  } catch (error) {
    logError(`命令执行失败: ${command}`);
    return false;
  }
}

/**
 * 官服热更管线生成 excel 数据（TS 实现，零 Python 依赖）：
 * 下载 bundle → UnityFS 解包 → FBO/AES 解码 → 服务端格式（camelCase + 枚举字符串）→ data/excel/
 */
function runOfficialExcelPipeline(): boolean {
  log(`运行官服热更 excel 管线...`);
  return executeCommand(
    "pnpm exec tsx scripts/official-excel.ts --download --decode --convert",
    path.join(__dirname, ".."),
  );
}

function generateTypes(): boolean {
  log(`生成 TypeScript 类型...`);
  // 类型生成已切换到 CS 反编译源（reference/com.hypergryph.arknights_2.7.61.cs），
  // 统一生成器同时产出 types-playerdata.ts 与 types_excel_gen.ts
  const csFile = path.join(__dirname, "../reference/com.hypergryph.arknights_2.7.61.cs");
  if (!fs.existsSync(csFile)) {
    // 新 clone 场景：reference/ 被 gitignore，类型文件已跟踪——跳过再生成而非失败
    // （excel 版本更新后类型可能滞后，但不阻断服务器运行）
    log(`跳过类型生成：缺少 ${csFile}（类型文件已随仓库跟踪；放回反编译源后可重新生成）`);
    return true;
  }
  return executeCommand("pnpm exec tsx scripts/generate-types.ts", path.join(__dirname, ".."));
}

/**
 * 数据更新入口
 *
 * 三种模式：
 * - 默认（在线更新）：官方热更管线生成 excel + 类型生成
 * - `skipUpdate=true`：跳过官服热更管线（excel 用本地缓存），仅执行类型生成
 * - `offline=true`（完全离线）：不进行任何网络操作，仅校验本地数据完整性
 *
 * 注：gacha 卡池详情（data/gacha_detail_table.json）已不在此管线合并生成
 * （data/gacha/ 源目录已移除）——由 admin `gacha sync` 从官服同步。
 *
 * @param skipUpdate - 是否跳过官服热更管线
 * @param offline - 是否完全离线模式（优先级最高）
 * @returns 0 表示成功，1 表示失败
 */
export async function main(skipUpdate: boolean = false, offline: boolean = false): Promise<number> {
  if (offline) {
    log("===== 完全离线模式 =====");
    log("跳过数据管线 / 类型生成，不进行任何网络操作");

    const missing = verifyLocalData();
    if (missing.length > 0) {
      logError(`本地数据不完整，缺少 ${missing.length} 个文件，无法离线启动：`);
      for (const file of missing) {
        logError(`  缺少: ${file}`);
      }
      logError("请先在有网络的环境执行 `pnpm run update` 完成数据初始化，");
      logError("或去掉 --offline 参数以在线模式启动（会自动回退到本地缓存）。");
      return 1;
    }

    log(`本地数据完整性校验通过（${REQUIRED_DATA_FILES.length} 个文件就绪）`);
    return 0;
  }

  log("===== 开始更新数据 =====");
  
  if (!skipUpdate) {
    log("\n官服热更 excel 管线（下载/解码/转换）...");
    if (!runOfficialExcelPipeline()) {
      logError("官服热更 excel 管线失败，使用本地缓存数据");
    }
  } else {
    log("跳过官服热更管线（使用本地 excel 缓存）");
  }
  
  log("\n生成类型文件...");
  if (!generateTypes()) {
    logError("生成类型文件失败");
    return 1;
  }

  log("\n同步最新游戏版本...");
  if (!(await syncGameVersion())) {
    logError("同步游戏版本失败，使用本地版本");
  }

  log("\n===== 数据更新完成 =====");
  return 0;
}

/**
 * 同步最新游戏版本与网络配置（参考 odpy tools/update_config.py）
 * - 版本：Android（默认）+ Windows（独立 resVersion——Windows 客户端资源路径用）
 * - 网络配置：拉取官服 network_config 的 funcVer，变化时旧 configs 复制到新 funcVer
 */
export async function syncGameVersion(): Promise<boolean> {
  try {
    const configPath = path.join(__dirname, "..", "data", "config.json");
    const configData = JSON.parse(fs.readFileSync(configPath, "utf8"));
    const old = `${configData.version?.clientVersion}/${configData.version?.resVersion}`;

    // TTL 缓存：1 小时内同步过且版本未变 → 跳过网络（启动提速）
    const TTL_MS = 60 * 60 * 1000;
    const lastSync = configData._lastVersionSyncTs ?? 0;
    if (Date.now() - lastSync < TTL_MS) {
      log(`版本同步 TTL 未过期（${Math.round((TTL_MS - (Date.now() - lastSync)) / 60000)} 分钟内已同步），跳过网络请求`);
      return true;
    }

    // 1. Android 版本（默认）
    const android = await getResVersion();

    // 2. Windows 版本（独立 resVersion）
    let windows: { clientVersion: string; resVersion: string } | null = null;
    try {
      const res = await fetch(`${CONF_API}/config/prod/official/Windows/version`);
      if (res.ok) {
        const data = await res.json();
        if (data?.resVersion && data?.clientVersion) {
          windows = { clientVersion: data.clientVersion, resVersion: data.resVersion };
        }
      }
    } catch {
      // Windows 版本获取失败不阻塞
    }

    // 3. funcVer 网络配置同步
    try {
      const ncRes = await fetch(`${CONF_API}/config/prod/official/network_config`);
      if (ncRes.ok) {
        const ncData = await ncRes.json();
        const content = JSON.parse(ncData.content);
        const funcVer: string | undefined = content.funcVer;
        if (funcVer && configData.NetworkConfig?.configs) {
          const configs = configData.NetworkConfig.configs;
          if (!configs[funcVer]) {
            const oldFuncVer = Object.keys(configs)[0];
            if (oldFuncVer) {
              configs[funcVer] = configs[oldFuncVer];
              delete configs[oldFuncVer];
            }
          }
          configData.NetworkConfig.funcVer = funcVer;
        }
      }
    } catch {
      // funcVer 同步失败不阻塞
    }

    // 写入（version.windows 为可选——Android 默认保持单 version 兼容）
    configData.version = {
      clientVersion: android.clientVersion,
      resVersion: android.resVersion,
    };
    if (windows) {
      configData.version.windows = windows;
    }
    configData._lastVersionSyncTs = Date.now(); // TTL 缓存标记
    fs.writeFileSync(configPath, JSON.stringify(configData, null, 2) + "\n");

    const next = `${android.clientVersion}/${android.resVersion}`;
    const winNext = windows ? ` + win:${windows.resVersion}` : "";
    if (old === next && !windows) {
      log(`游戏版本无变化（${next}${winNext}）`);
    } else {
      log(`游戏版本已更新: ${old} → ${next}${winNext}`);
    }
    return true;
  } catch (error) {
    logError(`同步游戏版本失败: ${(error as Error).message}`);
    return false;
  }
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const skipUpdate = args.includes("--skip-update") || args.includes("-s");
  const offline = args.includes("--offline") || args.includes("-o");

  main(skipUpdate, offline).then((code) => {
    process.exit(code);
  });
}