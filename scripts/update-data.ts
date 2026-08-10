import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";
import { getResVersion, CONF_API } from "./official-api";

interface RepositoryConfig {
  name: string;
  url: string;
  localPath: string;
  /** git 默认分支（ArknightsGameData 为 master） */
  branch: string;
}

const REPOS: RepositoryConfig[] = [
  {
    name: "ArknightsGameData",
    url: "https://github.com/Kengxxiao/ArknightsGameData.git",
    localPath: path.join(__dirname, "../ArknightsGameData"),
    branch: "master",
  },
];

const EXCEL_SOURCE_DIR = path.join(__dirname, "../ArknightsGameData/zh_CN/gamedata/excel");
const EXCEL_TARGET_DIR = path.join(__dirname, "../data/excel");
const BATTLE_SOURCE_DIR = path.join(__dirname, "../ArknightsGameData/zh_CN/gamedata/battle");
const LEVELS_SOURCE_DIR = path.join(__dirname, "../ArknightsGameData/zh_CN/gamedata/levels/enemydata");
const GACHA_SOURCE_DIR = path.join(__dirname, "../data/gacha");
const GACHA_DETAIL_TARGET = path.join(__dirname, "../data/gacha_detail_table.json");

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

function isGitRepository(dir: string): boolean {
  return fs.existsSync(path.join(dir, ".git"));
}

function cloneRepository(repo: RepositoryConfig): boolean {
  log(`克隆仓库 ${repo.name}...`);
  const parentDir = path.dirname(repo.localPath);
  if (!fs.existsSync(parentDir)) {
    fs.mkdirSync(parentDir, { recursive: true });
  }
  return executeCommand(`git clone ${repo.url}`, parentDir);
}

function pullRepository(repo: RepositoryConfig): boolean {
  log(`更新仓库 ${repo.name}...`);
  // 修复：各仓库默认分支可能不是 main（ArknightsGameData=master），按仓库配置拉取
  // 原硬编码 `git pull origin main` 对 master 仓库报 "couldn't find remote ref main"
  return executeCommand(`git pull origin ${repo.branch}`, repo.localPath);
}

function updateRepository(repo: RepositoryConfig): boolean {
  if (isGitRepository(repo.localPath)) {
    return pullRepository(repo);
  } else {
    return cloneRepository(repo);
  }
}

function copyExcelFiles(): boolean {
  log(`复制游戏数据文件...`);
  
  if (!fs.existsSync(EXCEL_SOURCE_DIR)) {
    logError(`源目录不存在: ${EXCEL_SOURCE_DIR}`);
    return false;
  }
  
  if (!fs.existsSync(EXCEL_TARGET_DIR)) {
    fs.mkdirSync(EXCEL_TARGET_DIR, { recursive: true });
  }
  
  let copiedCount = 0;
  
  try {
    const files = fs.readdirSync(EXCEL_SOURCE_DIR);
    
    files.forEach((file) => {
      const sourcePath = path.join(EXCEL_SOURCE_DIR, file);
      const targetPath = path.join(EXCEL_TARGET_DIR, file);
      
      if (fs.statSync(sourcePath).isFile()) {
        fs.copyFileSync(sourcePath, targetPath);
        copiedCount++;
      }
    });
  } catch (error) {
    logError(`复制excel文件失败: ${(error as Error).message}`);
    return false;
  }
  
  try {
    if (fs.existsSync(BATTLE_SOURCE_DIR)) {
      const battleFiles = ["ep_breakbuff_table.json", "extra_battlelog_table.json"];
      for (const file of battleFiles) {
        const sourcePath = path.join(BATTLE_SOURCE_DIR, file);
        const targetPath = path.join(EXCEL_TARGET_DIR, file);
        if (fs.existsSync(sourcePath)) {
          fs.copyFileSync(sourcePath, targetPath);
          copiedCount++;
        }
      }
    }
  } catch (error) {
    logError(`复制battle文件失败: ${(error as Error).message}`);
  }
  
  try {
    if (fs.existsSync(LEVELS_SOURCE_DIR)) {
      const levelsFiles = ["enemy_database.json"];
      for (const file of levelsFiles) {
        const sourcePath = path.join(LEVELS_SOURCE_DIR, file);
        const targetPath = path.join(EXCEL_TARGET_DIR, file);
        if (fs.existsSync(sourcePath)) {
          fs.copyFileSync(sourcePath, targetPath);
          copiedCount++;
        }
      }
    }
  } catch (error) {
    logError(`复制levels文件失败: ${(error as Error).message}`);
  }
  
  log(`复制完成，总计 ${copiedCount} 个文件`);
  return true;
}

function generateTypes(): boolean {
  log(`生成 TypeScript 类型...`);
  // 类型生成已切换到 CS 反编译源（reference/com.hypergryph.arknights_2.7.61.cs），
  // 统一生成器同时产出 types-playerdata.ts 与 types_excel_gen.ts
  return executeCommand("npx tsx scripts/generate-types.ts", path.join(__dirname, ".."));
}

function mergeGachaFiles(): boolean {
  log(`合并 gacha 文件...`);
  
  if (!fs.existsSync(GACHA_SOURCE_DIR)) {
    logError(`gacha 源目录不存在: ${GACHA_SOURCE_DIR}`);
    return false;
  }
  
  const SKIP_FILES = ["gacha.json", "normalGacha.json", "DEFAULT.json"];
  const result: { [key: string]: any } = { details: {} };
  let mergedCount = 0;
  
  try {
    const files = fs.readdirSync(GACHA_SOURCE_DIR);
    
    for (const file of files) {
      if (!file.endsWith(".json")) continue;
      if (SKIP_FILES.includes(file)) continue;
      
      const sourcePath = path.join(GACHA_SOURCE_DIR, file);
      if (!fs.statSync(sourcePath).isFile()) continue;
      
      const content = fs.readFileSync(sourcePath, "utf-8");
      let data: any;
      try {
        data = JSON.parse(content);
      } catch {
        continue;
      }
      
      if (data.detailInfo) {
        const gachaId = file.replace(".json", "");
        result.details[gachaId] = data.detailInfo;
        mergedCount++;
      }
    }
    
    fs.writeFileSync(GACHA_DETAIL_TARGET, JSON.stringify(result, null, 4));
    log(`合并完成，总计 ${mergedCount} 个卡池`);
    return true;
  } catch (error) {
    logError(`合并 gacha 文件失败: ${(error as Error).message}`);
    return false;
  }
}

/**
 * 数据更新入口
 *
 * 三种模式：
 * - 默认（在线更新）：拉取远端仓库并同步数据
 * - `skipUpdate=true`：跳过仓库拉取，仅执行本地复制/生成/合并
 * - `offline=true`（完全离线）：不进行任何网络操作，仅校验本地数据完整性
 *
 * @param skipUpdate - 是否跳过仓库更新
 * @param offline - 是否完全离线模式（优先级最高）
 * @returns 0 表示成功，1 表示失败
 */
export async function main(skipUpdate: boolean = false, offline: boolean = false): Promise<number> {
  if (offline) {
    log("===== 完全离线模式 =====");
    log("跳过仓库更新 / 数据复制 / 类型生成 / gacha 合并，不进行任何网络操作");

    const missing = verifyLocalData();
    if (missing.length > 0) {
      logError(`本地数据不完整，缺少 ${missing.length} 个文件，无法离线启动：`);
      for (const file of missing) {
        logError(`  缺少: ${file}`);
      }
      logError("请先在有网络的环境执行 `npm run update` 完成数据初始化，");
      logError("或去掉 --offline 参数以在线模式启动（会自动回退到本地缓存）。");
      return 1;
    }

    log(`本地数据完整性校验通过（${REQUIRED_DATA_FILES.length} 个文件就绪）`);
    return 0;
  }

  log("===== 开始更新数据 =====");
  
  if (!skipUpdate) {
    for (const repo of REPOS) {
      log(`\n处理仓库: ${repo.name}`);
      if (!updateRepository(repo)) {
        logError(`仓库 ${repo.name} 更新失败，使用本地缓存数据`);
      }
    }
  } else {
    log("跳过仓库更新");
  }
  
  log("\n复制游戏数据...");
  if (!copyExcelFiles()) {
    logError("复制游戏数据失败");
    return 1;
  }
  
  log("\n生成类型文件...");
  if (!generateTypes()) {
    logError("生成类型文件失败");
    return 1;
  }
  
  log("\n合并 gacha 文件...");
  if (!mergeGachaFiles()) {
    logError("合并 gacha 文件失败");
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