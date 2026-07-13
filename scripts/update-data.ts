import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";

interface RepositoryConfig {
  name: string;
  url: string;
  localPath: string;
}

const REPOS: RepositoryConfig[] = [
  {
    name: "OpenArknightsFBS",
    url: "https://github.com/MooncellWiki/OpenArknightsFBS.git",
    localPath: path.join(__dirname, "../OpenArknightsFBS"),
  },
  {
    name: "ArknightsGameData",
    url: "https://github.com/Kengxxiao/ArknightsGameData.git",
    localPath: path.join(__dirname, "../ArknightsGameData"),
  },
];

const EXCEL_SOURCE_DIR = path.join(__dirname, "../ArknightsGameData/zh_CN/gamedata/excel");
const EXCEL_TARGET_DIR = path.join(__dirname, "../data/excel");

function log(message: string): void {
  console.log(`[update-data] ${message}`);
}

function logError(message: string): void {
  console.error(`[update-data][ERROR] ${message}`);
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
  return executeCommand("git pull origin main", repo.localPath);
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
  
  try {
    const files = fs.readdirSync(EXCEL_SOURCE_DIR);
    
    files.forEach((file) => {
      const sourcePath = path.join(EXCEL_SOURCE_DIR, file);
      const targetPath = path.join(EXCEL_TARGET_DIR, file);
      
      if (fs.statSync(sourcePath).isFile()) {
        fs.copyFileSync(sourcePath, targetPath);
        log(`复制文件: ${file}`);
      }
    });
    
    log(`共复制 ${files.length} 个文件`);
    return true;
  } catch (error) {
    logError(`复制文件失败: ${(error as Error).message}`);
    return false;
  }
}

function generateTypes(): boolean {
  log(`生成 TypeScript 类型...`);
  return executeCommand("ts-node scripts/generate-types.ts", path.join(__dirname, ".."));
}

export async function main(skipUpdate: boolean = false): Promise<number> {
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
  
  log("\n===== 数据更新完成 =====");
  return 0;
}

const args = process.argv.slice(2);
const skipUpdate = args.includes("--skip-update") || args.includes("-s");

main(skipUpdate).then((code) => {
  process.exit(code);
});