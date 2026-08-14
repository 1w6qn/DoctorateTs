/**
 * 官服数据迁移 CLI
 *
 * 用法：pnpm run migrate:official -- --accounts <path> --template <uid>
 * - --accounts：账号文件路径（每行「手机号 密码」或「手机号\n密码」），默认 reference/checkin-master/accounts.txt
 * - --template：私服模板存档 uid（兜底字段来源），默认 1
 *
 * 流程：读账号 → 官服登录拉取数据 → 转换为私服存档 → 注册账号 + 写存档。
 */
import { readFileSync } from "fs";
import * as path from "path";
import { openDatabase } from "../app/db/database";
import { UserRepository } from "../app/db/user-repo";
import { syncPlayerData } from "./official-api";
import { convertOfficialData } from "./official-convert";
import { registerImportedUser } from "./official-register";

export interface MigrationResult {
  phone: string;
  uid?: string;
  nickName?: string;
  error?: string;
}

/**
 * 解析账号文件
 * 支持两种格式：
 * 1. 每行「手机号 密码」（空白分隔）
 * 2. 两行一组「手机号\n密码」（参考 accounts.txt：手机号、密码、备注各一行）
 * 忽略空行、注释行与非数字行（备注）。
 */
export function parseAccounts(content: string): { phone: string; pwd: string }[] {
  const accounts: { phone: string; pwd: string }[] = [];
  const lines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
  for (let i = 0; i < lines.length; i++) {
    const parts = lines[i].split(/\s+/);
    const isPhone = /^\d{6,}$/.test(parts[0]);
    if (!isPhone) continue; // 备注/非账号行
    if (parts.length >= 2) {
      // 同行「手机号 密码」
      accounts.push({ phone: parts[0], pwd: parts.slice(1).join(" ") });
    } else if (i + 1 < lines.length) {
      // 两行一组：下一行为密码（非数字行）
      const next = lines[i + 1];
      if (!/^\d{6,}$/.test(next)) {
        accounts.push({ phone: parts[0], pwd: next });
        i += 1; // 消费密码行（再下一行若是备注则下次循环跳过）
      }
    }
  }
  return accounts;
}

/**
 * 批量迁移
 * @param opts.accounts - 账号内容文本（每行「手机号 密码」或两行一组「手机号\n密码」；Dashboard 粘贴与 CLI 读文件共用）
 * @param opts.templateUid - 私服模板存档 uid（兜底字段来源）
 * @returns 每个账号的迁移结果（单个失败不中断其他账号）
 */
export async function runMigration(opts: {
  accounts: string;
  templateUid: string;
}): Promise<MigrationResult[]> {
  const accounts = parseAccounts(opts.accounts);

  // 读取模板存档（私服特有字段兜底）
  const templatePath = path.join(
    __dirname,
    "../data/user/databases",
    `${opts.templateUid}.json`,
  );
  const template = JSON.parse(readFileSync(templatePath, "utf8"));

  const results: MigrationResult[] = [];
  for (const { phone, pwd } of accounts) {
    try {
      const official = await syncPlayerData(phone, pwd);
      const newUid = String(
        Math.max(...Object.keys(readUsers()).map(Number).filter((n) => !Number.isNaN(n)), 0) + 1,
      );
      const converted = convertOfficialData(official, {
        newUid,
        template,
      });
      const reg = await registerImportedUser({
        phone,
        officialUid: official.status?.uid ?? "",
        convertedData: converted,
      });
      results.push({ phone, uid: reg.uid, nickName: reg.nickName });
      console.log(`[迁移成功] ${phone} → uid=${reg.uid} 昵称=${reg.nickName}`);
    } catch (err) {
      results.push({ phone, error: (err as Error).message });
      console.error(`[迁移失败] ${phone}: ${(err as Error).message}`);
    }
  }
  return results;
}

/** 读取现有用户（SQLite——users.json 已迁移为种子） */
function readUsers(): { [key: string]: any } {
  return new UserRepository(openDatabase()).getAll();
}

/** CLI 入口 */
if (require.main === module) {
  const args = process.argv.slice(2);
  const getArg = (name: string): string | undefined => {
    const idx = args.indexOf(name);
    return idx >= 0 ? args[idx + 1] : undefined;
  };
  const accountsPath =
    getArg("--accounts") ?? path.join(__dirname, "../reference/checkin-master/accounts.txt");
  const templateUid = getArg("--template") ?? "1";
  const content = readFileSync(accountsPath, "utf8");

  runMigration({ accounts: content, templateUid })
    .then((results) => {
      const ok = results.filter((r) => !r.error).length;
      console.log(`迁移完成：${ok}/${results.length} 成功`);
    })
    .catch((err) => {
      console.error("迁移失败:", err);
      process.exit(1);
    });
}
