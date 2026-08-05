#!/usr/bin/env ts-node
/**
 * DoctorateTs 管理命令行工具
 *
 * 用法：
 *   npm run admin -- <command> [options]
 *
 * 命令：
 *   users list                      列出所有用户
 *   users info <uid>                查看用户详情
 *   users create <phone> <password> 创建新用户
 *   users grant <uid> <itemId> <count>  发放物品/资源
 *   mail send <uid> <subject> <content> [--items id:count,...]  发送邮件
 *   server status                   查看服务器状态
 *   config show                     查看配置
 *   config set <key> <value>        修改配置（如 offline、PORT、admin.token）
 *   help                            显示帮助
 *
 * 说明：CLI 直接操作本地数据，无需启动服务器，完全离线可用。
 */
import { enablePatches } from "immer";
import excel from "@excel/excel";
import { accountManager } from "@game/manager/AccountManger";
import { adminService } from "../app/admin/AdminService";
import config from "../app/config";
import { writeJson, readJsonSync } from "@utils/file";

/** 解析结果 */
export interface ParsedArgs {
  command: string;
  args: string[];
  flags: { [key: string]: string };
}

/** 解析命令行参数：<command> [args...] [--key value] */
export function parseArgs(argv: string[]): ParsedArgs {
  const args: string[] = [];
  const flags: { [key: string]: string } = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      flags[key] = argv[i + 1] ?? "true";
      i++;
    } else {
      args.push(a);
    }
  }
  return { command: args[0] ?? "", args: args.slice(1), flags };
}

/** 初始化游戏数据（excel + 账户），CLI 每次运行前调用 */
export async function cliInit(): Promise<void> {
  enablePatches();
  await excel.init();
  await accountManager.init();
}

/** 打印帮助 */
export function printHelp(): void {
  console.log(`DoctorateTs 管理命令行工具
用法: npm run admin -- <command> [options]

用户管理:
  users list                       列出所有用户
  users info <uid>                 查看用户详情
  users create <phone> <password>  创建新用户
  users grant <uid> <itemId> <count>  发放物品（4001=金币 5001=合成玉，以游戏为准）

邮件:
  mail send <uid> <subject> <content> [--items id:count,id:count]  发送系统邮件

服务器:
  server status                    查看服务器状态与数据文件

配置:
  config show                      查看当前配置
  config set <key> <value>         修改配置（如 PORT 8443、offline false、admin.token xxx）

其他:
  help                             显示本帮助`);
}

/** users 子命令 */
async function runUsers(args: string[]): Promise<void> {
  const sub = args[0];
  if (sub === "list") {
    const users = await adminService.listUsers();
    console.log(`共 ${users.length} 个用户:`);
    console.table(
      users.map((u) => ({
        uid: u.uid,
        昵称: u.nickName,
        等级: u.level,
        手机: u.phone,
      })),
    );
  } else if (sub === "info") {
    const uid = args[1];
    if (!uid) {
      console.error("用法: users info <uid>");
      process.exitCode = 1;
      return;
    }
    const info = await adminService.getUserInfo(uid);
    if (!info) {
      console.error(`用户不存在: ${uid}`);
      process.exitCode = 1;
      return;
    }
    console.log(`用户 ${uid}（${info.nickName}#${info.nickNumber}） Lv.${info.level}`);
    console.log(`  金币 ${info.gold} | 合成玉 ${info.androidDiamond} | 寻访凭证 ${info.gachaTicket}`);
    console.log(`  招募许可 ${info.recruitLicense} | 演习券 ${info.practiceTicket} | 经验 ${info.exp}`);
    console.log(`  干员数 ${info.charCnt} | 注册时间 ${new Date(info.registerTs * 1000).toLocaleString()}`);
  } else if (sub === "create") {
    const phone = args[1];
    const password = args[2] ?? phone;
    if (!phone) {
      console.error("用法: users create <phone> [password]");
      process.exitCode = 1;
      return;
    }
    const uid = await adminService.createUser(phone, password);
    console.log(`已创建用户 uid=${uid}（手机 ${phone}）`);
  } else if (sub === "grant") {
    const uid = args[1];
    const itemId = args[2];
    const countStr = args[3];
    const count = Number(countStr);
    if (!uid || !itemId || !countStr || !Number.isInteger(count) || count <= 0) {
      console.error("用法: users grant <uid> <itemId> <count>（count 为正整数）");
      process.exitCode = 1;
      return;
    }
    await adminService.grantItem(uid, itemId, count);
    console.log(`已向用户 ${uid} 发放 ${itemId} x${count}`);
  } else {
    console.error(`未知 users 子命令: ${sub ?? ""}`);
    process.exitCode = 1;
  }
}

/** mail 子命令 */
async function runMail(args: string[], flags: { [key: string]: string }): Promise<void> {
  const uid = args[1];
  const subject = args[2];
  const content = args.slice(3).join(" ");
  if (!uid || !subject) {
    console.error("用法: mail send <uid> <subject> [content] [--items id:count,...]");
    process.exitCode = 1;
    return;
  }
  const items = (flags.items ?? "")
    .split(",")
    .filter(Boolean)
    .map((pair) => {
      const [id, cnt] = pair.split(":");
      return { id, count: Number(cnt ?? 1) };
    });
  const mail = await adminService.sendMail(uid, { subject, content, items });
  console.log(`已向用户 ${uid} 发送邮件 mailId=${mail.mailId}（附件 ${items.length} 种）`);
}

/** server 子命令 */
async function runServer(args: string[]): Promise<void> {
  const sub = args[0];
  if (sub !== "status") {
    console.error("用法: server status");
    process.exitCode = 1;
    return;
  }
  const st = await adminService.status();
  console.log(`DoctorateTs 服务器状态`);
  console.log(`  端口 ${st.port} | 离线模式 ${st.offline} | 运行时间 ${st.uptime}s`);
  console.log(`  客户端版本 ${st.clientVersion} | 资源版本 ${st.resVersion}`);
  console.log(`  用户数 ${st.userCount}`);
  console.table(
    st.dataFiles.map((f) => ({
      文件: f.path,
      存在: f.exists,
      大小: `${(f.size / 1024).toFixed(1)}KB`,
    })),
  );
}

/** config 子命令 */
async function runConfig(args: string[]): Promise<void> {
  const sub = args[0];
  if (sub === "show") {
    console.log(JSON.stringify(config, null, 2));
  } else if (sub === "set") {
    const key = args[1];
    const value = args[2];
    if (!key || value === undefined) {
      console.error("用法: config set <key> <value>");
      process.exitCode = 1;
      return;
    }
    const cfg = readJsonSync<any>("./data/config.json");
    const path = key.split(".");
    let cur = cfg;
    for (let i = 0; i < path.length - 1; i++) {
      cur = cur[path[i]] ??= {};
    }
    const raw: string = value;
    const parsed: unknown =
      raw === "true" ? true : raw === "false" ? false : /^\d+$/.test(raw) ? Number(raw) : raw;
    cur[path[path.length - 1]] = parsed;
    await writeJson("./data/config.json", cfg);
    console.log(`已修改 ${key} = ${JSON.stringify(parsed)}（重启后生效）`);
  } else {
    console.error("用法: config show | config set <key> <value>");
    process.exitCode = 1;
  }
}

/** 主入口 */
export async function main(): Promise<void> {
  const { command, args, flags } = parseArgs(process.argv.slice(2));
  if (!command || command === "help" || command === "-h" || command === "--help") {
    printHelp();
    return;
  }
  await cliInit();

  switch (command) {
    case "users":
      await runUsers(args);
      break;
    case "mail":
      await runMail(args, flags);
      break;
    case "server":
      await runServer(args);
      break;
    case "config":
      await runConfig(args);
      break;
    default:
      console.error(`未知命令: ${command}`);
      printHelp();
      process.exitCode = 1;
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error("[admin-cli] 执行失败:", err.message ?? err);
    process.exit(1);
  });
}
