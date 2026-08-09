#!/usr/bin/env ts-node
/**
 * DoctorateTs 管理命令行工具
 *
 * 用法：
 *   npm run admin -- <command> [options]    单命令执行
 *   npm run admin                           进入交互模式（REPL）
 *
 * 命令：
 * 用户:
 *   users list [--json] [--csv]                         列出所有用户
 *   users info <uid> [--json]                           查看用户详情
 *   users create <phone> [password]                     创建新用户
 *   users grant <uid> <itemId|名称> <count>             发放物品/资源（支持中文名/别名，如 "合成玉"）
 *   users grantchar <uid> <charId|干员名>               发放干员（重复按稀有度折算信物）
 *   users skin <uid> <skinId>                           解锁皮肤
 *   users chars <uid> [--json]                          干员列表
 *   users char <uid> <instId> [--level N] [--evolve N] [--potential N] [--skill N]   修改干员属性
 *   users maxout <uid>                                  一键满配（资源/背包/干员/基建/皮肤，不覆盖阵容）
 *   users building <uid> max                            基建满级
 *   users backup <uid>                                  备份存档
 *   users backups <uid> [--json]                        列出备份
 *   users restore <uid> <backupName>                    从备份恢复
 *   users dump <uid> [--pretty]                         导出原始玩家数据 JSON
 *
 * 邮件:
 *   mail send <uid[,uid...]|all> <subject> [content] [--items id:count,...]  发送邮件（uid 支持逗号分隔批量）
 *   mail list <uid> [--json]                           查看用户邮件
 *   mail delete <uid> <mailId>                         删除单封邮件
 *
 * 服务器:
 *   server status                                      查看服务器状态
 *   server refresh <uid>                               触发每日/每周刷新（理智/任务重置）
 *   server save [uid]                                  立即保存存档（缺省保存全部用户）
 *
 * 配置:
 *   config show                                        查看当前配置
 *   config set <key> <value>                           修改配置（如 PORT 8443、offline false、admin.token xxx）
 *
 * 日志:
 *   logs show [--last N] [--json]                      查看管理操作审计日志
 *
 * 卡池管理:
 *   gacha pools [--json]                               列出全部卡池
 *   gacha pool <poolId> [--json]                       卡池详情（UP/可用干员+概率）
 *   gacha state <uid> <poolId> [--json]                玩家卡池状态（UP 选择+保底计数）
 *   gacha up <uid> <poolId> [charId...]                设置玩家 UP（空=清除）
 *   gacha pity <uid> [ruleType] [count]                查看/设置玩家保底计数
 *
 * 官服迁移:
 *   official accounts <file> [--json]                  预览账号文件解析结果
 *   official migrate <file> [--template uid]           官服账号迁移（联网拉取→注册私服账号）
 *
 * 其他:
 *   help / exit                                        帮助 / 退出交互模式
 *   全局 --quiet / -q：抑制内部 INFO 日志（便于脚本化）
 *
 * 说明：CLI 直接操作本地数据，无需启动服务器，完全离线可用。
 */
import { enablePatches } from "immer";
import * as readline from "readline";
import { readFileSync } from "fs";
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

/** 输出：--json 时输出 JSON；否则表格/对象 */
function output(
  data: unknown,
  flags: { [key: string]: string },
  table?: (row: any) => string[] | null,
): void {
  if (flags.json) {
    console.log(JSON.stringify(data, null, 2));
    return;
  }
  if (Array.isArray(data) && table) {
    console.table(data.map(table));
    return;
  }
  if (typeof data === "object" && data !== null) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

/** 打印帮助 */
export function printHelp(): void {
  console.log(`DoctorateTs 管理命令行工具
用法: npm run admin -- <command> [options]     （无参数进入交互模式）

用户管理:
  users list [--json] [--csv] [--filter 关键字]     列出所有用户（可过滤）
  users info <uid> [--json]                         查看用户详情
  users create <phone> [password]                   创建新用户
  users grant <uid[,uid...]> <itemId|名称> <count>  发放物品（uid 支持逗号分隔批量）
  users grantchar <uid> <charId|干员名>             发放干员
  users skin <uid> <skinId>                         解锁皮肤
  users chars <uid> [--json]                        干员列表
  users char <uid> <instId> [--level N] [--evolve N] [--potential N] [--skill N]  修改干员属性
  users maxout <uid>                                一键满配（不覆盖阵容）
  users building <uid> max                          基建满级
  users backup <uid> / users backups <uid> / users restore <uid> <备份名>   备份/列出/恢复
  users dump <uid> [--pretty]                       导出原始玩家数据 JSON
  users grantall <uid> [count]                      批量发放全部物品（默认 999）
  users maxchars <uid>                              批量拉满全部已有干员
  users repairchars <uid>                           修复干员结构（补齐缺失字段）
  users stages <uid> [--json]                       查看玩家推图进度（只读）
  users unlock <uid> <stageId>                      解锁指定关卡
  users unlockall <uid>                             推图全解锁
  users items <关键字> [limit] [--json]             按名称/ID 搜索物品（供发放用）
  users missions <uid> [--json]                     查看任务进度统计（只读）
  users medals <uid> [--json]                       查看勋章进度（只读）
  users export <uid> [path]                         导出存档到 JSON（默认 ./exports/）
  users import <存档JSON> [uid]                     从 JSON 导入/替换存档
  users delete <uid> --yes                          删除用户（危险操作，需 --yes）
  users grantall <uid> [count]                      批量发放全部物品（默认 999）
  users maxchars <uid>                              批量拉满全部已有干员
  users repairchars <uid>                           修复干员结构（补齐缺失字段）
  users stages <uid> [--json]                       查看玩家推图进度（只读）
  users unlock <uid> <stageId>                      解锁指定关卡
  users unlockall <uid>                             推图全解锁
  users items <关键字> [limit] [--json]             按名称/ID 搜索物品（供发放用）
  users missions <uid> [--json]                     查看任务进度统计（只读）
  users medals <uid> [--json]                       查看勋章进度（只读）
  users export <uid> [path]                         导出存档到 JSON（默认 ./exports/）
  users import <存档JSON> [uid]                     从 JSON 导入/替换存档
  users delete <uid> --yes                          删除用户（危险操作，需 --yes）

邮件:
  mail send <uid[,uid...]|all> <subject> [content] [--items id:count,...]  发送邮件（uid 支持逗号分隔批量）
  mail list <uid> [--json]                          查看用户邮件
  mail delete <uid> <mailId>                        删除单封邮件

服务器:
  server status                                     查看服务器状态
  server refresh <uid>                              触发每日/每周刷新
  server save [uid]                                 立即保存存档（缺省全部用户）
  server check                                      数据完整性校验（status/troop/可序列化）

配置:
  config show / config set <key> <value>

日志:
  logs show [--last N] [--json]                     查看审计日志

卡池管理:
  gacha pools [--json]                              列出全部卡池
  gacha pool <poolId> [--json]                      卡池详情（UP/可用干员+概率）
  gacha state <uid> <poolId> [--json]               玩家卡池状态（UP 选择+保底计数）
  gacha up <uid> <poolId> [charId...]               设置玩家 UP（空=清除）
  gacha pity <uid> [ruleType] [count]               查看/设置玩家保底计数

官服迁移:
  official accounts <file> [--json]                 预览账号文件解析结果
  official migrate <file> [--template uid]          官服账号迁移（联网拉取→注册私服账号）

其他:
  help / exit                                       帮助 / 退出`);
}

/** users 子命令 */
async function runUsers(args: string[], flags: { [key: string]: string }): Promise<void> {
  const sub = args[0];
  switch (sub) {
    case "list": {
      const filter = flags.filter ?? "";
      const users = await adminService.listUsers(filter);
      if (flags.csv) {
        console.log("uid,nickName,level,phone,lastOnlineTs");
        for (const u of users) {
          console.log(
            [u.uid, u.nickName, u.level, u.phone, u.lastOnlineTs].join(","),
          );
        }
        return;
      }
      output(
        users,
        flags,
        (u: any) => ({ uid: u.uid, 昵称: u.nickName, 等级: u.level, 手机: u.phone }),
      );
      return;
    }
    case "info": {
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
      if (flags.json) {
        output(info, flags);
        return;
      }
      console.log(`用户 ${uid}（${info.nickName}#${info.nickNumber}） Lv.${info.level}`);
      console.log(`  龙门币 ${info.gold} | 合成玉 ${info.androidDiamond} | 寻访凭证 ${info.gachaTicket}`);
      console.log(`  招募许可 ${info.recruitLicense} | 演习券 ${info.practiceTicket} | 经验 ${info.exp}`);
      console.log(`  干员数 ${info.charCnt} | 注册时间 ${new Date(info.registerTs * 1000).toLocaleString()}`);
      const top = info.inventoryInfo.slice(0, 15);
      if (top.length) {
        console.log("  背包（前 15）:");
        for (const it of top) {
          console.log(`    ${it.name}(${it.id}) x${it.count}`);
        }
      }
      return;
    }
    case "create": {
      const phone = args[1];
      const password = args[2] ?? phone;
      if (!phone) {
        console.error("用法: users create <phone> [password]");
        process.exitCode = 1;
        return;
      }
      const uid = await adminService.createUser(phone, password);
      console.log(`已创建用户 uid=${uid}（手机 ${phone}）`);
      return;
    }
    case "grant": {
      const uidArg = args[1];
      const itemId = args[2];
      const countStr = args[3];
      const count = Number(countStr);
      const uids = String(uidArg ?? "").split(",").map((s) => s.trim()).filter(Boolean);
      if (!uids.length || !itemId || !countStr || !Number.isInteger(count) || count <= 0) {
        console.error("用法: users grant <uid[,uid...]> <itemId|名称> <count>（count 为正整数；uid 支持逗号分隔批量）");
        process.exitCode = 1;
        return;
      }
      for (const uid of uids) {
        await adminService.grantItem(uid, itemId, count);
        console.log(`已向用户 ${uid} 发放 ${itemId} x${count}`);
      }
      return;
    }
    case "grantchar": {
      const uid = args[1];
      const charId = args[2];
      if (!uid || !charId) {
        console.error("用法: users grantchar <uid> <charId|干员名>");
        process.exitCode = 1;
        return;
      }
      const res = await adminService.grantChar(uid, charId);
      console.log(`已向用户 ${uid} 发放干员 ${res.name}（${res.isNew ? "新干员" : "重复"}）`);
      return;
    }
    case "skin": {
      const uid = args[1];
      const skinId = args[2];
      if (!uid || !skinId) {
        console.error("用法: users skin <uid> <skinId>");
        process.exitCode = 1;
        return;
      }
      await adminService.grantSkin(uid, skinId);
      console.log(`已向用户 ${uid} 解锁皮肤 ${skinId}`);
      return;
    }
    case "chars": {
      const uid = args[1];
      if (!uid) {
        console.error("用法: users chars <uid> [--json]");
        process.exitCode = 1;
        return;
      }
      const chars = await adminService.listChars(uid);
      output(
        chars,
        flags,
        (c: any) => ({
          instId: c.instId,
          干员: `${c.name}(${c.charId})`,
          星级: c.rarity + 1,
          等级: `${c.level}/${c.maxLevel}`,
          精二: c.evolvePhase,
          潜能: c.potentialRank,
          技能: c.mainSkillLvl,
        }),
      );
      return;
    }
    case "char": {
      const uid = args[1];
      const instId = Number(args[2]);
      if (!uid || !Number.isInteger(instId)) {
        console.error("用法: users char <uid> <instId> [--level N] [--evolve N] [--potential N] [--skill N]");
        process.exitCode = 1;
        return;
      }
      const attrs: { [key: string]: number } = {};
      for (const key of ["level", "evolve", "potential", "skill"] as const) {
        if (flags[key] !== undefined && flags[key] !== "true") {
          const n = Number(flags[key]);
          if (!Number.isInteger(n)) {
            console.error(`参数 --${key} 必须是整数`);
            process.exitCode = 1;
            return;
          }
          attrs[key === "evolve" ? "evolvePhase" : key === "potential" ? "potentialRank" : key === "skill" ? "mainSkillLvl" : key] = n;
        }
      }
      // 无编辑参数 → 显示干员详情
      if (Object.keys(attrs).length === 0) {
        const d = await adminService.getCharDetail(uid, instId);
        if (!d) {
          console.error(`干员不存在: instId=${instId}`);
          process.exitCode = 1;
          return;
        }
        if (flags.json) {
          output(d, flags);
          return;
        }
        console.log(`${d.name}(${d.charId}) ${d.rarity + 1}★ instId=${d.instId}`);
        console.log(`  等级 ${d.level}/${d.maxLevel} | 精二 ${d.evolvePhase} | 潜能 ${d.potentialRank} | 技能 ${d.mainSkillLvl} | 信赖 ${d.favorPoint}`);
        console.log(`  语音 ${d.voiceLan} | 皮肤 ${d.skin ? `${d.skinName ?? d.skin}(${d.skin})` : "默认"}`);
        console.log(`  当前装备 ${d.currentEquip ?? "无"}`);
        if (d.skills.length) {
          console.log("  技能:");
          for (const s of d.skills) {
            console.log(`    ${s.skillId} [${s.unlock ? "解锁" : "未解锁"}] 专精 ${s.specializeLevel}`);
          }
        }
        return;
      }
      const result = await adminService.setCharAttrs(uid, instId, attrs);
      console.log(
        `已修改 ${result.name}(instId=${instId})：精二 ${result.evolvePhase} | 等级 ${result.level} | 潜能 ${result.potentialRank} | 技能 ${result.mainSkillLvl}`,
      );
      return;
    }
    case "maxout": {
      const uid = args[1];
      if (!uid) {
        console.error("用法: users maxout <uid>");
        process.exitCode = 1;
        return;
      }
      const stats = await adminService.maxOutAccount(uid);
      console.log(
        `已满配用户 ${uid}：干员 ${stats.chars} | 物品 ${stats.items} | 皮肤 ${stats.skins} | 基建 ${stats.rooms}`,
      );
      return;
    }
    case "building": {
      const uid = args[1];
      const act = args[2];
      if (!uid || act !== "max") {
        console.error("用法: users building <uid> max");
        process.exitCode = 1;
        return;
      }
      const result = await adminService.buildingMax(uid);
      console.log(`已满级基建 ${result.rooms} 间房间`);
      return;
    }
    case "backup": {
      const uid = args[1];
      if (!uid) {
        console.error("用法: users backup <uid>");
        process.exitCode = 1;
        return;
      }
      const info = await adminService.backup(uid);
      console.log(`已备份 ${info.name}（${(info.size / 1024).toFixed(1)}KB）`);
      return;
    }
    case "backups": {
      const uid = args[1];
      if (!uid) {
        console.error("用法: users backups <uid> [--json]");
        process.exitCode = 1;
        return;
      }
      const list = await adminService.listBackups(uid);
      if (flags.json) {
        output(list, flags);
        return;
      }
      if (!list.length) {
        console.log(`用户 ${uid} 暂无备份`);
        return;
      }
      console.table(
        list.map((b) => ({
          文件: b.name,
          大小: `${(b.size / 1024).toFixed(1)}KB`,
          时间: new Date(b.ts * 1000).toLocaleString(),
        })),
      );
      return;
    }
    case "restore": {
      const uid = args[1];
      const backup = args[2];
      if (!uid || !backup) {
        console.error("用法: users restore <uid> <backupName>");
        process.exitCode = 1;
        return;
      }
      await adminService.restore(uid, backup);
      console.log(`已从 ${backup} 恢复用户 ${uid}`);
      return;
    }
    case "dump": {
      const uid = args[1];
      if (!uid) {
        console.error("用法: users dump <uid> [--pretty]");
        process.exitCode = 1;
        return;
      }
      const data = await adminService.getRawJson(uid);
      console.log(
        JSON.stringify(data, null, flags.pretty === "true" || flags.pretty ? 2 : 0),
      );
      return;
    }
    case "grantall": {
      const uid = args[1];
      const count = Number(args[2] ?? 999);
      if (!uid || !Number.isInteger(count) || count <= 0) {
        console.error("用法: users grantall <uid> [count]（count 为正整数，默认 999）");
        process.exitCode = 1;
        return;
      }
      const result = await adminService.grantAllItems(uid, count);
      console.log(`已向用户 ${uid} 批量发放 ${result.items} 种物品 x${count}`);
      return;
    }
    case "maxchars": {
      const uid = args[1];
      if (!uid) {
        console.error("用法: users maxchars <uid>");
        process.exitCode = 1;
        return;
      }
      const result = await adminService.maxAllChars(uid);
      console.log(`已拉满用户 ${uid} 的 ${result.chars} 名干员`);
      return;
    }
    case "repairchars": {
      const uid = args[1];
      if (!uid) {
        console.error("用法: users repairchars <uid>");
        process.exitCode = 1;
        return;
      }
      const result = await adminService.repairChars(uid);
      console.log(`已修复用户 ${uid} 干员结构：${result.chars} 名干员 / ${result.fields} 个字段`);
      return;
    }
    case "stages": {
      const uid = args[1];
      if (!uid) {
        console.error("用法: users stages <uid> [--json]");
        process.exitCode = 1;
        return;
      }
      const st = await adminService.listStages(uid);
      if (flags.json) {
        output(st, flags);
        return;
      }
      console.log(`用户 ${uid} 推图进度：已解锁 ${st.total} 关 | 已完成 ${st.done} 关`);
      const top = st.stages.slice(0, 30);
      if (top.length) {
        console.table(
          top.map((s) => ({
            关卡: s.stageId,
            状态: s.state,
            完成次数: s.completeTimes,
          })),
        );
      }
      return;
    }
    case "unlock": {
      const uid = args[1];
      const stageId = args[2];
      if (!uid || !stageId) {
        console.error("用法: users unlock <uid> <stageId>");
        process.exitCode = 1;
        return;
      }
      const r = await adminService.unlockStage(uid, stageId);
      console.log(`已解锁用户 ${uid} 的关卡 ${r.stageId}`);
      return;
    }
    case "unlockall": {
      const uid = args[1];
      if (!uid) {
        console.error("用法: users unlockall <uid>");
        process.exitCode = 1;
        return;
      }
      const r = await adminService.unlockAllStages(uid);
      console.log(`已推图全解锁用户 ${uid}：新增 ${r.stages} 关（共 ${r.total} 关）`);
      return;
    }
    case "items": {
      const q = args[1] ?? "";
      const limit = Number(args[2] ?? flags.limit ?? 50);
      const list = adminService.searchItems(q, Number.isFinite(limit) ? limit : 50);
      if (flags.json) {
        output(list, flags);
        return;
      }
      if (!list.length) {
        console.log(`未找到匹配物品: ${q || "(空)"}`);
        return;
      }
      console.table(
        list.map((it) => ({ ID: it.id, 名称: it.name, 类型: it.classifyType })),
      );
      return;
    }
    case "missions": {
      const uid = args[1];
      if (!uid) {
        console.error("用法: users missions <uid> [--json]");
        process.exitCode = 1;
        return;
      }
      const st = await adminService.listMissionStats(uid);
      if (flags.json) {
        output(st, flags);
        return;
      }
      console.log(`用户 ${uid} 任务进度：已完成 ${st.done}/${st.total}`);
      if (st.groups.length) {
        console.table(
          st.groups.map((g) => ({ 任务组: g.group, 完成: g.done, 总数: g.total })),
        );
      }
      return;
    }
    case "medals": {
      const uid = args[1];
      if (!uid) {
        console.error("用法: users medals <uid> [--json]");
        process.exitCode = 1;
        return;
      }
      const st = await adminService.listMedals(uid);
      if (flags.json) {
        output(st, flags);
        return;
      }
      console.log(`用户 ${uid} 勋章进度：已解锁 ${st.unlocked}/${st.total}`);
      return;
    }
    case "export": {
      const uid = args[1];
      const target = args[2];
      if (!uid) {
        console.error("用法: users export <uid> [path]（缺省 ./exports/{uid}-{ts}.json）");
        process.exitCode = 1;
        return;
      }
      const r = await adminService.exportUser(uid, target);
      console.log(`已导出用户 ${uid} 存档 → ${r.path}（${(r.size / 1024).toFixed(1)}KB）`);
      return;
    }
    case "import": {
      const file = args[1];
      const uid = args[2];
      if (!file) {
        console.error("用法: users import <存档JSON> [uid]（uid 缺省取文件内 status.uid）");
        process.exitCode = 1;
        return;
      }
      const r = await adminService.importUser(file, uid);
      console.log(`已导入存档到用户 ${r.uid}`);
      return;
    }
    case "delete": {
      const uid = args[1];
      if (!uid) {
        console.error("用法: users delete <uid> --yes（危险操作，删除存档与账号）");
        process.exitCode = 1;
        return;
      }
      if (flags.yes !== "true") {
        console.error("危险操作：确认删除请加 --yes");
        process.exitCode = 1;
        return;
      }
      const r = await adminService.deleteUser(uid, "DELETE");
      console.log(`已删除用户 ${r.uid}`);
      return;
    }
    case "shop": {
      const uid = args[1];
      if (!uid) {
        console.error("用法: users shop <uid> [--json]");
        process.exitCode = 1;
        return;
      }
      const st = await adminService.getShopSummary(uid);
      if (flags.json) {
        output(st, flags);
        return;
      }
      console.log(`用户 ${uid} 商店数据：共 ${st.total} 条购买记录`);
      if (st.types.length) {
        console.table(
          st.types.map((t) => ({ 类型: t.type, 当前商店: t.curShopId ?? "-", 记录数: t.items })),
        );
      }
      return;
    }
    default:
      console.error(`未知 users 子命令: ${sub ?? ""}`);
      process.exitCode = 1;
  }
}

/** mail 子命令 */
async function runMail(args: string[], flags: { [key: string]: string }): Promise<void> {
  const sub = args[0];
  if (sub === "send") {
    const target = args[1];
    const subject = args[2];
    const content = args.slice(3).join(" ");
    if (!target || !subject) {
      console.error("用法: mail send <uid[,uid...]|all> <subject> [content] [--items id:count,...]");
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
    if (target === "all") {
      const result = await adminService.sendMailAll({ subject, content, items });
      console.log(`已向 ${result.sent} 个用户群发邮件「${subject}」（附件 ${items.length} 种）`);
    } else {
      const uids = target.split(",").map((s) => s.trim()).filter(Boolean);
      for (const uid of uids) {
        const mail = await adminService.sendMail(uid, { subject, content, items });
        console.log(`已向用户 ${uid} 发送邮件 mailId=${mail.mailId}（附件 ${items.length} 种）`);
      }
    }
    return;
  }
  if (sub === "list") {
    const uid = args[1];
    if (!uid) {
      console.error("用法: mail list <uid> [--json]");
      process.exitCode = 1;
      return;
    }
    const mails = await adminService.listMails(uid);
    if (flags.json) {
      output(mails, flags);
      return;
    }
    if (!mails.length) {
      console.log(`用户 ${uid} 暂无邮件`);
      return;
    }
    console.table(
      mails.map((m) => ({
        mailId: m.mailId,
        标题: m.subject,
        已领: m.receiveAt !== -1 ? "是" : "否",
        附件: m.items.map((it) => `${it.name}x${it.count}`).join(", ") || "-",
        时间: new Date(m.createAt * 1000).toLocaleString(),
      })),
    );
    return;
  }
  if (sub === "delete") {
    const uid = args[1];
    const mailId = Number(args[2]);
    if (!uid || !Number.isInteger(mailId)) {
      console.error("用法: mail delete <uid> <mailId>");
      process.exitCode = 1;
      return;
    }
    const ok = await adminService.deleteMail(uid, mailId);
    if (!ok) {
      console.error(`邮件不存在: ${mailId}`);
      process.exitCode = 1;
      return;
    }
    console.log(`已删除用户 ${uid} 的邮件 mailId=${mailId}`);
    return;
  }
  console.error("用法: mail send <uid|all> ... | mail list <uid> | mail delete <uid> <mailId>");
  process.exitCode = 1;
}

/** server 子命令 */
async function runServer(args: string[]): Promise<void> {
  const sub = args[0];
  if (sub === "status") {
    const st = await adminService.status();
    console.log(`DoctorateTs 服务器状态`);
    console.log(`  端口 ${st.port} | 离线模式 ${st.offline} | 运行时间 ${st.uptime}s`);
    console.log(`  客户端版本 ${st.clientVersion} | 资源版本 ${st.resVersion}`);
    console.log(`  用户数 ${st.userCount} | 数据总量 ${(st.totalDataKB / 1024).toFixed(1)}MB`);
    console.table(
      st.dataFiles.map((f) => ({
        文件: f.path,
        存在: f.exists,
        大小: `${(f.size / 1024).toFixed(1)}KB`,
      })),
    );
    return;
  }
  if (sub === "refresh") {
    const uid = args[1];
    if (!uid) {
      console.error("用法: server refresh <uid>");
      process.exitCode = 1;
      return;
    }
    await adminService.refreshUser(uid);
    console.log(`已触发用户 ${uid} 的每日/每周刷新`);
    return;
  }
  if (sub === "save") {
    const uid = args[1];
    if (uid) {
      await adminService.saveUser(uid);
      console.log(`已保存用户 ${uid} 存档`);
    } else {
      const users = await adminService.listUsers();
      for (const u of users) {
        await adminService.saveUser(u.uid);
      }
      console.log(`已保存全部 ${users.length} 个用户存档`);
    }
    return;
  }
  if (sub === "check") {
    const r = await adminService.checkData();
    console.log(`数据完整性校验：${r.ok ? "全部正常" : "存在异常"}`);
    console.table(
      r.users.map((u) => ({ uid: u.uid, 状态: u.ok ? "正常" : "异常", 详情: u.error ?? "-" })),
    );
    return;
  }
  console.error("用法: server status | server refresh <uid> | server save [uid] | server check");
  process.exitCode = 1;
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

/** logs 子命令 */
async function runLogs(args: string[], flags: { [key: string]: string }): Promise<void> {
  const sub = args[0];
  if (sub !== "show") {
    console.error("用法: logs show [--last N] [--json]");
    process.exitCode = 1;
    return;
  }
  const last = Number(flags.last ?? 50);
  const entries = await adminService.logs(Number.isFinite(last) ? last : 50);
  if (flags.json) {
    output(entries, flags);
    return;
  }
  if (!entries.length) {
    console.log("暂无操作日志");
    return;
  }
  console.table(
    entries.map((e) => ({
      时间: new Date(e.ts * 1000).toLocaleString(),
      操作: e.action,
      用户: e.uid || "-",
      详情: e.detail,
    })),
  );
}

/** gacha 子命令（卡池管理） */
async function runGacha(args: string[], flags: { [key: string]: string }): Promise<void> {
  const sub = args[0];
  if (sub === "pools") {
    const pools = adminService.listPools();
    if (flags.json) {
      output(pools, flags);
      return;
    }
    if (!pools.length) {
      console.log("暂无卡池数据");
      return;
    }
    console.table(
      pools.map((p) => ({
        poolId: p.poolId,
        名称: p.name,
        规则: p.ruleType,
        保底: p.guarantee5Count,
        开池: new Date(p.openTime * 1000).toLocaleDateString(),
        关池: new Date(p.endTime * 1000).toLocaleDateString(),
      })),
    );
    return;
  }
  if (sub === "pool") {
    const poolId = args[1];
    if (!poolId) {
      console.error("用法: gacha pool <poolId> [--json]");
      process.exitCode = 1;
      return;
    }
    const detail = adminService.poolDetail(poolId);
    if (!detail) {
      console.error(`卡池不存在: ${poolId}`);
      process.exitCode = 1;
      return;
    }
    if (flags.json) {
      output(detail, flags);
      return;
    }
    console.log(`卡池 ${detail.name}(${detail.poolId}) [${detail.ruleType}] 保底 ${detail.guarantee5Count}`);
    if (detail.upChars.length) {
      console.log("  UP 干员:");
      for (const c of detail.upChars) {
        console.log(`    ${c.name}(${c.charId}) ${c.percent}%`);
      }
    } else {
      console.log("  UP 干员:（无）");
    }
    console.log(`  可用干员 ${detail.availChars.length} 名 | 限时干员 ${detail.limitedChars.length} 名`);
    return;
  }
  if (sub === "state") {
    const uid = args[1];
    const poolId = args[2];
    if (!uid || !poolId) {
      console.error("用法: gacha state <uid> <poolId> [--json]");
      process.exitCode = 1;
      return;
    }
    const st = await adminService.getPlayerPoolState(uid, poolId);
    if (flags.json) {
      output(st, flags);
      return;
    }
    console.log(`玩家 ${uid} 卡池「${st.name}」(${st.poolId}) [${st.ruleType}]`);
    console.log(
      `  UP 选择: ${st.upChars.map((c) => `${c.name}(${c.charId})`).join(", ") || "（未选择）"}`,
    );
    console.log(`  保底计数: ${st.beforeNonHitCnt} / ${st.guarantee5Count}`);
    return;
  }
  if (sub === "up") {
    const uid = args[1];
    const poolId = args[2];
    const charIds = args.slice(3);
    if (!uid || !poolId) {
      console.error("用法: gacha up <uid> <poolId> [charId...]（空 = 清除 UP）");
      process.exitCode = 1;
      return;
    }
    const st = await adminService.setPlayerPoolUp(uid, poolId, charIds);
    console.log(
      `已设置玩家 ${uid} 卡池 ${poolId} UP: ${st.upChars.map((c) => c.name).join(", ") || "（清除）"}`,
    );
    return;
  }
  if (sub === "pity") {
    const uid = args[1];
    const ruleType = args[2];
    const countStr = args[3];
    if (!uid) {
      console.error("用法: gacha pity <uid> [ruleType] [count]（无 count 查看，有则设置）");
      process.exitCode = 1;
      return;
    }
    if (ruleType && countStr !== undefined) {
      const count = Number(countStr);
      if (!Number.isInteger(count) || count < 0) {
        console.error("保底计数必须为非负整数");
        process.exitCode = 1;
        return;
      }
      const r = await adminService.setPlayerPity(uid, ruleType, count);
      console.log(`已设置玩家 ${uid} ${r.ruleType} 保底计数 = ${r.beforeNonHitCnt}`);
      return;
    }
    if (ruleType) {
      const r = await adminService.getPlayerPity(uid, ruleType);
      if (flags.json) {
        output(r, flags);
        return;
      }
      console.log(`玩家 ${uid} ${r.ruleType} 保底计数 = ${r.beforeNonHitCnt}`);
      return;
    }
    const list = await adminService.listPlayerPity(uid);
    if (flags.json) {
      output(list, flags);
      return;
    }
    if (!list.length) {
      console.log(`玩家 ${uid} 暂无保底记录`);
      return;
    }
    console.table(
      list.map((r) => ({ 规则: r.ruleType, 保底计数: r.beforeNonHitCnt })),
    );
    return;
  }
  console.error("用法: gacha pools | pool <poolId> | state <uid> <poolId> | up <uid> <poolId> [charId...] | pity <uid> [ruleType] [count]");
  process.exitCode = 1;
}

/** official 子命令（官服账号迁移） */
async function runOfficial(
  args: string[],
  flags: { [key: string]: string },
): Promise<void> {
  const sub = args[0];
  if (sub === "accounts") {
    const file = args[1];
    if (!file) {
      console.error("用法: official accounts <file> [--json]");
      process.exitCode = 1;
      return;
    }
    const { parseAccounts } = await import("../scripts/migrate-official");
    const list = parseAccounts(readFileSync(file, "utf8"));
    if (flags.json) {
      output(list, flags);
      return;
    }
    if (!list.length) {
      console.log("未解析到账号（每行 手机号 密码，或两行一组 手机号\\n密码）");
      return;
    }
    console.table(
      list.map((a) => ({ 手机号: a.phone, 密码: a.pwd })),
    );
    return;
  }
  if (sub === "migrate") {
    const file = args[1];
    const templateUid = flags.template ?? "1";
    if (!file) {
      console.error("用法: official migrate <accounts文件> [--template uid]");
      process.exitCode = 1;
      return;
    }
    if (!(await import("fs")).existsSync(file)) {
      console.error(`账号文件不存在: ${file}`);
      process.exitCode = 1;
      return;
    }
    console.log("开始官服迁移（需公网访问官服，逐账号执行，请稍候）...");
    const results = await adminService.migrateOfficial(
      readFileSync(file, "utf8"),
      templateUid,
    );
    if (flags.json) {
      output(results, flags);
      return;
    }
    const ok = results.filter((r) => !r.error).length;
    for (const r of results) {
      if (r.error) {
        console.log(`  [失败] ${r.phone}: ${r.error}`);
      } else {
        console.log(`  [成功] ${r.phone} → uid=${r.uid} 昵称=${r.nickName}`);
      }
    }
    console.log(`迁移完成：${ok}/${results.length} 成功`);
    return;
  }
  console.error("用法: official migrate <accounts文件> [--template uid] | official accounts <file> [--json]");
  process.exitCode = 1;
}

/** 命令分发（main 与交互模式共用） */
export async function dispatch(
  command: string,
  args: string[],
  flags: { [key: string]: string },
): Promise<void> {
  switch (command) {
    case "users":
      await runUsers(args, flags);
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
    case "logs":
      await runLogs(args, flags);
      break;
    case "gacha":
      await runGacha(args, flags);
      break;
    case "official":
      await runOfficial(args, flags);
      break;
    case "help":
    case "-h":
    case "--help":
      printHelp();
      break;
    default:
      console.error(`未知命令: ${command}`);
      printHelp();
      process.exitCode = 1;
  }
}

/** 交互模式：逐行执行命令，help/exit 退出（Tab 补全命令名） */
function runRepl(): void {
  console.log("DoctorateTs 管理交互模式（输入 help 查看命令，exit 退出；Tab 补全）");
  const COMMANDS = ["users", "mail", "server", "config", "gacha", "official", "logs", "help", "exit", "quit"];
  const completer = (line: string): [string[], string] => {
    const hits = COMMANDS.filter((c) => c.startsWith(line));
    return [hits.length ? hits : COMMANDS, line];
  };
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: "admin> ",
    completer,
  });
  let pending = 0;
  rl.prompt();
  rl.on("line", async (line) => {
    const trimmed = line.trim();
    if (!trimmed) {
      rl.prompt();
      return;
    }
    const { command, args, flags } = parseArgs(trimmed.split(/\s+/));
    if (command === "exit" || command === "quit") {
      rl.close();
      return;
    }
    pending++;
    try {
      await dispatch(command, args, flags);
    } catch (err) {
      console.error("[admin] 执行失败:", (err as Error).message ?? err);
    } finally {
      pending--;
      rl.prompt();
    }
  });
  rl.on("close", async () => {
    console.log("再见");
    // 管道输入时 stdin 立即 EOF：等待进行中的命令输出完成再退出，避免截断
    while (pending > 0) {
      await new Promise((r) => setTimeout(r, 10));
    }
    process.exit(0);
  });
}

/** 主入口 */
export async function main(): Promise<void> {
  // 全局 --quiet/-q：抑制 CLI 内部 INFO 日志（便于脚本化）。
  // 先剔除该 flag 再 parseArgs（parseArgs 会把 --quiet 后的下一个 token 当值吞掉）
  const rawArgv = process.argv.slice(2);
  if (rawArgv.includes("--quiet") || rawArgv.includes("-q")) {
    process.env.LOG_LEVEL = "error";
  }
  const argv = rawArgv.filter((a) => a !== "--quiet" && a !== "-q");
  const { command, args, flags } = parseArgs(argv);
  if (!command) {
    await cliInit();
    runRepl();
    return;
  }
  if (command === "help" || command === "-h" || command === "--help") {
    printHelp();
    return;
  }
  await cliInit();
  await dispatch(command, args, flags);
}

if (require.main === module) {
  main().catch((err) => {
    console.error("[admin-cli] 执行失败:", err.message ?? err);
    process.exit(1);
  });
}
