/**
 * 社交数据迁移模块
 *
 * 首次创建 social.db 时，将 users.json 中每个用户的 social 字段
 * （friends / friendRequests / visited）导入 SQLite，
 * 之后 JSON 中的 social 字段不再作为数据源（重置为空结构）。
 */
import { DatabaseSync } from "node:sqlite";
import { FriendRepository } from "./friend-repo";
import { UserConfig } from "@game/manager/AccountManger";

/**
 * 从用户配置迁移社交数据到 SQLite，并重置 JSON 中的 social 字段
 * @param db - SQLite 连接
 * @param configs - accountManager.configs（user 配置映射）
 */
export function migrateFromUserConfigs(
  db: DatabaseSync,
  configs: { [key: string]: UserConfig },
): void {
  const repo = new FriendRepository(db);
  for (const uid of Object.keys(configs)) {
    const config = configs[uid];
    const social = (config as any).social;
    if (!social) continue;

    for (const friend of social.friends ?? []) {
      repo.addFriend(uid, friend.uid, friend.alias ?? "");
    }
    for (const fromUid of social.friendRequests ?? []) {
      repo.sendFriendRequest(fromUid, uid);
    }
    for (const visitedUid of social.visited ?? []) {
      repo.addVisit(uid, visitedUid);
    }
    // 重置 JSON 中的社交字段（SQLite 为唯一事实源）
    (config as any).social = { friends: [], friendRequests: [], visited: [] };
  }
}
