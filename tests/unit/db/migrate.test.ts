import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { SCHEMA_SQL, openDatabase, closeDatabase } from "@core/db/database";
import type { SqlDatabase } from "@core/db/types";
import { FriendRepository } from "@core/db/friend-repo";
import { migrateFromUserConfigs } from "@core/db/migrate";
import { accountManager } from "@game/modules/account/AccountManager";

describe("社交数据迁移", () => {
  let db: SqlDatabase;

  beforeEach(async () => {
    db = await openDatabase(":memory:");
    await db.exec(SCHEMA_SQL);
    vi.restoreAllMocks();
  });

  afterEach(async () => {
    await closeDatabase();
  });

  it("应从 users.json 的 social 字段迁移好友/申请/访问记录", async () => {
    (accountManager as any).configs = {
      "1": {
        uid: "1",
        social: {
          friends: [
            { uid: "2", alias: "阿米娅" },
            { uid: "3", alias: "" },
          ],
          friendRequests: ["4"],
          visited: ["5"],
        },
      },
      "2": { uid: "2", social: { friends: [], friendRequests: [], visited: [] } },
    };

    await migrateFromUserConfigs(db, accountManager.configs);

    const repo = new FriendRepository(db);
    expect(await repo.getFriendList("1")).toEqual([
      { uid: "2", alias: "阿米娅" },
      { uid: "3", alias: "" },
    ]);
    expect(await repo.getFriendRequests("1")).toEqual(["4"]);
    expect(await repo.getVisited("1")).toEqual(["5"]);
    // 迁移后 JSON 中的 social 被重置为空结构（社交表为唯一事实源）
    expect((accountManager.configs as any)["1"].social).toEqual({
      friends: [],
      friendRequests: [],
      visited: [],
    });
  });

  it("configs 缺失 social 字段时不应报错", async () => {
    (accountManager as any).configs = { "1": { uid: "1" } };
    await expect(
      migrateFromUserConfigs(db, accountManager.configs),
    ).resolves.toBeUndefined();
  });
});
