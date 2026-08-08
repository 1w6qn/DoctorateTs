import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { openDatabase, SCHEMA_SQL } from "../../../app/db/database";
import { ReplayRepository } from "../../../app/db/replay-repo";
import { AccountManager } from "../../../app/game/manager/AccountManger";

/**
 * AccountManager 战斗回放独立存储（R4）
 *
 * saveBattleReplay 写 replays 表（不再改写 configs/users 表），
 * getBattleReplay 从 replays 表读回——大字符串不参与用户配置全量保存。
 */
describe("AccountManager 回放独立存储", () => {
  let manager: AccountManager;
  let db: DatabaseSync;

  beforeEach(() => {
    vi.restoreAllMocks();
    db = openDatabase(":memory:");
    db.exec(SCHEMA_SQL);
    manager = new AccountManager();
    (manager as any)._replayRepo = new ReplayRepository(db);
    (manager as any).configs = { "1": { uid: "1", password: "p" } };
  });

  afterEach(() => {
    db.close();
  });

  it("saveBattleReplay 写 replays 表；configs 不再携带回放", async () => {
    const saveConfigSpy = vi
      .spyOn(manager, "saveUserConfig")
      .mockResolvedValue(undefined as any);
    await manager.saveBattleReplay("1", "st_01", "BASE64==");
    // configs 不被改写（回放不入配置）
    expect((manager as any).configs["1"]?.battle).toBeUndefined();
    // 读回走 replays 表
    expect(await manager.getBattleReplay("1", "st_01")).toBe("BASE64==");
    // 不再触发全量配置保存（每次战斗回放不重写 users 表）
    expect(saveConfigSpy).not.toHaveBeenCalled();
  });
});
