import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { openDatabase, SCHEMA_SQL, closeDatabase } from "@core/db/database";
import type { SqlDatabase } from "@core/db/types";
import { UserRepository, migrateUsersFromJsonFile } from "@core/db/user-repo";

const fileMock = vi.hoisted(() => ({ readJson: vi.fn() }));
vi.mock("@utils/file", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@utils/file")>();
  return { ...actual, readJson: fileMock.readJson };
});

describe("UserRepository", () => {
  let repo: UserRepository;
  let db: SqlDatabase;

  beforeEach(async () => {
    db = await openDatabase(":memory:");
    await db.exec(SCHEMA_SQL);
    repo = new UserRepository(db);
  });

  afterEach(async () => {
    await closeDatabase();
  });

  it("upsert 后 getAll 应回读完整 UserConfig（JSON 往返）", async () => {
    const conf = {
      uid: "1",
      password: "p",
      secret: "s",
      auth: {
        hgId: "1",
        phone: "1",
        email: "",
        identityNum: "d",
        identityName: "d",
        isMinor: false,
        isLatestUserAgreement: true,
      },
      social: { friends: [], friendRequests: [], visited: [] },
      battle: { stageId: "", replays: { act35side_09: "BASE64==" }, infos: {} },
      gacha: { NORMAL: { beforeNonHitCnt: 4 } },
      rlv2: {},
    } as any;
    await repo.upsert("1", conf);
    const persisted = (await repo.getAll())["1"];
    // 社交字段不入库（社交表为唯一事实源——R3）
    const { social: _social, ...expected } = conf;
    expect(persisted).toEqual(expected);
    expect((persisted as any).social).toBeUndefined();
    await expect(repo.count()).resolves.toBe(1);
  });

  it("upsertAll 默认剔除 social（社交单事实源）", async () => {
    await repo.upsertAll({
      "1": {
        uid: "1",
        password: "p",
        social: { friends: [{ uid: "2", alias: "" }], friendRequests: [], visited: [] },
      } as any,
    });
    const persisted = (await repo.getAll())["1"] as any;
    expect(persisted.social).toBeUndefined();
    expect(persisted.uid).toBe("1");
  });

  it("upsertAll keepSocial=true 保留 social（首次种子迁移 → 社交表的桥）", async () => {
    await repo.upsertAll(
      {
        "1": {
          uid: "1",
          social: { friends: [{ uid: "2", alias: "" }], friendRequests: [], visited: [] },
        } as any,
      },
      true,
    );
    const persisted = (await repo.getAll())["1"] as any;
    expect(persisted.social).toEqual({
      friends: [{ uid: "2", alias: "" }],
      friendRequests: [],
      visited: [],
    });
  });

  it("upsertAll 应事务全量覆盖（旧 uid 不残留）", async () => {
    await repo.upsertAll({ "1": { uid: "1" } as any, "2": { uid: "2" } as any });
    await expect(repo.count()).resolves.toBe(2);
    await repo.upsertAll({ "1": { uid: "1", password: "new" } as any });
    await expect(repo.count()).resolves.toBe(1);
    expect((await repo.getAll())["1"].password).toBe("new");
  });

  it("get 不存在返回 undefined", async () => {
    await expect(repo.get("999")).resolves.toBeUndefined();
  });

  it("get 存在返回对应 UserConfig", async () => {
    await repo.upsert("7", { uid: "7", password: "x" } as any);
    expect((await repo.get("7"))?.password).toBe("x");
  });
});

describe("migrateUsersFromJsonFile", () => {
  let repo: UserRepository;

  beforeEach(async () => {
    fileMock.readJson.mockReset();
    const db = await openDatabase(":memory:");
    await db.exec(SCHEMA_SQL);
    repo = new UserRepository(db);
  });

  afterEach(async () => {
    await closeDatabase();
  });

  it("users 表空时应从 users.json 导入", async () => {
    fileMock.readJson.mockResolvedValue({
      "1": { uid: "1", password: "p1" },
      "2": { uid: "2", password: "p2" },
    });
    const n = await migrateUsersFromJsonFile(repo);
    expect(n).toBe(2);
    await expect(repo.count()).resolves.toBe(2);
    expect((await repo.getAll())["2"].password).toBe("p2");
  });

  it("users 表非空时应跳过（幂等）", async () => {
    await repo.upsert("9", { uid: "9" } as any);
    const n = await migrateUsersFromJsonFile(repo);
    expect(n).toBe(0);
    await expect(repo.get("9")).resolves.toBeDefined();
    await expect(repo.count()).resolves.toBe(1);
  });

  it("users.json 不存在时返回 0 不抛错", async () => {
    fileMock.readJson.mockRejectedValue(new Error("ENOENT"));
    const n = await migrateUsersFromJsonFile(repo);
    expect(n).toBe(0);
  });
});
