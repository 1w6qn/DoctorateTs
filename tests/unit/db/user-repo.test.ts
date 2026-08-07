import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { openDatabase, SCHEMA_SQL } from "../../../app/db/database";
import { UserRepository, migrateUsersFromJsonFile } from "../../../app/db/user-repo";
import { DatabaseSync } from "node:sqlite";

const fileMock = vi.hoisted(() => ({ readJson: vi.fn() }));
vi.mock("@utils/file", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@utils/file")>();
  return { ...actual, readJson: fileMock.readJson };
});

describe("UserRepository", () => {
  let repo: UserRepository;
  let db: DatabaseSync;

  beforeEach(() => {
    db = openDatabase(":memory:");
    db.exec(SCHEMA_SQL);
    repo = new UserRepository(db);
  });

  afterEach(() => {
    db.close();
  });

  it("upsert 后 getAll 应回读完整 UserConfig（JSON 往返）", () => {
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
    repo.upsert("1", conf);
    expect(repo.getAll()["1"]).toEqual(conf);
    expect(repo.count()).toBe(1);
  });

  it("upsertAll 应事务全量覆盖（旧 uid 不残留）", () => {
    repo.upsertAll({ "1": { uid: "1" } as any, "2": { uid: "2" } as any });
    expect(repo.count()).toBe(2);
    repo.upsertAll({ "1": { uid: "1", password: "new" } as any });
    expect(repo.count()).toBe(1);
    expect(repo.getAll()["1"].password).toBe("new");
  });

  it("get 不存在返回 undefined", () => {
    expect(repo.get("999")).toBeUndefined();
  });

  it("get 存在返回对应 UserConfig", () => {
    repo.upsert("7", { uid: "7", password: "x" } as any);
    expect(repo.get("7")?.password).toBe("x");
  });
});

describe("migrateUsersFromJsonFile", () => {
  let db: DatabaseSync;
  let repo: UserRepository;

  beforeEach(() => {
    fileMock.readJson.mockReset();
    db = openDatabase(":memory:");
    db.exec(SCHEMA_SQL);
    repo = new UserRepository(db);
  });

  afterEach(() => {
    db.close();
  });

  it("users 表空时应从 users.json 导入", async () => {
    fileMock.readJson.mockResolvedValue({
      "1": { uid: "1", password: "p1" },
      "2": { uid: "2", password: "p2" },
    });
    const n = await migrateUsersFromJsonFile(db, repo);
    expect(n).toBe(2);
    expect(repo.count()).toBe(2);
    expect(repo.getAll()["2"].password).toBe("p2");
  });

  it("users 表非空时应跳过（幂等）", async () => {
    repo.upsert("9", { uid: "9" } as any);
    const n = await migrateUsersFromJsonFile(db, repo);
    expect(n).toBe(0);
    expect(repo.getAll()["9"]).toBeDefined();
    expect(repo.count()).toBe(1);
  });

  it("users.json 不存在时返回 0 不抛错", async () => {
    fileMock.readJson.mockRejectedValue(new Error("ENOENT"));
    const n = await migrateUsersFromJsonFile(db, repo);
    expect(n).toBe(0);
  });
});
