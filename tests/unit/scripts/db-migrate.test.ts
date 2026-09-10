import { describe, it, expect, afterEach, vi } from "vitest";
import { createDatabase } from "@core/db/database";
import type { SqlDatabase } from "@core/db/types";
import { copyTable, parseArgs, resolveTarget } from "../../../scripts/db-migrate";

/**
 * 跨后端搬迁脚本（scripts/db-migrate.ts）
 *
 * 端到端需要真实 MySQL / PostgreSQL 服务端；此处覆盖可离线验证的部分——
 * CLI 解析、目标配置合成、逐表复制（含二进制列）与 dry-run 语义。
 */
describe("parseArgs", () => {
  it("缺省：源为默认 SQLite 文件，目标待定（取配置），非 force/dry-run", () => {
    expect(parseArgs([])).toEqual({
      fromFile: "./data/user/social.db",
      to: undefined,
      file: undefined,
      host: undefined,
      port: undefined,
      user: undefined,
      password: undefined,
      database: undefined,
      force: false,
      dryRun: false,
    });
  });

  it("解析各连接参数与开关", () => {
    const a = parseArgs([
      "--from-file", "./old.db",
      "--to", "mysql",
      "--host", "db.local",
      "--port", "3307",
      "--user", "ak",
      "--password", "pw",
      "--database", "ark",
      "--force",
      "--dry-run",
    ]);
    expect(a).toMatchObject({
      fromFile: "./old.db",
      to: "mysql",
      host: "db.local",
      port: 3307,
      user: "ak",
      password: "pw",
      database: "ark",
      force: true,
      dryRun: true,
    });
  });

  it("后端别名归一：postgres/pg → postgresql，mariadb → mysql", () => {
    expect(parseArgs(["--to", "postgres"]).to).toBe("postgresql");
    expect(parseArgs(["--to", "PG"]).to).toBe("postgresql");
    expect(parseArgs(["--to", "mariadb"]).to).toBe("mysql");
  });

  it("未知后端应抛错（而非静默回退 sqlite）", () => {
    expect(() => parseArgs(["--to", "oracle"])).toThrow(/未知目标后端/);
  });
});

describe("resolveTarget", () => {
  it("未指定 --to 时取配置（本测试环境无 database 块 → sqlite 默认）", () => {
    expect(resolveTarget(parseArgs([]))).toEqual({
      backend: "sqlite",
      file: "./data/user/social.db",
    });
  });

  it("--to mysql 时用命令行参数覆盖配置", () => {
    const t = resolveTarget(
      parseArgs(["--to", "mysql", "--host", "h", "--user", "u", "--database", "d"]),
    );
    expect(t).toMatchObject({ backend: "mysql", host: "h", user: "u", database: "d" });
  });

  it("--to sqlite --file 指定目标文件", () => {
    expect(resolveTarget(parseArgs(["--to", "sqlite", "--file", "./new.db"]))).toEqual({
      backend: "sqlite",
      file: "./new.db",
    });
  });
});

describe("copyTable（跨后端整表复制）", () => {
  let source: SqlDatabase | null = null;
  let target: SqlDatabase | null = null;

  afterEach(async () => {
    await target?.close();
    await source?.close();
    source = null;
    target = null;
    vi.restoreAllMocks();
  });

  it("按主键覆盖写：行数一致且二进制列无损", async () => {
    source = await createDatabase({ backend: "sqlite", file: ":memory:" });
    target = await createDatabase({ backend: "sqlite", file: ":memory:" });

    const blob = Buffer.from([0x00, 0x01, 0xff, 0xfe, 0x80]);
    await source
      .prepare("INSERT INTO player_data (uid, data, updated_ts) VALUES (?, ?, ?)")
      .run("1", blob, 111);
    await source
      .prepare("INSERT INTO friends (uid, friend_uid, alias, create_ts, star) VALUES (?, ?, ?, ?, ?)")
      .run("1", "2", "阿米娅", 222, 1);

    await copyTable(source, target, "player_data", ["uid", "data", "updated_ts"], ["uid"], false);
    await copyTable(source, target, "friends", ["uid", "friend_uid", "alias", "create_ts", "star"], ["uid", "friend_uid"], false);

    const pd = await target
      .prepare("SELECT uid, data, updated_ts FROM player_data")
      .get<{ uid: string; data: Uint8Array; updated_ts: number }>();
    expect(pd?.uid).toBe("1");
    expect(pd?.updated_ts).toBe(111);
    expect(Array.from(pd!.data)).toEqual(Array.from(blob));

    const fr = await target
      .prepare("SELECT alias, star FROM friends WHERE uid = ? AND friend_uid = ?")
      .get<{ alias: string; star: number }>("1", "2");
    expect(fr).toEqual({ alias: "阿米娅", star: 1 });
  });

  it("重复复制不产生重复行（主键覆盖语义，可重复执行）", async () => {
    source = await createDatabase({ backend: "sqlite", file: ":memory:" });
    target = await createDatabase({ backend: "sqlite", file: ":memory:" });
    await source
      .prepare("INSERT INTO users (uid, data, updated_ts) VALUES (?, ?, ?)")
      .run("1", "{}", 1);

    await copyTable(source, target, "users", ["uid", "data", "updated_ts"], ["uid"], false);
    await copyTable(source, target, "users", ["uid", "data", "updated_ts"], ["uid"], false);

    const row = await target
      .prepare("SELECT COUNT(*) AS n FROM users")
      .get<{ n: number }>();
    expect(Number(row?.n)).toBe(1);
  });

  it("dry-run 只统计不写入", async () => {
    source = await createDatabase({ backend: "sqlite", file: ":memory:" });
    target = await createDatabase({ backend: "sqlite", file: ":memory:" });
    await source
      .prepare("INSERT INTO users (uid, data, updated_ts) VALUES (?, ?, ?)")
      .run("1", "{}", 1);

    const n = await copyTable(source, target, "users", ["uid", "data", "updated_ts"], ["uid"], true);
    expect(n).toBe(1);
    const row = await target.prepare("SELECT COUNT(*) AS n FROM users").get<{ n: number }>();
    expect(Number(row?.n)).toBe(0);
  });
});
