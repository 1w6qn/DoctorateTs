import { describe, it, expect } from "vitest";
import {
  convertPlaceholders,
  insertIgnoreSql,
  insertReplaceSql,
  normalizeParams,
  toCount,
} from "@core/db/dialect";
import { buildSchemaSql, physicalType, TABLES } from "@core/db/schema";
import { loadOptionalDriver } from "@core/db/drivers/load";
import { describeDatabase } from "@core/db/config";

/**
 * 多后端支持：方言层的纯函数测试
 *
 * MySQL / PostgreSQL 需要真实服务端才能端到端验证，此处覆盖可离线验证的部分——
 * SQL 生成、占位符改写、参数归一化、建表 DDL、可选驱动缺失时的错误文案。
 */
describe("dialect：忽略冲突插入（insertIgnoreSql）", () => {
  it("三种后端各自生成正确语法", () => {
    const cols = ["uid", "friend_uid"];
    expect(insertIgnoreSql("sqlite", "friends", cols)).toBe(
      "INSERT OR IGNORE INTO friends (uid, friend_uid) VALUES (?, ?)",
    );
    expect(insertIgnoreSql("mysql", "friends", cols)).toBe(
      "INSERT IGNORE INTO friends (uid, friend_uid) VALUES (?, ?)",
    );
    expect(insertIgnoreSql("postgresql", "friends", cols)).toBe(
      "INSERT INTO friends (uid, friend_uid) VALUES (?, ?) ON CONFLICT DO NOTHING",
    );
  });
});

describe("dialect：覆盖写入（insertReplaceSql）", () => {
  it("SQLite 用 INSERT OR REPLACE", () => {
    expect(
      insertReplaceSql("sqlite", "visited", ["uid", "visited_uid", "ts"], ["uid", "visited_uid"]),
    ).toBe("INSERT OR REPLACE INTO visited (uid, visited_uid, ts) VALUES (?, ?, ?)");
  });

  it("MySQL 用 ON DUPLICATE KEY UPDATE（主键列不出现在更新集）", () => {
    const sql = insertReplaceSql(
      "mysql",
      "visited",
      ["uid", "visited_uid", "ts"],
      ["uid", "visited_uid"],
    );
    expect(sql).toBe(
      "INSERT INTO visited (uid, visited_uid, ts) VALUES (?, ?, ?) " +
        "ON DUPLICATE KEY UPDATE ts = VALUES(ts)",
    );
    expect(sql).not.toContain("uid = VALUES(uid)");
  });

  it("PostgreSQL 用 ON CONFLICT (列) DO UPDATE SET ... EXCLUDED", () => {
    expect(
      insertReplaceSql("postgresql", "visited", ["uid", "visited_uid", "ts"], ["uid", "visited_uid"]),
    ).toBe(
      "INSERT INTO visited (uid, visited_uid, ts) VALUES (?, ?, ?) " +
        "ON CONFLICT (uid, visited_uid) DO UPDATE SET ts = EXCLUDED.ts",
    );
  });
});

describe("dialect：占位符改写（convertPlaceholders）", () => {
  it("PostgreSQL 改写为 $1..$n 且顺序正确", () => {
    expect(convertPlaceholders("SELECT * FROM t WHERE a = ? AND b = ?", "postgresql")).toBe(
      "SELECT * FROM t WHERE a = $1 AND b = $2",
    );
  });

  it("非 PostgreSQL 后端原样返回", () => {
    const sql = "SELECT * FROM t WHERE a = ?";
    expect(convertPlaceholders(sql, "sqlite")).toBe(sql);
    expect(convertPlaceholders(sql, "mysql")).toBe(sql);
  });

  it("跳过单引号字符串字面量内的 ?（不误判为占位符）", () => {
    expect(
      convertPlaceholders("SELECT '?' AS q FROM t WHERE a = ?", "postgresql"),
    ).toBe("SELECT '?' AS q FROM t WHERE a = $1");
  });

  it("跳过 '' 转义的单引号后仍能继续计数", () => {
    expect(
      convertPlaceholders("SELECT 'it''s ?' AS q, ? FROM t", "postgresql"),
    ).toBe("SELECT 'it''s ?' AS q, $1 FROM t");
  });

  it("跳过 -- 行注释内的 ?", () => {
    expect(
      convertPlaceholders("SELECT ? -- 注释里的 ?\nFROM t", "postgresql"),
    ).toBe("SELECT $1 -- 注释里的 ?\nFROM t");
  });
});

describe("dialect：参数归一化与计数", () => {
  it("undefined → null，boolean → 1/0（node:sqlite 不接受该两种绑定）", () => {
    expect(normalizeParams([undefined, true, false, "x", 1])).toEqual([null, 1, 0, "x", 1]);
  });

  it("toCount 兼容 number / bigint / 数字字符串（pg 的 COUNT 返回字符串）", () => {
    expect(toCount(5)).toBe(5);
    expect(toCount(5n)).toBe(5);
    expect(toCount("7")).toBe(7);
    expect(toCount(null)).toBe(0);
    expect(toCount("abc")).toBe(0);
  });
});

describe("schema：物理类型映射", () => {
  it("二进制列三后端各不相同（BLOB / LONGBLOB / BYTEA）", () => {
    expect(physicalType("blob", "sqlite")).toBe("BLOB");
    expect(physicalType("blob", "mysql")).toBe("LONGBLOB");
    expect(physicalType("blob", "postgresql")).toBe("BYTEA");
  });

  it("MySQL 短标识用 VARCHAR(191)（utf8mb4 索引键长限制；TEXT 不能作主键）", () => {
    expect(physicalType("uid", "mysql")).toBe("VARCHAR(191)");
    expect(physicalType("longtext", "mysql")).toBe("LONGTEXT");
  });

  it("毫秒时间戳三后端均为 64 位（INT4 上限 2.1e9 装不下 1.7e12）", () => {
    expect(physicalType("bigint", "sqlite")).toBe("INTEGER");
    expect(physicalType("bigint", "mysql")).toBe("BIGINT");
    expect(physicalType("bigint", "postgresql")).toBe("BIGINT");
  });
});

describe("schema：建表 DDL 生成", () => {
  it("覆盖全部声明表", () => {
    const sql = buildSchemaSql("sqlite");
    for (const t of TABLES) expect(sql).toContain(`CREATE TABLE IF NOT EXISTS ${t.name}`);
  });

  it("SQLite：CREATE INDEX IF NOT EXISTS，无 MySQL 表选项", () => {
    const sql = buildSchemaSql("sqlite");
    expect(sql).toContain("CREATE INDEX IF NOT EXISTS idx_friends_friend");
    expect(sql).not.toContain("ENGINE=InnoDB");
  });

  it("MySQL：索引内联为 KEY（MySQL 不支持 CREATE INDEX IF NOT EXISTS）", () => {
    const sql = buildSchemaSql("mysql");
    expect(sql).toContain("KEY idx_friends_friend (friend_uid)");
    expect(sql).not.toContain("CREATE INDEX IF NOT EXISTS");
    expect(sql).toContain("ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    expect(sql).toContain("data LONGBLOB NOT NULL");
  });

  it("PostgreSQL：独立 CREATE INDEX IF NOT EXISTS + BYTEA", () => {
    const sql = buildSchemaSql("postgresql");
    expect(sql).toContain("CREATE INDEX IF NOT EXISTS idx_friends_friend");
    expect(sql).toContain("data BYTEA NOT NULL");
    expect(sql).not.toContain("ENGINE=InnoDB");
  });

  it("幂等：DDL 只使用 IF NOT EXISTS 形式", () => {
    for (const backend of ["sqlite", "mysql", "postgresql"] as const) {
      const sql = buildSchemaSql(backend);
      const creates = sql.match(/CREATE (TABLE|INDEX)[^;]*/g) ?? [];
      expect(creates.length).toBeGreaterThan(0);
      for (const c of creates) expect(c).toContain("IF NOT EXISTS");
    }
  });
});

describe("可选驱动加载（loadOptionalDriver）", () => {
  it("未安装时抛出带安装指引的错误（而非裸 MODULE_NOT_FOUND）", async () => {
    await expect(
      loadOptionalDriver("no-such-driver-pkg-xyz", "no-such-driver-pkg-xyz", "测试后端"),
    ).rejects.toThrow(/pnpm add no-such-driver-pkg-xyz/);
  });

  it("已安装的可选驱动可正常加载", async () => {
    const mysql2 = await loadOptionalDriver<any>("mysql2/promise", "mysql2", "MySQL 后端");
    expect(typeof mysql2.createPool).toBe("function");
    const pg = await loadOptionalDriver<any>("pg", "pg", "PostgreSQL 后端");
    expect(typeof pg.Pool).toBe("function");
  });
});

describe("describeDatabase：日志描述不含密码", () => {
  it("sqlite 显示文件路径", () => {
    expect(describeDatabase({ backend: "sqlite", file: "./x.db" })).toBe("sqlite:./x.db");
  });

  it("网络型后端显示 user@host:port/db，不含密码", () => {
    const s = describeDatabase({
      backend: "mysql",
      host: "db.example.com",
      port: 3307,
      user: "ak",
      password: "supersecret",
      database: "ark",
    });
    expect(s).toBe("mysql://ak@db.example.com:3307/ark");
    expect(s).not.toContain("supersecret");
  });

  it("端口缺省按后端取默认值", () => {
    expect(describeDatabase({ backend: "postgresql" })).toBe(
      "postgresql://-@127.0.0.1:5432/arknights",
    );
  });
});
