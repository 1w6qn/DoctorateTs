import { describe, it, expect, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { logger, flush, subscribeLog, text2color } from "@utils/logger";

const tempDirs: string[] = [];

afterEach(() => {
  // 清理测试产生的临时日志目录
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  delete process.env.LOG_DIR;
  delete process.env.LOG_MAX_BYTES;
  delete process.env.LOG_RETAIN_DAYS;
});

describe("logger", () => {
  it("应提供统一的分级日志方法", () => {
    expect(typeof logger.debug).toBe("function");
    expect(typeof logger.info).toBe("function");
    expect(typeof logger.warn).toBe("function");
    expect(typeof logger.error).toBe("function");
  });

  it("应将日志同步落盘到 LOG_DIR 指定目录（去 ANSI 色码）", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zcode-log-"));
    tempDirs.push(dir);
    process.env.LOG_DIR = dir;

    logger.warn("test-tag", "file-line-1", { a: 1 });
    logger.info("test-tag", "plain message", 42);
    flush(); // 批量缓冲落盘——断言前显式 flush（A-1）

    const d = new Date();
    const p = (n: number) => String(n).padStart(2, "0");
    const file = path.join(
      dir,
      `server-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}.log`,
    );
    expect(fs.existsSync(file)).toBe(true);

    const content = fs.readFileSync(file, "utf-8");
    // 纯文本、含级别/标签/内容
    expect(content).toContain("[WARN]");
    expect(content).toContain("[test-tag]");
    expect(content).toContain("file-line-1");
    expect(content).toContain('{"a":1}');
    expect(content).toContain("[INFO]");
    expect(content).toContain("plain message");
    // 不含 ANSI 色码（\x1b[）
    expect(content).not.toContain("\x1b[");
  });

  it("Error 参数应记录 stack 而非 [object Object]", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zcode-log-"));
    tempDirs.push(dir);
    process.env.LOG_DIR = dir;

    logger.error("test-tag", new Error("boom"));
    flush(); // 批量缓冲落盘——断言前显式 flush（A-1）

    const d = new Date();
    const p = (n: number) => String(n).padStart(2, "0");
    const file = path.join(
      dir,
      `server-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}.log`,
    );
    const content = fs.readFileSync(file, "utf-8");
    expect(content).toContain("Error: boom");
    expect(content).toContain("at ");
  });

  it("subscribeLog 实时订阅通过级别过滤的日志事件；退订后不再收到", () => {
    const events: { level: string; tag: string; text: string }[] = [];
    const unsub = subscribeLog((e) => events.push({ level: e.level, tag: e.tag, text: e.text }));
    logger.info("evt-tag", "hello", { a: 1 });
    logger.error("evt-tag", "boom");
    expect(events.length).toBe(2);
    expect(events[0]).toMatchObject({ level: "info", tag: "evt-tag", text: "hello {\"a\":1}" });
    expect(events[1]).toMatchObject({ level: "error", tag: "evt-tag", text: "boom" });
    unsub();
    logger.info("evt-tag", "after-unsub");
    expect(events.length).toBe(2);
  });
});

describe("text2color", () => {
  it("应包含全部稀有度颜色映射", () => {
    expect(text2color["TIER_6"]).toBe("#FF0000");
    expect(text2color["TIER_5"]).toBe("#FFFF00");
    expect(text2color["TIER_4"]).toBe("#FF00FF");
    expect(text2color["TIER_3"]).toBe("#0000FF");
    expect(text2color["TIER_2"]).toBe("#FFFFFF");
    expect(text2color["TIER_1"]).toBe("#FFFFFF");
  });
});

describe("logger 日志上限保护（防止超大日志）", () => {
  /** 今天文件名（与 logger 一致） */
  function todayFile(dir: string): string {
    const d = new Date();
    const p = (n: number) => String(n).padStart(2, "0");
    return path.join(
      dir,
      `server-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}.log`,
    );
  }

  it("单文件超过大小上限时轮转归档（生成 .N 文件）", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zcode-log-rot-"));
    tempDirs.push(dir);
    process.env.LOG_DIR = dir;
    process.env.LOG_MAX_BYTES = "50"; // 极小上限，快速触发轮转

    // 分多次 flush 让文件逐步增长，最终跨过上限触发轮转
    for (let i = 0; i < 6; i++) {
      logger.info("rot", "short-line-" + i);
      flush();
    }

    const base = todayFile(dir);
    // 同一日期归档文件 server-YYYYMMDD.log.N 已生成
    expect(fs.readdirSync(dir).some((n) => n === `${base.split(path.sep).pop()}.1`)).toBe(true);
    // 当前文件仍在且未消失，可继续写入
    expect(fs.existsSync(base)).toBe(true);
    const re = /^server-\d{8}\.log(\.\d+)?$/;
    // 总日志文件（含归档）不超 MAX_ARCHIVES+1
    const total = fs.readdirSync(dir).filter((n) => re.test(n)).length;
    expect(total).toBeLessThanOrEqual(1 + 5);
  });

  it("清理早于保留天数的旧日志，保留当天日志", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zcode-log-prune-"));
    tempDirs.push(dir);
    process.env.LOG_DIR = dir;
    process.env.LOG_RETAIN_DAYS = "2";

    // 预写一个很久以前的日志（应被清理）
    fs.writeFileSync(path.join(dir, "server-20200101.log"), "old line\n");
    // 归档形式的旧文件也应被清理
    fs.writeFileSync(path.join(dir, "watchdog-20200101.log"), "old watchdog\n");

    logger.info("prune", "current");
    flush();

    expect(fs.existsSync(path.join(dir, "server-20200101.log"))).toBe(false);
    expect(fs.existsSync(path.join(dir, "watchdog-20200101.log"))).toBe(false);
    expect(fs.existsSync(todayFile(dir))).toBe(true);
  });
});
