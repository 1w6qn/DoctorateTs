import { describe, it, expect, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { logger, flush, text2color } from "@utils/logger";

const tempDirs: string[] = [];

afterEach(() => {
  // 清理测试产生的临时日志目录
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  delete process.env.LOG_DIR;
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
