import { describe, it, expect } from "vitest";
import { logger, text2color } from "@utils/logger";

describe("logger", () => {
  it("应提供统一的分级日志方法", () => {
    expect(typeof logger.debug).toBe("function");
    expect(typeof logger.info).toBe("function");
    expect(typeof logger.warn).toBe("function");
    expect(typeof logger.error).toBe("function");
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
