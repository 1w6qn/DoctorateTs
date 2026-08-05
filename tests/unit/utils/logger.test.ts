import { describe, it, expect } from "vitest";
import { logger, text2color } from "@utils/logger";

describe("logger", () => {
  it("应引用 console 作为日志记录器", () => {
    expect(logger).toBe(console);
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
