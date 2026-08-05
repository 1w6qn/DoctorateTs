import { describe, it, expect } from "vitest";
import { getAdminConfig } from "../../../app/admin/admin-config";

describe("admin 配置", () => {
  it("应能从 config 中读取 enable 与 token", () => {
    const cfg = getAdminConfig();
    expect(typeof cfg.enable).toBe("boolean");
    expect(typeof cfg.token).toBe("string");
  });
});
