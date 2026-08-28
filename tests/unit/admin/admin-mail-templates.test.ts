import { describe, it, expect } from "vitest";
import { MAIL_TEMPLATES, expandTemplate } from "@ops/admin/mail-templates";

describe("邮件模板", () => {
  it("应包含补偿/公告/欢迎模板", () => {
    const names = MAIL_TEMPLATES.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(["补偿", "公告", "欢迎"]));
  });

  it("expandTemplate 应按名称匹配并替换占位符", () => {
    const t = expandTemplate("补偿", { date: "2026-08-09" });
    expect(t!.subject).toBe("补偿发放");
    expect(t!.content).toContain("2026-08-09");
    expect(t!.items.length).toBeGreaterThan(0);
  });

  it("expandTemplate 支持包含匹配", () => {
    expect(expandTemplate("公", {})!.name).toBe("公告");
  });

  it("expandTemplate 未知模板应返回 null", () => {
    expect(expandTemplate("不存在", {})).toBeNull();
  });
});
