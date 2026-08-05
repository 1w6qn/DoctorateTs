import { describe, it, expect } from "vitest";
import { getAdminConfig } from "../../../app/admin/admin-config";
import {
  buildMailItem,
  nextMailId,
  MailDB,
} from "../../../app/game/manager/mail";
import { now } from "../../../app/utils/time";

describe("admin 配置", () => {
  it("应能从 config 中读取 enable 与 token", () => {
    const cfg = getAdminConfig();
    expect(typeof cfg.enable).toBe("boolean");
    expect(typeof cfg.token).toBe("string");
  });
});

describe("buildMailItem", () => {
  it("应构造带物品的邮件（receiveAt=-1，hasItem=1）", () => {
    const mail = buildMailItem("1", {
      subject: "测试标题",
      content: "测试内容",
      items: [{ id: "4001", type: "GOLD", count: 100, ts: 0 }],
    }, 9000001);
    expect(mail.uid).toBe("1");
    expect(mail.subject).toBe("测试标题");
    expect(mail.hasItem).toBe(1);
    expect(mail.receiveAt).toBe(-1);
    expect(mail.items[0].count).toBe(100);
    expect(mail.mailId).toBe(9000001);
    expect(mail.createAt).toBeGreaterThan(0);
  });

  it("无物品时 hasItem=0", () => {
    const mail = buildMailItem("1", {
      subject: "空邮件",
      content: "无附件",
      items: [],
    }, 9000002);
    expect(mail.hasItem).toBe(0);
    expect(mail.items).toEqual([]);
  });

  it("缺省过期时间为 30 天后", () => {
    const mail = buildMailItem("1", { subject: "过期", content: "", items: [] }, 9000003);
    expect(mail.expireAt).toBeGreaterThan(now());
  });
});

describe("nextMailId", () => {
  const db: MailDB = { user: {} };

  it("空库返回最小值 1000000", () => {
    expect(nextMailId(db)).toBe(1000000);
  });

  it("应返回现有最大 mailId + 1", () => {
    db.user["1"] = [
      buildMailItem("1", { subject: "a", content: "", items: [] }, 999999),
      buildMailItem("1", { subject: "b", content: "", items: [] }, 1000001),
    ];
    expect(nextMailId(db)).toBe(1000002);
  });
});
