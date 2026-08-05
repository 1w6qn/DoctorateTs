import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));
vi.mock("@game/manager/mail", () => ({
  MailManager: vi.fn(),
  mailManager: {
    listMailbox: vi.fn().mockResolvedValue([{ mailId: 1 }]),
    receiveMail: vi.fn().mockResolvedValue([{ id: "30012", type: "MATERIAL", count: 1 }]),
    getMetaInfoList: vi.fn().mockResolvedValue([{ mailId: 1 }]),
    receiveAllMail: vi.fn().mockResolvedValue([{ id: "4001", type: "GOLD", count: 100 }]),
    removeAllReceivedMail: vi.fn().mockResolvedValue(undefined),
  },
}));

import mailRouter from "../../../app/game/router/mail";
import httpContext from "express-http-context2";
import { mailManager } from "@game/manager/mail";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(req: any, res: any) {
  mailRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("mail 路由", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (vi.mocked(httpContext.get) as any).mockReturnValue({
      uid: "10000",
      status: { uid: "10000" },
      delta: { modified: {} },
    });
  });

  it("listMailbox 应返回邮件列表", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/listMailbox", body: { mailIdList: [1] } }, res);
    expect(mailManager.listMailbox).toHaveBeenCalledWith("10000", { mailIdList: [1] });
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ mailList: [{ mailId: 1 }] }));
  });

  it("receiveMail 应返回领取附件", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/receiveMail", body: { mailId: 1, type: 0 } }, res);
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ items: [{ id: "30012", type: "MATERIAL", count: 1 }] }));
  });

  it("getMetaInfoList 应返回元信息", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/getMetaInfoList", body: { from: 0 } }, res);
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ result: [{ mailId: 1 }] }));
  });

  it("receiveAllMail 应批量领取", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/receiveAllMail", body: { mailIdList: [1] } }, res);
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ items: [{ id: "4001", type: "GOLD", count: 100 }] }));
  });

  it("removeAllReceivedMail 应清理邮件", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/removeAllReceivedMail", body: { mailIdList: [1] } }, res);
    expect(mailManager.removeAllReceivedMail).toHaveBeenCalledWith("10000", { mailIdList: [1] });
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });
});
