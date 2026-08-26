import { describe, it, expect, vi } from "vitest";

vi.mock("@excel/excel", () => ({
  default: {
    DisplayMetaTable: {
      mailArchiveData: {
        mailArchiveInfoDict: {
          "mail_archive_001": {},
          "mail_archive_002": {},
        },
      },
    },
  },
}));

import mailCollectionRouter from "../../../app/game/service/router/mailCollection";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(req: any, res: any) {
  mailCollectionRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("mailCollection 路由（OBS 移植端点）", () => {
  it("getList 应返回收藏邮件列表与 extra（对齐 OBS bp_mail）", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/getList", body: {} }, res);
    expect(res.send).toHaveBeenCalledWith({
      collections: ["mail_archive_001", "mail_archive_002"],
      extra: [],
    });
  });
});
