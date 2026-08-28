import { describe, it, expect, vi } from "vitest";

vi.mock("@excel/excel", () => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

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

import mailCollectionRouter from "@game/modules/mail/mailCollection.routes";

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
