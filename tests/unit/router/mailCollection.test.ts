import { describe, it, expect, vi } from "vitest";

/** excel mock 行形状（本文件用到的字段子集） */
interface ExcelRowMock {
  name?: string;
}

/** 干员行夹具形状（本文件用到的字段子集） */
interface ExcelCharRowMock {
  charId?: string;
  rarity?: string;
  profession?: string;
}

vi.mock("@excel/excel", () => ({
  default: {
    ItemTable: undefined as { items?: Record<string, ExcelRowMock> } | undefined,
    CharacterTable: undefined as Record<string, ExcelCharRowMock> | undefined,
    StageTable: undefined as { stages?: Record<string, ExcelRowMock> } | undefined,
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string): ExcelRowMock | undefined { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string): ExcelCharRowMock | undefined { return this.CharacterTable?.[charId]; },
    stageData(stageId: string): ExcelRowMock | undefined { return this.StageTable?.stages?.[stageId]; },

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

import type { Response } from "express";
/** 路由测试请求体视图（本文件各端点字段合集） */
interface MailCollectionBody {
  [key: string]: never;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: MailCollectionBody;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

type RouterReq = Parameters<typeof mailCollectionRouter>[0];

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    sendStatus: vi.fn<Response["sendStatus"]>(),
    json: vi.fn<Response["json"]>(),
  };
}

async function call(req: MockReq, res: MockRes): Promise<MockRes> {
  // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
  mailCollectionRouter(req as RouterReq, res as Response, () => {});
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
