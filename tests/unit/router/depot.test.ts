import { describe, it, expect, vi } from "vitest";

const voucherTable = vi.hoisted(() => ({
  "voucher_pick_1": {
    voucherType: "CHAR_VOUCHER",
    pickNum: 1,
    voucherBgDec: null,
    extraDataDic: {},
    itemList: [{ id: "char_001", count: 1, type: "CHAR" }],
    validTimeInfo: { startTs: -1, endTs: -1 },
  },
}));

/** item_table 行夹具形状（本文件读到的字段子集） */
interface VoucherItemRow {
  name?: string;
  sortId?: number;
  voucherRelateList?: { voucherId: string; voucherItemType: string }[];
}

const itemTable = vi.hoisted<{ items: Record<string, VoucherItemRow> }>(() => ({
  items: {
    "30012": { sortId: 10, voucherRelateList: [{ voucherId: "voucher_mat_1", voucherItemType: "MATERIAL" }] },
    "30011": { sortId: 5, voucherRelateList: [{ voucherId: "voucher_mat_1", voucherItemType: "MATERIAL" }] },
    "4001": { sortId: 1 },
  },
}));

vi.mock("@utils/file", () => ({
  readJsonSync: vi.fn(() => voucherTable),
}));
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
    CharacterTable: undefined as Record<string, ExcelCharRowMock> | undefined,
    StageTable: undefined as { stages?: Record<string, ExcelRowMock> } | undefined,
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string): ExcelRowMock | undefined { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string): ExcelCharRowMock | undefined { return this.CharacterTable?.[charId]; },
    stageData(stageId: string): ExcelRowMock | undefined { return this.StageTable?.stages?.[stageId]; },
 ItemTable: itemTable },
}));
vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import excel from "@excel/excel";
import { voucherService } from "@game/modules/depot/voucher";
import depotRouter from "@game/modules/depot/routes";
import httpContext from "express-http-context2";
import type { Response } from "express";
import { mockGainItem } from "../../helpers";

/** 凭证请求体视图（本文件各端点字段合集） */
interface DepotBody {
  itemId?: string;
  instId?: number;
  count?: number;
  choices?: { id: string; count: number }[];
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: DepotBody;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

type RouterReq = Parameters<typeof depotRouter>[0];

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    sendStatus: vi.fn<Response["sendStatus"]>(),
    json: vi.fn<Response["json"]>(),
  };
}

describe("VoucherService", () => {
  it("getVoucher 应从 voucher.json 命中干员兑换券", () => {
    const info = voucherService.getVoucher("voucher_pick_1", excel);
    expect(info).not.toBeNull();
    expect(info!.voucherType).toBe("CHAR_VOUCHER");
    expect(info!.itemList).toHaveLength(1);
  });

  it("getVoucher 应从 item_table 反向构建材料凭证", () => {
    const info = voucherService.getVoucher("voucher_mat_1", excel);
    expect(info).not.toBeNull();
    expect(info!.voucherType).toBe("MATERIAL_VOUCHER");
    // 按 sortId 排序：30011(5) 在前，30012(10) 在后
    expect(info!.itemList.map((i) => i.id)).toEqual(["30011", "30012"]);
  });

  it("getVoucher 不存在的凭证应返回 null", () => {
    expect(voucherService.getVoucher("not_exist", excel)).toBeNull();
  });

  it("findRelatedItems 应按 sortId 排序返回关联物品", () => {
    const items = voucherService.findRelatedItems("voucher_mat_1", excel);
    expect(items.map((i) => i.itemId)).toEqual(["30011", "30012"]);
  });

  it("findRelatedItems 无关联物品应返回空数组", () => {
    expect(voucherService.findRelatedItems("nothing", excel)).toEqual([]);
  });
});

describe("depot 路由", () => {
  async function call(req: MockReq, res: MockRes): Promise<MockRes> {
    // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
    depotRouter(req as RouterReq, res as Response, () => {});
    await new Promise((r) => setTimeout(r, 20));
    return res;
  }

  it("getVoucherDetail 应返回凭证详情与 delta", async () => {
    vi.mocked(httpContext.get).mockReturnValue({ delta: { modified: {} }, excel });
    const res = mockRes();
    await call({ method: "POST", url: "/getVoucherDetail", body: { itemId: "voucher_pick_1" } }, res);
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ voucherType: "CHAR_VOUCHER", modified: {} }),
    );
  });

  it("getMaterialVoucherDetail 应返回材料凭证池", async () => {
    vi.mocked(httpContext.get).mockReturnValue({ delta: {}, excel });
    const res = mockRes();
    await call({ method: "POST", url: "/getMaterialVoucherDetail", body: { itemId: "voucher_mat_1" } }, res);
    const arg = vi.mocked(res.send).mock.calls[0][0];
    expect(arg.info.pool).toHaveLength(2);
    expect(arg.info.pool[0].itemId).toBe("30011");
  });

  it("voucherGacha 简化实现应返回 delta", async () => {
    vi.mocked(httpContext.get).mockReturnValue({ delta: { modified: {} } });
    const res = mockRes();
    await call({ method: "POST", url: "/voucherGacha", body: {} }, res);
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });

  it("useMaterialVoucher 材料池为空时不应消耗凭证（防白扣）", async () => {
    const player = { delta: {}, excel, gainItem: mockGainItem() };
    vi.mocked(httpContext.get).mockReturnValue(player);
    const res = mockRes();
    await call(
      { method: "POST", url: "/useMaterialVoucher", body: { itemId: "no_pool_voucher", instId: 1, count: 1 } },
      res,
    );
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ itemGet: [] }));
    // 不消耗（管道无任何入队/执行）
    expect(player.gainItem.use).not.toHaveBeenCalled();
    expect(player.gainItem.add).not.toHaveBeenCalled();
  });

  it("useMaterialVoucher 有池时应扣凭证并发放材料", async () => {
    const player = {
      delta: {},
      excel,
      gainItem: mockGainItem(),
      // 修复：使用凭证前需持有足量 consumable 实例
      _playerdata: { consumable: { voucher_mat_1: { 1: { count: 2 } } } },
    };
    vi.mocked(httpContext.get).mockReturnValue(player);
    const res = mockRes();
    await call(
      { method: "POST", url: "/useMaterialVoucher", body: { itemId: "voucher_mat_1", instId: 1, count: 2 } },
      res,
    );
    const arg = vi.mocked(res.send).mock.calls[0][0];
    expect(arg.itemGet).toHaveLength(2);
    expect(player.gainItem.add).toHaveBeenCalledWith({ id: "voucher_mat_1", count: 2, instId: 1 });
    expect(player.gainItem.use).toHaveBeenCalled();
  });

  // 修复（2026-09-09）：count 必须为正整数 —— 原实现 `count || 1` 直接透传负数，
  // 而 items:use 对负数走反向入账分支（items:get 发放 -count 个）→ 凭空复制凭证。
  it("useMaterialVoucher 负数 count 应拒绝（防凭证复制）", async () => {
    const player = {
      delta: {},
      excel,
      gainItem: mockGainItem(),
      _playerdata: { consumable: { voucher_mat_1: { 1: { count: 5 } } } },
    };
    vi.mocked(httpContext.get).mockReturnValue(player);
    const res = mockRes();
    await call(
      { method: "POST", url: "/useMaterialVoucher", body: { itemId: "voucher_mat_1", instId: 1, count: -5 } },
      res,
    );
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ itemGet: [] }));
    // 全程无消耗、无发放（原实现会走 items:use(count:-5) → 反向发放 5 张）
    expect(player.gainItem.use).not.toHaveBeenCalled();
    expect(player.gainItem.add).not.toHaveBeenCalled();
  });

  it("useMaterialVoucher 非整数 count（1.5）应拒绝", async () => {
    const player = {
      delta: {},
      excel,
      gainItem: mockGainItem(),
      _playerdata: { consumable: { voucher_mat_1: { 1: { count: 5 } } } },
    };
    vi.mocked(httpContext.get).mockReturnValue(player);
    const res = mockRes();
    await call(
      { method: "POST", url: "/useMaterialVoucher", body: { itemId: "voucher_mat_1", instId: 1, count: 1.5 } },
      res,
    );
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ itemGet: [] }));
    expect(player.gainItem.use).not.toHaveBeenCalled();
    expect(player.gainItem.add).not.toHaveBeenCalled();
  });

  it("useOptionVoucher 非法 choices（负数/不在凭证列表）应拒绝发放", async () => {
    const player = { delta: {}, excel, gainItem: mockGainItem() };
    vi.mocked(httpContext.get).mockReturnValue(player);
    const res = mockRes();
    // 负数数量
    await call(
      { method: "POST", url: "/useOptionVoucher", body: { itemId: "voucher_pick_1", instId: 1, choices: [{ id: "char_001", count: -5 }] } },
      res,
    );
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ itemGet: [] }));
    // 不在凭证 itemList 的物品
    await call(
      { method: "POST", url: "/useOptionVoucher", body: { itemId: "voucher_pick_1", instId: 1, choices: [{ id: "char_999", count: 1 }] } },
      res,
    );
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ itemGet: [] }));
    // 全程无消耗、无发放
    expect(player.gainItem.use).not.toHaveBeenCalled();
    expect(player.gainItem.add).not.toHaveBeenCalled();
  });

  it("useOptionVoucher 合法 choices 应消耗并发放", async () => {
    const player = {
      delta: {},
      excel,
      gainItem: mockGainItem(),
      // 修复：使用凭证前需持有足量 consumable 实例
      _playerdata: { consumable: { voucher_pick_1: { 1: { count: 1 } } } },
    };
    vi.mocked(httpContext.get).mockReturnValue(player);
    const res = mockRes();
    await call(
      { method: "POST", url: "/useOptionVoucher", body: { itemId: "voucher_pick_1", instId: 1, choices: [{ id: "char_001", count: 1 }] } },
      res,
    );
    const arg = vi.mocked(res.send).mock.calls[0][0];
    expect(arg.itemGet).toEqual([{ id: "char_001", count: 1 }]);
    expect(player.gainItem.add).toHaveBeenCalledWith({ id: "voucher_pick_1", count: 1, instId: 1 });
    expect(player.gainItem.use).toHaveBeenCalled();
  });
});
