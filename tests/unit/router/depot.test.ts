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

const itemTable = vi.hoisted(() => ({
  items: {
    "30012": { sortId: 10, voucherRelateList: [{ voucherId: "voucher_mat_1", voucherItemType: "MATERIAL" }] },
    "30011": { sortId: 5, voucherRelateList: [{ voucherId: "voucher_mat_1", voucherItemType: "MATERIAL" }] },
    "4001": { sortId: 1 },
  },
}));

vi.mock("@utils/file", () => ({
  readJsonSync: vi.fn(() => voucherTable),
}));
vi.mock("@excel/excel", () => ({
  default: { ItemTable: itemTable },
}));
vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));
vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import { VoucherDataManager } from "../../../app/game/router/depot";
import depotRouter from "../../../app/game/router/depot";
import httpContext from "express-http-context2";

describe("VoucherDataManager", () => {
  it("getVoucher 应从 voucher.json 命中干员兑换券", () => {
    const info = VoucherDataManager.getVoucher("voucher_pick_1");
    expect(info).not.toBeNull();
    expect(info!.voucherType).toBe("CHAR_VOUCHER");
    expect(info!.itemList).toHaveLength(1);
  });

  it("getVoucher 应从 item_table 反向构建材料凭证", () => {
    const info = VoucherDataManager.getVoucher("voucher_mat_1");
    expect(info).not.toBeNull();
    expect(info!.voucherType).toBe("MATERIAL_VOUCHER");
    // 按 sortId 排序：30011(5) 在前，30012(10) 在后
    expect(info!.itemList.map((i) => i.id)).toEqual(["30011", "30012"]);
  });

  it("getVoucher 不存在的凭证应返回 null", () => {
    expect(VoucherDataManager.getVoucher("not_exist")).toBeNull();
  });

  it("findRelatedItems 应按 sortId 排序返回关联物品", () => {
    const items = VoucherDataManager.findRelatedItems("voucher_mat_1");
    expect(items.map((i) => i.itemId)).toEqual(["30011", "30012"]);
  });

  it("findRelatedItems 无关联物品应返回空数组", () => {
    expect(VoucherDataManager.findRelatedItems("nothing")).toEqual([]);
  });
});

describe("depot 路由", () => {
  function mockRes() {
    return {
      send: vi.fn(),
      status: vi.fn().mockReturnThis(),
      sendStatus: vi.fn(),
      json: vi.fn(),
    };
  }

  async function call(req: any, res: any) {
    depotRouter(req, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
    return res;
  }

  it("getVoucherDetail 应返回凭证详情与 delta", async () => {
    (vi.mocked(httpContext.get) as any).mockReturnValue({ delta: { modified: {} } });
    const res = mockRes();
    await call({ method: "POST", url: "/getVoucherDetail", body: { itemId: "voucher_pick_1" } }, res);
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ voucherType: "CHAR_VOUCHER", modified: {} }),
    );
  });

  it("getMaterialVoucherDetail 应返回材料凭证池", async () => {
    (vi.mocked(httpContext.get) as any).mockReturnValue({ delta: {} });
    const res = mockRes();
    await call({ method: "POST", url: "/getMaterialVoucherDetail", body: { itemId: "voucher_mat_1" } }, res);
    const arg = res.send.mock.calls[0][0];
    expect(arg.info.pool).toHaveLength(2);
    expect(arg.info.pool[0].itemId).toBe("30011");
  });

  it("voucherGacha 简化实现应返回 delta", async () => {
    (vi.mocked(httpContext.get) as any).mockReturnValue({ delta: { modified: {} } });
    const res = mockRes();
    await call({ method: "POST", url: "/voucherGacha", body: {} }, res);
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });
});
