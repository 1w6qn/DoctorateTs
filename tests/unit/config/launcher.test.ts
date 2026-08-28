import { describe, it, expect, vi } from "vitest";

const configMock = vi.hoisted(() => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },
 version: { clientVersion: "2.7.61" }, Host: "http://127.0.0.1", PORT: 8443 },
}));
vi.mock("@core/config/index", () => configMock);

import launcherRouter from "@core/config/launcher";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(req: any, res: any) {
  launcherRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 10));
  return res;
}

describe("启动器 launcher 路由", () => {
  it("get_latest 应返回 action:0 + 空包（无需更新）", async () => {
    const res = mockRes();
    await call({ method: "GET", url: "/get_latest", query: { version: "76.0.0", sub_channel: "1" } }, res);
    const arg = res.send.mock.calls[0][0];
    expect(arg.action).toBe(0);
    expect(arg.state).toBe(0);
    expect(arg.launcher_action).toBe(0);
    expect(arg.version).toBe("76.0.0");
    expect(arg.request_version).toBe("76.0.0");
    expect(arg.pkg.packs).toEqual([]);
    expect(arg.pkg.total_size).toBe("0");
    expect(arg.pkg.sub_channel).toBe("1");
    expect(arg.patch).toBeNull();
    expect(arg.pre_patch).toBeNull();
    expect(arg.client_version).toBe("2.7.61");
  });

  it("get_latest 无 version 参数时应回退默认 76.0.0", async () => {
    const res = mockRes();
    await call({ method: "GET", url: "/get_latest", query: {} }, res);
    expect(res.send.mock.calls[0][0].version).toBe("76.0.0");
  });
});
