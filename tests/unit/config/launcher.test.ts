import { describe, it, expect, vi } from "vitest";
import type { Request, Response } from "express";

/** excel 行夹具视图（本文件不读取行字段） */
interface ExcelRowMock {
  name?: string;
}

/**
 * `@core/config/index` 替身夹具视图
 *
 * 只声明本文件写入的成员；excel 门面方法与 `ItemTable`/`CharacterTable`/`StageTable`
 * 占位是历史冗余成员（launcher 不读取），保留原样以免改变运行期替身形状。
 */
interface ConfigMockFixture {
  default: {
    getItem(id: string): ExcelRowMock | undefined;
    itemName(id: string): string;
    makeItem(id: string, count: number, type?: string): { id: string; count: number; type?: string };
    charData(charId: string): ExcelRowMock | undefined;
    stageData(stageId: string): ExcelRowMock | undefined;
    ItemTable?: { items?: Record<string, ExcelRowMock> };
    CharacterTable?: Record<string, ExcelRowMock>;
    StageTable?: { stages?: Record<string, ExcelRowMock> };
    version: { clientVersion: string };
    Host: string;
    PORT: number;
  };
}

const configMock = vi.hoisted(
  (): ConfigMockFixture => ({
    default: {
      // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
      getItem(id: string) {
        return this.ItemTable?.items?.[id];
      },
      itemName(id: string): string {
        return this.getItem(id)?.name ?? id;
      },
      makeItem(id: string, count: number, type?: string) {
        return type ? { id, count, type } : { id, count };
      },
      charData(charId: string) {
        return this.CharacterTable?.[charId];
      },
      stageData(stageId: string) {
        return this.StageTable?.stages?.[stageId];
      },
      ItemTable: undefined as { items?: Record<string, ExcelRowMock> } | undefined,
      CharacterTable: undefined as Record<string, ExcelRowMock> | undefined,
      StageTable: undefined as { stages?: Record<string, ExcelRowMock> } | undefined,
      version: { clientVersion: "2.7.61" },
      Host: "http://127.0.0.1",
      PORT: 8443,
    },
  }),
);
vi.mock("@core/config/index", () => configMock);

import launcherRouter from "@core/config/launcher";

/** 路由测试响应视图：只声明本文件读到的四个方法 */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

/** 路由测试请求视图：launcher 只读 method/url/query */
interface MockReq {
  method: Request["method"];
  url: Request["url"];
  query: Request["query"];
}

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    sendStatus: vi.fn<Response["sendStatus"]>(),
    json: vi.fn<Response["json"]>(),
  };
}

async function call(req: MockReq, res: MockRes) {
  launcherRouter(req as Request, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 10));
  return res;
}

describe("启动器 launcher 路由", () => {
  it("get_latest 应返回 action:0 + 空包（无需更新）", async () => {
    const res = mockRes();
    await call({ method: "GET", url: "/get_latest", query: { version: "76.0.0", sub_channel: "1" } }, res);
    const arg = vi.mocked(res.send).mock.calls[0][0];
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
    expect(vi.mocked(res.send).mock.calls[0][0].version).toBe("76.0.0");
  });
});
