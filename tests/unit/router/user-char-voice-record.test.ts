import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
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
    ActivityTable: {
      missionArchives: {
        mission_archive_main_14: {
          topicId: "mission_archive_main_14",
          nodes: [
            { nodeId: "main_node_1", clips: [{ charId: "char_4134_cetsyr", voiceId: "EX_CN_101", index: 1 }] },
            { nodeId: "main_node_2", clips: [{ charId: "char_4134_cetsyr", voiceId: "EX_CN_201", index: 1 }] },
          ],
          hiddenClips: [{ charId: "char_4134_cetsyr", voiceId: "EX_CN_601", index: 1 }],
        },
      },
    },
  },
}));
import type { Response } from "express";
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData, asModel } from "../../helpers";
import type { MockPlayerDataManager } from "../../helpers";
import type { PlayerMainlineRecord } from "@game/kernel/playerdata";

/** 语音档案请求体视图 */
interface CharVoiceBody {
  topicId?: string;
  nodeId?: string;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: CharVoiceBody;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  type: Response["type"];
  json: Response["json"];
}

type RouterReq = Parameters<typeof rootRouter>[0];

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    type: vi.fn<Response["type"]>().mockReturnThis(),
    json: vi.fn<Response["json"]>(),
  };
}

async function call(player: MockPlayerDataManager, url: string, body: CharVoiceBody): Promise<MockRes> {
  const res = mockRes();
  vi.mocked(httpContext.get).mockReturnValue(player);
  const req: MockReq = { method: "POST", url, body };
  // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
  rootRouter(req as RouterReq, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("语音档案 charVoiceRecord", () => {
  let player: MockPlayerDataManager;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({ status: { uid: "1" } });
  });

  it("enterCharVoiceRecord：写入 charVoiceRecord.isOpen/confirmEnterReward 并发干员本体", async () => {
    const res = await call(player, "/mainline/enterCharVoiceRecord", { topicId: "mission_archive_main_14" });
    const response = vi.mocked(res.send).mock.calls[0][0];
    expect(response.reward).toEqual([{ type: "CHAR", id: "char_4134_cetsyr", count: 1 }]);
    const archive = player._playerdata.mainline.charVoiceRecord["mission_archive_main_14"];
    expect(archive.isOpen).toBe(true);
    expect(archive.confirmEnterReward).toBe(true);
    expect(player.gainItem.handle).toHaveBeenCalled();
  });

  it("enterCharVoiceRecord：已领取入口奖励时幂等不发奖励", async () => {
    player._playerdata.mainline = asModel<PlayerMainlineRecord>({
      charVoiceRecord: { mission_archive_main_14: { isOpen: true, confirmEnterReward: true, nodes: {} } },
    });
    const res = await call(player, "/mainline/enterCharVoiceRecord", { topicId: "mission_archive_main_14" });
    expect(vi.mocked(res.send).mock.calls[0][0].reward).toEqual([]);
  });

  it("confirmCharVoiceRecordReward：写 nodes[nodeId]=2 并发 p_char_{charId} 信物", async () => {
    const res = await call(player, "/mainline/confirmCharVoiceRecordReward", {
      topicId: "mission_archive_main_14",
      nodeId: "main_node_2",
    });
    const response = vi.mocked(res.send).mock.calls[0][0];
    expect(response.reward).toEqual([{ type: "MATERIAL", id: "p_char_4134_cetsyr", count: 1 }]);
    expect(player._playerdata.mainline.charVoiceRecord["mission_archive_main_14"].nodes["main_node_2"]).toBe(2);
  });

  it("confirmCharVoiceRecordReward：节点已领取时幂等", async () => {
    player._playerdata.mainline = asModel<PlayerMainlineRecord>({
      charVoiceRecord: { mission_archive_main_14: { isOpen: true, confirmEnterReward: true, nodes: { main_node_2: 2 } } },
    });
    const res = await call(player, "/mainline/confirmCharVoiceRecordReward", {
      topicId: "mission_archive_main_14",
      nodeId: "main_node_2",
    });
    expect(vi.mocked(res.send).mock.calls[0][0].reward).toEqual([]);
  });
});
