import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
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
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() { return { send: vi.fn(), status: vi.fn().mockReturnThis(), type: vi.fn().mockReturnThis(), json: vi.fn() }; }
async function call(player: any, url: string, body: any) {
  const res = mockRes();
  (httpContext.get as any).mockReturnValue(player);
  rootRouter({ method: "POST", url, body } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("语音档案 charVoiceRecord", () => {
  let player: any;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({ status: { uid: "1" } as any });
  });

  it("enterCharVoiceRecord：写入 charVoiceRecord.isOpen/confirmEnterReward 并发干员本体", async () => {
    const res = await call(player, "/mainline/enterCharVoiceRecord", { topicId: "mission_archive_main_14" });
    const response = res.send.mock.calls[0][0];
    expect(response.reward).toEqual([{ type: "CHAR", id: "char_4134_cetsyr", count: 1 }]);
    const archive = player._playerdata.mainline.charVoiceRecord["mission_archive_main_14"];
    expect(archive.isOpen).toBe(true);
    expect(archive.confirmEnterReward).toBe(true);
    expect(player.gainItem.handle).toHaveBeenCalled();
  });

  it("enterCharVoiceRecord：已领取入口奖励时幂等不发奖励", async () => {
    player._playerdata.mainline = {
      charVoiceRecord: { mission_archive_main_14: { isOpen: true, confirmEnterReward: true, nodes: {} } },
    };
    const res = await call(player, "/mainline/enterCharVoiceRecord", { topicId: "mission_archive_main_14" });
    expect(res.send.mock.calls[0][0].reward).toEqual([]);
  });

  it("confirmCharVoiceRecordReward：写 nodes[nodeId]=2 并发 p_char_{charId} 信物", async () => {
    const res = await call(player, "/mainline/confirmCharVoiceRecordReward", {
      topicId: "mission_archive_main_14",
      nodeId: "main_node_2",
    });
    const response = res.send.mock.calls[0][0];
    expect(response.reward).toEqual([{ type: "MATERIAL", id: "p_char_4134_cetsyr", count: 1 }]);
    expect(player._playerdata.mainline.charVoiceRecord["mission_archive_main_14"].nodes["main_node_2"]).toBe(2);
  });

  it("confirmCharVoiceRecordReward：节点已领取时幂等", async () => {
    player._playerdata.mainline = {
      charVoiceRecord: { mission_archive_main_14: { isOpen: true, confirmEnterReward: true, nodes: { main_node_2: 2 } } },
    };
    const res = await call(player, "/mainline/confirmCharVoiceRecordReward", {
      topicId: "mission_archive_main_14",
      nodeId: "main_node_2",
    });
    expect(res.send.mock.calls[0][0].reward).toEqual([]);
  });
});
