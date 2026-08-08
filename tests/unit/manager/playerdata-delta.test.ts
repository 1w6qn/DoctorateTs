import { describe, it, expect, beforeEach } from "vitest";
import { enablePatches } from "immer";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";

enablePatches();

/**
 * 条件落盘回归测试
 *
 * delta getter 仅在存在变更时触发 save（Immer 补丁或 markDirty 的直接变更），
 * 纯读请求（syncStatus/syncPushMessage 等）不应触发全量落盘。
 * 注意：TypedEventEmitter（Emittery）的 emit 是异步的，断言前需 flush。
 */
describe("PlayerDataManager 条件落盘", () => {
  let player: PlayerDataManager;
  let saveCount: number;

  const flush = () => new Promise((r) => setTimeout(r, 20));

  beforeEach(async () => {
    const pd: any = mockPlayerData({
      mission: { missions: {} },
      medal: { medals: {}, custom: { currentIndex: "0", customs: {} } },
      rlv2: { outer: {}, current: {}, pinned: {} },
    });
    player = new PlayerDataManager(pd._playerdata as any);
    await flush();
    saveCount = 0;
    player._trigger.on("save", () => {
      saveCount++;
    });
  });

  /**
   * 消费构造期异步 init（mission.init 等）可能产生的补丁，建立干净基线。
   * 构造期补丁触发的 save 计入 saveCount，断言前重置为 0。
   */
  async function settleBaseline(): Promise<void> {
    for (let i = 0; i < 3; i++) {
      player.delta;
      await flush();
    }
    saveCount = 0;
  }

  it("纯读 delta 不触发 save；update() 后触发", async () => {
    await settleBaseline();

    player.delta;
    await flush();
    expect(saveCount).toBe(0);

    await player.update(async (draft) => {
      draft.status.level = 2;
    });
    player.delta;
    await flush();
    expect(saveCount).toBe(1);

    // 无新变更再读——不重复落盘
    player.delta;
    await flush();
    expect(saveCount).toBe(1);
  });

  it("markDirty 的直接变更触发 save", async () => {
    await settleBaseline();

    player.markDirty();
    player.delta;
    await flush();
    expect(saveCount).toBe(1);

    player.delta;
    await flush();
    expect(saveCount).toBe(1);
  });
});
