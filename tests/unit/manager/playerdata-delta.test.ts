import { describe, it, expect, beforeEach } from "vitest";
import { PlayerDataManager } from "@game/service/PlayerDataManager";
import { mockPlayerData } from "../../helpers";


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

  it("recipe 内嵌套 update 不丢变更（事件处理器再调 update 复用同一 draft）", async () => {
    // 前置：status 需含 gold 字段（mockPlayerData 默认不含，NaN 干扰断言）。
    // 经 update() 配方设置，兼容 setAutoFreeze(true)（直接改冻结对象会抛错）。
    await player.update(async (draft) => {
      draft.status.gold = 0;
    });
    await settleBaseline();

    // 模拟 items:get → gainItem → 事件处理器内再调 player.update（原实现内层
    // finishDraft 先提交、外层 finishDraft 再按旧 base 覆盖 → 嵌套变更从存档丢失）
    player._trigger.on("test:nested" as never, async () => {
      await player.update(async (draft) => {
        draft.status.gold += 100;
      });
    });
    await player.update(async (draft) => {
      draft.status.level = 5;
      await player._trigger.emit("test:nested" as never, []);
    });

    expect((player as any)._playerdata.status.gold).toBe(100);
    const delta = player.delta;
    expect(delta.playerDataDelta.modified.status.gold).toBe(100);
  });

  it("同路径多次 update 时 delta 下发最新值（补丁正序，非反转）", async () => {
    await settleBaseline();
    await player.update(async (draft) => {
      draft.status.nickName = "b";
    });
    await player.update(async (draft) => {
      draft.status.nickName = "c";
    });
    const delta = player.delta;
    expect(delta.playerDataDelta.modified.status.nickName).toBe("c");
  });
});
