import type { PlayerDataManager } from "@game/kernel/PlayerDataManager";
import type { PlayerDataModel } from "@game/kernel/playerdata";
import { mockExcel } from "./mockExcel";

export interface MockPlayerDataManager {
  update: ReturnType<typeof vi.fn>;
  get: ReturnType<typeof vi.fn>;
  toJSON: ReturnType<typeof vi.fn>;
  markDirty: ReturnType<typeof vi.fn>;
  forcePatch: ReturnType<typeof vi.fn>;
  pushMessage: ReturnType<typeof vi.fn>;
  _pushMessages: { path: string; payload: unknown }[];
  gainItem: any;
  get delta(): any;
  get uid(): string;
  _playerdata: Partial<PlayerDataModel>;
  _trigger: any;
  /**
   * excel 数据端口替身（管理器的 `player.excel` 依赖）
   *
   * 默认 `mockExcel()`（空表 + 门面方法）；用例需要具体表时直接覆写本字段，
   * 替代此前 "vi.mock('@excel/excel') 模块级打桩" 的做法。
   */
  excel: any;
}

/**
 * 物品管道 mock（GainItemPipeline 替身）
 *
 * 物品增减已从「直发 items:get/items:use 事件」收敛到 `player.gainItem` 管道，
 * 断言口径随之从 `trigger.emit` 换成本 mock 的 add/setTarget/use/handle 调用记录。
 * 手搓 mockPlayer 的测试用例统一挂 `gainItem: mockGainItem()`。
 */
export function mockGainItem(): any {
  const gainItem: any = {
    add: vi.fn(function (this: any) {
      return this;
    }),
    setTarget: vi.fn(function (this: any) {
      return this;
    }),
    use: vi.fn().mockResolvedValue(undefined),
    handle: vi.fn().mockResolvedValue(undefined),
    clear: vi.fn(function (this: any) {
      return this;
    }),
  };
  Object.defineProperty(gainItem, "size", { get: () => 0 });
  Object.defineProperty(gainItem, "targets", { get: () => [] });
  return gainItem;
}

/**
 * 创建一个 mock 的 PlayerDataManager
 * 使用 vitest 的 vi.fn() 模拟方法，避免在测试中依赖 Immer/管理器实例
 */
export function mockPlayerData(
  initialData: Partial<PlayerDataModel> = {}
): MockPlayerDataManager {
  const _playerdata: Partial<PlayerDataModel> = {
    status: { uid: 10000, nickName: "TestUser", nickNumber: 0, level: 1, exp: 0 } as any,
    ...initialData,
  };

  const update = vi
    .fn()
    .mockImplementation(
      async (recipe: (draft: any) => Promise<any> | any) => {
        const draft = JSON.parse(JSON.stringify(_playerdata));
        const result = await recipe(draft);
        Object.assign(_playerdata, draft);
        return result;
      }
    );

  const get = vi.fn().mockImplementation(() => _playerdata);

  const toJSON = vi.fn().mockImplementation(() => _playerdata);

  return {
    update,
    get,
    toJSON,
    markDirty: vi.fn(),
    forcePatch: vi.fn(),
    _pushMessages: [],
    pushMessage: vi.fn(function (path: string, payload: unknown) {
      this._pushMessages.push({ path, payload });
    }),
    gainItem: mockGainItem(),
    checkIn: {
      ensureShowCount: vi.fn().mockResolvedValue(undefined),
      checkIn: vi.fn().mockResolvedValue(undefined),
      dailyRefresh: vi.fn().mockResolvedValue(undefined),
      monthlyRefresh: vi.fn().mockResolvedValue(undefined),
    } as any,
    status: {
      buyAp: vi.fn(async () => {
        const remain = (_playerdata.status as any)?.buyApRemainTimes ?? 0;
        if (remain <= 0) return false;
        (_playerdata.status as any).buyApRemainTimes = remain - 1;
        return true;
      }),
      bindNickName: vi.fn().mockResolvedValue(undefined),
      changeSecretary: vi.fn().mockResolvedValue(undefined),
      changeAvatar: vi.fn().mockResolvedValue(undefined),
      changeResume: vi.fn().mockResolvedValue(undefined),
      receiveTeamCollectionReward: vi.fn().mockResolvedValue(undefined),
      exchangeDiamondShard: vi.fn().mockResolvedValue(undefined),
    } as any,
    _playerdata,
    _trigger: {
      emit: vi.fn(),
      on: vi.fn(),
      off: vi.fn(),
    },
    get delta() {
      return { playerDataDelta: {} };
    },
    get uid() {
      return (_playerdata.status as any)?.uid ?? 10000;
    },
    excel: mockExcel(),
  };
}
