import type { PlayerDataManager } from "@game/manager/PlayerDataManager";
import type { PlayerDataModel } from "@game/model/playerdata";

export interface MockPlayerDataManager {
  update: ReturnType<typeof vi.fn>;
  get: ReturnType<typeof vi.fn>;
  toJSON: ReturnType<typeof vi.fn>;
  markDirty: ReturnType<typeof vi.fn>;
  forcePatch: ReturnType<typeof vi.fn>;
  get delta(): any;
  get uid(): string;
  _playerdata: Partial<PlayerDataModel>;
  _trigger: any;
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
  };
}
