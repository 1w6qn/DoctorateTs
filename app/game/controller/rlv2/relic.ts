import excel from "@excel/excel";
import { PlayerRoguelikeV2, RoguelikeItemBundle } from "../../model/rlv2";
import { RoguelikeV2Controller } from "../rlv2";
import { now } from "@utils/time";
import { TypedEventEmitter } from "@game/model/events";

export class RoguelikeRelicManager {
  relics: { [key: string]: PlayerRoguelikeV2.CurrentData.Relic };
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._index = 0;
    this.relics = player.current.inventory?.relic || {};
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("rlv2:relic:gain", this.gain.bind(this));
    this._trigger.on("rlv2:init", () => {
      this.relics = {};
      this._index = 0;
    });
    this._trigger.on("rlv2:create", () => {
      this.relics = {};
      this._index = 0;
    });
  }

  _index: number;

  get index(): string {
    return `r_${this._index}`;
  }

  use(id: string): void {}

  /**
   * 移除收藏品（按 id 删除首个匹配实例）。
   * 事件消耗类用途（如愈创之心"消耗源私钥"）；buff 不回收（消耗型藏品效果服务端不结算）。
   * @param relicId 收藏品 id
   * @returns 已移除返回 true；未持有返回 false
   */
  lose(relicId: string): boolean {
    for (const [idx, r] of Object.entries(this.relics)) {
      if (r.id === relicId) {
        delete this.relics[idx];
        return true;
      }
    }
    return false;
  }

  async gain([relic]: [RoguelikeItemBundle]): Promise<void> {
    const theme = this._player.current.game!.theme;
    const buffs =
      excel.RoguelikeTopicTable.details[theme].relics[relic.id].buffs;
    await this._trigger.emit("rlv2:buff:apply", [[...buffs]]);
    // 收藏品获得推送（rlv2GotRandRelic，官服触发类 RoguelikeRelicGetTrigger）：
    // 携带本次获得的收藏品 id（force 建图时对非 rogue_6 主题由 pushMessage 内部静默跳过）。
    // 分队（bandRef 命中的 band_*）不是"随机获得的收藏品"——开局选分队会走这里，
    // 若推送会导致客户端弹"获得收藏品：XX分队"的藏品提示，故分队不推送。
    const isBand = !!(excel.RoguelikeTopicTable.details[theme] as any)
      ?.bandRef?.[relic.id];
    if (!isBand) {
      this._player.pushMessage("rlv2GotRandRelic", { idList: [relic.id] });
    }
    // 官方线格式：relic 库存以 index（r_N）为键，非 relic id
    this.relics[this.index] = {
      index: this.index,
      id: relic.id,
      count: relic.count,
      ts: now(),
    };
    this._index++;
    // 收藏记录：collect.relic[id].state = 2（已获得），客户端图鉴展示
    // outer 为 _playerdata.rlv2 引用（update() 后冻结），写入须放入配方
    const collect = this._player.outer[theme]?.collect as
      | { relic?: { [key: string]: { state: number; progress: unknown } } }
      | undefined;
    if (collect?.relic) {
      const prev = collect.relic[relic.id];
      if (!prev || prev.state < 2) {
        await this._player.update(async (draft) => {
          const draftCollect = (draft.outer[theme] as any)?.collect;
          if (!draftCollect?.relic || draftCollect.relic[relic.id]?.state >= 2) return;
          draftCollect.relic[relic.id] = {
            state: 2,
            progress: draftCollect.relic[relic.id]?.progress ?? null,
          };
        });
      }
    }
  }

  toJSON(): { [key: string]: PlayerRoguelikeV2.CurrentData.Relic } {
    return this.relics;
  }
}
