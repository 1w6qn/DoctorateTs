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

  async gain([relic]: [RoguelikeItemBundle]): Promise<void> {
    const theme = this._player.current.game!.theme;
    const buffs =
      excel.RoguelikeTopicTable.details[theme].relics[relic.id].buffs;
    await this._trigger.emit("rlv2:buff:apply", [[...buffs]]);
    // 收藏品获得推送（rlv2GotRandRelic，官服触发类 RoguelikeRelicGetTrigger）：
    // 携带本次获得的收藏品 id（force 建图时对非 rogue_6 主题由 pushMessage 内部静默跳过）
    this._player.pushMessage("rlv2GotRandRelic", { idList: [relic.id] });
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
