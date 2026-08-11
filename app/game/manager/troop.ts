import { PlayerSquad, PlayerSquadItem } from "../model/character";
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { now } from "@utils/time";
import { rarityToIndex } from "@utils/rarity";
import { reconcileCharSkills } from "@game/util/char-skills";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";

export class TroopManager {
  _trigger: TypedEventEmitter;
  _player: PlayerDataManager;

  constructor(player: PlayerDataManager, trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = trigger;
    this._trigger.on("game:fix", this.fix.bind(this));
  }
  async squadFormation(args: {
    squadId: number;
    slots: PlayerSquadItem[];
  }): Promise<void> {
    const { squadId, slots } = args;
    await this._player.update(async (draft) => {
      draft.troop.squads[squadId].slots = slots;
      await this._trigger.emit("SquadFormation", []);
    });
  }

  async changeSquadName(args: {
    squadId: number;
    name: string;
  }): Promise<void> {
    const { squadId, name } = args;
    await this._player.update(async (draft) => {
      draft.troop.squads[squadId].name = name;
    });
  }

  async decomposePotentialItem(args: {
    charInstIdList: string[];
  }): Promise<ItemBundle[]> {
    const { charInstIdList } = args;
    const draft = this._player._playerdata;
    const costs: ItemBundle[] = [];
    const items: ItemBundle[] = charInstIdList.reduce((acc, charInstId) => {
      const char = draft.troop.chars[charInstId];
      if (!char) return acc; // 防御：不存在的干员跳过
      // 修复：CharacterTable.rarity 为字符串枚举 "TIER_N"，items 表按数值键（0~5）——转索引
      const rarity = rarityToIndex(excel.CharacterTable[char.charId]?.rarity);
      const potentialItemId =
        excel.CharacterTable[char.charId].potentialItemId!;
      const count = draft.inventory[potentialItemId];
      costs.push({ id: potentialItemId, count: count });
      const item = excel.GachaTable.potentialMaterialConverter.items[rarity];
      if (!item) return acc; // 防御：无对应分解配置跳过
      acc.push({ id: item.id, count: item.count * count });
      return acc;
    }, [] as ItemBundle[]);
    await this._trigger.emit("items:use", [costs]);
    await this._trigger.emit("items:get", [items]);
    return items;
  }

  async decomposeClassicPotentialItem(args: {
    charInstIdList: string[];
  }): Promise<ItemBundle[]> {
    const { charInstIdList } = args;
    const draft = this._player._playerdata;
    const costs: ItemBundle[] = [];
    const items: ItemBundle[] = charInstIdList.reduce((acc, charInstId) => {
      const char = draft.troop.chars[charInstId];
      if (!char) return acc; // 防御：不存在的干员跳过
      // 修复：rarity 字符串枚举转数值索引
      const rarity = rarityToIndex(excel.CharacterTable[char.charId]?.rarity);
      const potentialItemId =
        excel.CharacterTable[char.charId].classicPotentialItemId!;
      const count = draft.inventory[potentialItemId];
      costs.push({ id: potentialItemId, count: count });
      const item =
        excel.GachaTable.classicPotentialMaterialConverter.items[rarity];
      if (!item) return acc; // 防御：无对应分解配置跳过
      acc.push({ id: item.id, count: item.count * count });
      return acc;
    }, [] as ItemBundle[]);
    await this._trigger.emit("items:use", [costs]);
    await this._trigger.emit("items:get", [items]);
    return items;
  }

  async addonStoryUnlock(args: { charId: string; storyId: string }) {
    const { charId, storyId } = args;
    await this._player.update(async (draft) => {
      // 防御：addon 条目缺失（新干员/发放干员无密录基座）时先初始化，避免 500
      draft.troop.addon[charId] = draft.troop.addon[charId] ?? {
        story: {},
        stage: {},
      };
      draft.troop.addon[charId].story = Object.assign(
        draft.troop.addon[charId].story || {},
        { [storyId]: { fts: now(), rts: now() } },
      );
    });
  }

  async addonStageBattleStart(args: {
    charId: string;
    stageId: string;
    squad: PlayerSquad;
    stageType: string;
  }) {
    const { stageId, squad } = args;
    await this._trigger.emit("battle:start", [
      {
        isRetro: 0,
        pray: 0,
        battleType: 0,
        continuous: {
          battleTimes: 1,
        },
        usePracticeTicket: 1,
        stageId: stageId,
        squad: squad,
        assistFriend: null,
        isReplay: 0,
        startTs: now(),
      },
    ]);
  }

  async addonStageBattleFinish(args: {
    data: string;
    battleData: { isCheat: string; completeTime: number };
  }) {
    let result: unknown;
    await this._trigger.emit("battle:finish", [
      args,
      (res: unknown) => {
        result = res;
      },
    ]);
    return result;
  }

  async fix(): Promise<void> {
    Object.values(this._player._playerdata.troop.chars).forEach((char) => {
      if (char.charId == "char_002_amiya") {
        return;
      }
      // 技能按官方规则回填/解锁（allSkillLvlup[i].unlockCond——test.json 378/378 验证；
      // ⚠️ 勿用 skill.unlockCond 顶层字段：与解锁条件 1504 处不同，历史地雷）
      reconcileCharSkills(char);
      const equips = excel.UniequipTable.equipDict;
      Object.values(equips)
        .filter((equip) => equip.charId == char.charId)
        .forEach((equip) => {
          char.equip = char.equip || {};
          char.equip[equip.uniEquipId] = char.equip[equip.uniEquipId] || {
            hide: 1,
            locked: 1,
            level: 1,
          };
        });
      if (char.evolvePhase == 2 && char.equip) {
        char.currentEquip = char.currentEquip || Object.keys(char.equip)[0]!;
      }
    });
    // 绕过 update() 的原地修复不产生 Immer 补丁，显式标记脏以触发条件落盘
    this._player.markDirty();
  }
}
