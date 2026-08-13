import { PlayerSquad, PlayerSquadItem, PlayerCharEquipInfo } from "../model/character";
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
    // 修复：同一潜能道具只按库存扣/转一次——原实现每个列出的干员都扣全库存
    //（同稀有度/重复干员 → 库存扣成负数 + 重复发放转换物刷奖励）
    const seen = new Set<string>();
    const costs: ItemBundle[] = [];
    const items: ItemBundle[] = [];
    for (const charInstId of charInstIdList) {
      const char = draft.troop.chars[charInstId];
      if (!char) continue; // 防御：不存在的干员跳过
      // 修复：CharacterTable.rarity 为字符串枚举 "TIER_N"，items 表按数值键（0~5）——转索引
      const rarity = rarityToIndex(excel.CharacterTable[char.charId]?.rarity);
      const potentialItemId = excel.CharacterTable[char.charId].potentialItemId!;
      if (seen.has(potentialItemId)) continue;
      seen.add(potentialItemId);
      const count = draft.inventory[potentialItemId] || 0;
      if (count <= 0) continue;
      const item = excel.GachaTable.potentialMaterialConverter.items[rarity];
      if (!item) continue; // 防御：无对应分解配置跳过
      costs.push({ id: potentialItemId, count: count });
      items.push({ id: item.id, count: item.count * count });
    }
    if (costs.length > 0) {
      await this._trigger.emit("items:use", [costs]);
    }
    if (items.length > 0) {
      await this._trigger.emit("items:get", [items]);
    }
    return items;
  }

  async decomposeClassicPotentialItem(args: {
    charInstIdList: string[];
  }): Promise<ItemBundle[]> {
    const { charInstIdList } = args;
    const draft = this._player._playerdata;
    // 修复：同一潜能道具只按库存扣/转一次（同 decomposePotentialItem）
    const seen = new Set<string>();
    const costs: ItemBundle[] = [];
    const items: ItemBundle[] = [];
    for (const charInstId of charInstIdList) {
      const char = draft.troop.chars[charInstId];
      if (!char) continue; // 防御：不存在的干员跳过
      // 修复：rarity 字符串枚举转数值索引
      const rarity = rarityToIndex(excel.CharacterTable[char.charId]?.rarity);
      const potentialItemId = excel.CharacterTable[char.charId].classicPotentialItemId!;
      if (seen.has(potentialItemId)) continue;
      seen.add(potentialItemId);
      const count = draft.inventory[potentialItemId] || 0;
      if (count <= 0) continue;
      const item = excel.GachaTable.classicPotentialMaterialConverter.items[rarity];
      if (!item) continue; // 防御：无对应分解配置跳过
      costs.push({ id: potentialItemId, count: count });
      items.push({ id: item.id, count: item.count * count });
    }
    if (costs.length > 0) {
      await this._trigger.emit("items:use", [costs]);
    }
    if (items.length > 0) {
      await this._trigger.emit("items:get", [items]);
    }
    return items;
  }

  /**
   * 解锁干员密录剧情（附加故事）
   * 对照官服抓包（tmp/charBuild_addonStory_unlock_res_1107.json）：
   * 写入 addon.story + 同步发放对应勋章（medal_story_x，CharStoryUnlock 模板）。
   *
   * @param args.charId - 干员 ID
   * @param args.storyId - 密录剧情 ID
   * @returns 发放的勋章 ID（无对应勋章配置时返回 null，供 router 组装 medalFinish pushMessage）
   */
  async addonStoryUnlock(args: {
    charId: string;
    storyId: string;
  }): Promise<string | null> {
    const { charId, storyId } = args;
    let medalId: string | null = null;
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
      // 对照官服抓包：解锁密录同步发放对应勋章
      // （medal_story_x，template CharStoryUnlock + unlockParam=[charId, storyId]，val 空数组、rts=-1）
      const medal = excel.MedalTable?.medalList?.find(
        (m) =>
          m.template === "CharStoryUnlock" &&
          m.unlockParam[0] === charId &&
          m.unlockParam[1] === storyId,
      );
      if (medal) {
        medalId = medal.medalId;
        draft.medal ??= {
          medals: {},
          custom: { currentIndex: "", customs: {} },
        };
        draft.medal.medals[medal.medalId] = {
          id: medal.medalId,
          val: [],
          fts: now(),
          rts: -1,
        };
      }
    });
    return medalId;
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
    // 模组回填：按归属干员（base 或 tmpl 变体各自 charId）补缺失条目
    const backfillOwner = (
      ownerId: string,
      dict: { [key: string]: PlayerCharEquipInfo },
    ) => {
      Object.values(excel.UniequipTable.equipDict)
        // 防御：equipDict 含 null 占位条目（26/924）
        .filter((equip) => equip && equip.charId === ownerId)
        .forEach((equip) => {
          dict[equip.uniEquipId] = dict[equip.uniEquipId] || {
            hide: 1,
            locked: 1,
            level: 1,
          };
        });
    };
    Object.values(this._player._playerdata.troop.chars).forEach((char) => {
      if (char.charId == "char_002_amiya") {
        return;
      }
      // 技能按官方规则回填/解锁（allSkillLvlup[i].unlockCond——test.json 378/378 验证；
      // ⚠️ 勿用 skill.unlockCond 顶层字段：与解锁条件 1504 处不同，历史地雷）
      reconcileCharSkills(char);
      char.equip = char.equip || {};
      backfillOwner(char.charId, char.equip);
      // 模板变体回填（tmpl 各形态按各自 charId 归属）
      if (char.tmpl) {
        Object.entries(char.tmpl).forEach(([tmplId, patch]) => {
          patch.equip = patch.equip || {};
          backfillOwner(tmplId, patch.equip);
        });
      }
      if (char.evolvePhase == 2 && char.equip) {
        char.currentEquip = char.currentEquip || Object.keys(char.equip)[0]!;
      }
    });
    // 绕过 update() 的原地修复不产生 Immer 补丁，显式标记脏以触发条件落盘
    this._player.markDirty();
  }
}
