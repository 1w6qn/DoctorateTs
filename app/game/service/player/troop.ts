import { PlayerSquad, PlayerSquadItem, PlayerCharEquipInfo, PlayerCharacter } from "../../domain/character";
import excel from "@excel/excel";
import { ItemBundle } from "@excel/excel";
import { now } from "@utils/time";
import { rarityToIndex } from "@utils/rarity";
import {
  reconcileCharEquips,
  reconcileCharSkills,
} from "@game/domain/util/char-skills";
import { PlayerDataManager } from "@game/service/PlayerDataManager";
import { TypedEventEmitter } from "@game/service/events";

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
    // 修复：ChangeSquadName 任务事件从未 emit → 改名类任务永不推进
    await this._trigger.emit("ChangeSquadName", []);
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
    // 修复①：原实现 emit "battle:start" 且丢弃返回值 → /charBuild/addonStage/battleStart
    // 响应不含 battleId，客户端结算时只能沿用上一次战斗（如肉鸽内层 ro6_*）的 battleId 解密，
    // 导致 battleFinish 读错 battleInfo → 未知关卡空结算。改为直接调用 battle.start 并返回结果，
    // 由路由把 battleId 等一并回传（与 /quest/battleStart 对齐）。
    //
    // 修复②（悖论模拟完整结算）：悖论模拟（mem_ 干员密录关卡）不是演习——
    // 首通会发放 handbook rewardItem（如合成玉）+ 记录 addon.stage。此前 usePracticeTicket=1
    // 固定练习模式，battle.finish 走练习分支直接返回 {result:0}，永不发奖/记录通关。改为
    // 真实战斗（usePracticeTicket=0）即可走标准结算；mem_ 关卡在 resolveStage 已保证 apCost=0/
    // expGain=0/goldGain=0，故不耗理智、不发经验金币，仅结算首通奖励与完成状态。
    return this._player.battle.start({
      isRetro: 0,
      pray: 0,
      battleType: 0,
      continuous: {
        battleTimes: 1,
      },
      usePracticeTicket: 0,
      stageId: stageId,
      squad: squad,
      assistFriend: null,
      isReplay: 0,
      startTs: now(),
    });
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

  /**
   * 读取玩家干员字典（跨模块只读查询，rlv2 等模块经此访问，不直接读 _playerdata）
   * @returns 干员字典（instId → 干员数据）
   */
  getChars(): Record<string, PlayerCharacter> {
    return this._player._playerdata.troop?.chars ?? {};
  }

  async fix(): Promise<void> {
    // 迁移：进度修复移入 update() 配方——配方内 mutate draft（可变代理，
    // push/splice/赋值均安全）会记录补丁，无需再 markDirty
    await this._player.update((draft) => {
      // 防御：某些测试/空基座构造传入无 troop 的数据，直接跳过
      if (!draft.troop?.chars) return Promise.resolve();
      Object.values(draft.troop.chars).forEach((char) => {
        if (char.charId == "char_002_amiya") {
          return;
        }
        // 技能按官服线格式回填/解锁（excel skills[i].unlockCond.phase；
        // test.json 378/378 验证；未解锁技能以 unlock:0 占位保留）
        reconcileCharSkills(char);
        // 模组回填 + 精二隐藏→显示校正（补齐缺失条目；hide 按 showEvolvePhase 置 0/1）
        reconcileCharEquips(char);
        // 模板变体回填（tmpl 各形态按各自 charId 归属，分别校正）
        if (char.tmpl) {
          Object.entries(char.tmpl).forEach(([tmplId, patch]) => {
            patch.equip = patch.equip || {};
            reconcileCharEquips({
              charId: tmplId,
              evolvePhase: char.evolvePhase ?? 0,
              equip: patch.equip,
              currentEquip: patch.currentEquip,
            });
          });
        }
      });
      return Promise.resolve();
    });
  }
}
