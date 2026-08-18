import excel from "@excel/excel";
import { TroopManager } from "../../manager/troop";
import { PlayerRoguelikeV2 } from "../../model/rlv2";
import { RoguelikeV2Controller } from "../rlv2";
import { now } from "@utils/time";
import { rarityToIndex } from "@utils/rarity";
import { TypedEventEmitter } from "@game/model/events";

export class RoguelikeRecruitManager {
  tickets: { [key: string]: PlayerRoguelikeV2.CurrentData.Recruit };
  _troop: TroopManager;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._index = 0;
    this.tickets = player.current.inventory?.recruit || {};
    this._troop = player._troop;
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("rlv2:init", () => {
      this.tickets = {};
      this._index = 0;
    });
    this._trigger.on("rlv2:create", () => {
      this.tickets = {};
      this._index = 0;
    });
    this._trigger.on("rlv2:recruit:gain", async ([id, from, mustExtra]) => {
      await this.gain(id, from, mustExtra);
    });
    this._trigger.on("rlv2:recruit:active", async ([id]) => {
      await this.active(id);
    });
    this._trigger.on("rlv2:recruit:done", async ([id, optionId]) => {
      await this.done(id, optionId);
    });
    this._trigger.on("rlv2:recruit:initial_char", async ([charId]) => {
      await this.initialChar(charId);
    });
    this._trigger.on("rlv2:create", () => {
      this.tickets = {};
    });
  }

  /**
   * 各主题招募希望消耗表（索引 = rarityIdx，TIER_1..6 → 0..5）：
   * 黑流树海（rogue_6）：4 星 0 希望、5 星 2、6 星 4（官方文本+实测确认，初始希望 6）
   * 萨卡兹的无终奇语（rogue_5）：4 星 0、5 星 2、6 星 6（官方表 000026）
   * 其余主题（rogue_1..4）：3 星 0、4 星 2、5 星 3、6 星 6（常规曲线）
   */
  private populationFor(rarityIdx: number): number {
    const theme = this._player.current.game?.theme || "";
    const map =
      theme === "rogue_6"
        ? [0, 0, 0, 0, 2, 4]
        : theme === "rogue_5"
          ? [0, 0, 0, 0, 2, 6]
          : [0, 0, 0, 2, 3, 6];
    return map[rarityIdx] || 0;
  }

  /**
   * 各主题干员进阶希望消耗表（索引 = rarityIdx，TIER_1..6 → 0..5）：
   * 萨卡兹的无终奇语（rogue_5）：4 星 1、5 星 1、6 星 3（官方表 000113；
   * 用户消息写 000123 疑笔误，以官方表 ★★★★★ 进阶 1 为准）
   * 进阶接口（如后续实现）按此扣希望；当前路由无进阶干员接口，表备用于客户端协议。
   */
  private advancePopulationFor(rarityIdx: number): number {
    const theme = this._player.current.game?.theme || "";
    const map =
      theme === "rogue_5" ? [0, 0, 0, 1, 1, 3] : [0, 0, 0, 0, 0, 0];
    return map[rarityIdx] || 0;
  }

  /**
   * 分队初始干员（immediate_recruit）：临时干员直接入队（TEMP 类型，不占招募票）
   * @param charId 干员 id（如 char_504_rguard）
   */
  async initialChar(charId: string): Promise<void> {
    const data = excel.CharacterTable[charId];
    if (!data) return;
    const rarity = rarityToIndex(data.rarity);
    const popMap = [0, 0, 0, 2, 3, 6];
    // 递增 troopInstId（1 基，与 getChar 直接使用 troopInstId 的约定一致——
    // 原实现此处 0 基 + getChar +1 错位到 2，首名初始干员 instId 应为 1）
    const troopInstId = Object.keys(this._player.troop.chars).length + 1;
    const char: PlayerRoguelikeV2.CurrentData.RecruitChar = {
      instId: 0,
      charId,
      type: "TEMP",
      upgradePhase: 0,
      upgradeLimited: true,
      population: popMap[rarity] || 0,
      isUpgrade: false,
      isCure: true,
      charBuff: [],
      troopInstId,
      level: 1,
      exp: 0,
      evolvePhase: 0,
      favorPoint: 0,
      potentialRank: 0,
      mainSkillLvl: 1,
      skills: [],
    } as any;
    await this._trigger.emit("rlv2:char:get", [char]);
  }

  _index: number;

  get index(): string {
    return `t_${this._index}`;
  }

  async active(id: string) {
    const theme = this._player.current.game!.theme;
    this.tickets[id].state = 1;
    const ticketInfo =
      excel.RoguelikeTopicTable.details[theme].recruitTickets[
        this.tickets[id].id
      ];
    // 候选干员来自玩家主队伍（collection，312 干员），非 rlv2 对局内 troop（初始为空）
    // 防御：troop 未初始化（构造/测试早期）时不崩
    const troopChars = this._player._player._playerdata.troop?.chars ?? {};
    const chars: PlayerRoguelikeV2.CurrentData.RecruitChar[] = Object.values(
      troopChars as {
        [key: string]: any;
      },
    ).reduce((acc, char) => {
      const data = excel.CharacterTable[char.charId];

      if (!ticketInfo.professionList.some((p) => data.profession.includes(p))) {
        return acc;
      }
      if (!ticketInfo.rarityList.some((r) => data.rarity == r)) {
        return acc;
      }
      let isUpgraded = false;
      const rarity = data.rarity;
      // rarity 为字符串枚举（"TIER_N"）→ 统一转数值下标（0 基）
      const rarityIdx = rarityToIndex(rarity);
      let population = this.populationFor(rarityIdx);
      for (const buff of this._player._buff.filterBuffs("recruit_cost")) {
        if (
          buff.blackboard[0].valueStr?.includes(data.rarity.toString()) &&
          buff.blackboard[1].valueStr?.includes(data.profession)
        ) {
          population += buff.blackboard[2].value!;
        }
      }
      // 难度效果：招募 N 星干员希望消耗 +cost（recruit_hop_cost，blackboard min_star/cost/gte）。
      // 语义：gte=1 表示"N 星及以上"（rogue_2/3，>= 阈值）；gte=0 表示精确 N 星
      // （rogue_1/4/5/6——难度13"五星+1"仅对 5 星、难度15"六星+1"仅对 6 星；
      // 原实现统一 >= 会让 6 星同时吃到 5 星与 6 星两条 4+1+1=6，官方应为 4+1=5）
      for (const buff of this._player._buff.filterBuffs("recruit_hop_cost")) {
        const minStar = buff.blackboard[0]?.value ?? 0;
        const cost = buff.blackboard[1]?.value ?? 0;
        const gte = buff.blackboard[2]?.value ?? 0;
        // rarityIdx 0 基：TIER_3→2 / TIER_4→3 / TIER_5→4 / TIER_6→5，与星级（3/4/5/6）差 1
        if (minStar > 0 && (gte ? rarityIdx + 1 >= minStar : rarityIdx + 1 === minStar)) {
          population += cost;
        }
      }
      // 分队效果：本源研修分队（recruit_cost_sub_profession）——本源系子职业干员（4星+）希望降低
      // 官方 buff：rarity "TIER_4,TIER_5,TIER_6" + sub_profession "primcaster,primprotector,primguard,ritualist" + delta -2
      for (const buff of this._player._buff.filterBuffs(
        "recruit_cost_sub_profession",
      )) {
        const rarities = (buff.blackboard[0]?.valueStr || "").split(",");
        const subProfs = (buff.blackboard[1]?.valueStr || "").split(",");
        const delta = buff.blackboard[2]?.value ?? 0;
        if (
          delta !== 0 &&
          rarities.includes(data.rarity) &&
          subProfs.includes(data.subProfessionId)
        ) {
          population += delta;
        }
      }
      for (const buff of this._player._buff.filterBuffs(
        "limited_direct_upgrade",
      )) {
        if (
          buff.blackboard[0].valueStr?.includes(data.rarity.toString()) &&
          buff.blackboard[1].valueStr?.includes(data.profession)
        ) {
          isUpgraded = Math.random() <= buff.blackboard[3].value!;
        }
      }

      if (char.charId == "char_4151_tinman") {
        population -= char.evolvePhase > 0 ? 2 : 1;
      }
      let levelPatch: {
        level?: number;
        exp?: number;
        evolvePhase?: number;
      } = {};
      if (char.evolvePhase == 2 && !isUpgraded) {
        const maxLevel = excel.GameDataConst.maxLevel[rarityIdx][1];
        levelPatch = {
          evolvePhase: 1,
          level: maxLevel,
          exp: 0,
        };
      }
      // 候选干员结构对齐官服（activeRecruitTicket 抓包）——精简结构：
      // 官服 list[0] = {instId:"0"(字符串), charId, type:"NORMAL", favorPoint,
      //   potentialRank, mainSkillLvl, skin, level, exp, evolvePhase,
      //   defaultSkillIndex, skills:[], upgradeLimited, upgradePhase,
      //   isUpgrade:false, isCure:false, population, charBuff:[], troopInstId:"0",
      //   master:{}}——skills/equip 空、instId/troopInstId 字符串、
      //   无 gainTime/currentEquip/voiceLan 等玩家养成字段（客户端按白名单解析）
      return [
        ...acc,
        {
          instId: String(acc.length),
          charId: char.charId,
          type: "NORMAL",
          favorPoint: char.favorPoint ?? 0,
          potentialRank: char.potentialRank ?? 0,
          mainSkillLvl: char.mainSkillLvl ?? 1,
          skin: char.skin ?? "",
          level: levelPatch.level ?? char.level ?? 1,
          exp: levelPatch.exp ?? char.exp ?? 0,
          evolvePhase: levelPatch.evolvePhase ?? char.evolvePhase ?? 0,
          defaultSkillIndex:
            (char.defaultSkillIndex ?? 0) >= 0 ? char.defaultSkillIndex ?? 0 : 0,
          skills: [],
          upgradeLimited: !isUpgraded,
          upgradePhase: isUpgraded ? 1 : 0,
          isUpgrade: false,
          isCure: false,
          population: population >= 0 ? population : 0,
          charBuff: [],
          troopInstId: String(
            (char as any).instId ?? Object.keys(this._player.troop.chars).length,
          ),
          master: {},
        },
      ];
    }, [] as PlayerRoguelikeV2.CurrentData.RecruitChar[]);

    const freeCharIndexes: number[] = [];
    const tierMap: { [key: string]: number } = {
      TIER_1: 1,
      TIER_2: 2,
      TIER_3: 3,
      TIER_4: 4,
      TIER_5: 5,
      TIER_6: 6,
    };

    for (let i = 0; i < chars.length; i++) {
      const char = chars[i];
      const charData = excel.CharacterTable[char.charId];
      if (!charData) continue;

      const extraFreeRarity = ticketInfo.extraFreeRarity || [];
      for (const tier of extraFreeRarity) {
        const tierNum = tierMap[tier];
        if (tierNum && charData.rarity === tier) {
          freeCharIndexes.push(i);
          break;
        }
      }
    }

    if (freeCharIndexes.length > 0) {
      const freeIndex = freeCharIndexes[Math.floor(Math.random() * freeCharIndexes.length)];
      chars[freeIndex].type = "FREE";
      chars[freeIndex].population = 0;
    }

    const sortedByRarity = [...chars].sort((a, b) => {
      const aRarity = excel.CharacterTable[a.charId]?.rarity || 0;
      const bRarity = excel.CharacterTable[b.charId]?.rarity || 0;
      return aRarity - bRarity;
    });

    if (sortedByRarity.length >= 3) {
      const thirdLowChar = sortedByRarity[2];
      const thirdLowIndex = chars.findIndex((c) => c.charId === thirdLowChar.charId);
      if (thirdLowIndex !== -1) {
        chars[thirdLowIndex].type = "THIRD_LOW";
      }
    }

    this.tickets[id].list = chars;
  }

  async done(id: string, optionId: string) {
    // 一张票只能招募一次（官方语义）：state=0 未打开 / 2 已招募 / 3 已放弃(close)
    // 都拒绝招募——仅 state=1（active 打开）可招募；已招募的票重复调用幂等返回
    // （不重复扣希望/入队），放弃的票不可复活。undefined 容错防 500。
    if (!this.tickets[id] || this.tickets[id].state !== 1) return;
    this.tickets[id].state = 2;
    const picked = this.tickets[id].list.find(
      (item) => String(item.instId) === String(optionId),
    ) as PlayerRoguelikeV2.CurrentData.RecruitChar | undefined;
    if (!picked) return;
    // 官服 recruitChar 响应结构（2026-08-18 抓包校准）：完整养成结构——
    //   instId = 玩家主队伍 instId（非候选序号）；troopInstId = 对局内入队序号（1 基递增）；
    //   skills/master/equip/currentEquip 从玩家源干员补齐（候选 list 为精简结构：
    //   skills 空/master {} /无 equip——activeRecruitTicket 抓包确认）。
    // 候选生成时 troopInstId 暂存玩家 instId（active() 里 troopInstId=char.instId），
    // 此处先读玩家源干员补齐养成，再覆写为对局内入队序号（1 基递增）。
    const troopChars = this._player._player._playerdata.troop?.chars ?? {};
    const src = troopChars[String(picked.troopInstId)] as any;
    const troopNo = Object.keys(this._player.troop.chars).length + 1;
    this.tickets[id].result = Object.assign({}, picked, {
      instId: String(picked.troopInstId),
      troopInstId: String(troopNo),
      skills: src?.skills || [],
      master: src?.master || {},
      equip: src?.equip || {},
      currentEquip: src?.currentEquip ?? "",
    }) as any;

    await this._trigger.emit("rlv2:char:get", [this.tickets[id].result!]);
    await this._trigger.emit("rlv2:get:items", [
      [
        {
          id: "",
          count: -this.tickets[id].result!.population || 0,
          type: "POPULATION",
        },
      ],
    ]);
    this.tickets[id].list = [];
  }

  async gain(id: string, from: string, mustExtra: number): Promise<void> {
    this.tickets[this.index] = {
      index: this.index,
      id,
      state: 0,
      list: [],
      result: null,
      from,
      mustExtra,
      needAssist: from == "initial",
      ts: now(),
    };
    this._index++;
  }

  toJSON(): { [key: string]: PlayerRoguelikeV2.CurrentData.Recruit } {
    return this.tickets;
  }
}
