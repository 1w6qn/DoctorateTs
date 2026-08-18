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
   * 黑流树海（rogue_6）：4 星 0 希望、5 星 2、6 星 4（官方机制，初始希望 6）
   * 其余主题：3 星 0、4 星 2、5 星 3、6 星 6（常规曲线）
   */
  private populationFor(rarityIdx: number): number {
    const theme = this._player.current.game?.theme || "";
    const map =
      theme === "rogue_6" ? [0, 0, 0, 0, 2, 4] : [0, 0, 0, 2, 3, 6];
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
    // 递增 troopInstId，避免多干员互相覆盖（getChar 按 troopInstId+1 定位 instId）
    const troopInstId = Object.keys(this._player.troop.chars).length;
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
      let levelPatch = {};
      if (char.evolvePhase == 2 && !isUpgraded) {
        const maxLevel = excel.GameDataConst.maxLevel[rarityIdx][1];
        levelPatch = {
          evolvePhase: 1,
          level: maxLevel,
          exp: 0,
          skills: char.skills?.map((s: { specializeLevel?: number }) => {
            return Object.assign({}, s, { specializeLevel: 0 });
          }),
        };
      }
      return [
        ...acc,
        Object.assign(
          {},
          char,
          {
            // instId 为候选列表序号（客户端 optionId 选择用）；troopInstId 为真实 troop 干员 instId
            instId: acc.length,
            type: "NORMAL",
            upgradePhase: isUpgraded ? 1 : 0,
            upgradeLimited: !isUpgraded,
            population: population >= 0 ? population : 0,
            isCure: false,
            charBuff: [],
            isUpgrade: false,
            troopInstId: (char as any).instId ?? Object.keys(this._player.troop.chars).length,
          },
          levelPatch,
        ),
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
    this.tickets[id].state = 2;
    this.tickets[id].result = this.tickets[id].list.find(
      (item) => String(item.instId) === String(optionId),
    ) as PlayerRoguelikeV2.CurrentData.RecruitChar;
    // 官服 recruit.result：instId/troopInstId 为字符串（troop 干员 instId），非序号
    if (this.tickets[id].result) {
      this.tickets[id].result = Object.assign({}, this.tickets[id].result, {
        instId: String(this.tickets[id].result.instId),
        troopInstId: String(this.tickets[id].result.troopInstId),
      }) as any;
    }

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
