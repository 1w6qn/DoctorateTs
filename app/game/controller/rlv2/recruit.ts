import excel from "@excel/excel";
import { TroopManager } from "../../manager/troop";
import { PlayerRoguelikeV2 } from "../../model/rlv2";
import { RoguelikeV2Controller } from "../rlv2";
import { now } from "@utils/time";
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
    });
    this._trigger.on("rlv2:create", () => {
      this.tickets = {};
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
    this._trigger.on("rlv2:create", () => {
      this.tickets = {};
    });
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
    const chars: PlayerRoguelikeV2.CurrentData.RecruitChar[] = Object.values(
      this._troop.chars,
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
      let population = [0, 0, 0, 0, 2, 6][rarity - 1]; //TODO other theme
      for (const buff of this._player._buff.filterBuffs("recruit_cost")) {
        if (
          buff.blackboard[0].valueStr?.includes(data.rarity.toString()) &&
          buff.blackboard[1].valueStr?.includes(data.profession)
        ) {
          population += buff.blackboard[2].value!;
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
        const maxLevel = excel.GameDataConst.maxLevel[rarity - 1][1];
        levelPatch = {
          evolvePhase: 1,
          level: maxLevel,
          exp: 0,
          skills: char.skills?.map((s) => {
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
            instId: acc.length,
            type: "NORMAL",
            upgradePhase: isUpgraded ? 1 : 0,
            upgradeLimited: !isUpgraded,
            population: population >= 0 ? population : 0,
            isCure: false,
            charBuff: [],
            isUpgrade: false,
            troopInstId: Object.keys(this._player.troop.chars).length,
          },
          levelPatch,
        ),
      ];
    }, [] as PlayerRoguelikeV2.CurrentData.RecruitChar[]);
    //TODO free & third-low
    this.tickets[id].list = chars;
  }

  async done(id: string, optionId: string) {
    this.tickets[id].state = 2;
    this.tickets[id].result = this.tickets[id].list.find(
      (item) => item.instId == parseInt(optionId),
    ) as PlayerRoguelikeV2.CurrentData.RecruitChar;

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
