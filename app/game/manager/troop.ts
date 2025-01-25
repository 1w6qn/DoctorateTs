import {
  PlayerCharacter,
  PlayerHandBookAddon,
  PlayerSquad,
  PlayerSquadItem,
} from "../model/character";
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { now } from "@utils/time";
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

  get chars(): { [key: string]: PlayerCharacter } {
    return this._player._playerdata.troop.chars;
  }

  get squads(): { [key: string]: PlayerSquad } {
    return this._player._playerdata.troop.squads;
  }

  get addon(): { [key: string]: PlayerHandBookAddon } {
    return this._player._playerdata.troop.addon;
  }

  getCharacterByInstId(instId: number): PlayerCharacter {
    return this.chars[instId];
  }

  async squadFormation(args: {
    squadId: number;
    slots: PlayerSquadItem[];
  }): Promise<void> {
    this.squads[args.squadId].slots = args.slots;
    await this._trigger.emit("SquadFormation", []);
  }

  async changeSquadName(args: {
    squadId: number;
    name: string;
  }): Promise<void> {
    this.squads[args.squadId].name = args.name;
    await this._trigger.emit("ChangeSquadName", []);
  }

  async decomposePotentialItem(args: {
    charInstIdList: string[];
  }): Promise<ItemBundle[]> {
    const costs: ItemBundle[] = [];
    const items: ItemBundle[] = args.charInstIdList.reduce(
      (acc, charInstId) => {
        const char = this.getCharacterByInstId(parseInt(charInstId));
        const rarity = excel.CharacterTable[char.charId].rarity;
        const potentialItemId =
          excel.CharacterTable[char.charId].potentialItemId!;
        const count = this._player._playerdata.inventory[potentialItemId];
        costs.push({ id: potentialItemId, count: count });
        const item =
          excel.GachaTable.potentialMaterialConverter.items[rarity - 1];
        acc.push({ id: item.id, count: item.count * count });
        return acc;
      },
      [] as ItemBundle[],
    );
    await this._trigger.emit("items:use", [costs]);
    await this._trigger.emit("items:get", [items]);
    return items;
  }

  async decomposeClassicPotentialItem(args: {
    charInstIdList: string[];
  }): Promise<ItemBundle[]> {
    const costs: ItemBundle[] = [];
    const items: ItemBundle[] = args.charInstIdList.reduce(
      (acc, charInstId) => {
        const char = this.getCharacterByInstId(parseInt(charInstId));
        const rarity = excel.CharacterTable[char.charId].rarity;
        const potentialItemId =
          excel.CharacterTable[char.charId].classicPotentialItemId!;
        const count = this._player._playerdata.inventory[potentialItemId];
        costs.push({ id: potentialItemId, count: count });
        const item =
          excel.GachaTable.classicPotentialMaterialConverter.items[rarity - 1];
        acc.push({ id: item.id, count: item.count * count });
        return acc;
      },
      [] as ItemBundle[],
    );
    await this._trigger.emit("items:use", [costs]);
    await this._trigger.emit("items:get", [items]);
    return items;
  }

  async addonStoryUnlock(args: { charId: string; storyId: string }) {
    if (!this.addon[args.charId].story) {
      this.addon[args.charId].story = {};
    }
    this.addon[args.charId].story![args.storyId] = {
      fts: now(),
      rts: now(),
    };
  }

  async addonStageBattleStart(args: {
    charId: string;
    stageId: string;
    squad: PlayerSquad;
    stageType: string;
  }) {
    const { stageId, squad } = args;
    //TODO
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
    await this._trigger.emit("battle:finish", [args]);
  }

  async fix(): Promise<void> {
    Object.values(this.chars).forEach((char) => {
      if (char.charId == "char_002_amiya") {
        //TODO
        return;
      }
      const skills = excel.CharacterTable[char.charId].skills;
      skills.forEach((skill) => {
        if (!char.skills?.some((s) => s.skillId == skill.skillId)) {
          char.skills?.push({
            skillId: skill.skillId!,
            unlock:
              char.evolvePhase >=
                parseInt(skill.unlockCond.phase.toString().slice(-1)) &&
              char.level >= skill.unlockCond.level
                ? 1
                : 0,
            state: 0,
            specializeLevel: 0,
            completeUpgradeTime: -1,
          });
        } else {
          char.skills!.find((s) => s.skillId == skill.skillId)!.unlock =
            char.evolvePhase >=
              parseInt(skill.unlockCond.phase.toString().slice(-1)) &&
            char.level >= skill.unlockCond.level
              ? 1
              : 0;
        }
      });
      char.defaultSkillIndex = skills
        ? char.defaultSkillIndex != -1
          ? char.defaultSkillIndex
          : 0
        : -1;
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
  }
}
