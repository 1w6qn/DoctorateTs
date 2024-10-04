import {
  PlayerCharacter,
  PlayerHandBookAddon,
  PlayerSquad,
  PlayerSquadItem,
} from "../model/character";
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { GachaResult } from "../model/gacha";
import { now } from "@utils/time";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";

export class TroopManager {
  _trigger: TypedEventEmitter;
  _player: PlayerDataManager;

  constructor(player: PlayerDataManager, trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = trigger;
    this._trigger.on("char:get", this.gainChar.bind(this));
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

  get charMission(): { [key: string]: { [key: string]: number } } {
    return this._player._playerdata.troop.charMission;
  }

  get curCharInstId(): number {
    return Object.keys(this.chars).length + 1;
  }

  getCharacterByCharId(charId: string): PlayerCharacter {
    return Object.values(this.chars).find(
      (char) => char.charId === charId,
    ) as PlayerCharacter;
  }

  getCharacterByInstId(instId: number): PlayerCharacter {
    return this.chars[instId] as PlayerCharacter;
  }

  async gainChar(
    charId: string,
    args: { from: string; extraItem?: ItemBundle } = { from: "NORMAL" },
    callback?: (res: GachaResult) => void,
  ): Promise<GachaResult> {
    const isNew = Object.values(this.chars).some(
      (char) => char.charId === charId,
    )
      ? 0
      : 1;
    let charInstId;
    const items: ItemBundle[] = [];
    const info = excel.CharacterTable[charId];
    console.log(
      `[TroopManager] 获得${info.rarity.slice(-1)}星干员 ${info.name} ${isNew} ${args.from}`,
    );
    if (!isNew) {
      charInstId = this.getCharacterByCharId(charId).instId;
      const potentId = excel.CharacterTable[charId].potentialItemId as string;
      items.push({ id: potentId, count: 1, type: "MATERIAL" });
      let t = false;
      if (this._player._playerdata.dexNav.character[charId]) {
        t = this._player._playerdata.dexNav.character[charId].count > 6;
      }
      if (args.from == "CLASSIC") {
        switch (excel.CharacterTable[charId].rarity) {
          case "TIER_6":
            items.push({ id: "classic_normal_ticket", count: 100 });
            break;
          case "TIER_5":
            items.push({ id: "classic_normal_ticket", count: 50 });
            break;
          case "TIER_4":
            items.push({ id: "classic_normal_ticket", count: 5 });
            break;
          case "TIER_3":
            items.push({ id: "classic_normal_ticket", count: 1 });
            break;
          default:
            break;
        }
      } else {
        switch (excel.CharacterTable[charId].rarity) {
          case "TIER_6":
            items.push({ id: "4004", count: t ? 15 : 10 });
            break;
          case "TIER_5":
            items.push({ id: "4004", count: t ? 8 : 5 });
            break;
          case "TIER_4":
            items.push({ id: "4005", count: 30 });
            break;
          case "TIER_3":
            items.push({ id: "4005", count: 5 });
            break;
          case "TIER_2":
            items.push({ id: "4005", count: 1 });
            break;
          case "TIER_1":
            items.push({ id: "4005", count: 1 });
            break;
          default:
            break;
        }
      }
    } else {
      charInstId = this.curCharInstId;
      this.chars[this.curCharInstId] = {
        instId: charInstId,
        charId,
        favorPoint: 0,
        potentialRank: 0,
        mainSkillLvl: 1,
        skinId: `${charId}#1`,
        level: 1,
        exp: 0,
        evolvePhase: 0,
        defaultSkillIndex: -1,
        gainTime: now(),
        skills: [],
        currentEquip: null,
        equip: {},
        voiceLan: "CN_MANDARIN",
      };
      this._trigger.emit("char:init", this.getCharacterByCharId(charId));
      if (args.from == "CLASSIC") {
        items.push({ id: "classic_normal_ticket", count: 10 });
      } else {
        items.push({ id: "4004", count: 1, type: "HGG_SHD" });
      }
      if (args.extraItem) {
        items.push(args.extraItem);
      }
      this._trigger.emit("game:fix");
    }
    this._trigger.emit("items:get", items);
    const res = {
      charInstId: charInstId,
      charId: charId,
      isNew: isNew,
      itemGet: items,
    };
    callback?.(res);
    return res;
  }

  async upgradeChar(args: {
    instId: number;
    expMats: ItemBundle[];
  }): Promise<void> {
    const { instId, expMats } = args;
    const char = this.getCharacterByInstId(instId);
    const expMap = excel.GameDataConst.characterExpMap;
    const goldMap = excel.GameDataConst.characterUpgradeCostMap;
    const expItems = excel.ItemTable.expItems;
    let expTotal = 0,
      gold = 0;
    const charId = char.charId;
    const evolvePhase = char.evolvePhase;
    const rarity = parseInt(excel.CharacterTable[charId].rarity.slice(-1));
    const maxLevel = excel.GameDataConst.maxLevel[rarity - 1][evolvePhase];
    for (let i = 0; i < expMats.length; i++) {
      expTotal += expItems[expMats[i].id].gainExp * expMats[i].count;
    }
    char.exp += expTotal;
    while (true) {
      if (char.exp >= expMap[evolvePhase][char.level - 1]) {
        char.exp -= expMap[evolvePhase][char.level - 1];
        char.level += 1;
        gold += goldMap[evolvePhase][char.level - 1];
        if (char.level >= maxLevel) {
          char.level = maxLevel;
          char.exp = 0;
          break;
        }
      } else {
        break;
      }
    }
    //TODO
    expMats.push({ id: "4001", count: gold });
    this._trigger.emit("items:use", expMats);
    this._trigger.emit("UpgradeChar", { char, exp: expTotal });
  }

  async evolveChar(args: {
    instId: number;
    destEvolvePhase: number;
  }): Promise<void> {
    const char = this.getCharacterByInstId(args.instId);
    const evolveCost = excel.CharacterTable[char.charId].phases[
      args.destEvolvePhase
    ].evolveCost as ItemBundle[];
    const rarity = parseInt(excel.CharacterTable[char.charId].rarity.slice(-1));
    const goldCost =
      excel.GameDataConst.evolveGoldCost[rarity][args.destEvolvePhase];
    this._trigger.emit(
      "items:use",
      evolveCost.concat([{ id: "4001", count: goldCost } as ItemBundle]),
    );
    char.evolvePhase = args.destEvolvePhase;
    char.level = 1;
    char.exp = 0;
    //TODO
    if (args.destEvolvePhase == 2) {
      this.chars[args.instId].skinId = char.charId + "#2";
    }
    this._trigger.emit("EvolveChar", { char });
  }

  async boostPotential(args: {
    instId: number;
    itemId: string;
    targetRank: number;
  }): Promise<void> {
    this._trigger.emit("items:use", [{ id: args.itemId, count: 1 }]);
    this.chars[args.instId].potentialRank = args.targetRank;
    this._trigger.emit("BoostPotential", { targetLevel: args.targetRank });
  }

  async setDefaultSkill(args: {
    instId: number;
    defaultSkillIndex: number;
  }): Promise<void> {
    this.chars[args.instId].defaultSkillIndex = args.defaultSkillIndex;
  }

  async upgradeSkill(args: {
    instId: number;
    targetLevel: number;
  }): Promise<void> {
    const { instId, targetLevel } = args;
    const char = this.getCharacterByInstId(instId);
    this._trigger.emit(
      "items:use",
      excel.CharacterTable[char.charId].allSkillLvlup[targetLevel - 2]
        .lvlUpCost as ItemBundle[],
    );
    char.mainSkillLvl = targetLevel;
    this._trigger.emit("BoostPotential", { targetLevel });
  }

  async changeCharSkin(args: {
    instId: number;
    skinId: string;
  }): Promise<void> {
    this.chars[args.instId].skinId = args.skinId;
  }

  async changeCharTemplate(args: {
    instId: number;
    templateId: string;
  }): Promise<void> {
    this.chars[args.instId].currentTmpl = args.templateId;
  }

  async batchSetCharVoiceLan(args: { voiceLan: string }): Promise<void> {
    Object.values(this.chars).forEach(
      (char) => (char.voiceLan = args.voiceLan),
    );
  }

  async setCharVoiceLan(args: { charList: number[]; voiceLan: string }) {
    const { charList, voiceLan } = args;
    charList.forEach((charInstId) => {
      const char = this.getCharacterByInstId(charInstId);
      char.voiceLan = voiceLan;
    });
  }

  async setEquipment(args: {
    charInstId: number;
    templateId: string;
    equipId: string;
  }): Promise<void> {
    const char = this.getCharacterByInstId(args.charInstId);
    if (args.templateId) {
      char.tmpl![args.templateId].currentEquip = args.equipId;
    } else {
      char.currentEquip = args.equipId;
    }
  }

  async unlockEquipment(args: {
    charInstId: number;
    templateId: string;
    equipId: string;
  }) {
    const char = this.getCharacterByInstId(args.charInstId);
    if (args.templateId) {
      char.tmpl![args.templateId].equip[args.equipId].hide = 0;
      char.tmpl![args.templateId].equip[args.equipId].locked = 0;
    } else {
      char.equip![args.equipId].hide = 0;
      char.equip![args.equipId].locked = 0;
    }
    this._trigger.emit(
      "items:use",
      excel.UniequipTable.equipDict[args.equipId].itemCost!["1"],
    );
    this._trigger.emit("HasEquipment", { char });
  }

  async upgradeEquipment(args: {
    charInstId: number;
    templateId: string;
    equipId: string;
    targetLevel: number;
  }) {
    const char = this.getCharacterByInstId(args.charInstId);
    const items: ItemBundle[] = [];
    if (args.templateId) {
      char.tmpl![args.templateId].equip[args.equipId].level = args.targetLevel;
    } else {
      char.equip![args.equipId].level = args.targetLevel;
    }
    for (
      let i = char.equip![args.equipId].level;
      i < args.targetLevel + 1;
      i++
    ) {
      items.push(...excel.UniequipTable.equipDict[args.equipId].itemCost![i]);
    }
    this._trigger.emit("items:use", items);
    this._trigger.emit("HasEquipment", { char });
  }

  async changeMarkStar(args: { chrIdDict: { [key: string]: number } }) {
    Object.entries(args.chrIdDict).forEach(([charId, mark]) => {
      const char = this.getCharacterByCharId(charId);
      char.starMark = mark;
    });
  }

  async lockChar(args: { charInstIdList: number[] }) {
    const { charInstIdList } = args;
    charInstIdList.forEach(() => {});
  }

  async sellChar(args: { charInstIdList: number[] }) {
    const { charInstIdList } = args;
    charInstIdList.forEach(() => {});
  }

  async upgradeSpecialization(args: {
    charInstId: number;
    skillIndex: number;
    targetLevel: number;
  }) {
    const { charInstId, skillIndex, targetLevel } = args;
    const char = this.getCharacterByInstId(charInstId);
    //TODO:
    char.skills![skillIndex].specializeLevel = targetLevel;
  }

  async completeUpgradeSpecialization(args: {
    charInstId: number;
    skillIndex: number;
    targetLevel: number;
  }) {
    const { charInstId, skillIndex, targetLevel } = args;
    //TODO
    const char = this.getCharacterByInstId(charInstId);
    char.skills![skillIndex].completeUpgradeTime = -1;
    char.skills![skillIndex].specializeLevel = targetLevel;
    this._trigger.emit("UpgradeSpecialization", args);
  }

  async getSpCharMissionReward(args: {
    charId: string;
    missionId: string;
  }): Promise<ItemBundle[]> {
    const items: ItemBundle[] =
      excel.CharMetaTable.spCharMissions[args.charId][args.missionId].rewards;
    this.charMission[args.charId][args.missionId] = 2;
    this._trigger.emit("items:get", items);
    return items;
  }

  async evolveCharUseItem(args: {
    charInstId: number;
    itemId: string;
    instId: number;
  }) {
    const char = this.getCharacterByInstId(args.charInstId);
    char.evolvePhase = 2;
    char.level = 1;
    char.exp = 0;
    this.chars[args.instId].skinId = char.charId + "#2";
    this._trigger.emit("items:use", [
      { id: args.itemId, count: 1, instId: args.instId },
    ]);
  }

  async upgradeCharLevelMaxUseItem(args: {
    charInstId: number;
    itemId: string;
    instId: number;
  }) {
    const char = this.getCharacterByInstId(args.charInstId);
    const rarity = parseInt(excel.CharacterTable[char.charId].rarity.slice(-1));
    char.level = excel.GameDataConst.maxLevel[rarity - 1][char.evolvePhase];
    char.exp = 0;
    this._trigger.emit("items:use", [
      { id: args.itemId, count: 1, instId: args.instId },
    ]);
  }

  async upgradeSpecializedSkillUseItem(args: {
    charInstId: number;
    skillIndex: number;
    itemId: string;
    instId: number;
  }) {
    const char = this.getCharacterByInstId(args.charInstId);
    char.skills![args.skillIndex].specializeLevel = 3;
    this._trigger.emit("items:use", [
      { id: args.itemId, count: 1, instId: args.instId },
    ]);
  }

  async squadFormation(
    squadId: number,
    slots: PlayerSquadItem[],
  ): Promise<void> {
    this.squads[squadId].slots = slots;
    this._trigger.emit("SquadFormation");
  }

  async changeSquadName(args: {
    squadId: number;
    name: string;
  }): Promise<void> {
    this.squads[args.squadId].name = args.name;
    this._trigger.emit("ChangeSquadName");
  }

  async decomposePotentialItem(args: {
    charInstIdList: string[];
  }): Promise<ItemBundle[]> {
    const costs: ItemBundle[] = [];
    const items: ItemBundle[] = args.charInstIdList.reduce(
      (acc, charInstId) => {
        const char = this.getCharacterByInstId(parseInt(charInstId));
        const rarity = parseInt(
          excel.CharacterTable[char.charId].rarity.slice(-1),
        );
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
    this._trigger.emit("items:use", costs);
    this._trigger.emit("items:get", items);
    return items;
  }

  async decomposeClassicPotentialItem(args: {
    charInstIdList: string[];
  }): Promise<ItemBundle[]> {
    const costs: ItemBundle[] = [];
    const items: ItemBundle[] = args.charInstIdList.reduce(
      (acc, charInstId) => {
        const char = this.getCharacterByInstId(parseInt(charInstId));
        const rarity = parseInt(
          excel.CharacterTable[char.charId].rarity.slice(-1),
        );
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
    this._trigger.emit("items:use", costs);
    this._trigger.emit("items:get", items);
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
    this._trigger.emit("battle:start", {
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
    });
  }

  async addonStageBattleFinish(args: {
    data: string;
    battleData: { isCheat: string; completeTime: number };
  }) {
    this._trigger.emit("battle:finish", args);
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
