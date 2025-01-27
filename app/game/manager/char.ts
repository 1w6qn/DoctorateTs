import { TypedEventEmitter } from "@game/model/events";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";
import excel from "@excel/excel";
import { GachaResult } from "@game/model/gacha";
import { now } from "@utils/time";
import { ceil } from "lodash";

export class CharManager {
  _trigger: TypedEventEmitter;
  _player: PlayerDataManager;

  constructor(player: PlayerDataManager, trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = trigger;
    this._trigger.on("char:get", () => {
      this.onCharGet.bind(this);
    });
  }

  async onCharGet([charId, args = { from: "NORMAL" }, callback]: [
    string,
    { from: string; extraItem?: ItemBundle },
    ((res: GachaResult) => void)?,
  ]): Promise<GachaResult> {
    let isNew: number = 0;
    let charInstId: number = 0;
    const items: ItemBundle[] = [];
    await this._player.update(async (draft) => {
      const { from, extraItem } = args;
      isNew = draft.dexNav.character[charId] ? 0 : 1;
      const info = excel.CharacterTable[charId];
      console.log(
        `[TroopManager] 获得${info.rarity + 1}星干员 ${info.name} ${isNew} ${from}`,
      );
      if (isNew) {
        draft.dexNav.character[charId] = {
          charInstId: draft.troop.curCharInstId,
          count: 0,
        };
      }
      const dexInfo = draft.dexNav.character[charId];
      if (from == "CLASSIC") {
        if (dexInfo.classicCount) {
          dexInfo.classicCount += 1;
        } else {
          dexInfo.classicCount = 1;
        }
      } else {
        dexInfo.count += 1;
      }
      charInstId = dexInfo.charInstId;
      if (!isNew) {
        const potentId = excel.CharacterTable[charId].potentialItemId!;
        items.push({ id: potentId, count: 1, type: "MATERIAL" });
        const mul: number = dexInfo.count > 6 ? 1.5 : 1;
        if (from == "CLASSIC") {
          switch (excel.CharacterTable[charId].rarity) {
            case 5:
              items.push({ id: "classic_normal_ticket", count: 100 });
              break;
            case 4:
              items.push({ id: "classic_normal_ticket", count: 50 });
              break;
            case 3:
              items.push({ id: "classic_normal_ticket", count: 5 });
              break;
            case 2:
              items.push({ id: "classic_normal_ticket", count: 1 });
              break;
            default:
              break;
          }
        } else {
          switch (excel.CharacterTable[charId].rarity) {
            case 5:
              items.push({ id: "4004", count: ceil(10 * mul) });
              break;
            case 4:
              items.push({ id: "4004", count: ceil(5 * mul) });
              break;
            case 3:
              items.push({ id: "4005", count: 30 });
              break;
            case 2:
              items.push({ id: "4005", count: 5 });
              break;
            case 1:
              items.push({ id: "4005", count: 1 });
              break;
            case 0:
              items.push({ id: "4005", count: 1 });
              break;
            default:
              break;
          }
        }
      } else {
        draft.troop.chars[charInstId] = {
          instId: charInstId,
          charId,
          favorPoint: 0,
          potentialRank: 0,
          mainSkillLvl: 1,
          skin: `${charId}#1`,
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
        await this._trigger.emit("char:init", [draft.troop.chars[charInstId]]);
        if (from == "CLASSIC") {
          items.push({ id: "classic_normal_ticket", count: 10 });
        } else {
          items.push({ id: "4004", count: 1, type: "HGG_SHD" });
        }
        if (extraItem) {
          items.push(extraItem);
        }
      }
      await this._trigger.emit("items:get", [items]);
    });
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
    charInstId: number;
    expMats: ItemBundle[];
  }): Promise<void> {
    await this._player.update(async (draft) => {
      const { charInstId, expMats } = args;
      const char = draft.troop.chars[charInstId];
      const expMap = excel.GameDataConst.characterExpMap;
      const goldMap = excel.GameDataConst.characterUpgradeCostMap;
      const expItems = excel.ItemTable.expItems;
      let expTotal = 0,
        gold = 0;
      const charId = char.charId;
      const evolvePhase = char.evolvePhase;
      const rarity = excel.CharacterTable[charId].rarity;
      const maxLevel = excel.GameDataConst.maxLevel[rarity][evolvePhase];
      for (let i = 0; i < expMats.length; i++) {
        expTotal += expItems[expMats[i].id].gainExp * expMats[i].count;
      }
      char.exp += expTotal;
      while (true) {
        console.log(gold);
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
      console.log(gold);
      expMats.push({ id: "4001", count: gold });
      console.log(expMats);
      await this._trigger.emit("items:use", [expMats]);
      await this._trigger.emit("UpgradeChar", [{ char, exp: expTotal }]);
    });
    //TODO
  }

  async evolveChar(args: {
    charInstId: number;
    destEvolvePhase: number;
  }): Promise<void> {
    await this._player.update(async (draft) => {
      const { charInstId, destEvolvePhase } = args;
      const char = draft.troop.chars[charInstId];
      const evolveCost = excel.CharacterTable[char.charId].phases[
        destEvolvePhase
      ].evolveCost as ItemBundle[];
      const rarity = excel.CharacterTable[char.charId].rarity;
      const goldCost =
        excel.GameDataConst.evolveGoldCost[rarity][destEvolvePhase];
      await this._trigger.emit("items:use", [
        evolveCost.concat([{ id: "4001", count: goldCost } as ItemBundle]),
      ]);
      char.evolvePhase = destEvolvePhase;
      char.level = 1;
      char.exp = 0;
      //TODO
      if (destEvolvePhase == 2) {
        char.skin = char.charId + "#2";
      }
      await this._trigger.emit("EvolveChar", [{ char }]);
    });
  }

  async boostPotential(args: {
    charInstId: number;
    itemId: string;
    targetRank: number;
  }): Promise<void> {
    await this._player.update(async (draft) => {
      const { charInstId, itemId, targetRank } = args;
      const char = draft.troop.chars[charInstId];
      char.potentialRank = targetRank;
      await this._trigger.emit("items:use", [[{ id: itemId, count: 1 }]]);
      await this._trigger.emit("BoostPotential", [{ targetLevel: targetRank }]);
    });
  }

  async setDefaultSkill(args: {
    charInstId: number;
    defaultSkillIndex: number;
  }): Promise<void> {
    await this._player.update(async (draft) => {
      const { charInstId, defaultSkillIndex } = args;
      const char = draft.troop.chars[charInstId];
      char.defaultSkillIndex = defaultSkillIndex;
    });
  }

  async upgradeSkill(args: {
    charInstId: number;
    targetLevel: number;
  }): Promise<void> {
    await this._player.update(async (draft) => {
      const { charInstId, targetLevel } = args;
      const char = draft.troop.chars[charInstId];
      const targetLevelCost =
        excel.CharacterTable[char.charId].allSkillLvlup[targetLevel - 2]
          .lvlUpCost!;
      char.mainSkillLvl = targetLevel;
      await this._trigger.emit("items:use", [targetLevelCost]);
      await this._trigger.emit("BoostPotential", [{ targetLevel }]);
    });
  }

  async changeCharSkin(args: {
    charInstId: number;
    skinId: string;
  }): Promise<void> {
    await this._player.update(async (draft) => {
      const { charInstId, skinId } = args;
      const char = draft.troop.chars[charInstId];
      char.skin = skinId;
    });
  }

  async changeCharTemplate(args: {
    charInstId: number;
    templateId: string;
  }): Promise<void> {
    await this._player.update(async (draft) => {
      const { charInstId, templateId } = args;
      const char = draft.troop.chars[charInstId];
      char.currentTmpl = templateId;
    });
  }

  async batchSetCharVoiceLan(args: { voiceLan: string }): Promise<void> {
    await this._player.update(async (draft) => {
      const { voiceLan } = args;
      Object.values(draft.troop.chars).forEach(
        (char) => (char.voiceLan = voiceLan),
      );
    });
  }

  async setCharVoiceLan(args: { charList: number[]; voiceLan: string }) {
    await this._player.update(async (draft) => {
      const { charList, voiceLan } = args;
      charList.forEach((charInstId) => {
        const char = draft.troop.chars[charInstId];
        char.voiceLan = voiceLan;
      });
    });
  }

  async setEquipment(args: {
    charInstId: number;
    templateId: string;
    equipId: string;
  }): Promise<void> {
    await this._player.update(async (draft) => {
      const { charInstId, templateId, equipId } = args;
      const char = draft.troop.chars[charInstId];
      if (templateId) {
        char.tmpl![templateId].currentEquip = equipId;
      } else {
        char.currentEquip = equipId;
      }
    });
  }

  async unlockEquipment(args: {
    charInstId: number;
    templateId: string;
    equipId: string;
  }) {
    await this._player.update(async (draft) => {
      const { charInstId, templateId, equipId } = args;
      const char = draft.troop.chars[charInstId];
      if (templateId) {
        char.tmpl![templateId].equip[equipId].hide = 0;
        char.tmpl![templateId].equip[equipId].locked = 0;
      } else {
        char.equip![equipId].hide = 0;
        char.equip![equipId].locked = 0;
      }
      await this._trigger.emit("items:use", [
        excel.UniequipTable.equipDict[equipId].itemCost!["1"],
      ]);
      await this._trigger.emit("HasEquipment", [{ char }]);
    });
  }

  async upgradeEquipment(args: {
    charInstId: number;
    templateId: string;
    equipId: string;
    targetLevel: number;
  }) {
    await this._player.update(async (draft) => {
      const { charInstId, templateId, equipId, targetLevel } = args;
      const char = draft.troop.chars[charInstId];
      const items: ItemBundle[] = [];
      if (templateId) {
        char.tmpl![templateId].equip[equipId].level = targetLevel;
      } else {
        char.equip![equipId].level = targetLevel;
      }
      for (let i = char.equip![equipId].level; i < targetLevel + 1; i++) {
        items.push(...excel.UniequipTable.equipDict[equipId].itemCost![i]);
      }
      await this._trigger.emit("items:use", [items]);
      await this._trigger.emit("HasEquipment", [{ char }]);
    });
  }

  async changeMarkStar(args: { chrIdDict: { [key: string]: number } }) {
    await this._player.update(async (draft) => {
      const { chrIdDict } = args;
      Object.entries(chrIdDict).forEach(([charId, mark]) => {
        const char = draft.troop.chars[charId];
        char.starMark = mark;
      });
    });
  }

  //Duplicated
  async lockChar(args: { charInstIdList: number[] }) {
    await this._player.update(async () => {
      const { charInstIdList } = args;
      charInstIdList.forEach(() => {});
    });
  }

  //Duplicated
  async sellChar(args: { charInstIdList: number[] }) {
    await this._player.update(async () => {
      const { charInstIdList } = args;
      charInstIdList.forEach(() => {});
    });
  }

  //Duplicated
  async upgradeSpecialization(args: {
    charInstId: number;
    skillIndex: number;
    targetLevel: number;
  }) {
    await this._player.update(async (draft) => {
      const { charInstId, skillIndex, targetLevel } = args;
      const char = draft.troop.chars[charInstId];
      char.skills![skillIndex].specializeLevel = targetLevel;
    });
  }

  //Duplicated
  async completeUpgradeSpecialization(args: {
    charInstId: number;
    skillIndex: number;
    targetLevel: number;
  }) {
    await this._player.update(async (draft) => {
      const { charInstId, skillIndex, targetLevel } = args;
      const char = draft.troop.chars[charInstId];
      char.skills![skillIndex].completeUpgradeTime = -1;
      char.skills![skillIndex].specializeLevel = targetLevel;
      await this._trigger.emit("UpgradeSpecialization", [args]);
    });
  }

  async getSpCharMissionReward(args: {
    charId: string;
    missionId: string;
  }): Promise<ItemBundle[]> {
    let items: ItemBundle[] = [];
    await this._player.update(async (draft) => {
      const { charId, missionId } = args;
      items = excel.CharMetaTable.spCharMissions[charId][missionId].rewards;
      draft.troop.charMission[charId][missionId] = 2;
      await this._trigger.emit("items:get", [items]);
    });
    return items;
  }

  async evolveCharUseItem(args: {
    charInstId: number;
    itemId: string;
    instId: number;
  }) {
    await this._player.update(async (draft) => {
      const { charInstId, itemId, instId } = args;
      const char = draft.troop.chars[charInstId];
      char.evolvePhase = 2;
      char.level = 1;
      char.exp = 0;
      char.skin = char.charId + "#2";
      await this._trigger.emit("items:use", [
        [{ id: itemId, count: 1, instId }],
      ]);
    });
  }

  async upgradeCharLevelMaxUseItem(args: {
    charInstId: number;
    itemId: string;
    instId: number;
  }) {
    await this._player.update(async (draft) => {
      const { charInstId, itemId, instId } = args;
      const char = draft.troop.chars[charInstId];
      const rarity = excel.CharacterTable[char.charId].rarity;
      char.level = excel.GameDataConst.maxLevel[rarity][2];
      char.exp = 0;
      await this._trigger.emit("items:use", [
        [{ id: itemId, count: 1, instId }],
      ]);
    });
  }

  async upgradeSpecializedSkillUseItem(args: {
    charInstId: number;
    skillIndex: number;
    itemId: string;
    instId: number;
  }) {
    await this._player.update(async (draft) => {
      const { charInstId, skillIndex, itemId, instId } = args;
      const char = draft.troop.chars[charInstId];
      char.skills![skillIndex].specializeLevel = 3;
      await this._trigger.emit("items:use", [
        [{ id: itemId, count: 1, instId }],
      ]);
    });
  }
}
