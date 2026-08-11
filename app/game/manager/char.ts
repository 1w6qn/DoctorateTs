import { TypedEventEmitter } from "@game/model/events";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";
import excel from "@excel/excel";
import { GachaResult } from "@game/model/gacha";
import { now } from "@utils/time";
import { ceil } from "lodash";
import { logger } from "@utils/logger";
import { rarityToIndex } from "@utils/rarity";

export class CharManager {
  _trigger: TypedEventEmitter;
  _player: PlayerDataManager;

  constructor(player: PlayerDataManager, trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = trigger;
    // 修复：原订阅丢弃了 onCharGet.bind() 结果（抽卡/招募干员从未入账）；
    // 改为异步闭包调用（事件处理器要求 void 返回）
    this._trigger.on("char:get", async (data) => {
      await this.onCharGet(data);
    });
    this._trigger.on("char:levelUp", async ([{ charId, level }]) => {
      await this._player.update(async (draft) => {
        const char = draft.troop.chars[charId];
        const charInfo = excel.CharacterTable[char.charId];
        if (rarityToIndex(charInfo.rarity) <= 1 && char.level == 30) {
          //unlock addonStage
          //unlock addonStory
          //unlock buildingSkill
        }
        if (rarityToIndex(charInfo.rarity) <= 2 && char.level == 55) {
          //unlock addonStage
          //unlock addonStory
          //unlock buildingSkill
        }
      });
    });
  }

  async onCharGet([charId, args = { from: "NORMAL" }, callback]: [
    string,
    ({ from: string; extraItem?: ItemBundle } | undefined)?,
    ((res: GachaResult) => void)?,
  ]): Promise<GachaResult> {
    let isNew: number = 0;
    let charInstId: number = 0;
    let potent: { delta: number; now: number } | undefined;
    /** 新干员 instId（recipe 结束后统一 emit char:init） */
    let createdCharInstId: number | undefined;
    const items: ItemBundle[] = [];
    await this._player.update(async (draft) => {
      const { from, extraItem } = args;
      isNew = draft.dexNav.character[charId] ? 0 : 1;
      const info = excel.CharacterTable[charId];
      logger.info(
        "CharManager",
        `获得${rarityToIndex(info.rarity) + 1}星干员 ${info.name} ${isNew ? "新" : "重复"} ${from}`,
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
      // 防御：dexNav.charInstId 悬空/错指（干员发放重建 roster 或导入损坏）时，
      // 客户端按 charInstId 查 troop.chars 失败 → 抽卡结果"获取干员信息"报错。
      // 按 charId 在 roster 找回正确 instId 并同步修正 dexNav（patch 随 delta 下发）。
      if (!isNew) {
        const liveChars = this._player._playerdata.troop.chars;
        const rosterChar = liveChars[charInstId];
        if (!rosterChar || rosterChar.charId !== charId) {
          const found = Object.entries(liveChars).find(
            ([, c]) => c.charId === charId,
          );
          if (found) {
            charInstId = Number(found[0]);
            dexInfo.charInstId = charInstId;
          }
        }
      }
      if (!isNew) {
        const potentId = excel.CharacterTable[charId].potentialItemId!;
        items.push({ id: potentId, count: 1, type: "MATERIAL" });
        // 修复：CS GachaResult.potent——未满潜的重复干员返回潜能提升信息（delta/now）
        const maxPotential = excel.CharacterTable[charId].maxPotentialLevel ?? 5;
        // 性能：从实时对象读（不经 draft 代理 troop.chars——只读子树被代理后
        // unfinalizedDrafts_ 永不归零，Immer finalize 全树遍历每次 update ~90ms）
        const repeatChar =
          this._player._playerdata.troop.chars[charInstId];
        if (repeatChar && (repeatChar.potentialRank ?? 0) < maxPotential) {
          potent = { delta: 1, now: (repeatChar.potentialRank ?? 0) + 1 };
        }
        const mul: number = dexInfo.count > 6 ? 1.5 : 1;
        if (from == "CLASSIC") {
          switch (rarityToIndex(excel.CharacterTable[charId].rarity)) {
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
          switch (rarityToIndex(excel.CharacterTable[charId].rarity)) {
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
          // 修复：新干员不写 currentTmpl/tmpl —— 官方参考（test.json 379 干员仅
          // char_002_amiya 有 currentTmpl/tmpl，且指向异格形态并带完整 tmpl 映射）。
          // 原实现 currentTmpl:charId + tmpl:{} 为自引用空模板 → 破坏存档结构
          //（客户端干员详情按 currentTmpl 查 tmpl 得 undefined）。
          currentEquip: null,
          equip: {},
          voiceLan: "CN_MANDARIN",
        };
        // 修复：新干员创建后递增 curCharInstId，避免后续新干员 instId 冲突互相覆盖
        draft.troop.curCharInstId += 1;
        createdCharInstId = charInstId;
        if (from == "CLASSIC") {
          items.push({ id: "classic_normal_ticket", count: 10 });
        } else {
          items.push({ id: "4004", count: 1, type: "HGG_SHD" });
        }
      }
      // 修复：extraItem（如限定池 LMTGSID 凭证）每抽发放，与是否新干员无关
      //（原实现只在 isNew 分支内发放 → 重复干员抽不到限定凭证）
      if (extraItem) {
        items.push(extraItem);
      }
    });
    // 优化+修复：items:get / char:init 移到 recipe 之后触发。
    // 原实现在 recipe 内 await emit("items:get") → gainItem 对同一 base 嵌套 update
    //（外层 draft 未关闭）→ Immer 无法增量 diff，每次 update 全树对比（十连每抽
    // ~250ms）；且内层 finishDraft 先替换 _playerdata、外层 finishDraft 再按旧 base
    // 覆盖 → 发放物品从存档丢失（数据一致性 bug）。移出后每次 update 只 diff 实际
    // 变更路径，入账物品也在干员落定后独立 update。
    if (createdCharInstId != null) {
      await this._trigger.emit("char:init", [
        this._player._playerdata.troop.chars[createdCharInstId],
      ]);
    }
    await this._trigger.emit("items:get", [items]);
    const res = {
      charInstId: charInstId,
      charId: charId,
      isNew: isNew,
      itemGet: items,
      ...(potent ? { potent } : {}),
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
      const rarity = rarityToIndex(excel.CharacterTable[charId].rarity);
      // 防御：稀有度/精二阶段超界（如 1 星机器人被满配生成器置为 phase 2）时钳制到有效档位
      const maxLevelArr = excel.GameDataConst.maxLevel[rarity] ?? [];
      const maxLevel =
        maxLevelArr[evolvePhase] ?? maxLevelArr[maxLevelArr.length - 1] ?? 0;
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
      expMats.push({ id: "4001", count: gold });
      await this._trigger.emit("items:use", [expMats]);
      await this._trigger.emit("UpgradeChar", [{ char, exp: expTotal }]);
    });
  }

  async evolveChar(args: {
    charInstId: number;
    destEvolvePhase: number;
  }): Promise<void> {
    await this._player.update(async (draft) => {
      const { charInstId, destEvolvePhase } = args;
      const char = draft.troop.chars[charInstId];
      const phaseConfig = excel.CharacterTable[char.charId].phases[
        destEvolvePhase
      ] as { evolveCost?: ItemBundle[] | null } | undefined;
      // 防御：部分特殊干员（预备干员等）无精二配置（evolveCost 为 null），跳过消耗直接升阶
      const evolveCost = phaseConfig?.evolveCost ?? [];
      const rarity = rarityToIndex(excel.CharacterTable[char.charId].rarity);
      const goldCost =
        excel.GameDataConst.evolveGoldCost[rarity][destEvolvePhase] ?? 0;
      await this._trigger.emit("items:use", [
        evolveCost.concat([{ id: "4001", count: goldCost } as ItemBundle]),
      ]);
      char.evolvePhase = destEvolvePhase;
      char.level = 1;
      char.exp = 0;
      if (destEvolvePhase >= 2) {
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
    return await this._player.update(async (draft) => {
      const { charId, missionId } = args;
      const items =
        excel.CharMetaTable.spCharMissions[charId][missionId].rewards;
      draft.troop.charMission[charId][missionId] = 2;
      await this._trigger.emit("items:get", [items]);
      return items;
    });
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
      const rarity = rarityToIndex(excel.CharacterTable[char.charId].rarity);
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
