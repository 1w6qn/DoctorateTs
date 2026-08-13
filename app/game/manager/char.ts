import { TypedEventEmitter } from "@game/model/events";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";
import excel from "@excel/excel";
import { GachaResult } from "@game/model/gacha";
import { now } from "@utils/time";
import { ceil } from "lodash";
import { logger } from "@utils/logger";
import { rarityToIndex } from "@utils/rarity";
import { reconcileCharSkills } from "@game/util/char-skills";
import { PlayerCharacter, PlayerCharPatch } from "@game/model/character";
import { UniEquipData } from "@excel/types_excel_gen";

/** 物品类型数字枚举 → 字符串（spCharMissions 等表的 rewards.type 为数字枚举） */
function itemTypeToString(itemType: number | string): string {
  const key =
    typeof itemType === "string" ? parseInt(itemType, 10) : itemType;
  if (isNaN(key)) return String(itemType);
  const map: { [key: number]: string } = {
    0: "NONE", 1: "CHAR", 2: "CARD_EXP", 3: "MATERIAL", 4: "GOLD",
    5: "EXP_PLAYER", 6: "TKT_TRY", 7: "TKT_RECRUIT", 8: "TKT_INST_FIN",
    9: "TKT_GACHA", 10: "DIAMOND", 11: "DIAMOND_SHD", 12: "LGG_SHD",
    13: "HGG_SHD", 14: "FURN", 15: "ACTIVITY_COIN", 16: "AP_GAMEPLAY",
  };
  return map[key] ?? String(itemType);
}

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
        // 修复：新干员按等级/精英化填充技能（官方规则 allSkillLvlup[i].unlockCond；
        // 原实现 skills 恒为空 → 客户端干员详情无技能可看）+ defaultSkillIndex
        reconcileCharSkills(draft.troop.chars[charInstId]);
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
      // 防御：空 id 的 extraItem 不发放（避免 gainItem 查 ItemTable[""] 警告跳过）
      if (extraItem && extraItem.id) {
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
    // 修复：HasChar 任务事件从未 emit（模板已注册监听）→ 拥有干员类任务永不推进；
    // 干员入账后补发（含新/重复干员）
    const liveChar = this._player._playerdata.troop.chars[charInstId];
    if (liveChar) {
      await this._trigger.emit("HasChar", [{ char: liveChar }]);
      // 修复：勋章事件从未 emit → 干员数量/获得干员勋章永不推进
      await this._trigger.emit("CharNum", [
        { curCharInstId: this._player._playerdata.troop.curCharInstId },
      ]);
      await this._trigger.emit("GotChars", [{ char: liveChar }]);
    }
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
          // 修复：先按当前等级累加本次升级费用，再提升等级——
          // 原实现先 level += 1 再读 goldMap[level-1]，每级都多扣下一级费用
          //（且升到 maxLevel 那一步会读越界档位的费用）
          gold += goldMap[evolvePhase][char.level - 1];
          char.level += 1;
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
      // 技能解锁：等级提升解锁对应技能（如 40/55 级解锁技能2），保留已有技能状态
      reconcileCharSkills(char);
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
      if (!char) return;
      const info = excel.CharacterTable[char.charId];
      const phases = info?.phases;
      // 修复：目标相位必须存在且高于当前——原实现无校验，可升到不存在的相位/免费升阶/倒降级
      if (
        !phases ||
        destEvolvePhase <= char.evolvePhase ||
        !phases[destEvolvePhase]
      ) {
        return;
      }
      const phaseConfig = phases[destEvolvePhase] as {
        evolveCost?: ItemBundle[] | null;
      } | undefined;
      // 防御：部分特殊干员（预备干员等）无精二配置（evolveCost 为 null），跳过消耗直接升阶
      const evolveCost = phaseConfig?.evolveCost ?? [];
      const rarity = rarityToIndex(info.rarity);
      // 修复：evolveGoldCost 中 -1 = 该稀有度无此相位（如 3 星无精二）——
      // 原实现 goldCost=-1 → items:use 反向 +1 金币；不可用相位直接拒绝
      const goldCost =
        excel.GameDataConst.evolveGoldCost[rarity]?.[destEvolvePhase] ?? -1;
      if (goldCost < 0) return;
      await this._trigger.emit("items:use", [
        evolveCost.concat([{ id: "4001", count: goldCost } as ItemBundle]),
      ]);
      char.evolvePhase = destEvolvePhase;
      char.level = 1;
      char.exp = 0;
      // 修复：勋章 CharEvolveCount 事件从未 emit → 精英化勋章永不推进
      await this._trigger.emit("CharEvolveCount", [{ char }]);
      // 技能解锁：精英化解锁对应技能（如 E1 解锁技能2、E2 解锁技能3），保留已有技能状态
      reconcileCharSkills(char);
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
      if (!char) return;
      const info = excel.CharacterTable[char.charId];
      // 修复：targetRank 无钳制可写超上限（如 maxPotential 5 写 99）+ 无道具归属校验；
      // 钳制到 [当前+1, maxPotential]，且只接受该干员潜能道具
      const maxPotential = info?.maxPotentialLevel ?? 5;
      const target = Math.min(Math.max(targetRank, (char.potentialRank ?? 0) + 1), maxPotential);
      const allowedItems = [
        info?.potentialItemId,
        info?.classicPotentialItemId,
        info?.activityPotentialItemId,
      ].filter(Boolean) as string[];
      if (allowedItems.length > 0 && !allowedItems.includes(itemId)) {
        return; // 非法道具：拒绝（防消耗任意库存物品）
      }
      char.potentialRank = target;
      await this._trigger.emit("items:use", [[{ id: itemId, count: 1 }]]);
      await this._trigger.emit("BoostPotential", [{ targetLevel: target }]);
      // 修复：勋章 CharPotential 事件从未 emit → 潜能提升勋章永不推进
      await this._trigger.emit("CharPotential", [{ targetLevel: target }]);
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
      // 防御：targetLevel < 2 时 allSkillLvlup[-] 越界（客户端正常只发 >=2）
      if (targetLevel < 2) {
        throw new Error(`技能目标等级 ${targetLevel} 非法（最低 2）`);
      }
      const targetLevelCost =
        excel.CharacterTable[char.charId].allSkillLvlup[targetLevel - 2]
          .lvlUpCost!;
      char.mainSkillLvl = targetLevel;
      await this._trigger.emit("items:use", [targetLevelCost]);
      // 修复：原实现发错事件 BoostPotential → 技能升级任务（监听 UpgradeSkill）永不推进；
      // 改为 UpgradeSkill
      await this._trigger.emit("UpgradeSkill", [{ targetLevel }]);
      // 修复：勋章 CharSkillCount 事件从未 emit → 技能升级勋章永不推进
      await this._trigger.emit("CharSkillCount", [{ targetLevel }]);
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
      if (!templateId || templateId === char.charId) {
        // 切回基础形态：清除 currentTmpl（避免自引用空模板破坏干员详情——
        // 原实现 currentTmpl:charId + tmpl:{} 使客户端按 currentTmpl 查 tmpl 得 undefined）
        char.currentTmpl = undefined;
        return;
      }
      this._ensureTmplPatch(char, templateId);
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

  // ===== 模组（uniequip）内部工具 =====

  /** 取模组配置（equipDict 含 null 占位条目——防御） */
  private _getEquipData(equipId: string): UniEquipData {
    const data = excel.UniequipTable.equipDict[equipId];
    if (!data) {
      throw new Error(`模组不存在: ${equipId}`);
    }
    return data;
  }

  /** EvolvePhase 枚举字符串 → 数值档位（"PHASE_2" → 2；缺省/未知 → 0） */
  private _phaseRank(phase: unknown): number {
    const m = typeof phase === "string" ? /^PHASE_(\d)$/.exec(phase) : null;
    return m ? Number(m[1]) : 0;
  }

  /** 校验模组归属（equipId 属于该干员或其模板变体） */
  private _assertEquipOwned(
    char: PlayerCharacter,
    equip: UniEquipData,
    templateId: string,
  ): void {
    const owner = templateId || char.charId;
    if (equip.charId !== owner && equip.charId !== char.charId) {
      throw new Error(`模组 ${equip.uniEquipId} 不属于干员 ${owner}`);
    }
  }

  /** 解锁/升级条件校验：精二阶段/等级/信赖（unlockFavors 值 null 表示不要求） */
  private _assertEquipCondition(
    char: PlayerCharacter,
    equip: UniEquipData,
    level: number,
  ): void {
    const phaseNeed = this._phaseRank(equip.unlockEvolvePhase);
    if (char.evolvePhase < phaseNeed) {
      throw new Error(
        `模组 ${equip.uniEquipId} 需精英化${phaseNeed}才能解锁（当前精${char.evolvePhase}）`,
      );
    }
    if (char.level < (equip.unlockLevel ?? 0)) {
      throw new Error(
        `模组 ${equip.uniEquipId} 需等级 ${equip.unlockLevel} 才能解锁（当前 ${char.level}）`,
      );
    }
    const favorNeed = equip.unlockFavors?.[String(level)];
    if (typeof favorNeed === "number" && (char.favorPoint ?? 0) < favorNeed) {
      throw new Error(
        `模组 ${equip.uniEquipId} 需信赖 ${favorNeed}（当前 ${char.favorPoint}）`,
      );
    }
  }

  /** 模组最高等级（itemCost 键的最大档位，缺省 1） */
  private _maxEquipLevel(equip: UniEquipData): number {
    const keys = Object.keys(equip.itemCost ?? {});
    return keys.length ? Math.max(...keys.map((k) => Number(k))) : 1;
  }

  /** 确保干员模板补丁存在（缺失时按基础形态初始化——皮肤/技能/模组状态拷贝） */
  private _ensureTmplPatch(
    char: PlayerCharacter,
    templateId: string,
  ): PlayerCharPatch {
    if (!char.tmpl) char.tmpl = {};
    if (!char.tmpl[templateId]) {
      char.tmpl[templateId] = {
        skinId: char.skin,
        defaultSkillIndex: char.defaultSkillIndex,
        skills: char.skills?.map((s) => ({ ...s })) ?? [],
        currentEquip: char.currentEquip,
        equip: { ...(char.equip ?? {}) },
      };
    }
    return char.tmpl[templateId];
  }

  /** 解析模组操作目标（base 或 tmpl 变体），并确保 equip 字典存在 */
  private _resolveEquipTarget(
    char: PlayerCharacter,
    templateId: string,
  ): PlayerCharacter | PlayerCharPatch {
    if (templateId) return this._ensureTmplPatch(char, templateId);
    if (!char.equip) char.equip = {};
    return char;
  }

  /** 特殊模组任务目标值（paramList 首个数值，缺省 1）——任务直接播种完成态 */
  private _missionTarget(missionId: string): number {
    const mission = excel.UniequipTable.missionList[missionId];
    for (const raw of mission?.paramList ?? []) {
      const n = Number(raw);
      if (Number.isFinite(n) && n > 0) return n;
    }
    return 1;
  }

  async setEquipment(args: {
    charInstId: number;
    templateId: string;
    equipId: string;
  }): Promise<void> {
    await this._player.update(async (draft) => {
      const { charInstId, templateId, equipId } = args;
      const char = draft.troop.chars[charInstId];
      const equipData = this._getEquipData(equipId);
      this._assertEquipOwned(char, equipData, templateId);
      const target = this._resolveEquipTarget(char, templateId);
      const entry = (target.equip[equipId] ??= { hide: 1, locked: 1, level: 1 });
      if (entry.locked) {
        throw new Error(`模组 ${equipId} 尚未解锁，无法装备`);
      }
      target.currentEquip = equipId;
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
      const equipData = this._getEquipData(equipId);
      this._assertEquipOwned(char, equipData, templateId);
      // 解锁条件：精二/等级/信赖（unlockFavors["1"] 数值时校验）
      this._assertEquipCondition(char, equipData, 1);
      const target = this._resolveEquipTarget(char, templateId);
      const entry = (target.equip[equipId] ??= { hide: 1, locked: 1, level: 1 });
      if (!entry.locked) {
        throw new Error(`模组 ${equipId} 已解锁`);
      }
      entry.hide = 0;
      entry.locked = 0;
      // 特殊模组解锁任务：播种完成态（私服无任务结算端点——客户端模组 UI 按
      // playerdata.equipment.missions 显示进度，直接完成可正常解锁/装备）
      if (equipData.missionList?.length) {
        if (!draft.equipment) draft.equipment = { missions: {} };
        if (!draft.equipment.missions) draft.equipment.missions = {};
        for (const missionId of equipData.missionList) {
          if (draft.equipment.missions[missionId]) continue;
          const targetValue = this._missionTarget(missionId);
          draft.equipment.missions[missionId] = {
            value: targetValue,
            target: targetValue,
          };
        }
      }
      await this._trigger.emit("items:use", [equipData.itemCost?.[1] ?? []]);
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
      const equipData = this._getEquipData(equipId);
      this._assertEquipOwned(char, equipData, templateId);
      const target = this._resolveEquipTarget(char, templateId);
      const entry = (target.equip[equipId] ??= { hide: 1, locked: 1, level: 1 });
      if (entry.locked) {
        throw new Error(`模组 ${equipId} 尚未解锁，无法升级`);
      }
      // 修复：先快照旧等级再算扣费（原实现先置 level 再按已更新等级循环——
      // 只扣了目标档一级，且 tmpl 变体误读 base 等级）
      const oldLevel = entry.level;
      if (targetLevel <= oldLevel) {
        throw new Error(`目标等级 ${targetLevel} 不高于当前等级 ${oldLevel}`);
      }
      const maxLevel = this._maxEquipLevel(equipData);
      if (targetLevel > maxLevel) {
        throw new Error(`模组 ${equipId} 最高等级为 ${maxLevel}`);
      }
      // 信赖门槛：unlockFavors[targetLevel] 数值时校验（如 2732/10070 信赖点）
      this._assertEquipCondition(char, equipData, targetLevel);
      const items: ItemBundle[] = [];
      for (let i = oldLevel + 1; i <= targetLevel; i++) {
        items.push(...(equipData.itemCost?.[i] ?? []));
      }
      entry.level = targetLevel;
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
      const mission = excel.CharMetaTable?.spCharMissions?.[charId]?.[missionId];
      if (!mission) {
        throw new Error(`异格干员任务不存在: ${charId}/${missionId}`);
      }
      // 加固：charMission 缺省初始化（新干员/导入存档可能无此键）
      if (!draft.troop.charMission) draft.troop.charMission = {};
      draft.troop.charMission[charId] = draft.troop.charMission[charId] || {};
      if (draft.troop.charMission[charId][missionId] === 2) {
        throw new Error(`任务奖励已领取: ${missionId}`);
      }
      // 资格校验：condType 数值 1 = EVOLVE_PHASE（JSON 数值与 TS 字符串枚举
      // 不一致——按数值/字符串双判断；param = [精二阶段, 等级]）
      const condType = mission.condType as unknown;
      if (condType === 1 || condType === "EVOLVE_PHASE") {
        const [phaseReq, levelReq] = (mission.param ?? []).map((p) => Number(p));
        const char = Object.values(draft.troop.chars).find(
          (c) => c.charId === charId,
        );
        if (!char) {
          throw new Error(`干员不存在: ${charId}`);
        }
        if (char.evolvePhase < phaseReq || char.level < levelReq) {
          throw new Error(
            `未满足异格干员任务条件（需精${phaseReq} 级${levelReq}）: ${missionId}`,
          );
        }
      }
      draft.troop.charMission[charId][missionId] = 2;
      // 修复：spCharMissions.rewards 的 type 是数字枚举（2=CARD_EXP、4=GOLD）——
      // gainItem 的 funcs 按字符串类型键（"CARD_EXP"/"GOLD"），数字 type 恒查不到
      // → 奖励被跳过但任务已标记领取（奖励永久丢失）；统一转字符串类型
      const rewards: ItemBundle[] = (mission.rewards ?? []).map((r: any) => ({
        id: r.id,
        count: r.count,
        type: itemTypeToString(r.type),
      }));
      await this._trigger.emit("items:get", [rewards]);
      return rewards;
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
      // 修复：原实现恒写 maxLevel[rarity][2]（精二满级）——maxLevel 数据为空桩时
      // 写 undefined（等级字段从存档消失）；且无视当前相位（E0 干员被写成 E2 满级）。
      // 按当前相位取对应上限：maxLevel[rarity][evolvePhase]
      const phaseMax =
        excel.GameDataConst.maxLevel[rarity]?.[char.evolvePhase] ??
        excel.GameDataConst.maxLevel[rarity]?.[0] ??
        1;
      char.level = phaseMax;
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
