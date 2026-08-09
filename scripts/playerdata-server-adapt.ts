import type { ClassDef } from "./playerdata-parser";

/**
 * 服务端协议适配层
 *
 * 客户端 2.7.61 反编译（Assembly-CSharp.dll）的 PlayerDataModel 与服务端 JSON
 * 序列化协议系统性分叉（服务端用保守旧 key/结构，且是超集，如 PlayerCharacter
 * 的 skin/tmpl 双结构并存）。本模块把生成类型视图从「客户端模型」变换为
 * 「服务端协议」，以 test.json（当前官服服务端数据）为权威校验基准。
 *
 * 三操作（按序应用）：
 * 1. renameFields   —— 客户端字段名 → 服务端 JSON key（如 campaign → campaignsV2）
 * 2. addFields      —— 服务端独有、客户端模型未声明的字段（如 PlayerStage.startTimes）
 * 3. overrideFields —— 字段类型整体替换（结构差异；"[server]" 键表示整接口覆盖为索引签名）
 */

/** 字段改名：接口名 → { 客户端字段名: 服务端 JSON key } */
export const SERVER_RENAME_FIELDS: Record<string, Record<string, string>> = {
  PlayerDataModel: {
    campaign: "campaignsV2",
    arkOdc: "arkodc",
    events: "event",
    playerNameCardStyle: "nameCardStyle",
    PlayerAvatar: "avatar",
    playerHomeBackground: "background",
    playerHomeTheme: "homeTheme",
    playerMainlineRecord: "mainline",
    playerAprilFool: "aprilFool",
    autoChessPerm: "autochessSeason",
    playerSetting: "setting",
  },
  PlayerSocial: {
    yesterdayCrisisSeasonId: "yCrisisSs",
    yesterdayCrisisV2SeasonId: "yCrisisV2Ss",
  },
  PlayerTroop: {
    curCharInstCount: "curCharInstId",
  },
  PlayerMedalBoard: {
    customIndex: "custom",
    templateGroupId: "template",
  },
  PlayerCrisis: {
    currentSeason: "current",
  },
  PlayerCharRotation: {
    currentPresetId: "current",
    presets: "preset",
  },
  PlayerAprilFool: {
    actFun3: "act3fun",
    actFun4: "act4fun",
    actFun5: "act5fun",
    actFun6: "act6fun",
    actFun7: "act7fun",
  },
  PlayerCampaign_StageOpenInfo: {
    rotateGroup: "rGroup",
    trainingGroup: "tGroup",
    trainingAllOpenGroup: "tAllOpen",
  },
  PlayerCheckIn_PlayerNewbiePackage: {
    isOpen: "open",
    checkinFinTs: "finish",
    stopSaleTs: "stopSale",
  },
  PlayerRoguelikeV2_OuterData_Collection: {
    endbook: "endBook",
  },
  PlayerRoguelikeV2_OuterData_PlayerRogueActivity: {
    roguelikeActivitySeedModeDatas: "SEED_MODE", // 服务端 activity 字典键为 SEED_MODE（种子模式活动）
  },
  PlayerActFun6Stage: {
    speedRunning: "speedrunning",
  },
  TowerTactical: {
    pioneer: "PIONEER",
    warrior: "WARRIOR",
    tank: "TANK",
    sniper: "SNIPER",
    caster: "CASTER",
    support: "SUPPORT",
    medic: "MEDIC",
    special: "SPECIAL",
  },
};

/** 服务端独有字段补充：接口名 → { 字段名: TS 类型 } */
export const SERVER_ADD_FIELDS: Record<string, Record<string, string>> = {
  PlayerDataModel: {
    deleted: "{ [key: string]: object }",
    checkMeta: "{ version: number; ts: number }",
  },
  PlayerStage: {
    startTimes: "number",
    practiceTimes: "number",
  },
  PlayerSpecialStage: {
    type: "string",
    val: "number",
    fts: "number",
    rts: "number",
  },
  PlayerStatus: {
    uid: "string",
    avatarId: "string",
    friendNumLimit: "number",
    tipMonthlyCardExpireTs: "number",
  },
  PlayerTroop: {
    charGroup: "{ [key: string]: object }",
  },
  PlayerCharPatch: {
    skills: "PlayerSkill[]",
  },
  PlayerNpcWithAudio: {
    npcShowAudioInfoFlag: "string",
  },
  PlayerReturnData: {
    current: "object",
  },
  PlayerHandBookAddon_GetInfo: {
    startTimes: "number",
    completeTimes: "number",
    state: "number",
    startTime: "number",
  },
  PlayerMedalBoard: {
    templateMedalList: "object[]",
  },
  PlayerMainlineRecord: {
    version: "number",
    charVoiceRecord: "{ [key: string]: object }",
  },
  PlayerAvatar: {
    avatar_icon: "{ [key: string]: object }",
  },
  PlayerHomeBackground: {
    selected: "string",
  },
  PlayerHomeTheme: {
    selected: "string",
  },
  PlayerCrisis: {
    lst: "number",
    nst: "number",
    map: "object",
    training: "object",
    box: "object",
  },
  PlayerCrisisV2: {
    current: "string",
    nst: "number",
  },
  PlayerGacha: {
    double: "object",
  },
  PlayerGacha_PlayerGachaPool: {
    rarity: "number",
  },
  PlayerCharacter: {
    skin: "string",
    defaultSkillIndex: "number",
    skills: "object[]",
    voiceLan: "string",
    currentEquip: "string",
    equip: "{ [key: string]: PlayerCharEquipInfo }",
    master: "object",
  },
  PlayerCharPatch: {
    skills: "object[]",
  },
  PlayerBuildingWorkshopStatus: { bonusActive: "number" },
  PlayerBuildingCharBubble: { ts: "number" },
  PlayerBuildingChar_BubbleContainer: { private: "object" },
  PlayerBuildingChar: { workTime: "number", privateRooms: "string[]" },
  PlayerBuildingRoomSlot: { charInstIds: "number[]" },
  PlayerBuildingControlBuff_Global: { roomCnt: "number" },
  PlayerBuildingControlBuff: {
    manufacture: "object", trading: "object", meeting: "object",
    apCost: "object", point: "object", hire: "object",
    power: "object", dormitory: "object", training: "object",
  },
  PlayerBuildingControl: { lastUpdateTime: "number" },
  PlayerBuildingPowerBuff: { apCost: "object", global: "object", manufacture: "object" },
  PlayerBuildingTradingBuff: {
    apCost: "object", rate: "object", tgw: "object[]", point: "object",
    manuLines: "object", orderBuff: "object[]", violatedInfo: "object",
    orderWtBuff: "object[]", speGoldOrder: "object",
  },
  PlayerBuildingTrading: { completeWorkTime: "number" },
  BuildingBuffDisplay: { base: "number" },
  PlayerBuildingTradingOrder: { delivery: "object", buff: "object" },
  PlayerBuildingWorkshopBuff: { recovery: "object", fFix: "object", activeBonus: "object" },
  PlayerBuildingWorkshop: { statistic: "object" },
  PlayerBuildingMeetingBuff: {
    weight: "object", flag: "object", apCost: "object",
    notOwned: "object", owned: "object",
  },
  PlayerBuildingMeetingClueChar: { skin: "string" },
  PlayerBuildingMeeting: {
    expiredReward: "number", mfc: "number", completeWorkTime: "number",
    startApCounter: "number", mustgetClue: "number",
  },
  PlayerBuildingHireBuff: { meeting: "object", stack: "object", point: "object", apCost: "object" },
  PlayerBuildingTrainingBuff: { lvEx: "object", lvCost: "object", reduce: "object", apCost: "object" },
  PlayerBuildingTrainingReduceTimeBd: { fulltime: "object", reset: "object" },
  PlayerBuildingTraining: { state: "number" },
  BuildingMusicState: { progress: "number" },
  // 其他散点
  PlayerArtMagazineLeafData: { leafId: "string", charSkin: "string", decorList: "string[]" },
  PlayerDexNav: { character: "object", teamV2: "object" },
  PlayerFormulaUnlockRecord: { shop: "object" },
  PlayerCrisisSeason: { permanent: "object", temporary: "object", sInfo: "object" },
  PlayerCrisisV2Season_PermanentMapInfo: {
    state: "number", scoreTotal: "number", rune: "object", challenge: "object",
  },
  PlayerHomeUnlockStatus: { unlock: "boolean" },
  PlayerHomeConditionProgress: { v: "number", t: "number" },
  // rlv2 outer
  PlayerRoguelikeV2_OuterData_Buff: { score: "number" },
  PlayerRoguelikeV2_OuterData_Collection: { chat: "object" },
  PlayerRoguelikeV2_OuterData_Collection_DifficultyUnlockInfo: { progress: "number" },
  PlayerRoguelikeV2_OuterData_MonthTeam: { valid: "boolean" },
  PlayerRoguelikeV2_OuterData_Record: { modeCnt: "number", endingCnt: "number" },
  PlayerRoguelikeV2_OuterData_Challenge: { highScore: "number" },
  PlayerRoguelikeV2_OuterData_Mission_MissionItem: { tmpl: "object" },
  PlayerRoguelikeV2_CurrentData: { record: "object" },
  // tower
  TowerCurrent_Status: { tower: "object", strategy: "object" },
  TowerCurrent_TowerGodCard: { id: "string" },
  TowerCurrent_HalftimeRecruit: { count: "number" },
  TowerOuter_TowerData: { unlockHard: "boolean" },
  TowerOuter: { pickedGodCard: "object", squad: "object" },
  TowerSeason: { passWithGodCard: "object", slots: "object" },
  TowerSeason_TowerSeasonPeriod: { cur: "number", len: "number" },
  // sandboxPerm
  PlayerSandboxPerm_PlayerSandboxTemplateData: { SANDBOX_V2: "object", SANDBOX_V3: "object" },
  PlayerSandboxPerm_PlayerSandboxSummaryData: { SANDBOX_V2: "object", SANDBOX_V3: "object" },
  PlayerRecalRuneStage: { runes: "object" },
  PlayerCampaign: { lastRefreshTs: "number" },
  PlayerCampaign_Stage: { rewardStatus: "number[]" },
  PlayerPerMedal: { val: "number" },
  PlayerRecruit_NormalModel_SlotModel: { tags: "number[]", selectTags: "number[]" },
  PlayerRetro: { lst: "number", nst: "number" },
  PlayerSetting: { perf: "{ lowPower: number }" },
  PlayerCharRotationPreset: { profileInst: "number" },
  PlayerActFun4: { cameraLv: "number", fans: "number" },
};

/** 结构差异覆盖：接口名 → { 字段名: 完整 TS 类型 }（"[server]" 表示整接口覆盖） */
export const SERVER_OVERRIDE_FIELDS: Record<string, Record<string, string>> = {
  // 服务端 activity = { [类型key]: { [actId]: 活动数据 } } 字典（客户端是 60 个分列表字段）
  PlayerActivity: {
    "[server]": "{ [typeKey: string]: { [actId: string]: object } }",
  },
  // 服务端 shop = LS/HS/ES/CASH/GP/FURNI/SOCIAL/EPGS/REP/CLASSIC/SKIN 缩写 key 字典
  // （缩写 ↔ 客户端完整名：LS=lowQCShop、HS=highQCShop、ES=extraQCShop、CASH=cashShop、
  //   GP=giftShop、FURNI=furnitureShop、SOCIAL=socialShop、EPGS=epgsQCShop、REP=repQCShop、
  //   CLASSIC=classicQCShop、SKIN=skinShop）
  PlayerShop: {
    "[server]":
      "{ LS: PlayerLowQCShopProgressData; HS: PlayerHighQCShopProgressData; ES: PlayerCommonShopProgressData; CASH: PlayerCashProgressData; GP: PlayerGiftProgressData; FURNI: PlayerFurnitureShopData; SOCIAL: PlayerSocialShopData; EPGS: PlayerEPGSProgressData; REP: PlayerEPGSProgressData; CLASSIC: PlayerClassicQCShopProgressData; SKIN: PlayerSkinShopData }",
  },
  // 服务端 building.rooms = { [房间类型大写key]: { [slotId]: 房间 } }（客户端是具名类 PlayerBuildingRoom）
  PlayerBuilding: {
    rooms: "{ [roomType: string]: { [slotId: string]: object } }",
  },
  // PlayerCartInfo.Cart 继承 Dictionary<CartAccessoryPos, string>（解析器生成空接口，实际是索引签名字典）
  PlayerCartInfo_Cart: {
    "[server]": "{ [key: string]: string }",
  },
};

/** 应用整接口覆盖（"[server]" 键）：返回覆盖后的类型别名；无覆盖返回 null */
function applyWholeOverride(iface: ClassDef): string | null {
  const override = SERVER_OVERRIDE_FIELDS[iface.name];
  if (!override) return null;
  const whole = override["[server]"];
  return whole === undefined ? null : whole;
}

/**
 * 应用服务端协议适配：rename → add → override（按序）
 * @param classes - 客户端闭包类定义
 * @returns 适配后的类定义列表（不修改入参）
 */
export function applyServerAdapt(classes: ClassDef[]): ClassDef[] {
  return classes.map(iface => {
    const rename = SERVER_RENAME_FIELDS[iface.name] ?? {};
    const add = SERVER_ADD_FIELDS[iface.name] ?? {};

    // 1. rename
    let fields = iface.fields.map(f => {
      const target = rename[f.name];
      return target ? { ...f, name: target } : { ...f };
    });

    // 2. add（不重复）
    for (const [name, type] of Object.entries(add)) {
      if (!fields.some(f => f.name === name)) {
        fields.push({ name, rawType: type, type });
      }
    }

    // 3. override（整接口覆盖优先：转为类型别名；字段级覆盖：替换类型）
    const aliasType = applyWholeOverride(iface);
    if (aliasType !== null) {
      return { ...iface, fields: [], aliasType };
    }
    const override = SERVER_OVERRIDE_FIELDS[iface.name];
    if (override) {
      fields = fields.map(f => {
        const target = override[f.name];
        return target ? { ...f, rawType: target, type: target } : f;
      });
    }

    return { ...iface, fields };
  });
}
