import type { ClassDef, FieldDef } from "./playerdata-parser";

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
};

/** 服务端独有字段补充：接口名 → { 字段名: TS 类型 } */
export const SERVER_ADD_FIELDS: Record<string, Record<string, string>> = {
  PlayerDataModel: {
    deleted: "{ [key: string]: object }",
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
  PlayerCharacter: {
    skin: "string",
    defaultSkillIndex: "number",
    skills: "PlayerSkill[]",
    voiceLan: "string",
    currentEquip: "string",
    equip: "{ [key: string]: PlayerCharEquipInfo }",
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
    templateMedalList: "{ [key: string]: object }",
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
};

/** 结构差异覆盖：接口名 → { 字段名: 完整 TS 类型 }（"[server]" 表示整接口覆盖） */
export const SERVER_OVERRIDE_FIELDS: Record<string, Record<string, string>> = {
  // 服务端 activity = { [类型key]: { [actId]: 活动数据 } } 字典（客户端是 60 个分列表字段）
  PlayerActivity: {
    "[server]": "{ [typeKey: string]: { [actId: string]: object } }",
  },
  // 服务端 shop = LS/HS/ES/CASH/GP/FURNI/SOCIAL/EPGS/REP/CLASSIC/SKIN 缩写 key 字典
  PlayerShop: {
    "[server]": "{ [shopType: string]: object }",
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

/** 应用整接口覆盖（"[server]" 键）：返回覆盖后的字段列表；无覆盖返回 null */
function applyWholeOverride(iface: ClassDef): FieldDef[] | null {
  const override = SERVER_OVERRIDE_FIELDS[iface.name];
  if (!override) return null;
  const whole = override["[server]"];
  if (whole === undefined) return null;
  return [{ name: "[server:index]", rawType: whole, type: whole }];
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

    // 3. override（整接口覆盖优先）
    const whole = applyWholeOverride(iface);
    if (whole) fields = whole;

    return { ...iface, fields };
  });
}
