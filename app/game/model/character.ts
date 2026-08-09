/**
 * 干员相关类型
 *
 * 与生成模型（@excel/types-playerdata.ts，经 app/game/model/playerdata.ts 导出）
 * 重叠的类型一律以生成版为准（单一权威定义）；本文件仅保留生成模型不含的
 * 服务端社交/分享专用类型与技能类型。
 */
import {
  AvatarInfo,
  PlayerCharEquipInfo,
  PlayerCharPatch,
  PlayerCharacter,
  PlayerFriendAssist,
  PlayerHandBookAddon,
  PlayerSquad,
  PlayerSquadItem,
  PlayerTroop,
} from "./playerdata";

export {
  AvatarInfo,
  PlayerCharEquipInfo,
  PlayerCharPatch,
  PlayerCharacter,
  PlayerFriendAssist,
  PlayerHandBookAddon,
  PlayerSquad,
  PlayerSquadItem,
  PlayerTroop,
} from "./playerdata";

/** 干员技能状态（客户端模型类，生成闭包外） */
export interface PlayerCharSkill {
  unlock: number;
  skillId: string;
  state: number;
  specializeLevel: number;
  completeUpgradeTime: number;
}

export interface SharedCharData {
  charId: string;
  potentialRank: number;
  mainSkillLvl: number;
  evolvePhase: number;
  level: number;
  favorPoint: number;
  crisisRecord: { [key: string]: number };
  crisisV2Record: { [key: string]: number };
  currentTmpl?: string;
  tmpl?: { [key: string]: TmplData };
}
export interface TmplData {
  skillIndex: number;
  skinId: string;
  skills: SharedCharSkillData[];
  selectEquip: string;
  equips: { [key: string]: CharEquipInfo };
}
export interface SharedCharSkillData {
  skillId: string;
  specializeLevel: number;
}
export interface CharEquipInfo {
  locked: boolean;
  level: number;
}

export interface OrigChar extends FriendCommonData {
  assistSlotIndex: number;
  aliasName: string;
  assistCharList: SharedCharData[];
  isFriend: boolean;
  canRequestFriend: boolean;
}

export interface FriendCommonData {
  nickName: string;
  uid: string;
  serverName: string;
  nickNumber: string;
  level: number;
  lastOnlineTime: Date;
  recentVisited: boolean;
  avatar: AvatarInfo;
}

export interface SquadFriendData extends FriendCommonData {
  assistChar: SharedCharData[];
  assistSlotIndex: number;
}
