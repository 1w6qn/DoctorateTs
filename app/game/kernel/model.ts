/**
 * 公共领域模型（shared 公共件：玩家数据模型 + 跨模块共享形状）
 *
 * 各业务模块一律从本层取共享模型，禁止跨模块直接引用对方模型：
 * - 玩家数据模型（PlayerCharacter/PlayerSquad 等）：re-export 自 domain/playerdata（生成权威）
 * - 干员社交/分享形状（SharedCharData/OrigChar 等）：原 domain/character.ts
 * - GachaResult：原 domain/gacha/gacha.ts（抽卡结果契约，depot/events 共用）
 */
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

export interface GachaResult {
  charInstId: number;
  charId: string;
  isNew: number;
  itemGet: ItemBundle[];
  potent?: {
    delta: number;
    now: number;
  };
}

import type { ItemBundle } from "@excel/excel";
import type { AvatarInfo } from "./playerdata";

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
