import { OrigChar, PlayerCharacter } from "../../kernel/model"
import type { RoguelikeBuff } from "@excel/excel"

// Assembly-CSharp
export enum TorappuRoguelikeEventType {
    NONE = 0,
    BATTLE_NORMAL = 1,
    BATTLE_ELITE = 2,
    BATTLE_BOSS = 4,
    SHOP = 8,
    REST = 16,
    INCIDENT = 32,
    TREASURE = 64,
    ENTERTAINMENT = 128,
    UNKNOWN = 256,
    WISH = 512,
    SACRIFICE = 1024,
    EXPEDITION = 2048,
    BATTLE_SHOP = 4096,
    PORTAL = 8192,
    MISSION = 16384,
    STORY = 32768,
    STORY_HIDDEN = 65536,
    ALCHEMY = 131072,
    DUEL = 262144,
    BATTLES = 7,
    CHOICES = 388848,
    EVENTS = 392952,
    ALL = 392959
}


// —— 模型 re-export（shared/rlv2-model：玩家肉鸽存档模型 + 领域形状）——
export {
  PlayerRoguelikeV2Dungeon,
  PlayerRoguelikeV2Zone,
  PlayerRoguelikeNode,
  RoguelikeShop,
  RoguelikeGoods,
  RoguelikeNodeLine,
  PlayerNodeDetailContent,
  PlayerNodeRollInfo,
  PlayerRoguelikeV2,
  FriendAssistData,
  RoguelikeNodePosition,
  PlayerRoguelikePendingEvent,
  RoguelikeItemBundle,
  RoguelikeReward,
  RoguelikeStageEarn,
} from "./rlv2-model";

export { RoguelikeBuff } from "@excel/excel";
