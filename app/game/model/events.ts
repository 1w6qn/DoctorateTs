import { EventEmitter } from "events";
import { ItemBundle } from "@excel/character_table";
import { GachaResult } from "@game/model/gacha";
import { BattleData, CommonStartBattleRequest } from "@game/model/battle";
import {
  PlayerRoguelikeV2,
  RoguelikeBuff,
  RoguelikeItemBundle,
} from "@game/model/rlv2";
import { PlayerCharacter } from "@game/model/character";
import { RoguelikeV2Controller } from "@game/controller/rlv2";

export interface EventMap {
  save: [];
  "game:fix": [];
  "status:refresh:time": [];
  "refresh:monthly": [];
  "refresh:weekly": [];
  "refresh:daily": [number];
  "stage:update": [];
  "char:get": [string, { from: string }?, ((res: GachaResult) => void)?];
  "char:init": [PlayerCharacter];
  useItems: [ItemBundle[]];
  gainItems: [ItemBundle[]];
  "player:levelUp": [];
  "building:char:init": [PlayerCharacter];
  "save:battle": [string, { stageId: string }];
  "battle:start": [CommonStartBattleRequest];
  "background:get": [string];
  "background:unlock": [{ bgID: string }];
  "background:condition:update": [string, string, number];
  "homeTheme:get": [string];
  "homeTheme:condition:update": [
    {
      themeId: string;
      conditionId: string;
      target: number;
    },
  ];
  "homeTheme:unlock": [{ themeId: string }];
  "recruit:refresh:tags": [{ slotId: number }];
  "openserver:chain:login": [number];
  //rlv2
  "rlv2:init": [RoguelikeV2Controller];
  "rlv2:module:init": [];
  "rlv2:create": [RoguelikeV2Controller];
  "rlv2:continue": [];
  "rlv2:move": [];
  "rlv2:get:items": [RoguelikeItemBundle[]];
  "rlv2:levelUp": [number];
  "rlv2:recruit:gain": [string, string, number];
  "rlv2:recruit:active": [string];
  "rlv2:recruit:done": [string, string];
  "rlv2:char:get": [PlayerRoguelikeV2.CurrentData.RecruitChar];
  "rlv2:choose_init_recruit_set": [string[]];
  "rlv2:relic:gain": [RoguelikeItemBundle];
  "rlv2:relic:recycle": [string];
  "rlv2:event:create": [string, object];
  "rlv2:buff:apply": [...RoguelikeBuff[]];
  "rlv2:zone:new": [number];
  "rlv2:battle:start": [string];
  "rlv2:battle:finish": [
    {
      battleLog: string;
      data: string;
      battleData: BattleData;
    },
  ];
  "rlv2:bankPut": [boolean];
  "rlv2:bank:withdraw": [];
  "rlv2:disaster:abstract": [];
  "rlv2:disaster:generate": [];
  "rlv2:node:attach": [string[], string[]];
  "rlv2:node:upgrade": [string];
  "rlv2:fragment:gain": [string];
  "rlv2:fragment:set_troop_carry": [string[]];
  "rlv2:fragment:use_inspiration": [string];
  "rlv2:fragment:change_type_weight": [RoguelikeBuff];
  "rlv2:fragment:max_weight:add": [number];
  "rlv2:fragment:use": [string, number];
  "rlv2:fragment:lose": [string];

  //mission
  CompleteStageAnyType: [any];
  ChangeSquadName: [];
}

export class TypedEventEmitter extends EventEmitter<EventMap> {}
