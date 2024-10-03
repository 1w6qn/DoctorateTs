import { RoguelikeBuff } from "@game/model/rlv2";

export interface RoguelikeConst {
  outbuff: { [key: string]: RoguelikeBuff[] };
  modebuff: { [key: string]: RoguelikeBuff[] };
  recruitGrps: { [key: string]: string[] };
}
