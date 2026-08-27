import { RoguelikeBuff } from "./character_table";

export interface RoguelikeConst {
  outbuff: { [key: string]: RoguelikeBuff[] };
  modebuff: { [key: string]: RoguelikeBuff[] };
  recruitGrps: { [key: string]: string[] };
}
