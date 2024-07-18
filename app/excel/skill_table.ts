import { Blackboard } from "./character_table";

export type StoryTable = {[key: string]:SkillDataBundle}
export interface SkillDataBundle {
    skillId: string;
    iconId:  null | string;
    hidden:  boolean;
    levels:  LevelData[];
}

export interface LevelData {
    name:         string;
    rangeId:      string | null;
    description:  null | string;
    skillType:    SkillType;
    durationType: SkillDurationType;
    spData:       SpData;
    prefabId:     null | string;
    duration:     number;
    blackboard:   Blackboard;
}
export interface SpData {
    spType:        SpType | number;
    levelUpCost:   null;
    maxChargeTime: number;
    spCost:        number;
    initSp:        number;
    increment:     number;
}
export enum SkillDurationType {
    Ammo = "AMMO",
    None = "NONE",
}

export enum SkillType {
    Auto = "AUTO",
    Manual = "MANUAL",
    Passive = "PASSIVE",
}
export enum SpType {
    IncreaseWhenAttack = "INCREASE_WHEN_ATTACK",
    IncreaseWhenTakenDamage = "INCREASE_WHEN_TAKEN_DAMAGE",
    IncreaseWithTime = "INCREASE_WITH_TIME",
}
