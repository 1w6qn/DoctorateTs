import {Blackboard,EquipTalentDataBundle,EquipTraitDataBundle}from "./character_table"
export interface BattleEquipTable {
    [key:string]:BattleEquipPack
}
export interface BattleEquipPack {
    phases: BattleEquipPerLevelPack[];
}

export interface BattleEquipPerLevelPack {
    equipLevel:               number;
    parts:                    BattleUniEquipData[];
    attributeBlackboard:      Blackboard;
    tokenAttributeBlackboard: {[key:string]:Blackboard};
}


export interface BattleUniEquipData {
    resKey:                        null | string;
    target:                        string;
    isToken:                       boolean;
    addOrOverrideTalentDataBundle: EquipTalentDataBundle;
    overrideTraitDataBundle:       EquipTraitDataBundle;
}

