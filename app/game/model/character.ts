
export interface PlayerCharacter{
    instId: number;
    charId:string;
    level:number;
    exp:number;
    evolvePhase:string;//EvolvePhase
    potentialRank:number;
    favorPoint:number;
    mainSkillLvl:number;
    gainTime:number;
    starMark?:number;
    currentTmpl?:string
    tmpl?:{[key:string]:PlayerCharPatch}
}
export interface PlayerCharPatch{
    skinId:string
    defaultSkillIndex:number
    skills:PlayerCharSkill[]
    currentEquip:string
    equip:{[key:string]:PlayerCharEquipInfo}
}
export interface PlayerCharSkill{
    unlock:boolean
    skillId:string
    specializeLevel:string
}
export interface PlayerCharEquipInfo{
    locked:boolean
    level:number
}
export interface SharedCharData{
    charId:string;
    potentialRank:number;
    mainSkillLvl:number;
    evolvePhase:number;
    level:number;
    favorPoint:number;
    crisisRecord:{[key:string]:number};
    crisisV2Record:{[key:string]:number};
    currentTmpl:string;
    tmpl:{[key:string]:TmplData};
}
export interface TmplData{
    skillIndex:number;
    skinId:string;
    skills:SharedCharSkillData[];
    selectEquip:string;
    equips:{[key:string]:CharEquipInfo};
}
export interface SharedCharSkillData{
    skillId:string;
    specializeLevel:number;
}
export interface CharEquipInfo{
    locked:boolean;
    level:number;
}