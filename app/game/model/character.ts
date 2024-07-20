
export interface PlayerCharacter{
    instId: number;
    charId:string;
    level:number;
    exp:number;
    evolvePhase:number;//EvolvePhase
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

export interface PlayerTroop {
    curCharInstId: number;
    curSquadCount: number;
    squads: { [key: string]: PlayerSquad };
    chars: { [key: string]: PlayerCharacter };
    addon: { [key: string]: PlayerHandBookAddon };
    charGroup: { [key: string]: { favorPoint: number } };
    charMission: { [key: string]: { [key: string]: number } };
}
export interface PlayerHandBookAddon {
    stage?: { [key: string]: PlayerHandBookAddon.GetInfo };
    story?: { [key: string]: PlayerHandBookAddon.GetInfo };
}
export namespace PlayerHandBookAddon {
    export interface GetInfo {
        fts?: number
        rts?: number
    }
}

export interface PlayerSquad {
    squadId: string;
    name: string;
    slots: Array<PlayerSquadItem | null>;
}



export interface PlayerSquadItem {
    charInstId: number;
    skillIndex: number;
    currentEquip: null | string;
}