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
    voiceLan: string;
    starMark?:number;
    currentTmpl?:string
    tmpl?:{[key:string]:PlayerCharPatch}
    skinId?:string
    defaultSkillIndex?:number
    skills?:PlayerCharSkill[]
    currentEquip?:string|null
    equip?:{[key:string]:PlayerCharEquipInfo}|null
}
export interface PlayerCharPatch{
    skinId:string
    defaultSkillIndex:number
    skills:PlayerCharSkill[]
    currentEquip:string
    equip:{[key:string]:PlayerCharEquipInfo}
}
export interface PlayerCharSkill{
    unlock:number
    skillId:string
    state:number
    specializeLevel:number
    completeUpgradeTime:number
}
export interface PlayerCharEquipInfo{
    locked:number
    level:number
    hide:number
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
    squadId: string|null;
    name: string|null;
    slots: Array<PlayerSquadItem | null>;
}



export interface PlayerSquadItem {
    charInstId: number;
    skillIndex: number;
    currentEquip: null | string;
    currentTmpl?: null | string;
}

export type PlayerFriendAssist =PlayerSquadItem


export interface OrigChar extends FriendCommonData {
    assistSlotIndex: number
    aliasName: string
    assistCharList: SharedCharData[]
    isFriend: boolean
    canRequestFriend: boolean
}

export interface FriendCommonData {
    nickName: string
    uid: string
    serverName: string
    nickNumber: string
    level: number
    lastOnlineTime: Date
    recentVisited: boolean
    avatar: AvatarInfo
}
export interface AvatarInfo {
    type: string//PlayerAvatarType
    id: string
}
export interface SquadFriendData extends FriendCommonData{
    assistChar:SharedCharData[]
    assistSlotIndex:number
}