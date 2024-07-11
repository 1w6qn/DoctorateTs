export interface KeyFrame<TInput, TOutput> {
    level: number
    data: TInput
}
export type KeyFrames<TData> = KeyFrame<TData, TData>[]
export type Blackboard = BlackboardDataPair[];

export interface CharacterTable {
    [key: string]: CharacterData
}
export interface CharacterData {
    name: string;
    description: null | string;
    canUseGeneralPotentialItem: boolean;
    canUseActivityPotentialItem: boolean;
    potentialItemId: null | string;
    activityPotentialItemId: null | string;
    classicPotentialItemId: null | string;
    nationId: null | string;
    groupId: null | string;
    teamId: null | string;
    displayNumber: null | string;
    appellation: string;
    position: BuildableType;
    tagList: string[] | null;
    itemUsage: null | string;
    itemDesc: null | string;
    itemObtainApproach: string | null;
    isNotObtainable: boolean;
    isSpChar: boolean;
    maxPotentialLevel: number;
    rarity: RarityRank;
    profession: ProfessionCategory;
    subProfessionId: string;
    trait: TraitDataBundle | null;
    phases: PhaseData[];
    skills: MainSkill[];
    displayTokenDict: { [key: string]: boolean } | null;
    talents: TalentDataBundle[] | null;
    potentialRanks: PotentialRank[];
    favorKeyFrames: KeyFrames<AttributesData> | null;
    allSkillLvlup: SkillLevelCost[];
}

export interface SkillLevelCost {
    unlockCond: UnlockCondition;
    lvlUpCost: ItemBundle[] | null;
}

export interface ItemBundle {
    id: string;
    count: number;
    type: string;
}

export interface UnlockCondition {
    phase: PhaseEnum;
    level: number;
}

export enum PhaseEnum {
    Phase0 = "PHASE_0",
    Phase1 = "PHASE_1",
    Phase2 = "PHASE_2",
}


export interface AttributesData {
    maxHp: number;
    atk: number;
    def: number;
    magicResistance: number;
    cost: number;
    blockCnt: number;
    moveSpeed: number;
    attackSpeed: number;
    baseAttackTime: number;
    respawnTime: number;
    hpRecoveryPerSec: number;
    spRecoveryPerSec: number;
    maxDeployCount: number;
    maxDeckStackCnt: number;
    tauntLevel: number;
    massLevel: number;
    baseForceLevel: number;
    stunImmune: boolean;
    silenceImmune: boolean;
    sleepImmune: boolean;
    frozenImmune: boolean;
    levitateImmune: boolean;
    disarmedCombatImmune: boolean;
}


export interface PhaseData {
    characterPrefabKey: string;
    rangeId: null | string;
    maxLevel: number;
    attributesKeyFrames: KeyFrames<AttributesData>;
    evolveCost: ItemBundle[] | null;
}

export enum BuildableType {
    None = "NONE",
    Melee = "MELEE",
    Ranged = "RANGED",
    All = "ALL",
}

export interface PotentialRank {
    type: PotentialRankType;
    description: string;
    buff: ExternalBuff | null;
    equivalentCost: null;
}

export interface ExternalBuff {
    attributes: Attributes;
}

export interface Attributes {
    abnormalFlags: null;
    abnormalImmunes: null;
    abnormalAntis: null;
    abnormalCombos: null;
    abnormalComboImmunes: null;
    attributeModifiers: AttributeModifier[];

}

export interface AttributeModifier {
    attributeType: AttributeType;
    formulaItem: string;
    value: number;
    loadFromBlackboard: boolean;
    fetchBaseValueFromSourceEntity: boolean;
}

export enum AttributeType {
    Atk = "ATK",
    AttackSpeed = "ATTACK_SPEED",
    Cost = "COST",
    Def = "DEF",
    MagicResistance = "MAGIC_RESISTANCE",
    MaxHP = "MAX_HP",
    RespawnTime = "RESPAWN_TIME",
}

export enum PotentialRankType {
    Buff = "BUFF",
    Custom = "CUSTOM",
}

export enum ProfessionCategory {
    Caster = "CASTER",
    Medic = "MEDIC",
    Pioneer = "PIONEER",
    Sniper = "SNIPER",
    Special = "SPECIAL",
    Support = "SUPPORT",
    Tank = "TANK",
    Token = "TOKEN",
    Trap = "TRAP",
    Warrior = "WARRIOR",
}

export enum RarityRank {
    Tier1 = "TIER_1",
    Tier2 = "TIER_2",
    Tier3 = "TIER_3",
    Tier4 = "TIER_4",
    Tier5 = "TIER_5",
    Tier6 = "TIER_6",
}

export interface MainSkill {
    skillId: null | string;
    overridePrefabKey: null | string;
    overrideTokenKey: null | string;
    levelUpCostCond: SpecializeLevelData[];
    unlockCond: UnlockCondition;
}

export interface SpecializeLevelData {
    unlockCond: UnlockCondition;
    lvlUpTime: number;
    levelUpCost: ItemBundle[] | null;
}


export interface EquipTalentDataBundle extends TalentDataBundle {
    candidates: EquipTalentData[] | null;
}
export interface EquipTalentData extends TalentData {
    displayRangeId: boolean;
    talentIndex: number;
    upgradeDescription: string
}
export interface TalentDataBundle {
    candidates: TalentData[] | null;
}


export interface TalentData {
    unlockCondition: UnlockCondition;
    requiredPotentialRank: number;
    prefabKey: string;
    name: null | string;
    description: null | string;
    rangeId: null | string;
    blackboard: Blackboard;
    tokenKey: null | string;
}

export interface BlackboardDataPair {
    key: string;
    value: number;
    valueStr: null | string;
}

export interface TraitDataBundle {
    candidates: TraitData[];
}

export interface TraitData {
    unlockCondition: UnlockCondition;
    requiredPotentialRank: number;
    blackboard: BlackboardDataPair[];
    overrideDescripton: null | string;
    prefabKey: null | string;
    rangeId: null | string;
}
export interface EquipTraitDataBundle {
    candidates: EquipTraitData[];
}

export interface EquipTraitData extends TraitData {
    additionalDescription: string;
}