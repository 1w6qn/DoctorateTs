import { ItemBundle } from "./character_table";
export type ListDict<Tkey, TValue> = {[key: string]: TValue[]};
export interface GameDataConsts {
    maxPlayerLevel:                      number;
    playerExpMap:                        number[];
    playerApMap:                         number[];
    maxLevel:                            number[][];
    characterExpMap:                     number[][];
    characterUpgradeCostMap:             number[][];
    evolveGoldCost:                      number[][];
    completeGainBonus:                   number;
    playerApRegenSpeed:                  number;
    maxPracticeTicket:                   number;
    advancedGachaCrystalCost:            number;
    completeCrystalBonus:                number;
    initPlayerGold:                      number;
    initPlayerDiamondShard:              number;
    initCampaignTotalFee:                number;
    initRecruitTagList:                  number[];
    initCharIdList:                      string[];
    attackMax:                           number;
    defMax:                              number;
    hpMax:                               number;
    reMax:                               number;
    diamondToShdRate:                    number;
    requestSameFriendCD:                 number;
    baseMaxFriendNum:                    number;
    hardDiamondDrop:                     number;
    instFinDmdShdCost:                   number;
    easyCrystalBonus:                    number;
    diamondMaterialToShardExchangeRatio: number;
    apBuyCost:                           number;
    apBuyThreshold:                      number;
    creditLimit:                         number;
    monthlySubRemainTimeLimitDays:       number;
    friendAssistRarityLimit:             number[];
    mainlineCompatibleDesc:              string;
    mainlineToughDesc:                   string;
    mainlineEasyDesc:                    string;
    mainlineNormalDesc:                  string;
    rejectSpCharMission:                 number;
    addedRewardDisplayZone:              string;
    richTextStyles:                      { [key: string]: string };
    charAssistRefreshTime:               CharAssistRefreshTimeState[];
    normalRecruitLockedString:           string[];
    commonPotentialLvlUpCount:           number;
    weeklyOverrideDesc:                  string;
    voucherDiv:                          number;
    recruitPoolVersion:                  number;
    v006RecruitTimeStep1Refresh:         number;
    v006RecruitTimeStep2Check:           number;
    v006RecruitTimeStep2Flush:           number;
    buyApTimeNoLimitFlag:                boolean;
    isLMGTSEnabled:                      boolean;
    legacyTime:                          number;
    legacyItemList:                      ItemBundle[];
    useAssistSocialPt:                   number;
    useAssistSocialPtMaxCount:           number;
    assistBeUsedSocialPt:                { [key: string]: number };
    pushForces:                          number[];
    pushForceZeroIndex:                  number;
    normalGachaUnlockPrice:              number[];
    pullForces:                          number[];
    pullForceZeroIndex:                  number;
    multiInComeByRank:                   string[];
    LMTGSToEPGSRatio:                    number;
    newBeeGiftEPGS:                      number;
    lMTGSDescConstOne:                   string;
    lMTGSDescConstTwo:                   string;
    defCDPrimColor:                      string;
    defCDSecColor:                       string;
    mailBannerType:                      string[];
    monthlySubWarningTime:               number;
    UnlimitSkinOutOfTime:                number;
    replicateShopStartTime:              number;
    TSO:                                 number;
    isDynIllustEnabled:                  boolean;
    isDynIllustStartEnabled:             boolean;
    isClassicQCShopEnabled:              boolean;
    isRoguelikeTopicFuncEnabled:         boolean;
    isSandboxPermFuncEnabled:            boolean;
    isRoguelikeAvgAchieveFuncEnabled:    boolean;
    isClassicPotentialItemFuncEnabled:   boolean;
    isClassicGachaPoolFuncEnabled:       boolean;
    isVoucherClassicItemDistinguishable: boolean;
    voucherSkinRedeem:                   number;
    voucherSkinDesc:                     string;
    charmEquipCount:                     number;
    termDescriptionDict:                 { [key: string]: TermDescriptionDict };
    storyReviewUnlockItemLackTip:        string;
    dataVersion:                         string;
    resPrefVersion:                      string;
    announceWebBusType:                  string;
    defaultMinContinuousBattleTimes:     number;
    defaultMaxContinuousBattleTimes:     number;
    continuousActionOpen:                boolean;
    subProfessionDamageTypePairs:        { [key: string]: string };
    classicProtectChar:                  string[];
}


export interface CharAssistRefreshTimeState {
    Hour:   number;
    Minute: number;
}



export enum SubProfessionAttackType {
    Heal = "HEAL",
    Magical = "MAGICAL",
    None = "NONE",
    Physical = "PHYSICAL",
}

export interface TermDescriptionDict {
    termId:      string;
    termName:    string;
    description: string;
}
