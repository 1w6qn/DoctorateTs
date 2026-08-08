/**
 * 自动生成的玩家数据类型定义文件
 * 从 reference/com.hypergryph.arknights_2.7.61.cs 反编译文件生成
 * （客户端闭包 + 服务端协议适配，见 scripts/playerdata-server-adapt.ts）
 * 生成命令: npm run generate:playerdata
 * 请勿手动修改此文件
 */

export type PlayerAvatarType = "NONE" | "ASSISTANT" | "ICON" | "DEFAULT";

export type PlayerSpecialOperatorNode_State = "LOCK" | "CONFIRMED";

export type PlayerActivity_PlayerMultiplayV2Activity_DailyMissionState = "NOT_CLAIM" | "CLAIMED";

export type PlayerActivity_PlayerMultiplayV2Activity_StageState = "LOCK" | "UNLOCKED";

export type PlayerActivity_PlayerEnemyDuelActivity_DailyMissionState = "NOT_CLAIM" | "CLAIMED";

export type PlayerActivity_PlayerArcadeActivity_BadgeStatus = "Error" | "InProgress" | "Unlocked";

export type PlayerActivity_PlayerAct24SideActivity_ToolState = "LOCK" | "UNSELECT" | "SELECT";

export type PlayerActivity_PlayerAct25SideActivity_MissionState = "UNFINISH" | "FINISHED" | "OBTAINED";

export type PlayerActivity_PlayerAct27SideActivity_SaleState = "BEFORE_SALE" | "PURCHASE" | "SELL" | "BEFORE_SETTLE" | "AFTER_SETTLE";

export type PlayerActivity_PlayerAct27SideActivity_SellGoodState = "NONE" | "DRINK" | "FOOD" | "SOUVENIR";

export type PlayerActivity_PlayerAct36SideActivity_RewardState = "UNFINISH" | "FINISHED" | "CLAIMED";

export type PlayerActivity_PlayerAct35SideActivity_GameState = "NONE" | "BUY" | "PROCESS" | "NEXT" | "SETTLE" | "INFO";

export type PlayerActivity_PlayerAct38SideActivity_PuzzleStatus = "LOCKED" | "UNLOCK" | "COMPLETE";

export type PlayerActivity_PlayerAutoChessV1Activity_AutoChessCharType = "OWN" | "BACK_UP" | "ASSIST_BY_FRIEND" | "DIY";

export type PlayerActivity_PlayerAutoChessV1Activity_AutoChessGameState = "SELECT_TEAM" | "SHOP" | "BATTLE" | "CHOOSE_BRAND" | "TO_SETTLE";

export type PlayerActivity_PlayerAct42SideActivity_TaskState = "LOCKED" | "UNLOCK" | "ACCEPTED" | "CAN_SUBMIT" | "COMPLETE";

export type PlayerActivity_PlayerAct42SideActivity_RewardState = "UNAVAILABLE" | "AVAILABLE";

export type PlayerActivity_PlayerAct45SideActivity_State = "LOCKED" | "UNLOCK" | "ACCEPTED";

export type PlayerActivity_PlayerAct44SideActivity_InformantState = "ENTRY" | "CHOICE" | "CHOICE_END" | "BEFORE_SINGLE_RESULT" | "SINGLE_RESULT" | "RESULT";

export type PlayerActivity_PlayerAct1VHalfIdleActivity_BossState = "NO_APPEAR" | "NO_KILL" | "KILL";

export type PlayerActivity_PlayerCommonDailyMission_DailyMissionState = "NOT_CLAIM" | "CLAIMED";

export type PlayerActivity_PlayerActAutoChessActivity_BandState = "LOCK" | "UNLOCKED";

export type PlayerActivity_PlayerActAutoChessActivity_AutoChessCharType = "OWN" | "BACK_UP" | "ASSIST_BY_FRIEND" | "DIY" | "PRESET";

export type PlayerActivity_PlayerAct46SideActivity_MonopolyStageStatus = "LOCK" | "UNLOCK" | "PASS";

export type PlayerSixStarTagFinishState = "NONE" | "FINISH_LEVEL1" | "FINISH_LEVEL2";

export type PlayerSixStarMilestoneState = "UNLOCK" | "FINISH" | "CONFIRMED";

export type PlayerCampaign_MissionState = "UNCOMPLETE" | "COMPLETE" | "FINISHED";

export type PlayerRecruit_NormalModel_SlotModel_State = "LOCK" | "IDLE" | "BUSY" | "FAST_FINISH";

export type PlayerGacha_PlayerDoubleGacha_HitCharState = "NONE" | "FIRST" | "SECOND";

export type NameCardMedalType = "EMPTY" | "CUSTOM" | "TEMPLATE";

export type PlayerTroop_CharMissionState = "UNCOMPLETE" | "FULLFILLED" | "COMPLETE";

export type PlayerBuildingHiringState = "EMPTY" | "HIRING";

export type PlayerBuildingTrainerState = "EMPTY" | "TRAINING" | "FINISH" | "WAITING";

export type PlayerBuildingTraineeState = "EMPTY" | "TRAINING" | "OUTOFDATE" | "WAITING";

export type MissionPlayerData_MissionGroupState = "Uncomplete" | "Complete";

export type PlayerCrisisV2Season_RuneState = "UNKNOWN" | "LOCKED" | "UNLOCK" | "FINISH";

export type PlayerCrisisV2Season_NodeState = "INACTIVE" | "ACTIVED" | "CLAIMED";

export type PlayerCrisisV2Season_BagState = "INCOMPLETE" | "COMPLETED" | "CLAIMED";

export type PlayerRecalRuneStage_State = "NO_PASS" | "PASSED";

export type PlayerRecalRuneReward_State = "UNCLAIMED" | "CLAIMED";

export type PlayerRoguelikeState = "NONE" | "GAME_REWARD_RELIC" | "GAME_REWARD_SCENE" | "GAME_REWARD_RECRUIT" | "MOVE_WAIT" | "BUY_WAIT" | "CHOICE_WAIT" | "REWARD_WAIT" | "BATTLE_WAIT_START" | "BATTLE_WAIT_END" | "GAME_END";

export type PlayerNodeForesightType = "NORMAL" | "HIDE_INVISIBLE" | "HIDE_BATTLE" | "PRESAGE";

export type RoguelikeArchiveItemUnlockStatus = "LOCKED" | "UNATTAINED" | "ATTAINED";

export type PlayerRoguelikeV2_CurrentData_PlayerStatus_NodeMission_NodeMissionState = "NOT_COMPLETED" | "COMPLETED" | "ALL_FINISHED";

export type PlayerRoguelikeV2_CurrentData_Troop_ExpedType = "EXPED" | "TRAVEL" | "CANDLE" | "NO_UPGRADE" | "GUIDED" | "NON_GUIDED" | "ENDING_RELIC";

export type PlayerRoguelikeV2_CurrentData_Recruit_State = "CREATE" | "ACTIVE" | "DONE";

export type PlayerRoguelikeV2_CurrentData_Module_SkyZoneNodeState = "LOCK" | "UNLOCK" | "FINISH" | "CLOSE";

export type PlayerRoguelikeV2_CurrentData_Module_GridMapZoneNodeStatus = "NOT_REACHED" | "RECURSIVE" | "FINISHED";

export type PlayerRoguelikeV2_OuterData_PlayerRogueActivity_PlayerRogueActivityUnlockInfo_PlayerRogueActivityUnlockState = "LOCKED" | "UNLOCKED_UNPLAYED" | "UNLOCKED_PLAYED";

export type PlayerReturnData_Version = "OLD" | "NEW";

export type PlayerRoguelikePlayerState = "NONE" | "INIT" | "PENDING" | "WAIT_MOVE";

export type PlayerRoguelikeZoneType = "NORMAL" | "SP";

export type RoguelikeBattleFailDisplay = "NORMAL" | "FAIL_R5_SKY";

export type PlayerRoguelikePlayerEventType = "NONE" | "GAME_INIT_MODE_RELIC" | "GAME_INIT_TEAM" | "GAME_INIT_RELIC" | "GAME_INIT_GIFT" | "GAME_INIT_SUPPORT" | "GAME_INIT_SUPPORT_MULTI" | "GAME_INIT_RECRUIT_SET" | "GAME_INIT_RECRUIT" | "GAME_INIT_EXPLORE_TOOL" | "GAME_INIT_END" | "RECRUIT" | "BATTLE" | "BATTLE_REWARD" | "SCENE" | "SHOP" | "GAME_SETTLE" | "DICE" | "SACRIFICE" | "EXPEDITION" | "BATTLE_SHOP" | "PREDICT" | "ALCHEMY" | "ALCHEMY_REWARD" | "CHANGE_COPPER" | "DRAW_COPPER" | "USE_STASHED_TICKET" | "GILD_COPPER";

export type PlayerRoguelikePendingEvent_PlayerRoguelikeChoiceRewardType = "NONE" | "ITEM" | "MISSION";

export type PlayerRoguelikeDifficultyStatus = "LOCKED" | "UNLOCKED" | "USED";

export type PlayerRoguelikeChallengeStatus = "LOCKED" | "UNLOCKED" | "COMPLETE";

export type PlayerDeepSea_PlaceStatus = "INVISIBLE" | "UNKNOWN" | "DISCOVERED";

export type PlayerDeepSea_NodeStatus = "LOCKED" | "UNLOCK" | "TRIGGERED";

export type PlayerDeepSea_ChoiceStatus = "LOCKED" | "UNLOCK" | "SELECTED";

export type PlayerDeepSea_ReadStatus = "UNREAD" | "READ";

export type PlayerDeepSea_TreasureStatus = "NOTGOT" | "GOT";

export type PlayerDeepSea_TechStatus = "LOCKED" | "UNLOCK" | "ACTIVED";

export type PlayerSiracusaMap_CharCardItemEnum = "NONE" | "UNUSED" | "USED";

export type PlayerSiracusaMap_StateEnum = "NONE" | "DOING" | "COMPLETED";

export type PlayerSiracusaMap_CharCardStatus = "NONE" | "NEW" | "DOING" | "COMPLETED";

export type PlayerSiracusaMap_TaskRingStatus = "NONE" | "DOING" | "TAKE_REWARD" | "COMPLETED";

export type PlayerSiracusaMap_OperaState = "UNRELEASED" | "RELEASE" | "RELEASED";

export type TowerGameStrategy = "NONE" | "OPTIMIZE";

export type TowerCurrent_TowerGameState = "NONE" | "INIT_GOD_CARD" | "INIT_BUFF" | "INIT_CARD" | "STANDBY" | "RECRUIT" | "SUB_GOD_CARD_RECRUIT" | "END";

export type TowerCurrent_TowerCardType = "CHAR" | "ASSIST" | "NPC";

export type PlayerMainlineExplore_DecisionNodeType = "NONE" | "CHECK" | "EVENT";

export type PlayerMainlineExplore_GameState = "NONE" | "WIN" | "FINISH_NODE" | "BLOCKING" | "WAIT_CONFIRM" | "FAIL";

export type PlayerMissionArchiveNodeState = "LOCKED" | "UNLOCKED" | "CLAIMED";

export type PlayerSandboxV2_GameState = "INACTIVE" | "ACTIVE" | "SETTLE_DATE" | "READING_ARCHIVE";

export type PlayerSandboxV2_NodeState = "LOCKED" | "UNLOCKED" | "COMPLETED";

export type PlayerSandboxV2_StageState = "UNEXPLORED" | "EXPLORED" | "COMPLETED";

export type PlayerSandboxV2_Dungeon_FloatSourceType = "NONE" | "SRC_QUEST" | "SRC_MARKET" | "SRC_RIFT_MAIN";

export type PlayerSandboxV2_RiftInfo_RiftGameStatus = "ACTIVE" | "SETTLE" | "INVALID";

export type PlayerSandboxV2_Challenge_ChallengeStatus = "NOT_IN_CHALLENGE" | "IN_CHALLENGE" | "CHALLENGE_SETTLE" | "UNDEFINED";

export type PlayerSandboxV3GameState = "NONE" | "BAND_SELECT" | "INIT_GAP" | "IN_BATTLE" | "GAP_REPORT" | "EXPEDITION" | "NORM_GAP" | "GAME_FINISH";

export type PlayerSandboxV3Node_State = "UNLOCK" | "PLAYED" | "PASSED";

export type PlayerSandboxV3Npc_DialogType = "NONE" | "BEFORE_BATTLE" | "IN_BATTLE" | "AFTER_BATTLE";

export type PlayerSandboxV3QuestGroup_Quest_State = "UNCOMPLETE" | "COMPLETED" | "CLOSED";

export type PlayerSandboxV3Difficulty_State = "LOCK" | "UNLOCK" | "PASSED";

export type SandboxV3SquadCharType = "PLAYER_REPO" | "TRYOUT_CHAR" | "TEMP_RECRUIT" | "ROOKIE" | "ASSIST" | "PRE_DEFINED" | "DEFEND";

export type CartCompetitionRank = "NONE" | "B" | "A" | "S" | "SS";

export type ActMultiV3MatchPosType = "NORMAL" | "COACH" | "STUDENT";

export type BuildingData_RoomType = "NONE" | "CONTROL" | "POWER" | "MANUFACTURE" | "SHOP" | "DORMITORY" | "MEETING" | "HIRE" | "ELEVATOR" | "CORRIDOR" | "TRADING" | "WORKSHOP" | "TRAINING" | "PRIVATE" | "FUNCTIONAL" | "ALL";

export type BuildingData_OrderType = "O_COMPOUND" | "O_GOLD" | "O_DIAMOND";

export type ItemType = "NONE" | "CHAR" | "CARD_EXP" | "MATERIAL" | "GOLD" | "EXP_PLAYER" | "TKT_TRY" | "TKT_RECRUIT" | "TKT_INST_FIN" | "TKT_GACHA" | "ACTIVITY_COIN" | "DIAMOND" | "DIAMOND_SHD" | "HGG_SHD" | "LGG_SHD" | "FURN" | "AP_GAMEPLAY" | "AP_BASE" | "SOCIAL_PT" | "CHAR_SKIN" | "TKT_GACHA_10" | "TKT_GACHA_PRSV" | "AP_ITEM" | "AP_SUPPLY" | "RENAMING_CARD" | "RENAMING_CARD_2" | "ET_STAGE" | "ACTIVITY_ITEM" | "VOUCHER_PICK" | "VOUCHER_CGACHA" | "VOUCHER_MGACHA" | "CRS_SHOP_COIN" | "CRS_RUNE_COIN" | "LMTGS_COIN" | "EPGS_COIN" | "LIMITED_TKT_GACHA_10" | "LIMITED_FREE_GACHA" | "REP_COIN" | "ROGUELIKE" | "LINKAGE_TKT_GACHA_10" | "VOUCHER_ELITE_II_4" | "VOUCHER_ELITE_II_5" | "VOUCHER_ELITE_II_6" | "VOUCHER_SKIN" | "RETRO_COIN" | "PLAYER_AVATAR" | "UNI_COLLECTION" | "VOUCHER_FULL_POTENTIAL" | "RL_COIN" | "RETURN_CREDIT" | "MEDAL" | "CHARM" | "HOME_BACKGROUND" | "EXTERMINATION_AGENT" | "OPTIONAL_VOUCHER_PICK" | "ACT_CART_COMPONENT" | "VOUCHER_LEVELMAX_6" | "VOUCHER_LEVELMAX_5" | "VOUCHER_LEVELMAX_4" | "VOUCHER_SKILL_SPECIALLEVELMAX_6" | "VOUCHER_SKILL_SPECIALLEVELMAX_5" | "VOUCHER_SKILL_SPECIALLEVELMAX_4" | "ACTIVITY_POTENTIAL" | "ITEM_PACK" | "SANDBOX" | "FAVOR_ADD_ITEM" | "CLASSIC_SHD" | "CLASSIC_TKT_GACHA" | "CLASSIC_TKT_GACHA_10" | "LIMITED_BUFF" | "CLASSIC_FES_PICK_TIER_5" | "CLASSIC_FES_PICK_TIER_6" | "RETURN_PROGRESS" | "NEW_PROGRESS" | "MCARD_VOUCHER" | "MATERIAL_ISSUE_VOUCHER" | "CRS_SHOP_COIN_V2" | "HOME_THEME" | "SANDBOX_PERM" | "SANDBOX_TOKEN" | "TEMPLATE_TRAP" | "NAME_CARD_SKIN" | "EMOTICON_SET" | "EXCLUSIVE_TKT_GACHA" | "EXCLUSIVE_TKT_GACHA_10" | "SO_CHAR_EXP" | "GIFTPACKAGE_TKT" | "VOUCHER_SKIN_V2" | "RANDOM_VOUCHER_SKIN" | "ACT1VHALFIDLE_ITEM" | "PLOT_ITEM" | "MAGAZINE_LEAF" | "STICKER" | "ARKHUB";

export type RoguelikeNodeLine_HiddenType = "SHOW" | "HIDE" | "APPEAR";

export type RoguelikeEventType = "NONE" | "BATTLE_NORMAL" | "BATTLE_ELITE" | "BATTLE_BOSS" | "SHOP" | "REST" | "INCIDENT" | "TREASURE" | "ENTERTAINMENT" | "UNKNOWN" | "WISH" | "SACRIFICE" | "EXPEDITION" | "BATTLE_SHOP" | "PORTAL" | "MISSION" | "STORY" | "STORY_HIDDEN" | "ALCHEMY" | "DUEL" | "STASHED_RECRUIT" | "SPECIAL_ZONE" | "SCRAP_SHOP" | "DOOR" | "FINAL" | "EVACUATE" | "EMPLOY" | "LIGHT" | "BATTLE_SAVAGE" | "EMPTY" | "BATTLES" | "CHOICES" | "EVENTS" | "ALL";

export type RoguelikeSacrificeType = "RELIC" | "TOTEM" | "COPPER" | "SCRAP";

export type RoguelikeExpeditionType = "NORMAL" | "CANDLE" | "GUIDED" | "ENDING_RELIC";

export type RoguelikeCharState = "NORMAL" | "UPGRADE" | "UPGRADE_BUFF" | "UPGRADE_BONUS" | "FREE" | "ASSIST" | "THIRD" | "MONTHLY" | "THIRD_LOW" | "MERCENARY";

export type RoguelikeTopicMode = "NONE" | "EASY" | "NORMAL" | "HARD" | "NORML_END" | "MONTH_TEAM" | "CHALLENGE";

export type RoguelikeGameItemType = "NONE" | "HP" | "HPMAX" | "GOLD" | "POPULATION" | "EXP" | "SQUAD_CAPACITY" | "RECRUIT_TICKET" | "UPGRADE_TICKET" | "RELIC" | "BP_POINT" | "GROW_POINT" | "BAND" | "ACTIVE_TOOL" | "CAPSULE" | "POOL" | "RL_BP" | "RL_GP" | "KEY_POINT" | "SAN_POINT" | "DICE_POINT" | "DICE_TYPE" | "SHIELD" | "LOCKED_TREASURE" | "CUSTOM_TICKET" | "TOTEM" | "TOTEM_EFFECT" | "FEATURE" | "VISION" | "CHAOS" | "CHAOS_PURIFY" | "CHAOS_LEVEL" | "EXPLORE_TOOL" | "FRAGMENT" | "MAX_WEIGHT" | "DISASTER" | "DISASTER_TYPE" | "ABSTRACT_DISASTER" | "PILL" | "BIGPILL" | "COPPER" | "COPPER_BUFF" | "DIVINATION_KIT" | "WRATH" | "SPECIAL_ZONE_AP" | "COPPER_DRAW_NUM" | "STASH_RECRUIT_LIMIT" | "NODE_BUOY" | "SCRAP" | "LEGACY" | "CHARACTER";

export type RoguelikeGameMonthTaskClass = "NONE" | "C" | "B" | "A";

export type SandboxV2NodeType = "NONE" | "HOME" | "HOME_OUTPOST" | "BATTLE" | "NEST" | "COLLECT" | "HUNT" | "CAVE" | "MINE" | "ENCOUNTER" | "EXPEDITION" | "SHOP" | "GATE" | "MARKET" | "HOME_PORTABLE" | "HOME_PORTABLE_RIFT" | "SELECTION" | "RACING";

export type SandboxV2WeatherType = "NORMAL" | "RAINFOREST" | "VOLCANO" | "DESERT";

export type SandboxV2SeasonType = "NONE" | "DRY" | "RAINY" | "CHALLENGE";

export type SandboxV2EnemyRushType = "NORMAL" | "ELITE" | "BOSS" | "BANDIT" | "RALLY" | "THIEF" | "MESSENGER" | "INSECT";

export type SandboxV2RareAnimalType = "RARE_DEAR" | "RARE_TURTLE" | "MESSENGER" | "PREY";

export type SandboxV2QuestLineBadgeType = "NONE" | "SIDE" | "GUIDE" | "MAIN" | "RIFT";

export type SandboxV3QuestLineBadgeType = "NONE" | "MAIN" | "SIDE" | "GUIDE";

export type VoiceLangType = "NONE" | "JP" | "CN_MANDARIN" | "EN" | "KR" | "CN_TOPOLECT" | "LINKAGE" | "ITA" | "GER" | "RUS" | "FRE" | "SPA";

export type CharStarMarkState = "NONE" | "STARED";

export type PlayerStageState = "UNLOCKED" | "PLAYED" | "PASS" | "COMPLETE";

export type PlayerRoomSlotState = "EMPTY" | "UPGRADING" | "BUILT";

export type PlayerRoomState = "STOP" | "RUN";

export type EvolvePhase = "PHASE_0" | "PHASE_1" | "PHASE_2" | "PHASE_3" | "E_NUM";

export type SharedConsts_Direction = "UP" | "RIGHT" | "DOWN" | "LEFT" | "E_NUM" | "INVALID";

export interface GridPosition {
    GRID_ZERO: GridPosition;
    GRID_LEFT: GridPosition;
    GRID_RIGHT: GridPosition;
    GRID_UP: GridPosition;
    GRID_DOWN: GridPosition;
    GRID_UP_LEFT: GridPosition;
    GRID_UP_RIGHT: GridPosition;
    GRID_DOWN_LEFT: GridPosition;
    GRID_DOWN_RIGHT: GridPosition;
    GRID_DISABLE_DUMMY: GridPosition;
    ZERO: GridPosition;
    ONE: GridPosition;
    NEGATIVE_ONE: GridPosition;
    row: number;
    col: number;
}

export interface PlayerStatus {
    nickName: string;
    nickNumber: string;
    serverName: string;
    ap: number;
    lastApAddTime: string;
    lastRefreshTs: string;
    lastOnlineTs: string;
    level: number;
    exp: number;
    maxAp: number;
    practiceTicket: number;
    gold: number;
    diamondShard: number;
    recruitLicense: number;
    gachaTicket: number;
    tenGachaTicket: number;
    instantFinishTicket: number;
    hggShard: number;
    lggShard: number;
    classicShard: number;
    socialPoint: number;
    buyApRemainTimes: number;
    apLimitUpFlag: boolean;
    classicGachaTicket: number;
    classicTenGachaTicket: number;
    registerTs: number;
    secretary: string;
    secretarySkinId: string;
    secretarySkinSp: boolean;
    resume: string;
    birthday: PlayerBirthday;
    monthlySubscriptionEndTime: string;
    monthlySubscriptionStartTime: string;
    progress: number;
    mainStageProgress: string;
    avatar: AvatarInfo;
    globalVoiceLan: VoiceLangType;
    iosDiamond: number;
    androidDiamond: number;
    payDiamond: number;
    freeDiamond: number;
    flags: { [key: string]: boolean };
    friendAssist: PlayerFriendAssist[];
    uid: string;
    avatarId: string;
    friendNumLimit: number;
    tipMonthlyCardExpireTs: number;
}

export interface AvatarInfo {
    type: PlayerAvatarType;
    id: string;
}

export interface PlayerSquadItem {}

export interface PlayerFriendAssist {}

export interface PlayerSquad {
    squadId: number;
    name: string;
}

export interface PlayerBirthday {
    month: number;
    day: number;
}

export interface PlayerCarousel_PlayerCarouselFurnitureShopData {
    goods: { [key: string]: number };
    groups: { [key: string]: number };
}

export interface PlayerCarousel {
    furnitureShop: PlayerCarousel_PlayerCarouselFurnitureShopData;
}

export interface PlayerCheckIn_PlayerNewbiePackage {
    open: boolean;
    groupId: string;
    checkInHistory: number[];
    finish: number;
    stopSale: number;
}

export interface PlayerCheckIn_PlayerNewbieChoosePackage {
    stopSaleTs: number;
}

export interface PlayerCheckIn {
    canCheckIn: boolean;
    checkInGroupId: string;
    checkInRewardIndex: number;
    checkInHistory: boolean[];
    newbiePackage: PlayerCheckIn_PlayerNewbiePackage;
    newbieChooseGP: { [key: string]: PlayerCheckIn_PlayerNewbieChoosePackage };
    showCount: number;
    longTermRecvRecord: { [key: string]: number };
}

export interface PlayerMonthlySubPer {
    monthlySubscriptionEndTime: number;
    monthlySubscriptionStartTime: number;
}

export interface PlayerCharEquipInfo {
    hide: boolean;
    locked: boolean;
    level: number;
}

export interface PlayerCharacter {
    instId: number;
    charId: string;
    level: number;
    exp: number;
    evolvePhase: EvolvePhase;
    potentialRank: number;
    favorPoint: number;
    mainSkillLvl: number;
    gainTime: number;
    starMark: CharStarMarkState;
    currentTmpl: string;
    tmpl: { [key: string]: PlayerCharPatch };
    skin: string;
    defaultSkillIndex: number;
    skills: PlayerSkill[];
    voiceLan: string;
    currentEquip: string;
    equip: { [key: string]: PlayerCharEquipInfo };
    master: object;
}

export interface PlayerCharPatch {
    skinId: string;
    defaultSkillIndex: number;
    currentEquip: string;
    equip: { [key: string]: PlayerCharEquipInfo };
    skills: PlayerSkill[];
}

export interface PlayerNpcWithAudio {
    voiceLan: VoiceLangType;
    npcShowAudioInfoFlag: string;
}

export interface MileStonePlayerInfo_MileStoneRewardTicketItem {
    ts: number;
    count: number;
}

export interface MileStonePlayerInfo {
    points: { [key: string]: number };
    rewards: { [key: string]: MileStonePlayerInfo_MileStoneRewardTicketItem };
}

export interface PlayerOpenServer {
    chainLogin: OpenServerChainLogin;
    checkIn: OpenServerCheckIn;
    fullOpen: OpenServerFullOpen;
}

export interface OpenServerFullOpen {
    isAvailable: boolean;
    startTs: number;
    today: boolean;
    remain: number;
}

export interface PlayerHandBookAddon_GetInfo {
    fts: number;
    rts: number;
    startTimes: number;
    completeTimes: number;
    state: number;
    startTime: number;
}

export interface PlayerHandBookAddon {
    stage: { [key: string]: PlayerHandBookAddon_GetInfo };
    story: { [key: string]: PlayerHandBookAddon_GetInfo };
}

export interface PlayerSpecialOperatorNode {
    id: string;
    state: PlayerSpecialOperatorNode_State;
    type: string;
}

export interface PlayerActivity_PlayerDefaultActivity {
    coin: number;
    shop: { [key: string]: number };
}

export interface PlayerActivity_PlayerMissionOnlyTypeActivity {}

export interface PlayerActivity_PlayerCheckinOnlyTypeActivity {
    history: number[];
    dynOpt: string[];
    extraHistory: number[];
}

export interface PlayerActivity_PlayerCheckinVsTypeActivity {
    sweetVote: number;
    saltyVote: number;
    canVote: boolean;
    todayVoteState: number;
    voteRewardState: number;
    signedCnt: number;
    availSignCnt: number;
    socialState: number;
    actDay: number;
}

export interface PlayerActivity_PlayerCheckinAllTypeActivity {
    history: number[];
    allRecord: { [key: string]: number };
    allRewardStatus: { [key: string]: number };
    personalRecord: { [key: string]: number };
}

export interface PlayerActivity_MilestoneInfo {
    point: number;
    got: string[];
}

export interface PlayerActivity_PlayerCollectionTypeActivity_PlayerCollectionInfo {
    ts: string;
}

export interface PlayerActivity_PlayerCollectionTypeActivity {
    point: { [key: string]: number };
    history: { [key: string]: PlayerActivity_PlayerCollectionTypeActivity_PlayerCollectionInfo };
}

export interface PlayerActivity_PlayerAVGOnlyTypeActivity {
    isOpen: boolean;
}

export interface PlayerActivity_PlayerLoginOnlyTypeActivity {
    reward: number;
}

export interface PlayerActivity_PlayerMiniStoryActivity {
    coin: number;
    favorList: string[];
}

export interface PlayerActivity_PlayerRoguelikeActivity_MileStone {
    token: number;
    rewards: { [key: string]: number };
}

export interface PlayerActivity_PlayerRoguelikeActivity_GameStatus {
    lastTs: number;
}

export interface PlayerActivity_PlayerRoguelikeActivity {
    buffToken: number;
    milestone: PlayerActivity_PlayerRoguelikeActivity_MileStone;
    game: PlayerActivity_PlayerRoguelikeActivity_GameStatus;
}

export interface PlayerActivity_PlayerPrayOnlyActivity_RewardInfo {
    index: number;
    count: number;
}

export interface PlayerActivity_PlayerPrayOnlyActivity {
    lastTs: number;
    extraCount: number;
    prayDaily: number;
    prayMaxIndex: number;
    praying: boolean;
    prayArray: PlayerActivity_PlayerPrayOnlyActivity_RewardInfo[];
}

export interface PlayerActivity_PlayerSwitchOnlyActivity {
    rewards: { [key: string]: number };
}

export interface PlayerActivity_PlayerFlipOnlyActivity_ActFlipItemBundle {
    id: string;
    type: string;
    count: number;
    ts: number;
    prizeId: string;
}

export interface PlayerActivity_PlayerFlipOnlyActivity {
    raffleCount: number;
    todayRaffleCount: number;
    remainingRaffleCount: number;
    luckyToday: boolean;
    normalRewards: { [key: number]: PlayerActivity_PlayerFlipOnlyActivity_ActFlipItemBundle };
    grandStatus: number;
}

export interface PlayerActivity_PlayerGridGachaActivity {
    lastDay: boolean;
    firstDay: boolean;
    openedPosition: number[];
    openedType: number;
    rewardCount: number;
    grandPositions: number[][];
}

export interface PlayerActivity_PlayerMultiplayActivity_Troop {
    init: number;
    squads: PlayerSquad[];
}

export interface PlayerActivity_PlayerMultiplayActivity_Stage {
    stageId: string;
    state: PlayerStageState;
    completeTimes: number;
}

export interface PlayerActivity_PlayerMultiplayActivity {
    troop: { [key: string]: PlayerActivity_PlayerMultiplayActivity_Troop };
    stages: { [key: string]: PlayerActivity_PlayerMultiplayActivity_Stage };
}

export interface PlayerActivity_PlayerMultiplayV2Activity_PlayerMultiplayV2SquadItem {
    instId: number;
}

export interface PlayerActivity_PlayerMultiplayV2Activity_Squads {
    prefer: PlayerActivity_PlayerMultiplayV2Activity_PlayerMultiplayV2SquadItem[];
    backup: PlayerActivity_PlayerMultiplayV2Activity_PlayerMultiplayV2SquadItem[];
}

export interface PlayerActivity_PlayerMultiplayV2Activity_DailyMission {
    process: number;
    state: PlayerActivity_PlayerMultiplayV2Activity_DailyMissionState;
}

export interface PlayerActivity_PlayerMultiplayV2Activity_StageInfo {
    stageId: string;
    score: number;
    state: PlayerActivity_PlayerMultiplayV2Activity_StageState;
    startTimes: number;
    completeTimes: number;
}

export interface PlayerActivity_PlayerMultiplayV2Activity_Match {
    beMentorCnt: number;
    lockMentor: boolean;
    bannedUntilTs: number;
}

export interface PlayerActivity_PlayerMultiplayV2Activity_MilestoneInfo {
    point: number;
    got: string[];
}

export interface PlayerActivity_PlayerMultiplayV2Activity {
    squads: PlayerActivity_PlayerMultiplayV2Activity_Squads;
    dailyMission: PlayerActivity_PlayerMultiplayV2Activity_DailyMission;
    milestone: PlayerActivity_PlayerMultiplayV2Activity_MilestoneInfo;
    stageInfoDict: { [key: string]: PlayerActivity_PlayerMultiplayV2Activity_StageInfo };
    match: PlayerActivity_PlayerMultiplayV2Activity_Match;
    globalBan: boolean;
}

export interface PlayerActivity_PlayerMultiV3Activity_Collection {
    info: PlayerActivity_PlayerMultiV3Activity_CollectionInfo;
    title: PlayerActivity_PlayerMultiV3Activity_Title;
    photo: PlayerActivity_PlayerMultiV3Activity_Photo;
}

export interface PlayerActivity_PlayerMultiV3Activity_CollectionInfo {
    finishCnt: number;
    mentorCnt: number;
    likeCnt: number;
}

export interface PlayerActivity_PlayerMultiV3Activity_Title {
    unlock: string[];
    select: string[];
}

export interface PlayerActivity_PlayerMultiV3Activity_Photo {
    template: { [key: string]: { [key: string]: PlayerActivity_PlayerMultiV3Activity_PhotoInstance } };
    album: { [key: string]: PlayerActivity_PlayerMultiV3Activity_Album };
}

export interface PlayerActivity_PlayerMultiV3Activity_PhotoInstance {
    players: PlayerActivity_PlayerMultiV3Activity_PhotoPlayerInfo;
    chars: PlayerActivity_PlayerMultiV3Activity_PhotoCharInfo[];
    stageId: string;
    ts: number;
}

export interface PlayerActivity_PlayerMultiV3Activity_PhotoPlayerInfo {
    mine: PlayerActivity_PlayerMultiV3Activity_PhotoSelfInfo;
    mate: PlayerActivity_PlayerMultiV3Activity_PhotoAssistInfo;
}

export interface PlayerActivity_PlayerMultiV3Activity_PhotoSelfInfo {
    title: string[];
}

export interface PlayerActivity_PlayerMultiV3Activity_PhotoAssistInfo {
    uid: string;
    sameChannel: boolean;
    title: string[];
    nickName: string;
    avatar: AvatarInfo;
    secretary: string;
    secretarySkinId: string;
    secretarySkinSp: boolean;
    level: number;
    nameCardSkinId: string;
    nameCardSkinTmpl: number;
}

export interface PlayerActivity_PlayerMultiV3Activity_PhotoCharInfo {
    charId: string;
    currentTmpl: string;
    skinId: string;
    slotIdx: number;
    frame: number;
    flip: boolean;
}

export interface PlayerActivity_PlayerMultiV3Activity_Album {
    commit: boolean;
    slot: { [key: string]: string };
}

export interface PlayerActivity_PlayerMultiV3Activity_Troop {
    buff: PlayerActivity_PlayerMultiV3Activity_TroopBuff;
    squads: { [key: string]: PlayerActivity_PlayerMultiV3Activity_Squad };
}

export interface PlayerActivity_PlayerMultiV3Activity_TroopBuff {
    unlock: string[];
    coin: number;
    star: number;
}

export interface PlayerActivity_PlayerMultiV3Activity_Squad {
    prefer: PlayerActivity_PlayerMultiV3Activity_SquadItem[];
    backup: PlayerActivity_PlayerMultiV3Activity_SquadItem[];
    buffId: string;
}

export interface PlayerActivity_PlayerMultiV3Activity_SquadItem {
    innerInstId: number;
}

export interface PlayerActivity_PlayerMultiV3Activity_StageInfo {
    star: number;
    exScore: number;
    matchTimes: number;
    startTimes: number;
    finishTimes: number;
}

export interface PlayerActivity_PlayerMultiV3Activity_MatchInfo {
    bannedUntilTs: number;
    lastModeList: string[];
    lastMentorType: ActMultiV3MatchPosType;
    lastReverse: number;
}

export interface PlayerActivity_PlayerMultiV3Activity_Milestone {
    point: number;
    got: string[];
}

export interface PlayerActivity_PlayerMultiV3Activity_Daily {
    process: number;
    state: number;
}

export interface PlayerActivity_PlayerMultiV3Activity_Scene {
    lastMate: string[];
}

export interface PlayerActivity_PlayerMultiV3Activity {
    collection: PlayerActivity_PlayerMultiV3Activity_Collection;
    troop: PlayerActivity_PlayerMultiV3Activity_Troop;
    match: PlayerActivity_PlayerMultiV3Activity_MatchInfo;
    milestone: PlayerActivity_PlayerMultiV3Activity_Milestone;
    daily: PlayerActivity_PlayerMultiV3Activity_Daily;
    stage: { [key: string]: PlayerActivity_PlayerMultiV3Activity_StageInfo };
    scene: PlayerActivity_PlayerMultiV3Activity_Scene;
    globalBan: boolean;
}

export interface PlayerActivity_PlayerInterlockActivity_DefendCharData {
    charInstId: number;
    currentTmpl: string;
}

export interface PlayerActivity_PlayerInterlockActivity {
    milestoneCoin: number;
    milestoneGot: string[];
    specialDefendStageId: string;
    defend: { [key: string]: PlayerActivity_PlayerInterlockActivity_DefendCharData[] };
}

export interface PlayerActivity_PlayerAct3D0Activity_BoxState {
    content: { [key: string]: number };
}

export interface PlayerActivity_PlayerAct3D0Activity_MileStone {
    point: number;
    rewards: { [key: string]: number };
}

export interface PlayerActivity_PlayerAct3D0Activity {
    faction: string;
    gachaCoin: number;
    ticket: number;
    clue: { [key: string]: number };
    box: { [key: string]: PlayerActivity_PlayerAct3D0Activity_BoxState };
    milestone: PlayerActivity_PlayerAct3D0Activity_MileStone;
    favorList: string[];
}

export interface PlayerActivity_PlayerAct4D0Activity_MileStone {
    point: number;
    rewards: { [key: string]: number };
}

export interface PlayerActivity_PlayerAct4D0Activity {
    story: { [key: string]: number };
    milestone: PlayerActivity_PlayerAct4D0Activity_MileStone;
}

export interface PlayerActivity_PlayerAct5D0Activity {
    milestone: MileStonePlayerInfo;
}

export interface PlayerActivity_PlayerAct5D1Activity_PlayerAct5D1Shop_ProgressInfo {
    count: number;
    order: number;
}

export interface PlayerActivity_PlayerAct5D1Activity_PlayerAct5D1Shop {
    info: { [key: string]: number };
    progressInfo: { [key: string]: PlayerActivity_PlayerAct5D1Activity_PlayerAct5D1Shop_ProgressInfo };
}

export interface PlayerActivity_PlayerAct5D1Activity_PlayerActRuneStage {
    schedule: string;
    available: number;
    scores: number;
    rune: { [key: string]: number };
}

export interface PlayerActivity_PlayerAct5D1Activity {
    coin: number;
    pt: number;
    shop: PlayerActivity_PlayerAct5D1Activity_PlayerAct5D1Shop;
    runeStage: { [key: string]: PlayerActivity_PlayerAct5D1Activity_PlayerActRuneStage };
    stageEnemy: { [key: string]: string[] };
}

export interface PlayerActivity_PlayerAct9D0Activity {
    coin: number;
    favorList: string[];
    news: { [key: string]: number };
    campaignCnt: number;
}

export interface PlayerActivity_PlayerAct12sideActivity_MilestoneInfo {
    point: number;
    got: string[];
}

export interface PlayerActivity_PlayerAct12sideActivity_CharmInfo {
    recycleStack: number;
    firstGotReward: string[];
}

export interface PlayerActivity_PlayerAct12sideActivity {
    coin: number;
    campaignCnt: number;
    favorList: string[];
    milestone: PlayerActivity_PlayerAct12sideActivity_MilestoneInfo;
    charm: PlayerActivity_PlayerAct12sideActivity_CharmInfo;
}

export interface PlayerActivity_PlayerAct13sideActivity_MilestoneInfo {
    point: number;
    got: string[];
}

export interface PlayerActivity_PlayerAct13sideActivity_Flag {
    agenda: boolean;
    mission: boolean;
}

export interface PlayerActivity_PlayerAct13sideActivity_SearchReward {
    id: string;
    type: ItemType;
}

export interface PlayerActivity_PlayerAct13sideActivity_SearchCondition {
    orgId: string;
    reward: PlayerActivity_PlayerAct13sideActivity_SearchReward;
}

export interface PlayerActivity_PlayerAct13sideActivity_DailyMissionData {
    missionId: string;
    orgId: string;
    principalId: string;
    principalDescIdx: number;
    rewardGroupId: string;
}

export interface PlayerActivity_PlayerAct13sideActivity_DailyMissionProgress {
    target: number;
    value: number;
}

export interface PlayerActivity_PlayerAct13sideActivity_DailyMissionWithProgressData {
    mission: PlayerActivity_PlayerAct13sideActivity_DailyMissionData;
    progress: PlayerActivity_PlayerAct13sideActivity_DailyMissionProgress;
}

export interface PlayerActivity_PlayerAct13sideActivity_DailyMissionPoolData {
    random: number;
    condition: PlayerActivity_PlayerAct13sideActivity_SearchCondition;
    pool: PlayerActivity_PlayerAct13sideActivity_DailyMissionData[];
    board: PlayerActivity_PlayerAct13sideActivity_DailyMissionWithProgressData[];
}

export interface PlayerActivity_PlayerAct13sideActivity {
    token: number;
    favorList: string[];
    milestone: PlayerActivity_PlayerAct13sideActivity_MilestoneInfo;
    agenda: number;
    flag: PlayerActivity_PlayerAct13sideActivity_Flag;
    mission: PlayerActivity_PlayerAct13sideActivity_DailyMissionPoolData;
}

export interface PlayerActivity_PlayerAct17D7Activity {
    isOpen: boolean;
}

export interface PlayerActivity_PlayerAprilFoolActivity {
    isOpen: boolean;
}

export interface PlayerActivity_PlayerAct17SideActivity {
    isOpen: boolean;
    coin: number;
    favorList: string[];
}

export interface PlayerActivity_PlayerBossRushActivity_MilestoneInfo {
    point: number;
    got: string[];
}

export interface PlayerActivity_PlayerBossRushActivity_TokenInfo {
    current: number;
    total: number;
}

export interface PlayerActivity_PlayerBossRushActivity_RelicInfo {
    token: PlayerActivity_PlayerBossRushActivity_TokenInfo;
    unlockedRelicLevelDic: { [key: string]: number };
    selectingRelicId: string;
}

export interface PlayerActivity_PlayerBossRushActivity {
    milestone: PlayerActivity_PlayerBossRushActivity_MilestoneInfo;
    relic: PlayerActivity_PlayerBossRushActivity_RelicInfo;
    bestWaveDic: { [key: string]: number };
}

export interface PlayerActivity_PlayerEnemyDuelActivity_MilestoneInfo {
    point: number;
    got: string[];
}

export interface PlayerActivity_PlayerEnemyDuelActivity_DailyMission {
    process: number;
    state: PlayerActivity_PlayerEnemyDuelActivity_DailyMissionState;
}

export interface PlayerActivity_PlayerEnemyDuelActivity_ModeInfo {
    highScore: number;
    curStage: string;
    isUnlock: boolean;
}

export interface PlayerActivity_PlayerEnemyDuelActivity {
    milestone: PlayerActivity_PlayerEnemyDuelActivity_MilestoneInfo;
    dailyMission: PlayerActivity_PlayerEnemyDuelActivity_DailyMission;
    modeInfo: { [key: string]: PlayerActivity_PlayerEnemyDuelActivity_ModeInfo };
    globalBan: boolean;
}

export interface PlayerActivity_PlayerVecBreakV2_DefendCharInfo {
    charInstId: number;
    currentTmpl: string;
}

export interface PlayerActivity_PlayerVecBreakV2_DefendStageInfo {
    stageId: string;
    defendSquad: PlayerActivity_PlayerVecBreakV2_DefendCharInfo[];
    recvTimeLimited: boolean;
    recvNormal: boolean;
}

export interface PlayerActivity_PlayerVecBreakV2 {
    milestone: PlayerActivity_MilestoneInfo;
    activatedBuff: string[];
    defendStages: { [key: string]: PlayerActivity_PlayerVecBreakV2_DefendStageInfo };
}

export interface PlayerActivity_PlayerArcadeActivity_MilestoneInfo {
    point: number;
    got: string[];
}

export interface PlayerActivity_PlayerArcadeActivity_BadgeInfo {
    status: PlayerActivity_PlayerArcadeActivity_BadgeStatus;
}

export interface PlayerActivity_PlayerArcadeActivity {
    milestone: PlayerActivity_PlayerArcadeActivity_MilestoneInfo;
    badge: { [key: string]: PlayerActivity_PlayerArcadeActivity_BadgeInfo };
    score: { [key: string]: { [key: string]: number } };
}

export interface PlayerActivity_PlayerAct20SideActivity_ActBaseInfo {
    actCoin: number;
    milestone: PlayerActivity_PlayerAct20SideActivity_MilestoneStateInfo;
}

export interface PlayerActivity_PlayerAct20SideActivity_MilestoneStateInfo {
    point: number;
    claimedCount: number;
}

export interface PlayerActivity_PlayerAct20SideActivity_HotValueInfo {
    hotVal: number;
    dailyHotVal: number;
}

export interface PlayerActivity_PlayerAct20SideActivity_EntertainCompBestRecord {
    performance: number;
    expression: number;
    operation: number;
    level: CartCompetitionRank;
}

export interface PlayerActivity_PlayerAct20SideActivity {
    actBase: PlayerActivity_PlayerAct20SideActivity_ActBaseInfo;
    dailyJudgeTimes: number;
    entertainmentCompetition: { [key: string]: PlayerActivity_PlayerAct20SideActivity_EntertainCompBestRecord };
    hotValue: PlayerActivity_PlayerAct20SideActivity_HotValueInfo;
    hasJoinedExhibition: boolean;
    campaignCnt: number;
    favorList: string[];
}

export interface PlayerActivity_PlayerActFloatParadeActivity_Result {
    strategy: number;
    eventId: string;
}

export interface PlayerActivity_PlayerActFloatParadeActivity {
    day: number;
    canRaffle: boolean;
    result: PlayerActivity_PlayerActFloatParadeActivity_Result;
}

export interface PlayerActivity_PlayerAct21SideActivity {
    isOpen: boolean;
    coin: number;
    favorList: string[];
}

export interface PlayerActivity_PlayerActMainlineBuff {
    favorList: string[];
}

export interface PlayerActivity_PlayerAct24SideActivity_Meal {
    chance: number;
    id: string;
    digested: boolean;
}

export interface PlayerActivity_PlayerAct24SideActivity_Alchemy {
    price: number;
    item: { [key: string]: number };
    gacha: { [key: string]: { [key: string]: number } };
}

export interface PlayerActivity_PlayerAct24SideActivity_Hunt {
    infoBook: { [key: string]: number };
    enemyKillCntStats: { [key: string]: number };
    collectRewards: number;
}

export interface PlayerActivity_PlayerAct24SideActivity {
    meal: PlayerActivity_PlayerAct24SideActivity_Meal;
    alchemy: PlayerActivity_PlayerAct24SideActivity_Alchemy;
    tool: { [key: string]: PlayerActivity_PlayerAct24SideActivity_ToolState };
    favorList: string[];
    hunt: PlayerActivity_PlayerAct24SideActivity_Hunt;
    unlockItemMap: { [key: string]: number };
    globalBan: boolean;
}

export interface PlayerActivity_PlayerAct25SideActivity_MissionProgress {
    target: number;
    value: number;
}

export interface PlayerActivity_PlayerAct25SideActivity_Mission {
    state: PlayerActivity_PlayerAct25SideActivity_MissionState;
    progress: PlayerActivity_PlayerAct25SideActivity_MissionProgress;
}

export interface PlayerActivity_PlayerAct25SideActivity_Area {
    missions: { [key: string]: PlayerActivity_PlayerAct25SideActivity_Mission };
    missionId: string;
    lastFinMissionId: string;
}

export interface PlayerActivity_PlayerAct25SideActivity_DailyHarvest {
    additionalHarvest: number;
    currentRate: number;
    preparedRate: number;
    lastHarvenessTs: number;
}

export interface PlayerActivity_PlayerAct25SideActivity {
    investigativeToken: number;
    actCoin: number;
    dailyTokenRefresh: boolean;
    areas: { [key: string]: PlayerActivity_PlayerAct25SideActivity_Area };
    favorList: string[];
    incremenalGame: PlayerActivity_PlayerAct25SideActivity_DailyHarvest;
    tokenRecvCnt: number;
    buff: string[];
}

export interface PlayerActivity_PlayerAct27SideActivity_InquireInfo {
    cur: number;
    max: number;
}

export interface PlayerActivity_PlayerAct27SideActivity_PurchaseInfo {
    strategy: number;
    count: number;
}

export interface PlayerActivity_PlayerAct27SideActivity_SellInfo {
    price: number;
    count: number;
    bonus: number;
}

export interface PlayerActivity_PlayerAct27SideActivity_Sale {
    stateSell: PlayerActivity_PlayerAct27SideActivity_SellGoodState;
    inquire: PlayerActivity_PlayerAct27SideActivity_InquireInfo;
    groupId: string;
    buyers: { [key: string]: number };
    purchases: { [key: string]: { [key: string]: PlayerActivity_PlayerAct27SideActivity_PurchaseInfo } };
    sells: { [key: string]: { [key: string]: PlayerActivity_PlayerAct27SideActivity_SellInfo } };
}

export interface PlayerActivity_PlayerAct27SideActivity_MilestoneInfo {
    point: number;
    got: string[];
}

export interface PlayerActivity_PlayerAct27SideActivity {
    day: number;
    signedIn: boolean;
    stock: { [key: string]: number };
    reward: ItemBundle;
    state: PlayerActivity_PlayerAct27SideActivity_SaleState;
    sale: PlayerActivity_PlayerAct27SideActivity_Sale;
    milestone: PlayerActivity_PlayerAct27SideActivity_MilestoneInfo;
    favorList: string[];
    coin: number;
    campaignCnt: number;
}

export interface PlayerActivity_PlayerAct42D0Activity_AreaInfo {
    canUseBuff: boolean;
    stages: { [key: string]: PlayerActivity_PlayerAct42D0Activity_NoramlStageInfo };
}

export interface PlayerActivity_PlayerAct42D0Activity_NoramlStageInfo {
    rating: number;
}

export interface PlayerActivity_PlayerAct42D0Activity_ChallengeStageInfo {
    missions: { [key: string]: PlayerActivity_PlayerAct42D0Activity_ChallengeStageMissionInfo };
}

export interface PlayerActivity_PlayerAct42D0Activity_ChallengeStageMissionInfo {
    target: number;
    value: number;
    state: number;
}

export interface PlayerActivity_PlayerAct42D0Activity {
    milestone: number;
    areas: { [key: string]: PlayerActivity_PlayerAct42D0Activity_AreaInfo };
    spStages: { [key: string]: PlayerActivity_PlayerAct42D0Activity_ChallengeStageInfo };
    milestoneRecv: string[];
    theHardestStage: string;
}

export interface PlayerActivity_PlayerUniqueOnlyActivity {
    reward: number;
}

export interface PlayerActivity_PlayerBlessOnlyActivity_BlessOnlyFestival {
    state: number;
    charId: string;
}

export interface PlayerActivity_PlayerBlessOnlyActivity {
    history: number[];
    festivalHistory: PlayerActivity_PlayerBlessOnlyActivity_BlessOnlyFestival[];
    lastTs: number;
}

export interface PlayerActivity_PlayerRecruitOnlyAct {
    used: number;
}

export interface PlayerActivity_PlayerAct29SideActivity_NpcInfo {
    npc: string;
    tryTimes: number;
    hasRecv: boolean;
}

export interface PlayerActivity_PlayerAct29SideActivity_MajorNpcInfo {
    isOpen: boolean;
    npc: PlayerActivity_PlayerAct29SideActivity_NpcInfo;
}

export interface PlayerActivity_PlayerAct29SideActivity_HiddenNpcInfo {
    needShow: boolean;
    npc: PlayerActivity_PlayerAct29SideActivity_NpcInfo;
}

export interface PlayerActivity_PlayerAct29SideActivity_DailyNpcInfo {
    slot: { [key: string]: PlayerActivity_PlayerAct29SideActivity_NpcInfo };
}

export interface PlayerActivity_PlayerAct29SideActivity {
    actCoin: number;
    accessToken: number;
    favorList: string[];
    rareMelodyMade: boolean;
    majorNPC: PlayerActivity_PlayerAct29SideActivity_MajorNpcInfo;
    hiddenNPC: PlayerActivity_PlayerAct29SideActivity_HiddenNpcInfo;
    dailyNPC: PlayerActivity_PlayerAct29SideActivity_DailyNpcInfo;
    fragmentBag: { [key: string]: number };
    melodyBag: { [key: string]: number };
    melodyNax: { [key: string]: number };
    majorFinDic: { [key: string]: number };
}

export interface PlayerActivity_PlayerYear5GeneralActivity {
    unconfirmedPoints: number;
    nextRewardIndex: number;
    coin: number;
    favorList: string[];
}

export interface PlayerActivity_PlayerAct36SideActivity_FoodHandbookInfo {
    enemySlot: { [key: string]: boolean };
    food: { [key: string]: boolean };
    rewardState: PlayerActivity_PlayerAct36SideActivity_RewardState;
}

export interface PlayerActivity_PlayerAct36SideActivity {
    foodHandbookInfo: PlayerActivity_PlayerAct36SideActivity_FoodHandbookInfo;
    coin: number;
    favorList: string[];
}

export interface PlayerActivity_PlayerAct35SideActivity_PlayerAct35SideCarving {
    id: string;
    round: number;
    score: number;
    state: PlayerActivity_PlayerAct35SideActivity_GameState;
    roundCoinAdd: number;
    material: { [key: string]: number };
    card: { [key: string]: number };
    slotCnt: number;
    shop: PlayerActivity_PlayerAct35SideActivity_PlayerAct35SideCarvingShop;
    mission: PlayerActivity_PlayerAct35SideActivity_CarvingTask;
}

export interface PlayerActivity_PlayerAct35SideActivity_PlayerAct35SideCarvingShop {
    coin: number;
    good: PlayerActivity_PlayerAct35SideActivity_ShopGood[];
    freeCardCnt: number;
    refreshPrice: number;
    slotPrice: number;
}

export interface PlayerActivity_PlayerAct35SideActivity_ShopGood {
    id: string;
    price: number;
}

export interface PlayerActivity_PlayerAct35SideActivity_CarvingTask {
    id: string;
    progress: number[];
}

export interface PlayerActivity_PlayerAct35SideActivity_MilestoneState {
    point: number;
    got: string[];
}

export interface PlayerActivity_PlayerAct35SideActivity {
    carving: PlayerActivity_PlayerAct35SideActivity_PlayerAct35SideCarving;
    unlock: { [key: string]: number };
    record: { [key: string]: number };
    milestone: PlayerActivity_PlayerAct35SideActivity_MilestoneState;
    coin: number;
    campaignCnt: number;
    favorList: string[];
}

export interface PlayerActivity_PlayerAct38SideActivity_PlayerAct38SidePuzzle {
    puzzleStatus: PlayerActivity_PlayerAct38SideActivity_PuzzleStatus;
    solutionList: FireworkData_PlateSlotData[];
}

export interface PlayerActivity_PlayerAct38SideActivity {
    coin: number;
    favorList: string[];
    fireworkPuzzleDict: { [key: string]: PlayerActivity_PlayerAct38SideActivity_PlayerAct38SidePuzzle };
}

export interface PlayerActivity_PlayerAutoChessV1Activity_ModeRecord {
    unlock: boolean;
    completeCnt: number;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_Milestone {
    point: number;
    got: string[];
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessCharCard {
    chessId: string;
    type: PlayerActivity_PlayerAutoChessV1Activity_AutoChessCharType;
    diyChar: string;
    potentialRank: number;
    cultivateEffect: string;
    skillIndex: number;
    currentEquip: string;
    skin: string;
    assistInfo: PlayerActivity_PlayerAutoChessV1Activity_AutoChessAssistInfo;
    diyOrigChessId: string;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessAssistInfo {
    uid: string;
    nickName: string;
    nickNumber: string;
    alias: string;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessBandUnlockInfo {
    state: number;
    progress: PlayerActivity_PlayerAutoChessV1Activity_AutoChessBandUnlockProgress;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessBandUnlockProgress {
    value: number;
    target: number;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_DailyMission {
    process: number;
    state: number;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Effect {
    instId: number;
    effectId: string;
    ts: number;
    startRound: number;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Health {
    hp: number;
    shield: number;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Store {
    lv: number;
    coin: number;
    isForzen: boolean;
    upgradePrice: number;
    refreshPrice: number;
    charGoods: { [key: number]: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_AutoChessCharGoods };
    trapGoods: { [key: number]: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_AutoChessTrapGoods };
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Table_RecruitCard {
    instId: number;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Table_Spell {
    instId: number;
    chessId: string;
    startRound: number;
    activated: boolean;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Table {
    recruitCard: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Table_RecruitCard;
    spellUsing: { [key: number]: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Table_Spell };
    gameInfo: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_AutoChessGameInfo;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_AutoChessGameInfo_BattleChessInstServer {
    instId: number;
    isToken: boolean;
    dir: SharedConsts_Direction;
    buildSeq: number;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_AutoChessGameInfo {
    chessInstMap: { [key: number]: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_AutoChessGameInfo_BattleChessInstServer };
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_AutoChessCharGoods {
    id: string;
    price: number;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_AutoChessTrapGoods {
    id: string;
    price: number;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_AutoChessForce {
    forceId: string;
    hp: number;
    extraForce: string[];
    effect: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Effect[];
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Buff_SpecialRefresh {
    cnt: number;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Buff_EnemyCounter {
    baseNum: number;
    process: number;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Buff_GainCoinCounter {
    baseNum: number;
    reduce: number;
    process: number;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Buff_EffectShowItem {
    leftCnt: number;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Buff_BattleLayerEffect {
    effectInst: number;
    count: number;
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Buff {
    gainCoinCounter: { [key: string]: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Buff_GainCoinCounter };
    killEnemyCounter: { [key: string]: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Buff_EnemyCounter };
    chessPurchase: { [key: string]: number };
    specialRefresh: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Buff_SpecialRefresh;
    battleLayers: { [key: string]: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Buff_BattleLayerEffect[] };
    equipCoinJar: { [key: number]: number };
    slotAdd: number;
    effectShow: { [key: number]: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Buff_EffectShowItem };
}

export interface PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame {
    startTs: string;
    seed: number;
    mode: string;
    state: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGameState;
    bandId: string;
    currForce: string;
    allForces: { [key: string]: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_AutoChessForce };
    rewardEnemyRound: number;
    health: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Health;
    turn: number;
    roundId: string;
    stageId: string;
    store: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Store;
    table: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Table;
    buff: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame_Buff;
}

export interface PlayerActivity_PlayerAutoChessV1Activity {
    chessPool: { [key: string]: PlayerActivity_PlayerAutoChessV1Activity_AutoChessCharCard };
    dailyMission: PlayerActivity_PlayerAutoChessV1Activity_DailyMission;
    protectTs: number;
    milestone: PlayerActivity_PlayerAutoChessV1Activity_Milestone;
    game: PlayerActivity_PlayerAutoChessV1Activity_AutoChessGame;
    band: { [key: string]: PlayerActivity_PlayerAutoChessV1Activity_AutoChessBandUnlockInfo };
    mode: { [key: string]: PlayerActivity_PlayerAutoChessV1Activity_ModeRecord };
}

export interface PlayerActivity_PlayerActMainSSActivity {
    favorList: string[];
    coin: number;
}

export interface PlayerActivity_PlayerAct42SideActivity_PlayerAct42sideTask {
    state: PlayerActivity_PlayerAct42SideActivity_TaskState;
}

export interface PlayerActivity_PlayerAct42SideActivity_PlayerAct42sideTrustedItem {
    has: number;
    got: number;
    dailyState: number;
}

export interface PlayerActivity_PlayerAct42SideActivity {
    coin: number;
    favorList: string[];
    outerPlayerOpen: boolean;
    taskMap: { [key: string]: PlayerActivity_PlayerAct42SideActivity_PlayerAct42sideTask };
    gunMap: { [key: string]: number };
    fileMap: { [key: string]: number };
    trustedItem: PlayerActivity_PlayerAct42SideActivity_PlayerAct42sideTrustedItem;
    dailyRewardState: PlayerActivity_PlayerAct42SideActivity_RewardState;
}

export interface PlayerActivity_PlayerAct45SideActivity {
    coin: number;
    favorList: string[];
    platformUnlock: boolean;
    charState: { [key: string]: PlayerActivity_PlayerAct45SideActivity_State };
    mailState: { [key: string]: PlayerActivity_PlayerAct45SideActivity_State };
}

export interface PlayerActivity_PlayerAct44SideActivity_Milestone {
    point: number;
    got: string[];
}

export interface PlayerActivity_PlayerAct44SideActivity_PlayerInformantInsight {
    patienceRecommend: number;
    trustRecommend: number;
    attentionRecommend: number;
    patienceMax: number;
    trustMax: number;
    attentionMax: number;
}

export interface PlayerActivity_PlayerAct44SideActivity_PlayerInformantTrader {
    patience: number;
    trust: number;
    attention: number;
    choices: string[];
    lastChoice: string;
}

export interface PlayerActivity_PlayerAct44SideActivity_PlayerInformantSettle {
    customerId: string;
    tagId: string;
    success: boolean;
    successRate: number;
    incomeRate: number;
    income: number;
}

export interface PlayerActivity_PlayerAct44SideActivity_PlayerInformant {
    state: PlayerActivity_PlayerAct44SideActivity_InformantState;
    customerList: number[];
    curCustomer: number;
    newsId: string;
    customerId: string;
    round: number;
    basicIncome: number;
    tag: string;
    customerDialog: string;
    keeperDialog: string;
    insightTimes: number;
    boom: boolean;
    insight: PlayerActivity_PlayerAct44SideActivity_PlayerInformantInsight;
    tradeInfo: PlayerActivity_PlayerAct44SideActivity_PlayerInformantTrader;
    settle: PlayerActivity_PlayerAct44SideActivity_PlayerInformantSettle[];
}

export interface PlayerActivity_PlayerAct44SideActivity {
    coin: number;
    favorList: string[];
    campaignCnt: number;
    informantPt: number;
    milestone: PlayerActivity_PlayerAct44SideActivity_Milestone;
    businessDay: number;
    unlockedCustomers: { [key: string]: number };
    unlockedTags: { [key: string]: number };
    isNew: boolean;
    outerOpen: boolean;
    informant: PlayerActivity_PlayerAct44SideActivity_PlayerInformant;
}

export interface PlayerActivity_PlayerAct1VHalfIdleActivity_StageInfo {
    rate: { [key: string]: number };
    bossState: PlayerActivity_PlayerAct1VHalfIdleActivity_BossState;
}

export interface PlayerActivity_PlayerAct1VHalfIdleActivity_SettleStageInfo {
    rate: { [key: string]: number };
    bossState: PlayerActivity_PlayerAct1VHalfIdleActivity_BossState;
    stageId: string;
    progress: number;
}

export interface PlayerActivity_PlayerAct1VHalfIdleActivity_ProductionInfo {
    rate: { [key: string]: number };
    product: { [key: string]: number };
    refreshTs: number;
    harvestTs: number;
}

export interface PlayerActivity_PlayerAct1VHalfIdleActivity_Act1VHalfIdleTroop {
    chars: { [key: string]: PlayerActivity_PlayerAct1VHalfIdleActivity_Act1VHalfIdleCharData };
    trap: string[];
    npc: string[];
    assist: SharedCharData[];
    extraAssist: boolean;
}

export interface PlayerActivity_PlayerAct1VHalfIdleActivity_Act1VHalfIdleCharData {
    instId: number;
    charId: string;
    level: number;
    skillLvlWithSpec: number;
    evolvePhase: number;
    isAssist: boolean;
    defaultSkillId: string;
    defaultEquipId: string;
}

export interface PlayerActivity_PlayerAct1VHalfIdleActivity_RecruitInfo {
    poolGain: { [key: string]: string[] };
    poolTimes: { [key: string]: number };
}

export interface PlayerActivity_PlayerAct1VHalfIdleActivity_Milestone {
    point: number;
    got: string[];
}

export interface PlayerActivity_PlayerAct1VHalfIdleActivity_TechTree {
    unlock: string[];
}

export interface PlayerActivity_PlayerAct1VHalfIdleActivity {
    coin: number;
    troop: PlayerActivity_PlayerAct1VHalfIdleActivity_Act1VHalfIdleTroop;
    stage: { [key: string]: PlayerActivity_PlayerAct1VHalfIdleActivity_StageInfo };
    settleInfo: PlayerActivity_PlayerAct1VHalfIdleActivity_SettleStageInfo;
    production: PlayerActivity_PlayerAct1VHalfIdleActivity_ProductionInfo;
    recruit: PlayerActivity_PlayerAct1VHalfIdleActivity_RecruitInfo;
    milestone: PlayerActivity_PlayerAct1VHalfIdleActivity_Milestone;
    inventory: { [key: string]: number };
    tech: PlayerActivity_PlayerAct1VHalfIdleActivity_TechTree;
    globalBan: boolean;
}

export interface PlayerActivity_PlayerCommonDailyMission {
    process: number;
    state: PlayerActivity_PlayerCommonDailyMission_DailyMissionState;
}

export interface PlayerActivity_PlayerActAutoChessActivity_Mode {
    unlock: boolean;
    completeCnt: number;
}

export interface PlayerActivity_PlayerActAutoChessActivity_BandUnlockProgress {
    value: number;
    target: number;
}

export interface PlayerActivity_PlayerActAutoChessActivity_BandElem {
    state: PlayerActivity_PlayerActAutoChessActivity_BandState;
    progress: PlayerActivity_PlayerActAutoChessActivity_BandUnlockProgress;
    passCnt: number;
}

export interface PlayerActivity_PlayerActAutoChessActivity_AutoChessSquadSlot {
    chessId: string;
    charId: string;
    tmplId: string;
    diyBackupChessId: string;
    cultivateEffect: string;
    currentEquip: string;
    skin: string;
    type: PlayerActivity_PlayerActAutoChessActivity_AutoChessCharType;
    potentialRank: number;
    skillIndex: number;
    assistInfo: PlayerActivity_PlayerActAutoChessActivity_AutoChessAssistInfo;
}

export interface PlayerActivity_PlayerActAutoChessActivity_AutoChessAssistInfo {
    uid: string;
    nickName: string;
    nickNumber: string;
    alias: string;
}

export interface PlayerActivity_PlayerActAutoChessActivity_MatchInfo {
    bannedUntilTs: number;
}

export interface PlayerActivity_PlayerActAutoChessActivity_Scene {
    lastMate: string[];
}

export interface PlayerActivity_PlayerActAutoChessActivity {
    mode: { [key: string]: PlayerActivity_PlayerActAutoChessActivity_Mode };
    dailyMission: PlayerActivity_PlayerCommonDailyMission;
    band: { [key: string]: PlayerActivity_PlayerActAutoChessActivity_BandElem };
    protectTs: number;
    trophyNum: number;
    milestone: PlayerActivity_MilestoneInfo;
    match: PlayerActivity_PlayerActAutoChessActivity_MatchInfo;
    scene: PlayerActivity_PlayerActAutoChessActivity_Scene;
    globalBan: boolean;
    chessSquad: { [key: string]: PlayerActivity_PlayerActAutoChessActivity_AutoChessSquadSlot };
}

export interface PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyGame {
    stageId: string;
    startTs: number;
    buff: PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyBuff[];
    turn: number;
    cardList: number[];
    lastCard: number;
    step: number;
    nodeList: PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyStageNode[];
    task: PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyTaskPanelInfo;
}

export interface PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyTaskItemProcess {
    requireType: string;
    value: number;
    target: number;
}

export interface PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyTask {
    id: string;
    point: number;
    process: PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyTaskItemProcess[];
}

export interface PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyBuff_BuffProcess {
    value: number;
    target: number;
}

export interface PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyBuff {
    id: string;
    process: PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyBuff_BuffProcess;
}

export interface PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyStage {
    state: PlayerActivity_PlayerAct46SideActivity_MonopolyStageStatus;
    highScore: number;
}

export interface PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyStageNode {
    resourceId: string;
    resourceBasicCount: number;
    buffRate: number;
    isNodeLock: boolean;
    hasChest: boolean;
}

export interface PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyTaskPanelInfo {
    shortList: PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyTask[];
    longList: PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyTask[];
    score: number;
}

export interface PlayerActivity_PlayerAct46SideActivity {
    coin: number;
    favorList: string[];
    outerOpen: boolean;
    game: PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyGame;
    monoStages: { [key: string]: PlayerActivity_PlayerAct46SideActivity_PlayerMonopolyStage };
}

export interface PlayerActivity_PlayerActFootballActivity_ScoreInfo {
    self: number;
    enemy: number;
}

export interface PlayerActivity_PlayerActFootballActivity_MilestoneInfo {
    point: number;
}

export interface PlayerActivity_PlayerActFootballActivity {
    stage: { [key: string]: PlayerActivity_PlayerActFootballActivity_ScoreInfo };
    milestone: PlayerActivity_PlayerActFootballActivity_MilestoneInfo;
    isBuffUnlocked: boolean;
}

export interface PlayerActivity_PlayerActArkhubActivity_Scene {
    lastMate: string[];
}

export interface PlayerActivity_PlayerActArkhubActivity {
    coin: number;
    secretary: string;
    secretarySkinId: string;
    secretarySkinSp: boolean;
    protectTs: number;
    squads: PlayerSquad[];
    globalBan: boolean;
    scene: PlayerActivity_PlayerActArkhubActivity_Scene;
}

export interface PlayerActivity_PlayerAct53SideActivity {
    actCoin: number;
    campaignCnt: number;
    favorList: string[];
}

export type PlayerActivity = { [typeKey: string]: { [actId: string]: object } };

export interface PlayerTemplateTrap_Trap {
    count: number;
}

export interface PlayerTemplateTrap_Domin {
    traps: { [key: string]: PlayerTemplateTrap_Trap };
    squad: string[];
}

export interface PlayerTemplateTrap {
    domains: { [key: string]: PlayerTemplateTrap_Domin };
}

export interface OpenServerChainLogin {
    isAvailable: boolean;
    nowIndex: number;
    history: boolean[];
}

export interface OpenServerCheckIn {
    isAvailable: boolean;
    history: boolean[];
}

export interface PlayerDungeon {
    stages: { [key: string]: PlayerStage };
    zones: { [key: string]: PlayerZone };
    cowLevel: { [key: string]: PlayerSpecialStage };
    hideStages: { [key: string]: PlayerHiddenStage };
    mainlineBannedStages: string[];
    sixStar: PlayerSixStar;
}

export interface PlayerSixStar {
    stages: { [key: string]: PlayerSixStarStage };
    groups: { [key: string]: PlayerSixStarMilestone };
}

export interface PlayerSixStarStage {
    tagFinish: PlayerSixStarTagFinishState;
    tagSelected: string[];
}

export interface PlayerSixStarMilestone {
    point: number;
    rewards: { [key: string]: PlayerSixStarMilestoneItem };
}

export interface PlayerSixStarMilestoneItem {
    state: PlayerSixStarMilestoneState;
}

export interface PlayerHiddenStage {
    missions: MissionCalcState[];
    unlock: number;
}

export interface PlayerSpecialStage {
    id: string;
    unlockTs: number;
    rewardTs: number;
    type: string;
    val: number;
    fts: number;
    rts: number;
}

export interface PlayerZone {
    completeTimes: number;
}

export interface PlayerStage {
    stageId: string;
    completeTimes: number;
    state: PlayerStageState;
    hasBattleReplay: boolean;
    noCostCnt: number;
    startTimes: number;
    practiceTimes: number;
}

export interface PlayerAutoChessPerm {
    band: { [key: string]: number };
    trainingModeFin: { [key: string]: number };
}

export interface PlayerCampaign_StageOpenInfo {
    permanent: string[];
    training: string[];
    rotate: string;
    rGroup: string;
    tGroup: string;
    tAllOpen: string;
}

export interface PlayerCampaign_Stage {
    maxKills: number;
    rewardStatus: number[];
}

export interface PlayerCampaign {
    campaignCurrentFee: number;
    campaignTotalFee: number;
    activeGroupId: string;
    open: PlayerCampaign_StageOpenInfo;
    missions: { [key: string]: PlayerCampaign_MissionState };
    instances: { [key: string]: PlayerCampaign_Stage };
    sweepMaxKills: { [key: string]: number };
    lastRefreshTs: number;
}

export interface PlayerRecruit_NormalModel_SlotModel {
    state: PlayerRecruit_NormalModel_SlotModel_State;
    startTs: string;
    maxFinishTs: string;
    realFinishTs: string;
    durationInSec: number;
    tags: number[];
    selectTags: number[];
}

export interface PlayerRecruit_NormalModel {
    slots: { [key: string]: PlayerRecruit_NormalModel_SlotModel };
}

export interface PlayerRecruit {
    normal: PlayerRecruit_NormalModel;
}

export interface PlayerGacha_PlayerNewbeeGachaPool {
    openFlag: boolean;
    cnt: number;
    poolId: string;
}

export interface PlayerGacha_PlayerGachaPool {
    cnt: number;
    maxCnt: number;
    avail: boolean;
    rarity: number;
}

export interface PlayerGacha_PlayerFreeLimitGacha {
    leastFree: number;
    poolCnt: number;
    recruitedFreeChar: boolean;
}

export interface PlayerGacha_PlayerAttainGacha {
    attain6Count: number;
}

export interface PlayerGacha_PlayerSingleGacha {
    cnt: number;
    maxCnt: number;
    avail: boolean;
    singleEnsureCnt: number;
    singleEnsureUse: boolean;
    singleEnsureChar: string;
}

export interface PlayerGacha_PlayerDoubleGacha {
    showCnt: number;
    hitCharState: PlayerGacha_PlayerDoubleGacha_HitCharState;
    hitCharId: string;
}

export interface PlayerGacha_PlayerFesClassicGacha {
    upChar: { [key: number]: string[] };
}

export interface PlayerGacha_PlayerSpecialGacha {
    upChar: { [key: number]: string[] };
}

export interface PlayerGacha_PlayerReturnGacha {
    upChar: { [key: number]: string[] };
}

export interface PlayerGacha {
    newbee: PlayerGacha_PlayerNewbeeGachaPool;
    normal: { [key: string]: PlayerGacha_PlayerGachaPool };
    limit: { [key: string]: PlayerGacha_PlayerFreeLimitGacha };
    linkage: { [key: string]: { [key: string]: object } };
    attain: { [key: string]: PlayerGacha_PlayerAttainGacha };
    single: { [key: string]: PlayerGacha_PlayerSingleGacha };
    doubleGacha: { [key: string]: PlayerGacha_PlayerDoubleGacha };
    fesClassic: { [key: string]: PlayerGacha_PlayerFesClassicGacha };
    special: { [key: string]: PlayerGacha_PlayerSpecialGacha };
    backflow: { [key: string]: PlayerGacha_PlayerReturnGacha };
    double: object;
}

export interface PlayerMedalBoard {
    type: NameCardMedalType;
    custom: string;
    template: string;
    templateMedalList: object[];
}

export interface PlayerSocialReward {
    canReceive: boolean;
    first: number;
    assistAmount: number;
    comfortAmount: number;
}

export interface PlayerSocial {
    yCrisisSs: string;
    yCrisisV2Ss: string;
    assistCharList: PlayerFriendAssist[];
    yesterdayReward: PlayerSocialReward;
    medalBoard: PlayerMedalBoard;
    starFriendFlag: number;
}

export interface PlayerTroop {
    troopCapacity: number;
    curSquadCount: number;
    curCharInstId: number;
    squads: { [key: string]: PlayerSquad };
    chars: { [key: string]: PlayerCharacter };
    addon: { [key: string]: PlayerHandBookAddon };
    charMission: { [key: string]: { [key: string]: PlayerTroop_CharMissionState } };
    spOperator: { [key: string]: { [key: string]: { [key: string]: PlayerSpecialOperatorNode } } };
    charGroup: { [key: string]: object };
}

export interface PlayerGoodItemData {
    id: string;
    count: number;
}

export interface PlayerGoodProgressData {
    count: number;
    order: number;
}

export interface PlayerCommonShopProgressData {
    curShopId: string;
    info: PlayerGoodItemData[];
}

export interface PlayerLowQCShopProgressData {
    curGroupId: string;
    lggCostTotal: number;
}

export interface PlayerHighQCShopProgressData {
    info: PlayerGoodItemData[];
    progressInfo: { [key: string]: PlayerGoodProgressData };
}

export interface PlayerClassicQCShopProgressData {
    info: PlayerGoodItemData[];
    progressInfo: { [key: string]: PlayerGoodProgressData };
}

export interface PlayerLMTGSProgressData {
    info: PlayerGoodItemData[];
}

export interface PlayerEPGSProgressData {
    info: PlayerGoodItemData[];
}

export interface PlayerCashProgressData {
    info: PlayerGoodItemData[];
}

export interface PlayerGiftProgressPerData {
    info: PlayerGoodItemData[];
    valid: string[];
}

export interface PlayerSocialShopData {
    info: PlayerGoodItemData[];
}

export interface PlayerFurnitureShopData {
    info: PlayerGoodItemData[];
    groupInfo: { [key: string]: number };
}

export interface PlayerSkinShopData {
    info: PlayerGoodItemData[];
    gachaGood: PlayerBlindboxData;
}

export interface PlayerBlindboxData {
    info: PlayerGoodItemData[];
}

export interface PlayerGiftProgressData {
    oneTime: PlayerGiftProgressPerData;
    level: PlayerGiftProgressPerData;
    weekly: PlayerGiftProgressPerData;
    monthly: PlayerGiftProgressPerData;
    choose: PlayerGiftProgressPerData;
    conditionChoose: PlayerGiftProgressPerData;
}

export interface PlayerTemplateShop {
    coin: number;
    info: PlayerGoodItemData[];
    progressInfo: { [key: string]: PlayerGoodProgressData };
}

export type PlayerShop = { LS: PlayerLowQCShopProgressData; HS: PlayerHighQCShopProgressData; ES: PlayerCommonShopProgressData; CASH: PlayerCashProgressData; GP: PlayerGiftProgressData; FURNI: PlayerFurnitureShopData; SOCIAL: PlayerSocialShopData; EPGS: PlayerEPGSProgressData; REP: PlayerEPGSProgressData; CLASSIC: PlayerClassicQCShopProgressData; SKIN: PlayerSkinShopData };

export interface PlayerInviteInfo {
    uid: string;
    idx: number;
    ts: number;
    msg: string[];
}

export interface PlayerInviteData {
    closeAccept: boolean;
    newInvite: boolean;
    inviteList: PlayerInviteInfo[];
}

export interface PlayerConsumableItem {
    ts: number;
    count: number;
}

export interface PlayerTicketItem {
    ts: number;
    count: number;
}

export interface PlayerPushFlags {
    hasGifts: boolean;
    hasFriendRequest: boolean;
    hasClues: boolean;
    hasFreeLevelGP: boolean;
    status: number;
}

export interface PlayerEvents {
    building: string;
    status: number;
}

export interface PlayerBuildingLabor {
    buffSpeed: number;
    value: number;
    maxValue: number;
    lastUpdateTime: string;
    processPoint: number;
}

export interface PlayerBuildingWorkshopStatus {
    bonus: { [key: string]: number[] };
    bonusActive: number;
}

export interface PlayerBuildingStatus {
    labor: PlayerBuildingLabor;
    workshop: PlayerBuildingWorkshopStatus;
}

export interface PlayerBuildingCharBubble {
    add: number;
    ts: number;
}

export interface PlayerBuildingChar_BubbleContainer {
    normal: PlayerBuildingCharBubble;
    assist: PlayerBuildingCharBubble;
    privateBubble: PlayerBuildingCharBubble;
    private: object;
}

export interface PlayerBuildingChar {
    charId: string;
    lastApAddTime: string;
    ap: number;
    roomSlotId: string;
    index: number;
    changeScale: number;
    bubble: PlayerBuildingChar_BubbleContainer;
    skinIdInVisit: string;
    workTime: number;
    privateRooms: string[];
}

export interface PlayerBuildingRoomSlot {
    level: number;
    state: PlayerRoomSlotState;
    roomId: BuildingData_RoomType;
    completeConstructTime: string;
    charInstIds: number[];
}

export interface PlayerBuildingFurnitureInfo {
    count: number;
    inUse: number;
}

export interface PlayerEnemyHandBook {
    enemies: { [key: string]: number };
    stage: { [key: string]: string[] };
}

export interface PlayerFormulaUnlockRecord {
    manufacture: { [key: string]: number };
    workshop: { [key: string]: number };
    shop: object;
}

export interface PlayerDexNav {
    enemy: PlayerEnemyHandBook;
    formula: PlayerFormulaUnlockRecord;
    character: object;
    teamV2: object;
}

export interface PlayerSkins {
    characterSkins: { [key: string]: number };
    skinTs: { [key: string]: number };
    skinSp: { [key: string]: boolean };
}

export interface PlayerPerMedal {
    id: string;
    fts: number;
    rts: number;
    reward: string;
    val: number;
}

export interface PlayerMedalCustomLayoutItem {
    id: string;
}

export interface PlayerMedalCustomLayout {
    layout: PlayerMedalCustomLayoutItem[];
}

export interface PlayerMedalCustom {
    currentIndex: string;
    customs: { [key: string]: PlayerMedalCustomLayout };
}

export interface PlayerMedal {
    medals: { [key: string]: PlayerPerMedal };
    custom: PlayerMedalCustom;
}

export interface PlayerRetro {
    coin: number;
    supplement: boolean;
    block: { [key: string]: PlayerRetroBlock };
    trail: { [key: string]: { [key: string]: boolean } };
    rewardPerm: string[];
    lst: number;
    nst: number;
}

export interface PlayerRetroBlock {
    locked: boolean;
    open: boolean;
}

export interface PlayerAvatar {
    playerAvatarIcons: { [key: string]: PlayerAvatarBlock };
    avatar_icon: { [key: string]: object };
}

export interface PlayerAvatarBlock {
    ts: number;
    src: string;
}

export interface PlayerCollection {
    team: { [key: string]: number };
}

export interface PlayerEquipment {
    missions: { [key: string]: PlayerEquipMission };
}

export interface PlayerEquipMission {
    value: number;
    target: number;
}

export interface PlayerBuildingManufactureBuff {
    speed: number;
    capacity: number;
}

export interface PlayerBuildingManufacture {
    buff: PlayerBuildingManufactureBuff;
    state: PlayerRoomState;
    formulaId: string;
    remainSolutionCnt: number;
    outputSolutionCnt: number;
    lastUpdateTime: string;
    processPoint: number;
    saveTime: number;
    completeWorkTime: string;
    capacity: number;
    apCost: number;
    display: BuildingBuffDisplay;
    presetQueue: number[][];
}

export interface BuildingBuffDisplay {
    baseBuff: number;
    buff: number;
    base: number;
}

export interface PlayerBuildingShopOutputItem {
    type: ItemType;
    count: number;
}

export interface PlayerBuildingShop {
    outputItem: PlayerBuildingShopOutputItem[];
}

export interface PlayerBuildingPowerBuff {
    laborSpeed: number;
    apCost: object;
    global: object;
    manufacture: object;
}

export interface PlayerBuildingPower {
    buff: PlayerBuildingPowerBuff;
    presetQueue: number[][];
}

export interface PlayerBuildingControlBuff_Global {
    apCost: number;
    roomCnt: number;
}

export interface PlayerBuildingControlBuff {
    global: PlayerBuildingControlBuff_Global;
    manufacture: object;
    trading: object;
    meeting: object;
    apCost: object;
    point: object;
    hire: object;
    power: object;
    dormitory: object;
    training: object;
}

export interface PlayerBuildingControl {
    buff: PlayerBuildingControlBuff;
    apCost: number;
    presetQueue: number[][];
    lastUpdateTime: number;
}

export interface PlayerBuildingWorkshopBuff_Cost {
    type: string;
    limit: number;
    reduction: number;
}

export interface PlayerBuildingWorkshopBuff_CostRe {
    type: string;
    from: number;
    change: number;
}

export interface PlayerBuildingWorkshopBuff_CostFormula {
    formulaIds: string[];
    reduction: number;
}

export interface PlayerBuildingWorkshopBuff_CostForce {
    type: string;
    cost: number;
}

export interface PlayerBuildingWorkshopBuff_CostDevide {
    type: string;
    limit: number;
    denominator: number;
}

export interface PlayerBuildingWorkshopBuff_Frate {
    fid: string;
    rate: number;
}

export interface PlayerBuildingWorkshopBuff {
    rate: { [key: string]: number };
    apRate: { [key: string]: { [key: string]: number } };
    frate: PlayerBuildingWorkshopBuff_Frate[];
    goldFree: { [key: string]: number };
    cost: PlayerBuildingWorkshopBuff_Cost;
    costRe: PlayerBuildingWorkshopBuff_CostRe;
    costFormula: PlayerBuildingWorkshopBuff_CostFormula;
    costForce: PlayerBuildingWorkshopBuff_CostForce;
    costDevide: PlayerBuildingWorkshopBuff_CostDevide;
    recovery: object;
    fFix: object;
    activeBonus: object;
}

export interface PlayerBuildingWorkshop {
    buff: PlayerBuildingWorkshopBuff;
    statistic: object;
}

export interface PlayerBuildingMeetingClueChar {
    charId: string;
    level: number;
    evolvePhase: number;
    skin: string;
}

export interface PlayerBuildingMeetingClue {
    id: string;
    type: string;
    number: number;
    uid: number;
    nickNum: string;
    name: string;
    chars: PlayerBuildingMeetingClueChar[];
    inUse: number;
    ts: number;
}

export interface PlayerBuildingMeetingSocialReward {
    daily: boolean;
    search: boolean;
}

export interface PlayerBuildingMeetingInfoShareState {
    ts: number;
    reward: number;
}

export interface PlayerBuildingMeetingBuff {
    speed: number;
    weight: object;
    flag: object;
    apCost: object;
    notOwned: object;
    owned: object;
}

export interface PlayerBuildingMessageLeaveSP {
    lastWeek: number;
    lastWeekSum: number;
    thisWeek: number;
    thisWeekSum: number;
}

export interface PlayerBuildingMessageLeave {
    inUse: boolean;
    lastVisitTs: number;
    lastShowTs: number;
    lastUpdateSpTs: number;
    sp: PlayerBuildingMessageLeaveSP;
}

export interface PlayerBuildingMeeting {
    visitedUser: string[];
    buff: PlayerBuildingMeetingBuff;
    state: number;
    processPoint: number;
    speed: number;
    ownStock: PlayerBuildingMeetingClue[];
    receiveStock: PlayerBuildingMeetingClue[];
    board: { [key: string]: string };
    socialReward: PlayerBuildingMeetingSocialReward;
    received: number;
    infoShare: PlayerBuildingMeetingInfoShareState;
    lastUpdateTime: string;
    dailyReward: PlayerBuildingMeetingClue;
    presetQueue: number[][];
    messageLeave: PlayerBuildingMessageLeave;
    diySolution: PlayerBuildingDIYSolution;
    expiredReward: number;
    mfc: number;
    completeWorkTime: number;
    startApCounter: number;
    mustgetClue: number;
}

export interface PlayerBuildingHireBuff {
    speed: number;
    meeting: object;
    stack: object;
    point: object;
    apCost: object;
}

export interface PlayerBuildingHire {
    buff: PlayerBuildingHireBuff;
    recruitSlotId: number;
    state: PlayerBuildingHiringState;
    processPoint: number;
    speed: number;
    lastUpdateTime: string;
    refreshCount: number;
    completeWorkTime: string;
    presetQueue: number[][];
}

export interface PlayerBuildingTradingOrder_TradingGoldTag {
    activated: boolean;
    from: string;
}

export interface PlayerBuildingTradingOrder {
    instId: number;
    type: BuildingData_OrderType;
    gain: ItemBundle;
    extraCost: boolean;
    specGoldTag: PlayerBuildingTradingOrder_TradingGoldTag;
    delivery: object;
    buff: object;
}

export interface PlayerBuildingTradingBuff {
    speed: number;
    limit: number;
    apCost: object;
    rate: object;
    tgw: object[];
    point: object;
    manuLines: object;
    orderBuff: object[];
    violatedInfo: object;
    orderWtBuff: object[];
    speGoldOrder: object;
}

export interface PlayerBuildingTradingNext {
    order: number;
    processPoint: number;
    speed: number;
    maxPoint: number;
}

export interface PlayerBuildingTrading {
    buff: PlayerBuildingTradingBuff;
    state: PlayerRoomState;
    lastUpdateTime: string;
    strategy: BuildingData_OrderType;
    stockLimit: number;
    apCost: number;
    stock: PlayerBuildingTradingOrder[];
    next: PlayerBuildingTradingNext;
    display: BuildingBuffDisplay;
    presetQueue: number[][];
    completeWorkTime: number;
}

export interface PlayerBuildingGridPosition {
    x: number;
    y: number;
    dir: number;
}

export interface PlayerBuildingFurniturePositionInfo {
    id: string;
    coordinate: PlayerBuildingGridPosition;
}

export interface PlayerBuildingDIYSolution {
    wallPaper: string;
    floor: string;
    carpet: PlayerBuildingFurniturePositionInfo[];
    other: PlayerBuildingFurniturePositionInfo[];
}

export interface PlayerBuildingDIYPreset {
    name: string;
    roomType: string;
    solution: PlayerBuildingDIYSolution;
    thumbnail: string;
}

export interface PlayerBuildingDormitory_Buff_APCost_SingleTarget {
    target: string;
    value: number;
}

export interface PlayerBuildingDormitory_Buff_APCost {
    all: number;
    single: PlayerBuildingDormitory_Buff_APCost_SingleTarget;
}

export interface PlayerBuildingDormitory_Buff {
    apCost: PlayerBuildingDormitory_Buff_APCost;
}

export interface PlayerBuildingDormitory {
    buff: PlayerBuildingDormitory_Buff;
    comfort: number;
    diySolution: PlayerBuildingDIYSolution;
}

export interface PlayerBuildingPrivate {
    comfort: number;
    diySolution: PlayerBuildingDIYSolution;
}

export interface PlayerBuildingTrainer {
    state: PlayerBuildingTrainerState;
    charInstId: number;
}

export interface PlayerBuildingTrainee {
    state: PlayerBuildingTraineeState;
    charInstId: number;
    processPoint: number;
    speed: number;
    targetSkill: number;
}

export interface PlayerBuildingTrainingReduceTimeBd {
    activated: boolean;
    cnt: number;
    fulltime: object;
    reset: object;
}

export interface PlayerBuildingTrainingBuff {
    speed: number;
    reduceTimeBd: PlayerBuildingTrainingReduceTimeBd;
    lvEx: object;
    lvCost: object;
    reduce: object;
    apCost: object;
}

export interface PlayerBuildingTraining {
    buff: PlayerBuildingTrainingBuff;
    lastUpdateTime: string;
    trainer: PlayerBuildingTrainer;
    trainee: PlayerBuildingTrainee;
    completeWorkTime: string;
    state: number;
}

export interface PlayerBuildingRoom {
    manufact: { [key: string]: PlayerBuildingManufacture };
    shop: { [key: string]: PlayerBuildingShop };
    power: { [key: string]: PlayerBuildingPower };
    control: { [key: string]: PlayerBuildingControl };
    meeting: { [key: string]: PlayerBuildingMeeting };
    hire: { [key: string]: PlayerBuildingHire };
    dorm: { [key: string]: PlayerBuildingDormitory };
    privateDorm: { [key: string]: PlayerBuildingPrivate };
    training: { [key: string]: PlayerBuildingTraining };
    workshop: { [key: string]: PlayerBuildingWorkshop };
    trading: { [key: string]: PlayerBuildingTrading };
}

export interface BuildingMusic {
    inUse: boolean;
    selected: string;
    state: { [key: string]: BuildingMusicState };
}

export interface BuildingMusicState {
    unlock: boolean;
    progress: number;
}

export interface PlayerBuilding_PlayerBuildingSolution {
    furnitureTs: { [key: string]: number };
}

export interface PlayerBuilding {
    status: PlayerBuildingStatus;
    chars: { [key: string]: PlayerBuildingChar };
    assist: number[];
    roomSlots: { [key: string]: PlayerBuildingRoomSlot };
    rooms: { [roomType: string]: { [slotId: string]: object } };
    furniture: { [key: string]: PlayerBuildingFurnitureInfo };
    diyPresetSolutions: { [key: string]: PlayerBuildingDIYPreset };
    solution: PlayerBuilding_PlayerBuildingSolution;
    music: BuildingMusic;
}

export interface MissionCalcState {
    target: number;
    value: number;
    compare: string;
}

export interface MissionDailyRewards {
    dailyPoint: number;
    weeklyPoint: number;
    rewards: { [key: string]: { [key: string]: number } };
}

export interface MissionPlayerDataGroup {}

export interface MissionPlayerData {
    missions: MissionPlayerDataGroup;
    missionRewards: MissionDailyRewards;
    missionGroups: { [key: string]: MissionPlayerData_MissionGroupState };
    pinnedSpecialOperator: string;
}

export interface PlayerCrisisShop {
    coin: number;
    info: PlayerGoodItemData[];
    progressInfo: { [key: string]: PlayerGoodProgressData };
}

export interface PlayerCrisisSeason {
    coin: number;
    tCoin: number;
    permanent: object;
    temporary: object;
    sInfo: object;
}

export interface PlayerCrisisSocialInfo_AssistChar {
    charId: string;
    cnt: number;
}

export interface PlayerCrisisSocialInfo {
    assistCnt: number;
    maxPnt: number;
    chars: PlayerCrisisSocialInfo_AssistChar[];
}

export interface PlayerCrisis {
    current: string;
    shop: PlayerCrisisShop;
    season: { [key: string]: PlayerCrisisSeason };
    lst: number;
    nst: number;
    map: object;
    training: object;
    box: object;
}

export interface PlayerCrisisV2Season_RewardInfo {
    state: PlayerCrisisV2Season_NodeState;
    progress: number;
}

export interface PlayerCrisisV2Season_PermanentMapInfo {
    scoreSingle: number[];
    comment: string[];
    exRunes: { [key: string]: PlayerCrisisV2Season_RuneState };
    runePack: { [key: string]: PlayerCrisisV2Season_BagState };
    reward: { [key: string]: PlayerCrisisV2Season_RewardInfo };
    state: number;
    scoreTotal: number;
    rune: object;
    challenge: object;
}

export interface PlayerCrisisV2Season_BasicMapInfo {
    state: boolean;
    scoreTotal: number[];
    rune: { [key: string]: PlayerCrisisV2Season_RuneState };
    challenge: { [key: string]: PlayerCrisisV2Season_NodeState };
}

export interface PlayerCrisisV2Season {
    coin: number;
    permanent: PlayerCrisisV2Season_PermanentMapInfo;
    temporary: { [key: string]: PlayerCrisisV2Season_BasicMapInfo };
    social: PlayerCrisisSocialInfo;
}

export interface PlayerCrisisV2 {
    currentSeason: string;
    seasons: { [key: string]: PlayerCrisisV2Season };
    shop: PlayerCrisisShop;
    newRecordTs: number;
    nextRefreshTs: number;
    current: string;
    nst: number;
}

export interface PlayerRecalRune {
    seasons: { [key: string]: PlayerRecalRuneSeason };
}

export interface PlayerRecalRuneSeason {
    stage: { [key: string]: PlayerRecalRuneStage };
    reward: PlayerRecalRuneReward;
}

export interface PlayerRecalRuneStage {
    state: PlayerRecalRuneStage_State;
    record: number;
    passedRunes: string[];
    runes: object;
}

export interface PlayerRecalRuneReward {
    junior: PlayerRecalRuneReward_State;
    senior: PlayerRecalRuneReward_State;
}

export interface PlayerStoryReview {
    groups: { [key: string]: PlayerStoryReviewUnlockInfo };
    tags: { [key: string]: number };
}

export interface PlayerStoryReviewUnlockInfo {
    rts: number;
    stories: StoryReviewUnlockInfo[];
    trailRewards: string[];
}

export interface StoryReviewUnlockInfo {
    id: string;
    uts: number;
    rc: number;
}

export interface PlayerPerformanceStory {
    unlock: { [key: string]: number };
}

export interface PlayerRoguelikeInitialReward {
    relic: RoguelikeReward;
    scene: PlayerRoguelikePendingEvent_SceneContent;
    recruit: RoguelikeReward;
}

export interface PlayerRoguelikeCursor {
    zoneIndex: number;
    position: RoguelikeNodePosition;
    state: PlayerRoguelikeState;
}

export interface PlayerRoguelikeStatus {
    uuid: string;
    level: number;
    exp: number;
    hp: number;
    gold: number;
    squadCapacity: number;
    populationCost: number;
    populationMax: number;
    cursor: PlayerRoguelikeCursor;
    perfectWinStreak: number;
    mode: string;
    ending: string;
    showBattleCharInstId: number;
    startTime: number;
    endTime: number;
}

export interface PlayerRoguelikeItem {
    instId: string;
    id: string;
    count: number;
    ts: number;
    recruit: RoguelikeRecruitUpgradeCharacter[];
    upgrade: RoguelikeRecruitUpgradeCharacter[];
}

export interface PlayerRoguelikeCharacter {
    upgradePhase: number;
    upgradeLimited: boolean;
    isAddition: number;
    isElite: number;
    isFree: number;
}

export interface PlayerNodeDetailContent_BattleShop {
    hasShopBoss: boolean;
    goods: string[];
}

export interface PlayerNodeDetailContent {
    scene: string;
    battleShop: PlayerNodeDetailContent_BattleShop;
    wish: string[];
    battle: string[];
    hasShopBoss: boolean;
}

export interface PlayerNodeRollInfo {
    count: number;
    cost: number;
}

export interface PlayerRoguelikeNode {
    pos: RoguelikeNodePosition;
    next: RoguelikeNodeLine[];
    type: RoguelikeEventType;
    nodeDisplaySubType: number;
    fts: number;
    realContent: PlayerNodeDetailContent;
    attach: string[];
    shop: RoguelikeShop;
    scenes: PlayerRoguelikePendingEvent_SceneContent[];
    stage: string;
    visibility: PlayerNodeForesightType;
    refresh: PlayerNodeRollInfo;
}

export interface PlayerRoguelikeZone {
    zoneId: string;
    nodes: { [key: number]: PlayerRoguelikeNode };
}

export interface PlayerRoguelikeDungeon {
    zones: { [key: number]: PlayerRoguelikeZone };
}

export interface PlayerRoguelikeRecord {
    passedZone: number;
    moveTimes: number;
    battleNormalTimes: number;
    battleEliteTimes: number;
    battleBossTimes: number;
    holdRelicCount: number;
    recruitChars: number;
    initialRelic: string;
    totalSeconds: number;
    ending: string;
    isDead: boolean;
    totalScore: number;
    unlockRelic: string[];
    unlockMode: string[];
}

export interface PlayerRoguelike_CurrentData {
    status: PlayerRoguelikeStatus;
    initialRewards: PlayerRoguelikeInitialReward;
    map: PlayerRoguelikeDungeon;
    inventory: { [key: string]: PlayerRoguelikeItem };
    chars: { [key: string]: PlayerRoguelikeCharacter };
    record: PlayerRoguelikeRecord;
}

export interface PlayerRoguelike_StableData_RelicRecord {
    uts: number;
    cnt: number;
}

export interface PlayerRoguelike_StableData_StageRecord {
    count: number;
}

export interface PlayerRoguelike_StableData_EndingRecord {
    cnt: number;
    initialRelic: { [key: string]: number };
}

export interface PlayerRoguelike_StableData_ModeRecord {
    uts: number;
    cnt: number;
}

export interface PlayerRoguelike_StableData_StatsRecords {
    complete_battle: number;
    cost_hp: number;
    recruit_char: number;
    into_node_nobattle: number;
    shop_cost_gold: number;
    upgrade_char: number;
    enemy_kill: { [key: string]: number };
    gain_resource: { [key: string]: number };
    scene_count: { [key: string]: number };
    choice_count: { [key: string]: number };
}

export interface PlayerRoguelike_StableData {
    outBuff: { [key: string]: number };
    relic: { [key: string]: PlayerRoguelike_StableData_RelicRecord };
    stages: { [key: string]: PlayerRoguelike_StableData_StageRecord };
    ending: { [key: string]: PlayerRoguelike_StableData_EndingRecord };
    mode: { [key: string]: PlayerRoguelike_StableData_ModeRecord };
    stats: PlayerRoguelike_StableData_StatsRecords;
}

export interface PlayerRoguelike {
    current: PlayerRoguelike_CurrentData;
    stable: PlayerRoguelike_StableData;
}

export interface PlayerRoguelikeV2_CurrentData_PlayerStatus_Properties_Hp {
    current: number;
    max: number;
}

export interface PlayerRoguelikeV2_CurrentData_PlayerStatus_Properties_Population {
    cost: number;
    max: number;
}

export interface PlayerRoguelikeV2_CurrentData_PlayerStatus_Properties {
    exp: number;
    level: number;
    maxLevel: number;
    hp: PlayerRoguelikeV2_CurrentData_PlayerStatus_Properties_Hp;
    shield: number;
    gold: number;
    capacity: number;
    population: PlayerRoguelikeV2_CurrentData_PlayerStatus_Properties_Population;
    conPerfectBattle: number;
}

export interface PlayerRoguelikeV2_CurrentData_PlayerStatus_NodePosition {
    zone: number;
    position: RoguelikeNodePosition;
}

export interface PlayerRoguelikeV2_CurrentData_PlayerStatus_Status {
    bankPut: number;
}

export interface PlayerRoguelikeV2_CurrentData_PlayerStatus_InnerMission {
    tmpl: string;
    id: string;
}

export interface PlayerRoguelikeV2_CurrentData_PlayerStatus_NodeMission {
    id: string;
    state: PlayerRoguelikeV2_CurrentData_PlayerStatus_NodeMission_NodeMissionState;
    tip: boolean;
}

export interface PlayerRoguelikeV2_CurrentData_PlayerStatus_ZoneRewardItem {
    id: string;
    count: number;
    instId: string;
}

export interface PlayerRoguelikeV2_CurrentData_PlayerStatus {
    state: PlayerRoguelikePlayerState;
    property: PlayerRoguelikeV2_CurrentData_PlayerStatus_Properties;
    cursor: PlayerRoguelikeV2_CurrentData_PlayerStatus_NodePosition;
    pending: PlayerRoguelikePendingEvent[];
    trace: PlayerRoguelikeV2_CurrentData_PlayerStatus_NodePosition[];
    status: PlayerRoguelikeV2_CurrentData_PlayerStatus_Status;
    toEnding: string;
    chgEnding: boolean;
    innerMission: PlayerRoguelikeV2_CurrentData_PlayerStatus_InnerMission[];
    nodeMission: PlayerRoguelikeV2_CurrentData_PlayerStatus_NodeMission;
    zoneReward: { [key: string]: PlayerRoguelikeV2_CurrentData_PlayerStatus_ZoneRewardItem[] };
    traderReturn: { [key: string]: PlayerRoguelikeV2_CurrentData_PlayerStatus_ZoneRewardItem[] };
}

export interface PlayerRoguelikeV2_CurrentData_Char {
    upgradePhase: number;
    upgradeLimited: boolean;
    type: RoguelikeCharState;
    charBuff: string[];
}

export interface PlayerRoguelikeV2_CurrentData_RecruitChar {
    type: RoguelikeCharState;
    upgradePhase: number;
    upgradeLimited: boolean;
    population: number;
    isUpgrade: boolean;
    troopInstId: number;
    charBuff: string[];
}

export interface PlayerRoguelikeV2_CurrentData_ExpeditionReturn_Char {
    instId: string;
    isUpgrade: boolean;
    isCure: boolean;
    isCandle: boolean;
}

export interface PlayerRoguelikeV2_CurrentData_ExpeditionReturn {
    charList: PlayerRoguelikeV2_CurrentData_ExpeditionReturn_Char[];
}

export interface PlayerRoguelikeV2_CurrentData_Troop {
    chars: { [key: string]: PlayerRoguelikeV2_CurrentData_Char };
    expedition: string[];
    expeditionDetails: { [key: string]: PlayerRoguelikeV2_CurrentData_Troop_ExpedType };
    expeditionReturn: PlayerRoguelikeV2_CurrentData_ExpeditionReturn;
    hasExpeditionReturn: boolean;
}

export interface PlayerRoguelikeV2_CurrentData_Relic {
    index: string;
    id: string;
    count: number;
    layer: number;
    ts: number;
    used: boolean;
}

export interface PlayerRoguelikeV2_CurrentData_Trap {
    id: string;
    ts: number;
}

export interface PlayerRoguelikeV2_CurrentData_ExploreTool {
    id: string;
    ts: number;
}

export interface PlayerRoguelikeV2_CurrentData_Recruit_OrigChar {
    assistSlotIndex: number;
    aliasName: string;
    isFriend: boolean;
    canRequestFriend: boolean;
    isStarFriend: boolean;
}

export interface PlayerRoguelikeV2_CurrentData_Recruit_FriendAssistData {
    orig: PlayerRoguelikeV2_CurrentData_Recruit_OrigChar;
    recruit: PlayerRoguelikeV2_CurrentData_RecruitChar;
}

export interface PlayerRoguelikeV2_CurrentData_Recruit {
    index: string;
    id: string;
    state: PlayerRoguelikeV2_CurrentData_Recruit_State;
    result: PlayerRoguelikeV2_CurrentData_RecruitChar;
    ts: number;
    needAssist: boolean;
    assistList: { [key: string]: PlayerRoguelikeV2_CurrentData_Recruit_FriendAssistData[] };
    starFriendAssistList: { [key: string]: PlayerRoguelikeV2_CurrentData_Recruit_FriendAssistData[] };
}

export interface PlayerRoguelikeV2_CurrentData_Inventory {
    relic: { [key: string]: PlayerRoguelikeV2_CurrentData_Relic };
    recruit: { [key: string]: PlayerRoguelikeV2_CurrentData_Recruit };
    stashedRecruit: string[];
    stashedRecruitLimit: number;
    trap: PlayerRoguelikeV2_CurrentData_Trap;
    exploreTool: { [key: string]: PlayerRoguelikeV2_CurrentData_ExploreTool };
    consumable: { [key: string]: number };
}

export interface PlayerRoguelikeV2_CurrentData_Buff {
    tmpHP: number;
    capsule: PlayerRoguelikeV2_CurrentData_Capsule;
    squadBuff: string[];
}

export interface PlayerRoguelikeV2_CurrentData_Capsule {
    id: string;
    ts: number;
    active: boolean;
}

export interface PlayerRoguelikeV2_CurrentData_Game_OuterBuff {}

export interface PlayerRoguelikeV2_CurrentData_Game {
    uid: string;
    theme: string;
    mode: RoguelikeTopicMode;
    modeGrade: number;
    equivalentGrade: number;
    predefined: string;
    difficult: number;
    outerBuff: PlayerRoguelikeV2_CurrentData_Game_OuterBuff;
    start: number;
    activity: string;
}

export interface PlayerRoguelikeV2_CurrentData_Module_San {
    sanity: number;
}

export interface PlayerRoguelikeV2_CurrentData_Module_Dice {
    id: string;
    count: number;
}

export interface PlayerRoguelikeV2_CurrentData_Module_InventoryTotem {
    id: string;
    instId: string;
    used: boolean;
    affix: string;
    ts: number;
}

export interface PlayerRoguelikeV2_CurrentData_Module_Totem {
    totemPiece: PlayerRoguelikeV2_CurrentData_Module_InventoryTotem[];
    predictTotemId: string;
}

export interface PlayerRoguelikeV2_CurrentData_Module_Vision {
    value: number;
    isMax: boolean;
}

export interface PlayerRoguelikeV2_CurrentData_Module_ChaosZoneDelta {
    dValue: number;
    preLevel: number;
    afterLevel: number;
    dChaos: string[];
}

export interface PlayerRoguelikeV2_CurrentData_Module_Chaos {
    value: number;
    level: number;
    curMaxValue: number;
    chaosList: string[];
    predict: string;
    deltaChaos: PlayerRoguelikeV2_CurrentData_Module_ChaosZoneDelta;
    lastBattleGain: number;
}

export interface PlayerRoguelikeV2_CurrentData_Module_Fragment {
    totalWeight: number;
    limitWeight: number;
    overWeight: number;
    fragments: { [key: string]: PlayerRoguelikeV2_CurrentData_Module_InventoryFragment };
    troopWeights: { [key: number]: number };
    troopCarry: number[];
    sellCount: number;
    currInspiration: PlayerRoguelikeV2_CurrentData_Module_InventoryInspiration;
}

export interface PlayerRoguelikeV2_CurrentData_Module_InventoryFragment {
    id: string;
    index: string;
    used: boolean;
    ts: number;
    weight: number;
    value: number;
    price: number;
}

export interface PlayerRoguelikeV2_CurrentData_Module_InventoryInspiration {
    instId: string;
    id: string;
}

export interface PlayerRoguelikeV2_CurrentData_Module_Disaster {
    curDisasterId: string;
    disperseStep: number;
}

export interface PlayerRoguelikeV2_CurrentData_Module_NodeUpgrade {
    nodeTypeInfoMap: { [key: string]: PlayerRoguelikeV2_CurrentData_Module_NodeUpgradeInfo };
}

export interface PlayerRoguelikeV2_CurrentData_Module_NodeUpgradeInfo {
    tempUpgrade: string;
    upgradeList: string[];
}

export interface PlayerRoguelikeV2_CurrentData_Module_Copper {
    bag: { [key: string]: PlayerRoguelikeV2_CurrentData_Module_InventoryCopper };
    redrawCost: number;
    redrawFreeze: boolean;
    redrawFreezeCnt: number;
}

export interface PlayerRoguelikeV2_CurrentData_Module_InventoryCopper {
    id: string;
    isDrawn: boolean;
    layer: number;
    countDown: number;
    ts: number;
}

export interface PlayerRoguelikeV2_CurrentData_Module_Wrath {
    newWrath: number;
}

export interface PlayerRoguelikeV2_CurrentData_Module_Sky {
    zones: { [key: number]: PlayerRoguelikeV2_CurrentData_Module_SkyZoneInfo };
}

export interface PlayerRoguelikeV2_CurrentData_Module_SkyZoneInfo {
    id: string;
    ap: number;
    nodes: { [key: number]: PlayerRoguelikeV2_CurrentData_Module_SkyZoneNodeInfo };
    mapExPad: PlayerRoguelikeV2_CurrentData_Module_SkyZoneExPadInfo;
}

export interface PlayerRoguelikeV2_CurrentData_Module_SkyZoneExPadInfo {
    left: number;
    right: number;
}

export interface PlayerRoguelikeV2_CurrentData_Module_SkyZoneNodeInfo {
    state: PlayerRoguelikeV2_CurrentData_Module_SkyZoneNodeState;
    type: number;
    sceneSubType: number;
    shopIsEmpty: boolean;
    shopGoodIds: string[];
    shopRefreshShow: boolean;
    shopRefreshCnt: number;
    shopRefreshCost: number;
}

export interface PlayerRoguelikeV2_CurrentData_Module_GridMapData {
    zones: { [key: string]: PlayerRoguelikeV2_CurrentData_Module_GridMapZoneData };
    stepRemain: number;
    needConfirmStepZero: boolean;
}

export interface PlayerRoguelikeV2_CurrentData_Module_GridMapZoneData {
    nodes: { [key: string]: PlayerRoguelikeV2_CurrentData_Module_GridMapZoneNodeData };
}

export interface PlayerRoguelikeV2_CurrentData_Module_GridMapZoneNodeContentData {
    savage: PlayerRoguelikeV2_CurrentData_Module_GridMapNodeSavageData;
    shop: PlayerRoguelikeV2_CurrentData_Module_GridMapNodeShopData;
}

export interface PlayerRoguelikeV2_CurrentData_Module_GridMapZoneNodeData {
    content: PlayerRoguelikeV2_CurrentData_Module_GridMapZoneNodeContentData;
    state: PlayerRoguelikeV2_CurrentData_Module_GridMapZoneNodeStatus;
    show: boolean;
}

export interface PlayerRoguelikeV2_CurrentData_Module_GridMapNodeSavageData {
    stageId: string;
}

export interface PlayerRoguelikeV2_CurrentData_Module_GridMapNodeShopData {}

export interface PlayerRoguelikeV2_CurrentData_Module_ScrapInventoryInfo {
    instId: string;
    id: string;
    value: number;
    useCnt: number;
    ts: number;
}

export interface PlayerRoguelikeV2_CurrentData_Module_GridZoneCurrMoveTypeInfo {
    instId: string;
    isWalk: boolean;
}

export interface PlayerRoguelikeV2_CurrentData_Module_GridZoneScrapInfo {
    activeVehicle: PlayerRoguelikeV2_CurrentData_Module_GridZoneCurrMoveTypeInfo;
    inventory: { [key: string]: PlayerRoguelikeV2_CurrentData_Module_ScrapInventoryInfo };
    limit: number;
}

export interface PlayerRoguelikeV2_CurrentData_Module_Weather {
    currentMain: string;
    currentSub: string;
    eye: string;
    effectArea: { [key: string]: number };
    weatherStep: number;
}

export interface PlayerRoguelikeV2_CurrentData_Module {
    san: PlayerRoguelikeV2_CurrentData_Module_San;
    dice: PlayerRoguelikeV2_CurrentData_Module_Dice;
    totem: PlayerRoguelikeV2_CurrentData_Module_Totem;
    vision: PlayerRoguelikeV2_CurrentData_Module_Vision;
    chaos: PlayerRoguelikeV2_CurrentData_Module_Chaos;
    fragment: PlayerRoguelikeV2_CurrentData_Module_Fragment;
    disaster: PlayerRoguelikeV2_CurrentData_Module_Disaster;
    nodeUpgrade: PlayerRoguelikeV2_CurrentData_Module_NodeUpgrade;
    copper: PlayerRoguelikeV2_CurrentData_Module_Copper;
    wrath: PlayerRoguelikeV2_CurrentData_Module_Wrath;
    sky: PlayerRoguelikeV2_CurrentData_Module_Sky;
    gridZone: PlayerRoguelikeV2_CurrentData_Module_GridMapData;
    scrap: PlayerRoguelikeV2_CurrentData_Module_GridZoneScrapInfo;
    weather: PlayerRoguelikeV2_CurrentData_Module_Weather;
}

export interface PlayerRoguelikeV2_CurrentData {
    player: PlayerRoguelikeV2_CurrentData_PlayerStatus;
    map: PlayerRoguelikeV2Dungeon;
    inventory: PlayerRoguelikeV2_CurrentData_Inventory;
    game: PlayerRoguelikeV2_CurrentData_Game;
    troop: PlayerRoguelikeV2_CurrentData_Troop;
    buff: PlayerRoguelikeV2_CurrentData_Buff;
    module: PlayerRoguelikeV2_CurrentData_Module;
    record: object;
}

export interface PlayerRoguelikeV2_OuterData_Record_History {
    seed: string;
    bandId: string;
    mode: RoguelikeTopicMode;
    modeGrade: number;
    ending: string;
    failEnding: string;
    result: number;
    endTs: number;
}

export interface PlayerRoguelikeV2_OuterData_Record {
    last: number;
    stageCnt: { [key: string]: number };
    bandCnt: { [key: string]: { [key: string]: number } };
    bandGrade: { [key: string]: { [key: string]: number } };
    history: PlayerRoguelikeV2_OuterData_Record_History[];
    legacy: string[];
    modeCnt: number;
    endingCnt: number;
}

export interface PlayerRoguelikeV2_OuterData_BattlePass {
    point: number;
    reward: { [key: string]: number };
}

export interface PlayerRoguelikeV2_OuterData_Mission_MissionSlot {
    type: RoguelikeGameMonthTaskClass;
    mission: PlayerRoguelikeV2_OuterData_Mission_MissionItem;
}

export interface PlayerRoguelikeV2_OuterData_Mission_MissionItem {
    type: RoguelikeGameMonthTaskClass;
    id: string;
    state: number;
    target: number;
    value: number;
    tmpl: object;
}

export interface PlayerRoguelikeV2_OuterData_Mission {
    updateId: string;
    refresh: number;
    list: PlayerRoguelikeV2_OuterData_Mission_MissionSlot[];
}

export interface PlayerRoguelikeV2_OuterData_TotemCollection {
    totem: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    affix: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
}

export interface PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo {
    state: RoguelikeArchiveItemUnlockStatus;
    progress: number[];
}

export interface PlayerRoguelikeV2_OuterData_Collection_WeatherCollection {
    main: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    sub: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
}

export interface PlayerRoguelikeV2_OuterData_Collection_DifficultyUnlockInfo {
    state: PlayerRoguelikeDifficultyStatus;
    progress: number;
}

export interface PlayerRoguelikeV2_OuterData_Collection {
    band: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    relic: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    capsule: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    activeTool: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    mode: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    modeGrade: { [key: string]: { [key: number]: PlayerRoguelikeV2_OuterData_Collection_DifficultyUnlockInfo } };
    recruitSet: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    bgm: { [key: string]: number };
    pic: { [key: string]: number };
    chatV2: { [key: string]: string[] };
    endBook: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    buff: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    totem: PlayerRoguelikeV2_OuterData_TotemCollection;
    chaos: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    fragment: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    disaster: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    nodeUpgrade: { [key: string]: PlayerRoguelikeV2_OuterData_NodeUpgradeInfo };
    copper: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    wrath: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    scrap: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
    weather: PlayerRoguelikeV2_OuterData_Collection_WeatherCollection;
    chat: object;
}

export interface PlayerRoguelikeV2_OuterData_Bank {
    show: boolean;
    current: number;
    record: number;
    totalPut: number;
    reward: { [key: string]: number };
}

export interface PlayerRoguelikeV2_OuterData_Buff {
    pointOwned: number;
    pointCost: number;
    unlocked: { [key: string]: number };
    score: number;
}

export interface PlayerRoguelikeV2_OuterData_MonthTeam {
    reward: { [key: string]: number };
    mission: { [key: string]: number[] };
    valid: boolean;
}

export interface PlayerRoguelikeV2_OuterData_ChallengeCollection {
    exploreTool: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
}

export interface PlayerRoguelikeV2_OuterData_Challenge {
    reward: { [key: string]: number };
    grade: { [key: string]: PlayerRoguelikeChallengeStatus };
    collect: PlayerRoguelikeV2_OuterData_ChallengeCollection;
    highScore: number;
}

export interface PlayerRoguelikeV2_OuterData_NodeUpgradeInfo {
    unlockList: string[];
}

export interface PlayerRoguelikeV2_OuterData_PlayerRogueActivity_PlayerRoguelikeActivitySeedModeData {
    unlockState: PlayerRoguelikeV2_OuterData_PlayerRogueActivity_PlayerRogueActivityUnlockInfo;
    seed: string;
}

export interface PlayerRoguelikeV2_OuterData_PlayerRogueActivity_PlayerRogueActivityUnlockInfo {
    state: PlayerRoguelikeV2_OuterData_PlayerRogueActivity_PlayerRogueActivityUnlockInfo_PlayerRogueActivityUnlockState;
    progress: number[];
}

export interface PlayerRoguelikeV2_OuterData_PlayerRogueActivity {
    roguelikeActivitySeedModeDatas: { [key: string]: PlayerRoguelikeV2_OuterData_PlayerRogueActivity_PlayerRoguelikeActivitySeedModeData };
}

export interface PlayerRoguelikeV2_OuterData {
    bp: PlayerRoguelikeV2_OuterData_BattlePass;
    buff: PlayerRoguelikeV2_OuterData_Buff;
    mission: PlayerRoguelikeV2_OuterData_Mission;
    collect: PlayerRoguelikeV2_OuterData_Collection;
    bank: PlayerRoguelikeV2_OuterData_Bank;
    record: PlayerRoguelikeV2_OuterData_Record;
    monthTeam: PlayerRoguelikeV2_OuterData_MonthTeam;
    challenge: PlayerRoguelikeV2_OuterData_Challenge;
    activity: PlayerRoguelikeV2_OuterData_PlayerRogueActivity;
}

export interface PlayerRoguelikeV2 {
    current: PlayerRoguelikeV2_CurrentData;
    outer: { [key: string]: PlayerRoguelikeV2_OuterData };
    pinned: string;
}

export interface PlayerReturnData_CurrentV2Data {
    start: number;
    finishTs: number;
    lastOnlineTs: number;
    groupId: string;
    checkIn: PlayerReturnData_CheckInV2;
    fullOpen: PlayerReturnData_FullOpen;
    campaignFullOpen: PlayerReturnData_CampaignFullOpen;
    gacha: PlayerReturnData_Gacha;
    mission: PlayerReturnData_MissionV2;
    hasOnceRewardGot: boolean;
    backGiftPack: PlayerReturnData_GiftPackData;
    loginPack: PlayerReturnData_LoginPackData;
}

export interface PlayerReturnData_GiftPackData {
    packs: { [key: string]: PlayerReturnData_GiftPackItemData };
}

export interface PlayerReturnData_GiftPackItemData {
    boughtCount: number;
    saleEndAt: number;
}

export interface PlayerReturnData_LoginPackData {
    hasBought: boolean;
    groupId: string;
    loginRecord: number;
    recvStage: number;
    checkinFinTs: number;
    gpSaleEndAt: number;
}

export interface PlayerReturnData_MissionV2 {
    point: number;
    stageAward: number[];
    dailySupply: number[];
    longMission: { [key: string]: PlayerReturnData_MissionV2Data[] };
    dailyMission: { [key: string]: PlayerReturnData_MissionV2Data[] };
}

export interface PlayerReturnData_MissionV2Data {
    missionId: string;
    current: number;
    target: number;
    status: number;
}

export interface PlayerReturnData_CheckInV2 {
    groupId: string;
    history: number[];
}

export interface PlayerReturnData_FullOpen {
    last: number;
    today: boolean;
    remain: number;
}

export interface PlayerReturnData_CampaignFullOpen {
    today: boolean;
    remain: number;
}

export interface PlayerReturnData_Gacha {
    poolId: string;
    endTs: number;
}

export interface PlayerReturnData {
    open: boolean;
    currentV2: PlayerReturnData_CurrentV2Data;
    version: PlayerReturnData_Version;
    current: object;
}

export interface PlayerRoguelikeV2Zone {
    id: string;
    nodes: { [key: number]: PlayerRoguelikeNode };
    variation: string[];
    zoneType: PlayerRoguelikeZoneType;
}

export interface PlayerRoguelikeV2Dungeon {
    zones: { [key: number]: PlayerRoguelikeV2Zone };
    verticalCostDelta: number;
}

export interface PlayerRoguelikePendingEvent_BattleRewardContent {
    rewards: RoguelikeReward[];
    earn: RoguelikeStageEarn;
    show: string;
    state: number;
    isPerfect: number;
}

export interface PlayerRoguelikePendingEvent_BattleContent {
    state: number;
    chestCnt: number;
    goldTrapCnt: number;
    tmpChar: PlayerRoguelikeV2_CurrentData_Char[];
    unKeepBuff: RoguelikeBuff[];
    diceRoll: number[];
    sanity: number;
    boxInfo: { [key: string]: number };
    isFailProtect: boolean;
    seed: number;
    enemyHpInfo: { [key: string]: number };
    battleSnapshot: string;
    battleFailDisplay: RoguelikeBattleFailDisplay;
}

export interface PlayerRoguelikePendingEvent_InitRecruitContent {
    team: string;
}

export interface PlayerRoguelikePendingEvent_InitRecruitSetContent {}

export interface PlayerRoguelikePendingEvent_InitRelicContent {
    items: { [key: string]: RoguelikeItemBundle };
}

export interface PlayerRoguelikePendingEvent_InitGift {
    items: RoguelikeItemBundle[];
}

export interface PlayerRoguelikePendingEvent_InitModeRelic {
    items: string[];
}

export interface PlayerRoguelikePendingEvent_InitTeam_Char {
    charId: string;
    tmplId: string;
    uniEquipIdOfChar: string;
    type: RoguelikeCharState;
}

export interface PlayerRoguelikePendingEvent_InitTeam {
    chars: PlayerRoguelikePendingEvent_InitTeam_Char[];
    team: string;
}

export interface PlayerRoguelikePendingEvent_InitSupport {
    scene: PlayerRoguelikePendingEvent_SceneContent;
}

export interface PlayerRoguelikePendingEvent_InitSupportMulti {
    scene: PlayerRoguelikePendingEvent_SceneMultiChoiceContent;
}

export interface PlayerRoguelikePendingEvent_InitExploreTool {
    items: { [key: string]: RoguelikeItemBundle };
}

export interface PlayerRoguelikePendingEvent_ChoiceAddition_Reward {
    id: string;
    type: PlayerRoguelikePendingEvent_PlayerRoguelikeChoiceRewardType;
}

export interface PlayerRoguelikePendingEvent_ChoiceAddition_Cost {
    id: string;
    instId: string;
    type: RoguelikeGameItemType;
}

export interface PlayerRoguelikePendingEvent_ChoiceAddition {
    rewards: PlayerRoguelikePendingEvent_ChoiceAddition_Reward[];
    costs: PlayerRoguelikePendingEvent_ChoiceAddition_Cost[];
}

export interface PlayerRoguelikePendingEvent_SceneContent {
    id: string;
    choices: { [key: string]: boolean };
    choiceAdditional: { [key: string]: PlayerRoguelikePendingEvent_ChoiceAddition };
}

export interface PlayerRoguelikePendingEvent_SceneMultiChoiceContent {
    id: string;
    choices: { [key: string]: boolean };
    chance: number;
}

export interface PlayerRoguelikePendingEvent_Recruit {
    ticket: string;
}

export interface PlayerRoguelikePendingEvent_Dice_Result {
    diceEventId: string;
    diceRoll: number;
    mutation: PlayerRoguelikePendingEvent_Dice_MutationResult;
}

export interface PlayerRoguelikePendingEvent_Dice_MutationResult {
    id: string;
}

export interface PlayerRoguelikePendingEvent_Dice {
    result: PlayerRoguelikePendingEvent_Dice_Result;
    rerollCount: number;
}

export interface PlayerRoguelikePendingEvent_ShopContent_Bank {
    cost: number;
    open: boolean;
    canPut: boolean;
    canWithdraw: boolean;
    withdraw: number;
    withdrawLimit: number;
}

export interface PlayerRoguelikePendingEvent_ShopContent_Goods {
    index: string;
    itemId: string;
    count: number;
    priceId: string;
    priceCount: number;
    origCost: number;
    displayPriceChg: boolean;
    ban: number;
}

export interface PlayerRoguelikePendingEvent_ShopContent {
    bank: PlayerRoguelikePendingEvent_ShopContent_Bank;
    id: string;
    goods: PlayerRoguelikePendingEvent_ShopContent_Goods[];
    canBattle: boolean;
    hasBoss: boolean;
    showRefresh: boolean;
    refreshCnt: number;
    refreshCost: number;
    recycleGoods: PlayerRoguelikePendingEvent_ShopContent_Goods[];
    recycleCount: number;
    buyLimit: number;
    hasBuyLimit: boolean;
}

export interface PlayerRoguelikePendingEvent_SacrificeContent {
    type: RoguelikeSacrificeType;
    priceId: string;
    cost: number;
    _choiceId: string;
}

export interface PlayerRoguelikePendingEvent_ExpeditionContent {
    type: RoguelikeExpeditionType;
    priceId: string;
    cost: number;
    _choiceId: string;
}

export interface PlayerRoguelikePendingEvent_EndingResult {
    brief: PlayerRoguelikePendingEvent_EndingBrief;
    record: PlayerRoguelikePendingEvent_EndingRecord;
}

export interface PlayerRoguelikePendingEvent_EndingBrief {
    level: number;
    success: number;
    ending: string;
    failEnding: string;
    theme: string;
    mode: RoguelikeTopicMode;
    predefined: string;
    band: string;
    startTs: number;
    endTs: number;
    endZoneId: string;
    modeGrade: number;
    seed: string;
    activity: string;
}

export interface PlayerRoguelikePendingEvent_EndingRecord {
    cntZone: number;
    relicList: string[];
    capsuleList: string[];
    activeToolList: string[];
    charBuff: string[];
    squadBuff: string[];
    totemList: string[];
    exploreToolList: string[];
    fragmentList: string[];
    copperCounter: { [key: string]: number };
    scrapCounter: { [key: string]: number };
    legacyList: string[];
}

export interface PlayerRoguelikePendingEvent_AlchemyContent {
    canAlchemy: boolean;
}

export interface PlayerRoguelikePendingEvent_UseStashedTicketContent {
    count: number;
    recruitCostAdd: number;
}

export interface PlayerRoguelikePendingEvent_GildCopperContent {
    type: string;
    cost: number;
    priceId: string;
}

export interface PlayerRoguelikePendingEvent_AlchemyRewardContent {
    items: RoguelikeItemBundle[];
    isSSR: boolean;
    isFail: boolean;
}

export interface PlayerRoguelikePendingEvent_SwapCopper {
    newCopper: string;
}

export interface PlayerRoguelikePendingEvent_DrawCopper {
    copper: string[];
    divineEventId: string;
    hitReason: { [key: string]: number };
    exchangeInfo: PlayerRoguelikePendingEvent_CopperExchangeInfo[];
}

export interface PlayerRoguelikePendingEvent_CopperExchangeInfo {
    cost: string;
    gain: string;
}

export interface PlayerRoguelikePendingEvent_Content {
    scene: PlayerRoguelikePendingEvent_SceneContent;
    initRecruit: PlayerRoguelikePendingEvent_InitRecruitContent;
    battle: PlayerRoguelikePendingEvent_BattleContent;
    initRelic: PlayerRoguelikePendingEvent_InitRelicContent;
    initGift: PlayerRoguelikePendingEvent_InitGift;
    initRecruitSet: PlayerRoguelikePendingEvent_InitRecruitSetContent;
    initModeRelic: PlayerRoguelikePendingEvent_InitModeRelic;
    initTeam: PlayerRoguelikePendingEvent_InitTeam;
    initSupport: PlayerRoguelikePendingEvent_InitSupport;
    initSupportMulti: PlayerRoguelikePendingEvent_InitSupportMulti;
    initExploreTool: PlayerRoguelikePendingEvent_InitExploreTool;
    battleReward: PlayerRoguelikePendingEvent_BattleRewardContent;
    recruit: PlayerRoguelikePendingEvent_Recruit;
    dice: PlayerRoguelikePendingEvent_Dice;
    shop: PlayerRoguelikePendingEvent_ShopContent;
    result: PlayerRoguelikePendingEvent_EndingResult;
    battleShop: PlayerRoguelikePendingEvent_ShopContent;
    sacrifice: PlayerRoguelikePendingEvent_SacrificeContent;
    expedition: PlayerRoguelikePendingEvent_ExpeditionContent;
    detailStr: string;
    popReport: boolean;
    alchemy: PlayerRoguelikePendingEvent_AlchemyContent;
    alchemyReward: PlayerRoguelikePendingEvent_AlchemyRewardContent;
    changeCopper: PlayerRoguelikePendingEvent_SwapCopper;
    drawCopper: PlayerRoguelikePendingEvent_DrawCopper;
    useStashedTicket: PlayerRoguelikePendingEvent_UseStashedTicketContent;
    gildCopper: PlayerRoguelikePendingEvent_GildCopperContent;
    done: boolean;
}

export interface PlayerRoguelikePendingEvent {
    index: string;
    type: PlayerRoguelikePlayerEventType;
    content: PlayerRoguelikePendingEvent_Content;
}

export interface CharmStatus {
    charms: { [key: string]: number };
    squad: string[];
}

export type PlayerCartInfo_Cart = { [key: string]: string };

export interface PlayerCartInfo_CompInfo {
    id: string;
    num: number;
}

export interface PlayerCartInfo {
    battleCar: PlayerCartInfo_Cart;
    exhibitionCar: PlayerCartInfo_Cart;
    accessories: { [key: string]: PlayerCartInfo_CompInfo };
}

export interface PlayerDeepSea_TechData {
    state: PlayerDeepSea_TechStatus;
    branch: string;
}

export interface PlayerDeepSea {
    places: { [key: string]: PlayerDeepSea_PlaceStatus };
    nodes: { [key: string]: PlayerDeepSea_NodeStatus };
    choices: { [key: string]: PlayerDeepSea_ChoiceStatus[] };
    events: { [key: string]: PlayerDeepSea_ReadStatus };
    treasures: { [key: string]: PlayerDeepSea_TreasureStatus };
    stories: { [key: string]: PlayerDeepSea_ReadStatus };
    techTrees: { [key: string]: PlayerDeepSea_TechData };
    logs: { [key: string]: string[] };
}

export interface PlayerSiracusaMap_BattleProgress {
    value: number;
    target: number;
}

export interface PlayerSiracusaMap_TaskInfo {
    state: PlayerSiracusaMap_StateEnum;
    option: string[];
    progress: PlayerSiracusaMap_BattleProgress;
}

export interface PlayerSiracusaMap_TaskRing {
    task: { [key: string]: PlayerSiracusaMap_TaskInfo };
    state: PlayerSiracusaMap_TaskRingStatus;
}

export interface PlayerSiracusaMap_CharCard {
    item: { [key: string]: PlayerSiracusaMap_CharCardItemEnum };
    taskRing: { [key: string]: PlayerSiracusaMap_TaskRing };
    state: PlayerSiracusaMap_CharCardStatus;
}

export interface PlayerSiracusaMap_Opera {
    total: number;
    show: string;
    release: { [key: string]: PlayerSiracusaMap_OperaState };
    like: { [key: string]: string };
}

export interface PlayerSiracusaMap {
    select: string;
    card: { [key: string]: PlayerSiracusaMap_CharCard };
    opera: PlayerSiracusaMap_Opera;
    area: { [key: string]: number };
}

export interface PlayerFirework_PlayerPlate {
    unlock: { [key: string]: number };
    slots: FireworkData_PlateSlotData[];
}

export interface PlayerFirework_PlayerAnimal {
    unlock: { [key: string]: number };
    select: string;
}

export interface PlayerFirework {
    unlock: boolean;
    plate: PlayerFirework_PlayerPlate;
    animal: PlayerFirework_PlayerAnimal;
}

export interface PlayerTower {
    current: TowerCurrent;
    outer: TowerOuter;
    season: TowerSeason;
}

export interface TowerTactical {
    PIONEER: string;
    WARRIOR: string;
    TANK: string;
    SNIPER: string;
    CASTER: string;
    SUPPORT: string;
    MEDIC: string;
    SPECIAL: string;
}

export interface TowerCurrent_Status {
    state: TowerCurrent_TowerGameState;
    towerId: string;
    coord: number;
    tactical: TowerTactical;
    start: number;
    isHard: boolean;
    tower: object;
    strategy: object;
}

export interface TowerCurrent_TowerGodCard {
    godCardId: string;
    subGodCardId: string;
    id: string;
}

export interface TowerCurrent_TowerGameLayer {
    id: string;
    tryNum: number;
    pass: boolean;
}

export interface TowerCurrent_GameCard {
    relation: string;
    type: TowerCurrent_TowerCardType;
}

export interface TowerCurrent_TowerTrapInfo {
    id: string;
    alias: string;
}

export interface TowerCurrent_HalftimeRecruit {
    remainCount: number;
    candidate: TowerCurrent_HalftimeCandidateGroup[];
    canGiveUp: boolean;
    count: number;
}

export interface TowerCurrent_HalftimeCandidateGroup {
    groupId: string;
    type: TowerCurrent_TowerCardType;
    cards: TowerCurrent_GameCard[];
}

export interface TowerCurrent {
    status: TowerCurrent_Status;
    godCard: TowerCurrent_TowerGodCard;
    layer: TowerCurrent_TowerGameLayer[];
    cards: { [key: string]: TowerCurrent_GameCard };
    trap: TowerCurrent_TowerTrapInfo[];
    halftime: TowerCurrent_HalftimeRecruit;
}

export interface TowerOuter_TowerData {
    best: number;
    reward: number[];
    isHardValid: boolean;
    hardBest: number;
    canSweep: boolean;
    canSweepHard: boolean;
    unlockHard: boolean;
}

export interface TowerOuter {
    training: { [key: string]: number };
    towers: { [key: string]: TowerOuter_TowerData };
    hasTowerPass: number;
    tactical: TowerTactical;
    strategy: TowerGameStrategy;
    pickedGodCard: object;
    squad: object;
}

export interface TowerSeason_TowerSeasonMission {
    target: number;
    value: number;
    hasRecv: boolean;
}

export interface TowerSeason_TowerSeasonPeriod {
    termTs: number;
    items: { [key: string]: number };
    periodCurr: number;
    periodCount: number;
    cur: number;
    len: number;
}

export interface TowerSeason {
    id: string;
    finishTs: number;
    missions: { [key: string]: TowerSeason_TowerSeasonMission };
    period: TowerSeason_TowerSeasonPeriod;
    passWithGodCard: object;
    slots: object;
}

export interface PlayerHomeUnlockStatus {
    unlockTime: number;
    conditions: { [key: string]: PlayerHomeConditionProgress };
    unlock: boolean;
}

export interface PlayerHomeConditionProgress {
    curProgress: number;
    total: number;
    DEFAULT: PlayerHomeConditionProgress;
    v: number;
    t: number;
}

export interface PlayerHomeBackground {
    selectedId: string;
    bgs: { [key: string]: PlayerHomeUnlockStatus };
    selected: string;
}

export interface PlayerHomeTheme {
    selectedId: string;
    themes: { [key: string]: PlayerHomeUnlockStatus };
    selected: string;
}

export interface PlayerSetting {
    settingPerf: PlayerSettingPerf;
    perf: { lowPower: number };
}

export interface PlayerSettingPerf {
    lowPower: boolean;
}

export interface PlayerAprilFool {
    act3fun: PlayerActFun3;
    act4fun: PlayerActFun4;
    act5fun: PlayerActFun5;
    act6fun: PlayerActFun6;
    act7fun: PlayerActFun7;
}

export interface PlayerActFun3 {
    stages: { [key: string]: PlayerActFunStage };
}

export interface PlayerActFunStage {
    state: PlayerStageState;
    scores: number[];
}

export interface PlayerActFun4 {
    stages: { [key: string]: PlayerActFun4Stage };
    liveEndings: { [key: string]: number };
    tokenLevel: number;
    fansNum: number;
    posts: number;
    missions: { [key: string]: PlayerActFun4Mission };
    cameraLv: number;
    fans: number;
}

export interface PlayerActFun4Stage {
    state: PlayerStageState;
    liveTimes: number;
}

export interface PlayerActFun4Mission {
    value: number;
    target: number;
    finished: boolean;
    hasRecv: boolean;
}

export interface PlayerActFun5 {
    stageState: { [key: string]: number };
    highScore: number;
}

export interface PlayerActFun6Stage {
    stageId: string;
    achievements: { [key: string]: number };
    speedrunning: number;
    state: PlayerStageState;
}

export interface PlayerActFun6 {
    stages: { [key: string]: PlayerActFun6Stage };
    recvList: string[];
}

export interface PlayerActFun7 {
    stages: { [key: string]: PlayerStageState };
}

export interface PlayerMainlineRecord {
    record: { [key: string]: number };
    cache: ItemBundle[];
    additionalMission: { [key: string]: PlayerZoneRecordMissionData };
    missionArchive: { [key: string]: PlayerMissionArchive };
    explore: PlayerMainlineExplore;
    clue: PlayerMainlineClue;
    version: number;
    charVoiceRecord: { [key: string]: object };
}

export interface PlayerMainlineExplore_PlayerExploreGameContext {
    state: PlayerMainlineExplore_PlayerExploreGameContextState;
    node: PlayerMainlineExplore_PlayerExploreGameContextNode;
    map: PlayerMainlineExplore_PlayerExploreGameContextMap;
    log: PlayerMainlineExplore_PlayerExploreGameContextLog;
}

export interface PlayerMainlineExplore_PlayerExploreGameContextState {
    abilities: { [key: string]: number };
    groupId: string;
    groupCode: string;
    state: PlayerMainlineExplore_GameState;
    targets: string[];
    stageId: string;
    nextStageId: string;
    stageNodeIndex: number;
    blockStageId: string;
    broadCast: string[];
    startTs: number;
}

export interface PlayerMainlineExplore_PlayerExploreGameContextNode {
    type: PlayerMainlineExplore_DecisionNodeType;
    nodeEvent: PlayerMainlineExplore_PlayerExploreGameContextNodeEvent;
}

export interface PlayerMainlineExplore_PlayerExploreGameContextNodeEvent {
    events: string[];
    choices: PlayerMainlineExplore_PlayerExploreGameContextNodeEventChoice[];
}

export interface PlayerMainlineExplore_PlayerExploreGameContextNodeEventChoice {
    eventId: string;
    choiceId: string;
    abilitiesDelta: { [key: string]: number };
    abilitiesCondition: { [key: string]: number };
    successRate: number;
}

export interface PlayerMainlineExplore_PlayerExploreGameContextMap {
    display: PlayerMainlineExplore_PlayerExploreGameContextMapDisplay;
}

export interface PlayerMainlineExplore_PlayerExploreGameContextMapDisplay {
    nodeSeed: number;
    pathSeed: number;
    controlPoints: PlayerMainlineExplore_PlayerExploreGameContextMapControlPoint[];
}

export interface PlayerMainlineExplore_PlayerExploreGameContextMapControlPoint {
    stageId: string;
    pos: PlayerMainlineExplore_PlayerPosition;
}

export interface PlayerMainlineExplore_PlayerPosition {
    x: number;
    y: number;
}

export interface PlayerMainlineExplore_PlayerExploreGameContextLog {
    passEvents: string[];
    passTargets: string[];
}

export interface PlayerMainlineExplore_PlayerExploreOuterContext {
    isOpen: boolean;
    mission: { [key: string]: PlayerMainlineExplore_PlayerExploreOuterContextMissionState };
    lastGameResult: PlayerMainlineExplore_PlayerExploreGameResult;
    historyPaths: PlayerMainlineExplore_PlayerExploreOuterContextHistoryPath[];
}

export interface PlayerMainlineExplore_PlayerExploreGameResult {
    groupId: string;
    groupCode: string;
    heritageAbilities: { [key: string]: number };
}

export interface PlayerMainlineExplore_PlayerExploreOuterContextMissionState {
    state: number;
    progress: number[];
}

export interface PlayerMainlineExplore_PlayerExploreOuterContextHistoryPath {
    success: boolean;
    path: PlayerMainlineExplore_PlayerExploreGameContextMapDisplay;
}

export interface PlayerMainlineExplore {
    game: PlayerMainlineExplore_PlayerExploreGameContext;
    outer: PlayerMainlineExplore_PlayerExploreOuterContext;
}

export interface PlayerMainlineClue {
    unlock: boolean;
    state: { [key: string]: number };
    reward: { [key: string]: number };
}

export interface PlayerLimitedDropBuff_DailyUsage {
    times: number;
    ts: number;
}

export interface PlayerLimitedDropBuff_LimitedBuffGroup {
    ts: number;
    count: number;
}

export interface PlayerLimitedDropBuff {
    dailyUsage: { [key: string]: PlayerLimitedDropBuff_DailyUsage };
    inventory: { [key: string]: PlayerLimitedDropBuff_LimitedBuffGroup };
}

export interface PlayerZoneRecordMissionData {
    state: number;
    process: PlayerZoneRecordMissionProcessData;
}

export interface PlayerZoneRecordMissionProcessData {
    target: number;
    value: number;
}

export interface PlayerMissionArchive {
    entryOpen: boolean;
    entryRewardClaimed: boolean;
    nodes: { [key: string]: PlayerMissionArchiveNodeState };
}

export interface PlayerSandboxV2_Status {
    state: PlayerSandboxV2_GameState;
    ts: number;
    isRift: boolean;
    isGuide: boolean;
    isChallenge: boolean;
    mode: number;
}

export interface PlayerSandboxV2_BaseInfo {
    baseLv: number;
    portableUnlock: boolean;
    outpostUnlock: boolean;
    trapLimit: { [key: string]: number };
    upgradeProgress: number[][];
    repairDiscount: number;
    bossKill: string[];
}

export interface PlayerSandboxV2_Dungeon_Game {
    mapId: string;
    day: number;
    maxDay: number;
    ap: number;
    maxAp: number;
}

export interface PlayerSandboxV2_Dungeon_Zone {
    unlocked: boolean;
    weather: SandboxV2WeatherType;
}

export interface PlayerSandboxV2_Dungeon_NodeRelate {
    pos: number[];
    adj: string[];
    depth: number;
}

export interface PlayerSandboxV2_Dungeon_Node {
    zone: string;
    type: SandboxV2NodeType;
    state: PlayerSandboxV2_NodeState;
    relate: PlayerSandboxV2_Dungeon_NodeRelate;
    stageId: string;
    weatherLv: number;
}

export interface PlayerSandboxV2_Dungeon_Season {
    type: SandboxV2SeasonType;
    remain: number;
    total: number;
}

export interface PlayerSandboxV2_Dungeon_Map {
    season: PlayerSandboxV2_Dungeon_Season;
    zone: { [key: string]: PlayerSandboxV2_Dungeon_Zone };
    node: { [key: string]: PlayerSandboxV2_Dungeon_Node };
}

export interface PlayerSandboxV2_Dungeon_Stage {
    node: { [key: string]: PlayerSandboxV2_Dungeon_NodeStage };
}

export interface PlayerSandboxV2_Dungeon_Report {
    settle: PlayerSandboxV2_Dungeon_ReportSettle;
    daily: PlayerSandboxV2_Dungeon_ReportDaily;
}

export interface PlayerSandboxV2_Dungeon_ReportDetail {
    dayScore: number;
    hasRift: boolean;
    riftScore: number;
    apScore: number;
    exploreScore: number;
    homeInfo: { [key: string]: number };
    make: PlayerSandboxV2_Dungeon_ReportMake;
}

export interface PlayerSandboxV2_Dungeon_ReportMake {
    tacticalScore: number;
    foodScore: number;
}

export interface PlayerSandboxV2_Dungeon_ReportDaily {
    isLoad: boolean;
    fromDay: number;
    seasonChange: boolean;
    mission: PlayerSandboxV2_Dungeon_ReportMission;
    baseProduct: PlayerSandboxV2_Dungeon_ReportGainItem[];
}

export interface PlayerSandboxV2_Dungeon_ReportMission {
    squad: number[][];
    reward: PlayerSandboxV2_Dungeon_ReportGainItem[];
}

export interface PlayerSandboxV2_Dungeon_ReportGainItem {
    itemId: string;
    count: number;
}

export interface PlayerSandboxV2_Dungeon_ReportSettle {
    scoreTotal: number;
    scoreRatio: string;
    techToken: number;
    techCent: number;
    shopCoin: number;
    shopCoinMax: boolean;
    detail: PlayerSandboxV2_Dungeon_ReportDetail;
}

export interface PlayerSandboxV2_Dungeon_BaseInfo {}

export interface PlayerSandboxV2_Dungeon_Portable {}

export interface PlayerSandboxV2_Dungeon_Nest {}

export interface PlayerSandboxV2_Dungeon_Cave {
    extraParam: number;
}

export interface PlayerSandboxV2_Dungeon_Gate {}

export interface PlayerSandboxV2_Dungeon_Mine {}

export interface PlayerSandboxV2_Dungeon_Selection {
    count: number[];
}

export interface PlayerSandboxV2_Dungeon_Collect {
    count: number[];
    extraParam: number;
}

export interface PlayerSandboxV2_Dungeon_Hunt {
    key: string;
    count: number[];
}

export interface PlayerSandboxV2_Dungeon_Trap {}

export interface PlayerSandboxV2_Dungeon_Building {
    key: string;
    pos: number[];
    hpRatio: number;
    dir: number;
}

export interface PlayerSandboxV2_Dungeon_CatchAnimal_CatchAnimalInfo {
    id: string;
    count: number;
}

export interface PlayerSandboxV2_Dungeon_CatchAnimal {
    room: number;
    enemy: PlayerSandboxV2_Dungeon_CatchAnimal_CatchAnimalInfo[];
}

export interface PlayerSandboxV2_Dungeon_NodeStage {
    id: string;
    state: PlayerSandboxV2_StageState;
    view: string;
    baseInfo: PlayerSandboxV2_Dungeon_BaseInfo[];
    port: PlayerSandboxV2_Dungeon_Portable[];
    nest: PlayerSandboxV2_Dungeon_Nest[];
    cave: PlayerSandboxV2_Dungeon_Cave[];
    gate: PlayerSandboxV2_Dungeon_Gate[];
    mine: PlayerSandboxV2_Dungeon_Mine[];
    insect: PlayerSandboxV2_Dungeon_Selection[];
    collect: PlayerSandboxV2_Dungeon_Collect[];
    hunt: PlayerSandboxV2_Dungeon_Hunt[];
    trap: PlayerSandboxV2_Dungeon_Trap[];
    building: PlayerSandboxV2_Dungeon_Building[];
    action: number[][];
    actionKill: number[][];
    animal: PlayerSandboxV2_Dungeon_CatchAnimal[];
}

export interface PlayerSandboxV2_Dungeon_FloatSource {
    type: PlayerSandboxV2_Dungeon_FloatSourceType;
    id: string;
}

export interface PlayerSandboxV2_Dungeon_EnemyRushBossStatus {
    hpRatio: number;
    modeIndex: number;
}

export interface PlayerSandboxV2_Dungeon_EnemyRush {
    enemyRushType: SandboxV2EnemyRushType;
    groupKey: string;
    state: number;
    day: number;
    path: string[];
    enemy: number[][];
    boss: { [key: string]: PlayerSandboxV2_Dungeon_EnemyRushBossStatus };
    badge: SandboxV2QuestLineBadgeType;
    src: PlayerSandboxV2_Dungeon_FloatSource;
}

export interface PlayerSandboxV2_Dungeon_RareAnimal {
    rareAnimalType: SandboxV2RareAnimalType;
    enemyId: string;
    enemyGroupKey: string;
    day: number;
    path: string[];
    badge: SandboxV2QuestLineBadgeType;
    src: PlayerSandboxV2_Dungeon_FloatSource;
    extra: PlayerSandboxV2_Dungeon_RareAnimalExtraInfo;
}

export interface PlayerSandboxV2_Dungeon_RareAnimalExtraInfo {
    hpRatio: number;
    found: boolean;
}

export interface PlayerSandboxV2_Dungeon_Enemy {
    enemyRush: { [key: string]: PlayerSandboxV2_Dungeon_EnemyRush };
    rareAnimal: { [key: string]: PlayerSandboxV2_Dungeon_RareAnimal };
}

export interface PlayerSandboxV2_Dungeon_NpcGroup_Npc_NpcMeta_GachaItemPair {
    id: string;
    count: number;
}

export interface PlayerSandboxV2_Dungeon_NpcGroup_Npc_NpcMeta {
    gacha: PlayerSandboxV2_Dungeon_NpcGroup_Npc_NpcMeta_GachaItemPair[];
}

export interface PlayerSandboxV2_Dungeon_NpcGroup_Npc {
    id: string;
    instId: number;
    isBlackMarketNpc: boolean;
    enable: boolean;
    dialog: { [key: number]: PlayerSandboxV2_Dungeon_NpcGroup_Npc_NpcMeta };
    badge: SandboxV2QuestLineBadgeType;
    src: PlayerSandboxV2_Dungeon_FloatSource;
}

export interface PlayerSandboxV2_Dungeon_NpcGroup {
    node: { [key: string]: PlayerSandboxV2_Dungeon_NpcGroup_Npc[] };
    favor: { [key: string]: number };
}

export interface PlayerSandboxV2_Dungeon_Effect {
    instId: number;
    id: string;
    day: number;
}

export interface PlayerSandboxV2_Dungeon_EventGroup_Event {
    id: string;
    instId: number;
    scene: string;
    state: number;
    badge: SandboxV2QuestLineBadgeType;
    src: PlayerSandboxV2_Dungeon_FloatSource;
}

export interface PlayerSandboxV2_Dungeon_EventGroup {
    node: { [key: string]: PlayerSandboxV2_Dungeon_EventGroup_Event[] };
    effect: PlayerSandboxV2_Dungeon_Effect[];
}

export interface PlayerSandboxV2_Dungeon {
    game: PlayerSandboxV2_Dungeon_Game;
    map: PlayerSandboxV2_Dungeon_Map;
    stage: PlayerSandboxV2_Dungeon_Stage;
    enemy: PlayerSandboxV2_Dungeon_Enemy;
    npc: PlayerSandboxV2_Dungeon_NpcGroup;
    events: PlayerSandboxV2_Dungeon_EventGroup;
    report: PlayerSandboxV2_Dungeon_Report;
}

export interface PlayerSandboxV2_Troop_CharFood {
    id: string;
    sub: string[];
    day: number;
}

export interface PlayerSandboxV2_Troop_Squad {
    slots: PlayerSquadItem[];
    tools: string[];
}

export interface PlayerSandboxV2_Troop {
    food: { [key: number]: PlayerSandboxV2_Troop_CharFood };
    squad: PlayerSandboxV2_Troop_Squad[];
    usedChar: number[];
}

export interface PlayerSandboxV2_Cook_Food {
    id: string;
    sub: string[];
    count: number;
}

export interface PlayerSandboxV2_Cook {
    drink: number;
    extraDrink: number;
    book: { [key: string]: number };
    food: { [key: string]: PlayerSandboxV2_Cook_Food };
}

export interface PlayerSandboxV2_Build {
    book: { [key: string]: number };
    building: { [key: string]: number };
    tactical: { [key: string]: number };
    animal: { [key: string]: number };
}

export interface PlayerSandboxV2_Bag {
    material: { [key: string]: number };
}

export interface PlayerSandboxV2_Bank {
    book: string[];
    coin: { [key: string]: number };
}

export interface PlayerSandboxV2_Tech {
    token: number;
    cent: number;
}

export interface PlayerSandboxV2_QuestGroup_Quest {
    id: string;
    completed: boolean;
    progress: string[][];
}

export interface PlayerSandboxV2_QuestGroup {
    quests: PlayerSandboxV2_QuestGroup_Quest[];
    complete: string[];
}

export interface PlayerSandboxV2_Shop_ShopSlotData {
    goodId: string;
    count: number;
    price: number;
}

export interface PlayerSandboxV2_Shop {
    unlock: boolean;
    day: number;
    slots: PlayerSandboxV2_Shop_ShopSlotData[];
}

export interface PlayerSandboxV2_Month {
    rushPass: string[];
}

export interface PlayerSandboxV2_RiftInfo_RewardItem {
    id: string;
    count: number;
}

export interface PlayerSandboxV2_RiftInfo_Reservation {
    instId: number;
    rift: string;
    mainTarget: string;
    subTarget: string;
    climate: string;
    terrain: string;
    map: string;
    enemy: string;
    effect: string;
    difficulty: string;
    team: string;
}

export interface PlayerSandboxV2_RiftInfo_GameInfo_RiftFloat {
    nodeId: string;
    badge: SandboxV2QuestLineBadgeType;
    src: PlayerSandboxV2_Dungeon_FloatSource;
}

export interface PlayerSandboxV2_RiftInfo_GameInfo {
    status: PlayerSandboxV2_RiftInfo_RiftGameStatus;
    mainProgress: number[];
    subProgress: number[];
    mainFail: boolean;
    pin: PlayerSandboxV2_RiftInfo_GameInfo_RiftFloat;
}

export interface PlayerSandboxV2_RiftInfo_SettleReward {
    main: PlayerSandboxV2_RiftInfo_RewardItem[];
    sub: PlayerSandboxV2_RiftInfo_RewardItem[];
}

export interface PlayerSandboxV2_RiftInfo_SettleInfo {
    reward: PlayerSandboxV2_RiftInfo_SettleReward;
    portHp: number;
}

export interface PlayerSandboxV2_RiftInfo {
    isUnlocked: boolean;
    randomRemain: number;
    reservedRifts: { [key: string]: number };
    completedDifficultyLevel: { [key: string]: number };
    teamLv: number;
    fixFinish: string[];
    reservation: PlayerSandboxV2_RiftInfo_Reservation;
    gameInfo: PlayerSandboxV2_RiftInfo_GameInfo;
    settleInfo: PlayerSandboxV2_RiftInfo_SettleInfo;
}

export interface PlayerSandboxV2_Supply {
    unlock: boolean;
    enable: boolean;
    slotCnt: number;
    charInstList: number[];
}

export interface PlayerSandboxV2_Expedition_Squad {
    id: string;
    day: number;
    charInstList: number[];
}

export interface PlayerSandboxV2_Expedition {
    squad: PlayerSandboxV2_Expedition_Squad[];
}

export interface PlayerSandboxV2_Save {
    day: number;
    maxAp: number;
    season: PlayerSandboxV2_Dungeon_Season;
    ts: number;
}

export interface PlayerSandboxV2_Archive {
    save: PlayerSandboxV2_Save[];
    nextLoadTs: number;
    loadTs: number;
    daily: PlayerSandboxV2_Save;
}

export interface PlayerSandboxV2_Collect_Pending {
    achievement: { [key: string]: number[] };
}

export interface PlayerSandboxV2_Collect_Complete {
    achievement: string[];
    quest: string[];
    music: string[];
}

export interface PlayerSandboxV2_Collect {
    pending: PlayerSandboxV2_Collect_Pending;
    complete: PlayerSandboxV2_Collect_Complete;
}

export interface PlayerSandboxV2_Buff_Runes {
    global: string[];
    node: { [key: string]: string[] };
    characters: { [key: string]: string[] };
}

export interface PlayerSandboxV2_Buff {
    rune: PlayerSandboxV2_Buff_Runes;
}

export interface PlayerSandboxV2_Racing_RacerName {
    prefix: string;
    suffix: string;
}

export interface PlayerSandboxV2_Racing_TempRacerInfo {}

export interface PlayerSandboxV2_Racing_RacerInfo {
    name: PlayerSandboxV2_Racing_RacerName;
    mark: boolean;
    medal: string[];
}

export interface PlayerSandboxV2_Racing_TempRacerBag {
    racer: { [key: string]: PlayerSandboxV2_Racing_TempRacerInfo };
}

export interface PlayerSandboxV2_Racing_RacerBag {
    racer: { [key: string]: PlayerSandboxV2_Racing_RacerInfo };
}

export interface PlayerSandboxV2_Racing {
    unlock: boolean;
    bag: PlayerSandboxV2_Racing_RacerBag;
    bagTmp: PlayerSandboxV2_Racing_TempRacerBag;
    token: number;
}

export interface PlayerSandboxV2_Challenge_Current {
    startDay: number;
    startLoadTimes: number;
    hardRatio: number;
    enemyKill: number;
}

export interface PlayerSandboxV2_Challenge_History {
    startDay: number;
    startLoadTimes: number;
    ts: number;
    day: number;
}

export interface PlayerSandboxV2_Challenge {
    unlock: { [key: string]: number[] };
    status: PlayerSandboxV2_Challenge_ChallengeStatus;
    cur: PlayerSandboxV2_Challenge_Current;
    best: PlayerSandboxV2_Challenge_History;
    last: PlayerSandboxV2_Challenge_History;
    reward: { [key: string]: number };
    challengeModeActivated: boolean;
    hasEnteredOnce: boolean;
}

export interface PlayerSandboxV2 {
    status: PlayerSandboxV2_Status;
    baseInfo: PlayerSandboxV2_BaseInfo;
    main: PlayerSandboxV2_Dungeon;
    rift: PlayerSandboxV2_Dungeon;
    quest: PlayerSandboxV2_QuestGroup;
    expedition: PlayerSandboxV2_Expedition;
    troop: PlayerSandboxV2_Troop;
    cook: PlayerSandboxV2_Cook;
    build: PlayerSandboxV2_Build;
    bag: PlayerSandboxV2_Bag;
    bank: PlayerSandboxV2_Bank;
    shop: PlayerSandboxV2_Shop;
    riftInfo: PlayerSandboxV2_RiftInfo;
    supply: PlayerSandboxV2_Supply;
    tech: PlayerSandboxV2_Tech;
    month: PlayerSandboxV2_Month;
    record: PlayerSandboxV2_Archive;
    archive: PlayerSandboxV2_Collect;
    buff: PlayerSandboxV2_Buff;
    racing: PlayerSandboxV2_Racing;
    challenge: PlayerSandboxV2_Challenge;
}

export interface PlayerSandboxV3 {
    current: PlayerSandboxV3CurrentGame;
    game: PlayerSandboxV3Game;
    map: PlayerSandboxV3Map;
    npc: PlayerSandboxV3Npc;
    quest: PlayerSandboxV3QuestGroup;
    basement: PlayerSandboxV3Basement;
    dungeon: PlayerSandboxV3Dungeon;
    development: PlayerSandboxV3Development;
    band: { [key: string]: PlayerSandboxV3Band };
    inventory: PlayerSandboxV3Inventory;
    collect: PlayerSandboxV3Collect;
}

export interface PlayerSandboxV3Game {
    modeId: string;
}

export interface PlayerSandboxV3Map {
    unlockZones: { [key: string]: PlayerSandboxV3Zone };
    unlockNodes: { [key: string]: PlayerSandboxV3Node };
}

export interface PlayerSandboxV3Zone_Defend {
    main: number;
    sub: number[];
}

export interface PlayerSandboxV3Zone {
    defend: PlayerSandboxV3Zone_Defend;
}

export interface PlayerSandboxV3Node {
    state: PlayerSandboxV3Node_State;
}

export interface PlayerSandboxV3Npc_Normal {
    id: string;
    instId: number;
    enable: boolean;
    badge: SandboxV3QuestLineBadgeType;
    dialog: PlayerSandboxV3Npc_DialogType[];
}

export interface PlayerSandboxV3Npc_Base_Trap {
    instId: number;
    id: string;
    enable: boolean;
}

export interface PlayerSandboxV3Npc_Base {
    trap: PlayerSandboxV3Npc_Base_Trap[];
    enemy: string[];
}

export interface PlayerSandboxV3Npc {
    normal: { [key: string]: PlayerSandboxV3Npc_Normal[] };
    basement: PlayerSandboxV3Npc_Base;
}

export interface PlayerSandboxV3QuestGroup_Quest {
    id: string;
    state: PlayerSandboxV3QuestGroup_Quest_State;
    progress: number[][];
}

export interface PlayerSandboxV3QuestGroup {
    quests: PlayerSandboxV3QuestGroup_Quest[];
    complete: string[];
}

export interface PlayerSandboxV3Basement {
    level: number;
    cond: PlayerSandboxV3BasementCond[];
    wonder: string[];
    shop: PlayerSandboxV3BaseShop;
    building: { [key: string]: PlayerSandboxV3BaseBuilding[] };
    animal: PlayerSandboxV3BaseAnimal[];
    debris: number[][];
    score: number;
    harvest: PlayerSandboxV3Harvest;
}

export interface PlayerSandboxV3Harvest {
    unlock: boolean;
    rate: { [key: string]: number };
    refreshTs: number;
    harvestTs: number;
}

export interface PlayerSandboxV3BasementCond {}

export interface PlayerSandboxV3BaseShop {
    good: { [key: string]: PlayerSandboxV3BaseShopGood };
}

export interface PlayerSandboxV3BaseShopGood {
    count: number;
}

export interface PlayerSandboxV3BaseBuilding {
    pos: number[];
    dir: number;
}

export interface PlayerSandboxV3BaseAnimal {
    pos: number[];
    enemy: { [key: string]: number };
}

export interface PlayerSandboxV3Dungeon {
    difficulty: { [key: string]: PlayerSandboxV3Difficulty };
}

export interface PlayerSandboxV3Difficulty {
    state: PlayerSandboxV3Difficulty_State;
    cond: boolean[];
}

export interface PlayerSandboxV3Development {
    token: number;
}

export interface PlayerSandboxV3Inventory {
    coin: { [key: string]: number };
    trap: { [key: string]: number };
    cookbook: string[];
}

export interface PlayerSandboxV3Band {
    level: number;
    cond: number[];
    badge: boolean;
}

export interface PlayerSandboxV3CurrentMap {
    subStage: string[];
    unlockIndex: number[];
    initIndex: number[];
}

export interface PlayerSandboxV3CurrentBand {
    id: string;
    level: number;
}

export interface PlayerSandboxV3CurrentShop_Slot {
    goodId: string;
    sortId: number;
    stock: number;
    nowPrice: number;
    oriPrice: number;
}

export interface PlayerSandboxV3CurrentShop_Recruit {
    show: boolean;
    price: number;
}

export interface PlayerSandboxV3CurrentShop {
    shopId: string;
    slots: PlayerSandboxV3CurrentShop_Slot[];
    recruit: PlayerSandboxV3CurrentShop_Recruit;
    refreshPrice: number;
    sellPrice: { [key: string]: number };
    showBattleShop: boolean;
}

export interface PlayerSandboxV3CurrentDayPassSettlement {
    gainPower: number;
    pros: number;
    aesth: number;
    aesthCoin: number;
    weather: string;
}

export interface PlayerSandboxV3CurrentBag {
    coin: { [key: string]: number };
    material: { [key: string]: number };
    relic: string[];
    recipe: string[];
    trap: { [key: string]: number };
}

export interface PlayerSandboxV3CurrentEvent_RewardItem {
    id: string;
    count: number;
}

export interface PlayerSandboxV3CurrentEvent {
    id: string;
    scene: string;
    choiceReward: { [key: string]: PlayerSandboxV3CurrentEvent_RewardItem[] };
}

export interface PlayerSandboxV3CurrentChar {
    charType: SandboxV3SquadCharType;
}

export interface PlayerSandboxV3CurrentTroop {
    slots: PlayerSquadItem[];
    chars: { [key: string]: PlayerSandboxV3CurrentChar };
    food: { [key: string]: PlayerSandboxV3FoodInfo };
    maxRecruit: number;
    canRecruit: number;
    currentRecruit: string[];
    removeChar: string[];
    defend: PlayerSandboxV3DefendInfo;
    refreshPrice: number;
}

export interface PlayerSandboxV3FoodInfo {
    id: string;
    sub: string[];
}

export interface PlayerSandboxV3DefendInfo {
    mainIds: string[];
    otherIds: string[];
}

export interface PlayerSandboxV3CurrentInfo {
    idx: number;
    openTs: number;
    difficultyId: string;
    npcInstId: number;
    day: number;
    weather: string;
    windDir: SharedConsts_Direction;
    power: number;
    pros: number;
    aesth: number;
}

export interface SandboxV3CharSave {
    id: string;
    tmpId: string;
    position: GridPosition;
    direction: SharedConsts_Direction;
    hpRatio: FP;
    sp: number;
    createTime: FP;
    itemId: string;
}

export interface SandboxV3PredefinedLikeSave {
    inst: LevelData_PredefinedData_PredefinedCharacter;
    itemId: string;
    hpRatio: FP;
    sp: number;
    isPredefine: boolean;
}

export interface SandboxV3ItemSave {
    itemId: string;
    cnt: number;
}

export interface SandboxV3TaskOption {
    taskId: string;
    rewards: SandboxV3ItemSave[];
}

export interface SandboxV3TaskSave {
    current: SandboxV3TaskClaimedSave;
    options: SandboxV3TaskOption[];
    finished: string[];
    refreshTimes: number;
}

export interface SandboxV3TaskClaimedSave {
    taskId: string;
    rewards: SandboxV3ItemSave[];
    progress: number[];
}

export interface SandboxV3MilestoneSave {
    finishTimes: number;
    cache: SandboxV3MilestoneCache;
}

export interface SandboxV3MilestoneCache {
    recipes: string[];
    milestoneCfgId: string;
    refreshTimes: number;
    customWeight: { [key: string]: number };
}

export interface SandboxV3ResourceSave {
    gridPosition: GridPosition;
    deathTimes: number;
    remainResource: { [key: string]: number };
}

export interface SandboxV3EnemyDeathSave {
    actionId: SandboxV3ActionId;
    count: number;
}

export interface SandboxV3ImportantEnemySave {
    actionID: SandboxV3ActionId;
    id: string;
    hpRatio: FP;
    sp: FP;
    respawnCnt: number;
}

export interface SandboxV3RoomSave {
    index: number;
    pastFrameCnt: number;
    waveStartFrameCnt: number[];
}

export interface SandboxV3ProcessorRecipeSave {
    gridPosition: GridPosition;
    recipeIdx: number;
    isEnabled: boolean;
}

export interface SandboxV3LevelRandomSave {
    subIndex: number;
    actions: SandboxV3ActionId[];
}

export interface SandboxV3ServiceSave {
    gridPosition: GridPosition;
    recipeIdx: number;
    isAffecting: boolean;
}

export interface SandboxV3AnimalSave {
    animalId: string;
    gridPosition: GridPosition;
    hpRatio: FP;
    sp: FP;
}

export interface SummonEnemy {
    enemyId: string;
    count: number;
}

export interface SandboxV3SummonEnemiesSave {
    gridPosition: GridPosition;
    id: string;
    enemies: SummonEnemy[];
}

export interface SandboxV3ShopEntrySave {
    row: number;
    col: number;
}

export interface SandboxV3ActionId {
    subSchedulerI: number;
    waveI: number;
    fragmentI: number;
    actionI: number;
}

export interface PlayerSandboxV3CurrentSave {
    charSaves: SandboxV3CharSave[];
    resSaves: SandboxV3ResourceSave[];
    predefineLikeSave: SandboxV3PredefinedLikeSave[];
    roomSave: SandboxV3RoomSave[];
    enemyDeathSave: SandboxV3EnemyDeathSave[];
    importantEnemySave: SandboxV3ImportantEnemySave[];
    processorSaves: SandboxV3ProcessorRecipeSave[];
    levelRandomSaves: SandboxV3LevelRandomSave[];
    animalSaves: SandboxV3AnimalSave[];
    powerValue: number;
    decimalPowerValue: number;
    day: number;
    milestoneSave: SandboxV3MilestoneSave;
    taskSave: SandboxV3TaskSave;
    summonEnemiesSaves: SandboxV3SummonEnemiesSave[];
    relicSaves: { [key: string]: { [key: number]: number } };
    serviceSaves: SandboxV3ServiceSave[];
    showedPredefinedAlias: string[];
    prosperity: number;
    aesthetics: number;
    enemyDeathCountByLevel: { [key: number]: number };
    enemyDeathCountByTag: { [key: string]: number };
    shopEntryPos: SandboxV3ShopEntrySave;
}

export interface SandboxV3EffectData {
    rune: string[];
    shopRefreshDiscount: number;
    shopRefreshFree: number;
    shopSlotAdd: number;
    shopStockAdd: { [key: string]: number };
    shopDiscountRate: number;
    gapGainItem: { [key: string]: number };
    recipeRefreshDiscount: number;
    productAdd: { [key: string]: SandboxV3BattleProductData[] };
    trapDrop: { [key: string]: { [key: string]: SandboxV3BattleTrapDropData[] } };
    buildReturn: { [key: string]: number };
    taskRefreshAdd: number;
}

export interface SandboxV3BattleProductData {
    rate: number;
    add: number;
}

export interface SandboxV3BattleTrapDropData {
    rate: number;
    extra: string[];
}

export interface PlayerSandboxV3CurrentGame {
    nodeId: string;
    state: PlayerSandboxV3GameState;
    game: PlayerSandboxV3CurrentInfo;
    map: PlayerSandboxV3CurrentMap;
    band: PlayerSandboxV3CurrentBand;
    troop: PlayerSandboxV3CurrentTroop;
    shop: PlayerSandboxV3CurrentShop;
    dailyReport: PlayerSandboxV3CurrentDayPassSettlement;
    bag: PlayerSandboxV3CurrentBag;
    eventInfo: PlayerSandboxV3CurrentEvent;
    effect: SandboxV3EffectData;
    save: PlayerSandboxV3CurrentSave;
}

export interface PlayerSandboxV3Collect_Pending {
    achievement: { [key: string]: number[] };
}

export interface PlayerSandboxV3Collect_Complete {
    achievement: string[];
    quest: string[];
    music: string[];
}

export interface PlayerSandboxV3Collect {
    pending: PlayerSandboxV3Collect_Pending;
    complete: PlayerSandboxV3Collect_Complete;
}

export interface PlayerSandboxV2Summary {
    day: number;
    inChallenge: boolean;
    seasonType: number;
}

export interface PlayerSandboxV3Summary {
    baseLv: number;
    inCurrent: boolean;
}

export interface PlayerSandboxPerm_PlayerSandboxTemplateData {
    sandboxV2TemplateData: { [key: string]: PlayerSandboxV2 };
    sandboxV3TemplateData: { [key: string]: PlayerSandboxV3 };
    SANDBOX_V2: object;
    SANDBOX_V3: object;
}

export interface PlayerSandboxPerm_PlayerSandboxSummaryData {
    sandboxV2SummaryData: { [key: string]: PlayerSandboxV2Summary };
    sandboxV3SummaryData: { [key: string]: PlayerSandboxV3Summary };
    SANDBOX_V2: object;
    SANDBOX_V3: object;
}

export interface PlayerSandboxPerm {
    topic: string;
    template: PlayerSandboxPerm_PlayerSandboxTemplateData;
    isClose: boolean;
    loadTs: number;
    pin: string;
    summary: PlayerSandboxPerm_PlayerSandboxSummaryData;
}

export interface PlayerCrossAppShare_ShareMissionData {
    counter: number;
}

export interface PlayerCrossAppShare {
    shareMissions: { [key: string]: PlayerCrossAppShare_ShareMissionData };
}

export interface PlayerEmoticon {
    unlockTheme: string[];
}

export interface PlayerNameCardSkin_SkinState {
    unlock: boolean;
    progress: number[][];
    unlockTs: number;
}

export interface PlayerNameCardSkin {
    selected: string;
    state: { [key: string]: PlayerNameCardSkin_SkinState };
    tmpl: { [key: string]: number };
}

export interface PlayerNameCardMisc {
    showDetail: boolean;
    showBirthday: boolean;
}

export interface PlayerNameCardStyle {
    componentOrder: string[];
    skin: PlayerNameCardSkin;
    misc: PlayerNameCardMisc;
}

export interface PlayerTrainingCamp {
    stages: { [key: string]: PlayerTrainingCampStage };
}

export interface PlayerTrainingCampStage {
    stageId: string;
    state: number;
    rts: number;
}

export interface PlayerCharRotationSlot {
    charId: string;
    skinId: string;
    skinSp: boolean;
}

export interface PlayerCharRotationPreset {
    name: string;
    background: string;
    homeTheme: string;
    profile: string;
    profileSp: boolean;
    slots: PlayerCharRotationSlot[];
    profileInst: number;
}

export interface PlayerCharRotation {
    current: string;
    preset: { [key: string]: PlayerCharRotationPreset };
}

export interface PlayerGallery {
    firstRewards: boolean;
    leafMap: { [key: string]: PlayerArtMagazineLeafData };
    magazineSquad: string[];
    collectionRewards: { [key: string]: boolean };
    stickerMap: { [key: string]: number };
    offlineList: { [key: string]: { [key: string]: number } };
}

export interface PlayerArtMagazineLeafData {
    getTs: number;
    version: number;
    leafId: string;
    charSkin: string;
    decorList: string[];
}

export interface PlayerArkOdc {
    topics: { [key: string]: PlayerArkOdcTopic };
}

export interface PlayerArkOdcTopic_Position {
    x: number;
    y: number;
    z: number;
}

export interface PlayerArkOdcTopic {
    varSeqs: { [key: string]: number };
    rewards: { [key: string]: number };
    position: PlayerArkOdcTopic_Position;
}

export interface PlayerDataModel {
    ACTIVITY_FIELD: string;
    SANDBOX_PERM_FIELD: string;
    SANDBOX_PERM_TEMPLATE_FIELD: string;
    event: PlayerEvents;
    pushFlags: PlayerPushFlags;
    status: PlayerStatus;
    monthlySub: { [key: string]: PlayerMonthlySubPer };
    troop: PlayerTroop;
    dungeon: PlayerDungeon;
    checkIn: PlayerCheckIn;
    openServer: PlayerOpenServer;
    activity: PlayerActivity;
    templateTrap: PlayerTemplateTrap;
    retro: PlayerRetro;
    dexNav: PlayerDexNav;
    skin: PlayerSkins;
    medal: PlayerMedal;
    avatar: PlayerAvatar;
    collectionReward: PlayerCollection;
    equipment: PlayerEquipment;
    inventory: { [key: string]: number };
    consumable: { [key: string]: { [key: number]: PlayerConsumableItem } };
    ticket: { [key: string]: PlayerTicketItem };
    shop: PlayerShop;
    invite: { [key: string]: { [key: string]: PlayerInviteData } };
    tshop: { [key: string]: PlayerTemplateShop };
    recruit: PlayerRecruit;
    carousel: PlayerCarousel;
    gacha: PlayerGacha;
    social: PlayerSocial;
    mission: MissionPlayerData;
    building: PlayerBuilding;
    crisis: PlayerCrisis;
    crisisV2: PlayerCrisisV2;
    recalRune: PlayerRecalRune;
    storyreview: PlayerStoryReview;
    roguelike: PlayerRoguelike;
    rlv2: PlayerRoguelikeV2;
    backflow: PlayerReturnData;
    campaignsV2: PlayerCampaign;
    autochessSeason: PlayerAutoChessPerm;
    charm: CharmStatus;
    deepSea: PlayerDeepSea;
    car: PlayerCartInfo;
    tower: PlayerTower;
    siracusaMap: PlayerSiracusaMap;
    firework: PlayerFirework;
    sandboxPerm: PlayerSandboxPerm;
    emoticon: PlayerEmoticon;
    share: PlayerCrossAppShare;
    trainingGround: PlayerTrainingCamp;
    background: PlayerHomeBackground;
    homeTheme: PlayerHomeTheme;
    nameCardStyle: PlayerNameCardStyle;
    setting: PlayerSetting;
    aprilFool: PlayerAprilFool;
    npcAudio: { [key: string]: PlayerNpcWithAudio };
    charRotation: PlayerCharRotation;
    gallery: PlayerGallery;
    arkodc: PlayerArkOdc;
    mainline: PlayerMainlineRecord;
    limitedBuff: PlayerLimitedDropBuff;
    performanceStory: PlayerPerformanceStory;
    deleted: { [key: string]: object };
    checkMeta: { version: number; ts: number };
}

export interface FireworkData_PlateSlotData {
    id: string;
    idx: number;
}

export interface Blackboard {}

export interface SharedCharData_TmplData {
    skillIndex: number;
    skinId: string;
    selectEquip: string;
    equips: { [key: string]: SharedCharData_CharEquipInfo };
    overrideSkillIndex: number;
    overrideEquipId: string;
}

export interface SharedCharData_CharEquipInfo {
    locked: boolean;
    level: number;
}

export interface SharedCharData {
    charId: string;
    potentialRank: number;
    mainSkillLvl: number;
    evolvePhase: number;
    level: number;
    favorPoint: number;
    crisisRecord: { [key: string]: number };
    crisisV2Record: { [key: string]: number };
    currentTmpl: string;
    tmpl: { [key: string]: SharedCharData_TmplData };
    overrideSkillIndex: number;
    overrideEquipId: string;
}

export interface ItemBundle {
    id: string;
    count: number;
    type: ItemType;
}

export interface LevelData_PredefinedData_PredefinedCharacter {
    position: GridPosition;
    direction: SharedConsts_Direction;
}

export interface RoguelikeRecruitUpgradeCharacter {
    population: number;
    isAddition: number;
    isElite: number;
    isFree: number;
    upgradePhase: number;
    upgradeLimited: boolean;
}

export interface RoguelikeItemBundle {
    sub: number;
    id: string;
    count: number;
}

export interface RoguelikeShop {
    goods: RoguelikeGoods[];
}

export interface RoguelikeGoods {
    instId: string;
    itemId: string;
    count: number;
    priceId: string;
    priceCount: number;
}

export interface RoguelikeReward {
    index: string;
    items: RoguelikeItemBundle[];
    done: boolean;
    exDrop: boolean;
    exDropSrc: string;
}

export interface RoguelikeStageEarn {
    exp: number;
    populationMax: number;
    squadCapacity: number;
    hp: number;
    shield: number;
    maxHpUp: number;
}

export interface RoguelikeNodeLine {
    x: number;
    y: number;
    hidden: RoguelikeNodeLine_HiddenType;
    key: boolean;
}

export interface RoguelikeNodePosition {
    x: number;
    y: number;
}

export interface RoguelikeBuff {
    key: string;
    blackboard: Blackboard;
}

export interface FP {
    _serializedValue: number;
    MAX_VALUE: number;
    MIN_VALUE: number;
    NUM_BITS: number;
    FRACTIONAL_PLACES: number;
    ONE: number;
    TEN: number;
    HALF: number;
    PI_TIMES_2: number;
    PI: number;
    PI_OVER_2: number;
    LUT_SIZE: number;
    Precision: number;
    MaxValue: FP;
    MinValue: FP;
    One: FP;
    Ten: FP;
    Half: FP;
    Zero: FP;
    PositiveInfinity: FP;
    NegativeInfinity: FP;
    NaN: FP;
    EN1: FP;
    EN2: FP;
    EN3: FP;
    EN4: FP;
    EN5: FP;
    EN6: FP;
    EN7: FP;
    EN8: FP;
    Epsilon: FP;
    Pi: FP;
    PiOver2: FP;
    PiTimes2: FP;
    PiInv: FP;
    PiOver2Inv: FP;
    Deg2Rad: FP;
    Rad2Deg: FP;
    LutInterval: FP;
}

