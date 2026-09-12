/**
 * 自动生成的 excel 表类型定义文件
 * 从 reference/com.hypergryph.arknights_2.7.71.cs 反编译文件生成
 * （客户端表类闭包 + excel 协议适配 + JSON 实际键对照，见 scripts/excel-server-adapt.ts / excel-json-keys.ts）
 * 生成命令: pnpm run generate:types
 * 请勿手动修改此文件
 */
import type { JsonValue } from "./json-value";

export type SubProfessionAttackType = "NONE" | "PHYSICAL" | "MAGICAL" | "HEAL";

export type StageType = "MAIN" | "DAILY" | "TRAINING" | "ACTIVITY" | "GUIDE" | "SUB" | "CAMPAIGN" | "SPECIAL_STORY" | "HANDBOOK_BATTLE" | "CLIMB_TOWER" | "ENUM";

export type BattleDialogType = "NONE" | "BEFORE" | "REACT" | "AFTER" | "ENUM";

export type ActArchiveCopperType = "LUCK" | "COPPER" | "GILD";

export type RoguelikeCopperType = "NONE" | "BLANK" | "FIGHT" | "RESOURCE" | "UNSOUND" | "TREASURE" | "SPECIAL";

export type ActArchiveTotemType = "LOCATION" | "EFFECT" | "AFFIX";

export type Act12SideData_ActZoneClass = "NONE" | "NORMAL" | "HIGHLEVEL" | "SUB";

export type Act12SideData_RecycleDialogType = "NONE" | "EMPTY" | "LOW" | "MEDIUM" | "HIGH" | "GACHA";

export type Act12SideData_RecycleAnimationState = "NONE" | "NORMAL" | "SMILE";

export type Act13SideData_PrestigeRank = "D" | "C" | "B" | "A" | "S";

export type Act13SideData_ActZoneClass = "NONE" | "NORMAL" | "HIGHLEVEL" | "SUB";

export type Act13SideData_UnlockCondition = "NONE" | "PRESTIGE" | "STAGE";

export type Act17sideData_NodeType = "LANDMARK" | "STORY" | "BATTLE" | "ENDING" | "TREASURE" | "EVENT" | "TECH" | "CHOICE";

export type Act17sideData_TreasureType = "SMALL" | "SPECIAL";

export type Act17sideData_TrackPointType = "NONE" | "MAIN" | "SUB";

export type Act17sideData_ArchiveItemUnlockCondition = "NONE" | "STAGE" | "NODE";

export type Act17sideData_ArchiveItemStageUnlockParam = "NONE" | "PLAYED" | "PASS" | "COMPLETE";

export type Act17sideData_ChapterIconType = "NORMAL" | "EX" | "HARD";

export type Act1VHalfIdleItemType = "NONE" | "LEVEL_EXP" | "SKILL_EXP" | "STRATEGY_POINT" | "ASC" | "GACHA" | "MODEL" | "ACTIVITY_ITEM";

export type Act1VHalfIdleGachaPoolType = "NONE" | "GACHA_NORMAL" | "GACHA_NEWPLAYER" | "GACHA_PAC" | "GACHA_DIRECT";

export type Act1VHalfIdlePlotType = "NONE" | "LANDSCAPE" | "ROAD" | "ROADSIDE" | "SPECIAL";

export type Act1VHalfIdlePlotCombineType = "NONE" | "SINGLE" | "PLUS" | "PLUS_OR";

export type Act1VHalfIdleTechTreeNodeType = "NONE" | "NORMAL" | "DIFFICULTY";

export type HalfIdleTrapBuildableType = "NONE" | "HIGHLAND" | "LOWLAND" | "IGNORE_TILE_HEIGHT" | "LHHE" | "LHPLT" | "LHRUIN" | "LHBOT";

export type Act1VHalfIdleBattleItemType = "EQUIP" | "TRAP";

export type Act1VHalfIdleEquipType = "WEAPON" | "ARMOR" | "ACCESSORY" | "NUM";

export type CartComponents_CartAccessoryType = "NONE" | "ROOF" | "HEADSTOCK" | "TRUNK" | "CAR_OS";

export type CartComponents_CartAccessoryPos = "NONE" | "ROOF" | "HEADSTOCK" | "TRUNK_01" | "TRUNK_02" | "CAR_OS_01" | "CAR_OS_02";

export type SiracusaData_ZoneUnlockType = "NONE" | "STAGE_UNLOCK" | "TASK_UNLOCK";

export type SiracusaData_CardGainType = "NONE" | "STAGE_GAIN" | "TASK_GAIN";

export type SiracusaData_TaskRingLogicType = "NONE" | "LINEAR" | "AND" | "OR";

export type SiracusaData_TaskType = "NONE" | "BATTLE" | "AVG";

export type SiracusaData_NavigationType = "NONE" | "AVG" | "LEVEL" | "CHAR_CARD";

export type Act24SideData_MeldingGoodDisplayType = "NONE" | "RARE_1" | "RARE_2" | "RARE_3";

export type Act24SideData_MeldingGoodGachaType = "NONE" | "LIMITED" | "UNLIMITED";

export type Act24SideData_MissionType = "NONE" | "HUNTING_TASK" | "COLLECTION_TASK" | "EXPLORATION_TASK" | "MONSTER_TASK" | "INVATION_TASK";

export type Act24SideData_MeldingItemRarityType = "NONE" | "RARITY_1" | "RARITY_2" | "RARITY_3" | "RARITY_4" | "RARITY_5" | "RARITY_6";

export type Act25SideData_Act25SideArchiveItemType = "PIC" | "STORY" | "BATTLE_PERFORMANCE" | "KEY" | "ENUM";

export type Act25SideData_Act25SideArchiveItemUnlockType = "MISSION" | "STAGE" | "BUFF";

export type Act25SideData_Act25sideTechType = "TECH_1" | "TECH_2" | "TECH_3" | "TECH_4" | "TECH_NUM";

export type Act29SideData_Act29SideInvestType = "MAJOR" | "RARE" | "NORMAL";

export type Act29SideData_Act29SideProductType = "PRODUCT_TYPE_1" | "PRODUCT_TYPE_2" | "PRODUCT_TYPE_3" | "PRODUCT_TYPE_4" | "PRODUCT_TYPE_5" | "ENUM";

export type Act29SideData_Act29SideOrcheType = "ORCHE_1" | "ORCHE_2" | "ORCHE_3" | "ENUM";

export type Act35SideData_DialogueType = "NONE" | "ENTRY" | "BONUS" | "BUY" | "PROCESS";

export type Act35SideData_DialogueNameBgType = "NONE" | "GREEN" | "BLUE";

export type Act38SideData_NpcDialogType = "NONE" | "ENTER_PUZZLE" | "PLATE_ERROR" | "HINT_SUCC" | "HINT_FAIL" | "PUZZLE_SOLVED";

export type Act3D0Data_GoodType = "NORMAL" | "SPECIAL";

export type Act3D0Data_GachaBoxType = "LIMITED" | "UNLIMITED";

export type Act42D0Data_Act42D0AreaDifficulty = "NONE" | "NORMAL" | "HARD";

export type Act44SideData_InsightType = "PATIENCE" | "ATTENTION" | "TRUST";

export type MileStoneInfo_GoodType = "NORMAL" | "SPECIAL";

export type Act5D1Data_GoodType = "NORMAL" | "PROGRESS";

export type Act9D0Data_ActivityNewsLineType = "TextContent" | "ImageContent";

export type ActArcadeData_Rank = "B" | "A" | "S" | "SS" | "SSS";

export type ActArcadeData_SubModeType = "IGNORE" | "MINER" | "DRAW" | "LINE" | "CAR" | "E_NUM";

export type ActArcadeData_BadgeType = "COMMON" | "ZONE" | "ULTIMATE";

export type ActArkHubItemType = "NONE" | "ACTIVITY_COIN" | "COIN" | "ARKDEX" | "PIXEL";

export type ActArkHubModuleType = "NONE" | "ARKDEX" | "ARKPIXEL";

export type ActArkHubActorType = "FURNI" | "LOGIN_REWARDS" | "ARKDEX_DUEL" | "ARKDEX_PLAYER";

export type ActArkHubMenuType = "NONE" | "INVITE_FRIEND" | "MESSAGE" | "SETTING" | "ARKDEX_CREATURE" | "ARKDEX_ITEM" | "ARKDEX_ALBUM" | "ARKPIXEL" | "ARKDEX_TRADE";

export type ActArkHubNameCardState = "NONE" | "BATTLE" | "CAPTURE" | "MATCH" | "PIXEL" | "INTERACT";

export type SpineFlipMode = "INPUT" | "VELOCITY";

export type EasingType = "INSTANT" | "LINEAR" | "EASE_IN" | "EASE_OUT" | "EASE_IN_OUT" | "EXPONENTIAL";

export type TurningMode = "INSTANT" | "MOMENTUM";

export type ArkdexModeType = "NONE" | "ARKDEX_DUEL_SINGLEROUND" | "ARKDEX_DUEL_BO3" | "ARKDEX_DUEL_4PLAYER";

export type ArkDexNpcTileStrategy = "RANDOM" | "PREFER_NEAR_SELF" | "PREFER_FAR_SELF" | "RANGED_NEAR_MELEE_FAR" | "PREFER_MIDDLE" | "RANDOM_FROM_ALL";

export type ArkDexNpcCardStrategy = "RANDOM" | "FIXED_ORDER" | "PREFER_ELEMENT_0" | "PREFER_ELEMENT_1" | "PREFER_ELEMENT_2" | "PREFER_RANGED" | "PREFER_RARITY" | "COUNTER_PLAYER_MAJOR" | "COUNTERED_BY_PLAYER_MAJOR" | "BAG_MIN_ELEMENT" | "BAG_MAX_ELEMENT" | "RANDOM_FROM_ALL";

export type AutoChessEffectType = "NONE" | "BAND_INITIAL" | "ENEMY" | "ENEMY_TEMPORARY" | "ALLY" | "EQUIP" | "MAGIC" | "CHAR_MAP" | "BOND" | "ENEMY_GAIN" | "BUFF_GAIN" | "GARRISON";

export type AutoChessPrepareStepType = "NONE" | "INFO_CHECK" | "BAND_CHECK" | "BATTLE_CHECK";

export type AutoChessBondType = "NONE" | "REGULAR" | "SEASON";

export type AutoChessShopTokenDisplayType = "DEFAULT" | "HIDDEN";

export type AutoChessSkillTriggerType = "DEFAULT" | "ALWAYS" | "SEARCH" | "MLYSS_WTRMAN" | "MARCILS2" | "TRY_SEARCH_ENEMY_SKILL" | "TRY_SEARCH_ALLY_SKILL" | "CUSTOM_RANGE_SEARCH_ENEMY" | "CUSTOM_RANGE_SEARCH_ALLY" | "GDGLOW_SKILL_2" | "ACT_DEFAULT" | "AUTO_STOP" | "TAKE_DAMAGE";

export type AutoChessCountType = "NONE" | "BATTLE_LAYER" | "COUNTING" | "PROFESSIONS" | "GROUPS" | "LEVEL" | "PURCHASE";

export type AutoChessEffectCounterType = "NONE" | "TURN_COUNT" | "TRIGGER_COUNT" | "CHAR_COUNT" | "STACK_COUNT" | "COIN_JAR";

export type ActAutoChessModeType = "NONE" | "LOCAL" | "SINGLE" | "MULTI";

export type ActAutoChessModeDifficultyType = "NONE" | "TRAINING" | "FUNNY" | "NORMAL" | "HARD" | "ABYSS";

export type AutoChessEffectChoiceType = "EQUIP_FREE" | "EQUIP_PAID" | "BOUNTY_HUNT" | "BUFF_SELECT" | "PERSONAL_CHOOSE";

export type AutoChessItemType = "CHAR" | "EQUIP" | "MAGIC" | "TOKEN";

export type ActAutoChessBondActiveType = "BATTLE" | "ALL" | "MANI";

export type ActAutoChessBondActiveConditionType = "BOARD" | "BOARD_AND_DECK" | "DECK" | "BOARD_ALL_CHESS";

export type AutoChessBroadcastType = "NONE" | "GOLDEN_CHAR" | "SHOP_LEVEL" | "BOSS_HIT" | "CHAR_DAMAGE" | "CHAR_GIFT" | "BOND_EFFECT";

export type AutoChessChessType = "NORMAL" | "DIY" | "PRESET";

export type ActivityBossRushData_BossRushStageType = "NONE" | "NORMAL" | "TEAM" | "EX" | "SP";

export type VersusCheckInData_TasteType = "DRAW" | "SWEET" | "SALT";

export type ActivityCollectionData_JumpType = "NONE" | "ROGUE" | "CHAR_REPO";

export type EnemyDuelBetStrategy = "DEFAULT" | "CHOOSE_WIN" | "CHOOSE_ODD" | "FOLLOW_FEWER" | "FOLLOW_MORE" | "CHOOSE_ODD_ENEMY_COUNT" | "CHOOSE_EVEN_ENEMY_COUNT" | "ALWAYS_LEFT";

export type EnemyDuelModeType = "OPERATION" | "STAND";

export type ActivityInterlockData_InterlockStageType = "NONE" | "NORMAL" | "INTERLOCK" | "FINAL";

export type ActMultiV3PrepareStepType = "NONE" | "STAGE_CHOOSE" | "ENTRANCE" | "CHAR_PICK" | "SYS_ALLOC" | "SQUAD_CHECK";

export type ActMultiV3IdentityType = "NONE" | "HIGH" | "LOW" | "TEMPORARY" | "ALL";

export type ActMultiV3MapModeType = "NONE" | "NORMAL" | "FOOTBALL" | "DEFENCE" | "RAFT";

export type ActMultiV3MatchPosType = "NORMAL" | "COACH" | "STUDENT";

export type ActMultiV3MapDiffType = "NONE" | "TRAINING" | "ORDINARY" | "DIFFICULTY" | "EXTREMELY";

export type ActMultiV3BlockType = "NONE" | "START" | "END" | "MID";

export type ActMultiV3BlockDirType = "NONE" | "UP" | "RIGHT" | "DOWN" | "LEFT";

export type ActVecBreakV2ParticleType = "NONE" | "HARD";

export type ActVecBreakV2StageOrderType = "NONE" | "A" | "B" | "C" | "D";

export type FireworkData_FireworkDirectionType = "TWO_DIR" | "FOUR_DIR";

export type FireworkData_FireworkType = "RED" | "BLUE" | "YELLOW" | "GREEN";

export type ActivityType = "DEFAULT" | "MISSION_ONLY" | "CHECKIN_ONLY" | "CHECKIN_ALL_PLAYER" | "TYPE_ACT3D0" | "TYPE_ACT4D0" | "TYPE_ACT5D0" | "TYPE_ACT5D1" | "COLLECTION" | "AVG_ONLY" | "TYPE_ACT9D0" | "TYPE_ACT12SIDE" | "TYPE_ACT13SIDE" | "TYPE_ACT17SIDE" | "LOGIN_ONLY" | "MINISTORY" | "ROGUELIKE" | "PRAY_ONLY" | "MULTIPLAY" | "MULTIPLAY_VERIFY2" | "TYPE_ACT17D7" | "GRID_GACHA" | "GRID_GACHA_V2" | "INTERLOCK" | "APRIL_FOOL" | "BOSS_RUSH" | "TYPE_ACT20SIDE" | "FLOAT_PARADE" | "TYPE_ACT21SIDE" | "MAIN_BUFF" | "TYPE_ACT24SIDE" | "FLIP_ONLY" | "TYPE_ACT25SIDE" | "CHECKIN_VS" | "SWITCH_ONLY" | "TYPE_ACT27SIDE" | "UNIQUE_ONLY" | "MAINLINE_BP" | "TYPE_ACT42D0" | "TYPE_ACT29SIDE" | "BLESS_ONLY" | "CHECKIN_ACCESS" | "YEAR_5_GENERAL" | "TYPE_ACT35SIDE" | "VEC_BREAK" | "TYPE_ACT36SIDE" | "TYPE_ACT38SIDE" | "AUTOCHESS_VERIFY1" | "CHECKIN_VIDEO" | "ARCADE" | "MULTIPLAY_V3" | "TYPE_MAINSS" | "ENEMY_DUEL" | "VEC_BREAK_V2" | "TYPE_ACT42SIDE" | "TYPE_ACT44SIDE" | "HALFIDLE_VERIFY1" | "TYPE_ACT45SIDE" | "TEAM_QUEST" | "RECRUIT_ONLY" | "TYPE_ACT46SIDE" | "AUTOCHESS_SEASON" | "ARK_HUB" | "ACT_FOOTBALL" | "TYPE_ACT53SIDE" | "TYPE_ACT54SIDE" | "ACT_DP" | "ENUM";

export type ActivityDisplayType = "NONE" | "SIDESTORY" | "BRANCHLINE" | "MINISTORY";

export type ActivityCompleteType = "SPECIAL" | "CAN_COMPLETE" | "CANNOT_COMPLETE";

export type ActivityThemeType = "NONE" | "ACTIVITY" | "CRISIS" | "MAINLINE" | "ROGUELIKE" | "CRISISV2" | "SANDBOX_PERM" | "ACTIVITY_COMP";

export type Anniv7thDisplayNodeType = "LETTER" | "TYPE_WRITER" | "RECORD" | "SIGN";

export type Act4funStageAttributeType = "POS" | "NEG";

export type Act4funSuperChatType = "ROLLED" | "RELATED";

export type NpcStrategy = "DEFAULT" | "CHOOSE_WIN" | "CHOOSE_ODD" | "FOLLOW_FEWER" | "FOLLOW_MORE";

export type Act6FunAchievementType = "NORMAL" | "EX";

export type ArkventTaskActorType = "NONE" | "NPC" | "FURNITURE" | "TRIGGER" | "COLLIDER" | "VIRTUAL" | "NPC_SHOW_ONLY" | "FURNITURE_SHOW_ONLY" | "TRIGGER_SHOW_ONLY" | "SCENE_OBJECT_CONTROL" | "EFFECT" | "FLAG_EXPRESSION";

export type ArkventTaskActorTriggerType = "NONE" | "AUTO" | "ENTER" | "INTERACT" | "AUTO_ONCE";

export type ArkventTaskVarSeqCompareOperation = "NONE" | "GT" | "GE" | "EQ" | "NEQ" | "LE" | "LT";

export type ArkventCameraBlendStyle = "Default" | "Cut" | "EaseInOut" | "EaseIn" | "EaseOut" | "HardIn" | "HardOut" | "Linear";

export type ArkventSpineFaceType = "RIGHT" | "LEFT";

export type ArkventNPCSpineType = "BUILDING" | "ARKVENT";

export type AttributeModifierData_AttributeModifier_FormulaItemType = "ADDITION" | "MULTIPLIER" | "FINAL_ADDITION" | "FINAL_SCALER";

export type BuildingData_RoomCategory = "NONE" | "FUNCTION" | "OUTPUT" | "CUSTOM" | "ELEVATOR" | "CORRIDOR" | "SPECIAL" | "CUSTOM_P" | "ELEVATOR_P" | "CORRIDOR_P" | "ALL";

export type BuildingData_RoomType = "NONE" | "CONTROL" | "POWER" | "MANUFACTURE" | "SHOP" | "DORMITORY" | "MEETING" | "HIRE" | "ELEVATOR" | "CORRIDOR" | "TRADING" | "WORKSHOP" | "TRAINING" | "PRIVATE" | "FUNCTIONAL" | "ALL";

export type BuildingData_FurnitureCategory = "FURNITURE" | "WALL" | "FLOOR";

export type BuildingData_FurnitureType = "FLOOR" | "CARPET" | "SEATING" | "BEDDING" | "TABLE" | "CABINET" | "DECORATION" | "WALLPAPER" | "WALLDECO" | "WALLLAMP" | "CEILING" | "CEILINGLAMP" | "FUNCTION" | "INTERACT";

export type BuildingData_FurnitureSubType = "NONE" | "CHAIR" | "SOFA" | "BARSTOOL" | "STOOL" | "BENCH" | "ORTHER_S" | "POSTER" | "CURTAIN" | "BOARD_WD" | "SHELF" | "INSTRUMENT_WD" | "ART_WD" | "PLAQUE" | "CONTRACT" | "ANNIHILATION" | "ORTHER_WD" | "FLOORLAMP" | "PLANT" | "PARTITION" | "COOKING" | "CATERING" | "DEVICE" | "INSTRUMENT_D" | "ART_D" | "BOARD_D" | "ENTERTAINMENT" | "STORAGE" | "DRESSING" | "WARM" | "WASH" | "ORTHER_D" | "COLUMN" | "DECORATION_C" | "CURTAIN_C" | "DEVICE_C" | "CONTRACT_2" | "LIGHT" | "ORTHER_C" | "VISITOR" | "MUSIC";

export type BuildingData_FurnitureLocation = "NONE" | "WALL" | "FLOOR" | "CARPET" | "CEILING" | "POSTER" | "CEILINGDECAL";

export type BuildingData_FurnitureInteract = "NONE" | "ANIMATOR" | "MUSIC" | "FUNCTION";

export type BuildingData_FormulaItemType = "NONE" | "F_EVOLVE" | "F_BUILDING" | "F_GOLD" | "F_DIAMOND" | "F_FURNITURE" | "F_EXP" | "F_ASC" | "F_SKILL";

export type BuildingData_DiySortType = "NONE" | "THEME" | "FURNITURE" | "FURNITURE_IN_THEME" | "RECENT_THEME" | "RECENT_FURNITURE" | "MEETING_THEME" | "MEETING_FURNITURE" | "MEETING_FURNITURE_IN_THEME" | "MEETING_RECENT_THEME" | "MEETING_RECENT_FURNITURE";

export type BuildingData_DiyUISortOrder = "DESC" | "ASC";

export type BuildingData_LayoutData_StoreyData_Type = "UPGROUND" | "DOWNGROUND";

export type BuildingData_BuffCategory = "NONE" | "FUNCTION" | "OUTPUT" | "RECOVERY";

export type BuildingData_CharStationFilterType = "All" | "DormLock" | "NotStationed";

export type CampaignStageType = "NONE" | "PERMANENT" | "ROTATE" | "TRAINING";

export type CGGalleryCGSource = "IMAGE" | "BACKGROUND" | "ITEM";

export type CGGalleryCGCompositeType = "NONE" | "HORIZONTAL" | "VERTICAL" | "GRID";

export type CharacterData_PotentialRank_TypeEnum = "BUFF" | "CUSTOM";

export type CharmRarity = "NONE" | "LOW" | "MEDIUM" | "HIGH";

export type SpCharMissionCondType = "NONE" | "EVOLVE_PHASE";

export type CharMasterType = "NONE" | "SYSTEM" | "BATTLE";

export type CharWordShowType = "HOME_SHOW" | "HOME_PLACE" | "HOME_WAIT" | "GACHA" | "EVOLVE_ONE" | "EVOLVE_TWO" | "FOUR_STAR" | "THREE_STAR" | "TWO_STAR" | "LOSE" | "LEVEL_UP" | "SQUAD" | "SQUAD_FIRST" | "BATTLE_START" | "BATTLE_FACE_ENEMY" | "BATTLE_SELECT" | "BATTLE_PLACE" | "BATTLE_SKILL_1" | "BATTLE_SKILL_2" | "BATTLE_SKILL_3" | "BATTLE_SKILL_4" | "BUILDING_PLACE" | "BUILDING_DRAGGING" | "BUILDING_FAVOR_BUBBLE" | "BUILDING_TOUCHING" | "LOADING_PANEL" | "BIRTHDAY" | "NEW_YEAR" | "VALENT_DAY" | "DRAGON_BOAT_FESTIVAL" | "HALLOWEEN_DAY" | "CHRISMATS_DAY" | "GREETING" | "ANNIVERSARY" | "UNUSED" | "E_ALL";

export type CharWordVoiceType = "ONLY_TEXT" | "HAVE_CV" | "ENUM";

export type FestivalVoiceTimeType = "NONE" | "FESTIVAL" | "BIRTHDAY";

export type ClimbTowerLevelType = "NORMAL" | "HIGHLEVEL" | "BOSS";

export type ClimbTowerTaticalBuffType = "A" | "B";

export type ClimbTowerTowerType = "TRAINING" | "NORMAL";

export type ClimbTowerCardType = "SEASON" | "TOWER";

export type CrisisV2AppraiseType = "RANK_D" | "RANK_C" | "RANK_B" | "RANK_A" | "RANK_S" | "RANK_SS" | "RANK_SSS";

export type HomeMultiFormChangeRule = "NONE" | "TIME";

export type PlayerAvatarGroupType = "NONE" | "ASSISTANT" | "DEFAULT" | "SPECIAL" | "ACTIVITY" | "DYNAMIC";

export type NameCardV2ModuleType = "NONE" | "BACKGROUND" | "ILLUST" | "COLLECT" | "AVATAR" | "REMOVABLE" | "AVATAR_SIMPLE";

export type NameCardV2ModuleSubType = "NONE" | "SIGN" | "ASSIST" | "MEDAL" | "MAINLINE" | "EQUIPMENT";

export type NameCardV2SkinType = "NONE" | "BASE" | "SPECIAL" | "DYNAMIC";

export type MailArchiveItemType = "NORMAL" | "BIRTHDAY" | "OPEN_SERVER";

export type EmojiSceneType = "NONE" | "ACTMULTIV3_ROOM" | "ACTMULTIV3_PICK" | "ACTMULTIV3_BATTLE" | "ENEMYDUEL_BATTLE" | "AUTOCHESS_ROOM" | "AUTOCHESS_BATTLE" | "BUILDING_ACTION" | "ARKHUB_ROOM";

export type UIGuideTarget = "NONE" | "BUILDING_CONTROL" | "BUILDING_DORM" | "BUILDING_HIRE" | "BUILDING_MANUFACT" | "BUILDING_MEETING" | "BUILDING_TRADING" | "CHAR_INFO" | "FRIEND" | "RECRUIT" | "SHOP" | "SQUAD_NORMAL" | "SQUAD_BATTLE" | "STAGE_MAINLINE" | "BUILDING_POWER" | "MISSION" | "CHAR_SKILL_SELECT" | "BUILDING_WORKSHOP" | "STAGE_CAMPAIGN" | "CHAR_EVOLVE" | "HANDBOOK" | "BUILDING_FURN_SHOP" | "BUILDING_TRAINING" | "STAGE_ACTIVITY" | "CRISIS_STAGE" | "ROGUELIKE_CHARSELECT" | "ROGUELIKE_BP" | "CLIMB_TOWER_ENTRY" | "CLIMB_TOWER_LAYER" | "ROGUELIKE_DUNGEON" | "RL03_TOTEM" | "GROCERY" | "TUNING" | "CRISIS_V2" | "MISSION_ARCHIVE" | "FIFTH_ANNIV_EXPLORE" | "CARVING" | "VEC_BREAK" | "FIREWORK" | "BUILDING_STATION_MANAGE" | "ACT_MULTI_V3" | "ENEMY_DUEL" | "VEC_BREAK_V2" | "GUN_TASK" | "SPECIAL_OPERATOR" | "INFORMANT" | "ACT1VHALFIDLE" | "MONOPOLY" | "AUTO_CHESS" | "ART_GALLERY" | "ART_MAGAZINE" | "ACT_FOOTBALL" | "PIXEL_MAP" | "ARK_HUB" | "ARK_ODC" | "ACT54SIDE_CARD" | "ACT_VASEBREAKER";

export type KeyCodeType = "KEYBOARD" | "MOUSE";

export type KeySettingGroup = "BATTLE" | "NORMAL";

export type KeyEffectGroup = "BATTLE" | "OUT_BATTLE" | "ARKVENT" | "ALL";

export type CollectType = "ALL" | "ROGUE" | "SANDBOX";

export type MagazineLeafType = "DEFAULT" | "ROGUE" | "SANDBOX" | "AMIYA";

export type StickerType = "DEFAULT" | "ROGUE" | "SANDBOX" | "AMIYA";

export type EnemyLevelType = "NORMAL" | "ELITE" | "BOSS" | "E_NUM";

export type UniEquipTarget = "NONE" | "TRAIT" | "TRAIT_DATA_ONLY" | "TALENT" | "TALENT_DATA_ONLY" | "DISPLAY" | "OVERWRITE_BATTLE_DATA";

export type FifthAnnivExploreValueType = "TEAMVALUE_1" | "TEAMVALUE_2" | "TEAMVALUE_3";

export type GachaRuleType = "NORMAL" | "LIMITED" | "LINKAGE" | "ATTAIN" | "CLASSIC" | "SINGLE" | "FESCLASSIC" | "CLASSIC_ATTAIN" | "SPECIAL" | "DOUBLE" | "CLASSIC_DOUBLE" | "BACKFLOW";

export type DataUnlockType = "DIRECT" | "AWAKE" | "FAVOR" | "STAGE" | "ITEM" | "NEVER" | "PATCH" | "NONE";

export type IllustNPCResType = "NONE" | "NPC" | "CHAR";

export type HandbookDisplayCondition_DisplayType = "DISPLAY_IF_CHAREXIST" | "INVISIBLE_IF_CHAREXIST";

export type HotUpdateMetaPicData_PicType = "NONE" | "SKIN";

export type ItemType = "NONE" | "CHAR" | "CARD_EXP" | "MATERIAL" | "GOLD" | "EXP_PLAYER" | "TKT_TRY" | "TKT_RECRUIT" | "TKT_INST_FIN" | "TKT_GACHA" | "ACTIVITY_COIN" | "DIAMOND" | "DIAMOND_SHD" | "HGG_SHD" | "LGG_SHD" | "FURN" | "AP_GAMEPLAY" | "AP_BASE" | "SOCIAL_PT" | "CHAR_SKIN" | "TKT_GACHA_10" | "TKT_GACHA_PRSV" | "AP_ITEM" | "AP_SUPPLY" | "RENAMING_CARD" | "RENAMING_CARD_2" | "ET_STAGE" | "ACTIVITY_ITEM" | "VOUCHER_PICK" | "VOUCHER_CGACHA" | "VOUCHER_MGACHA" | "CRS_SHOP_COIN" | "CRS_RUNE_COIN" | "LMTGS_COIN" | "EPGS_COIN" | "LIMITED_TKT_GACHA_10" | "LIMITED_FREE_GACHA" | "REP_COIN" | "ROGUELIKE" | "LINKAGE_TKT_GACHA_10" | "VOUCHER_ELITE_II_4" | "VOUCHER_ELITE_II_5" | "VOUCHER_ELITE_II_6" | "VOUCHER_SKIN" | "RETRO_COIN" | "PLAYER_AVATAR" | "UNI_COLLECTION" | "VOUCHER_FULL_POTENTIAL" | "RL_COIN" | "RETURN_CREDIT" | "MEDAL" | "CHARM" | "HOME_BACKGROUND" | "EXTERMINATION_AGENT" | "OPTIONAL_VOUCHER_PICK" | "ACT_CART_COMPONENT" | "VOUCHER_LEVELMAX_6" | "VOUCHER_LEVELMAX_5" | "VOUCHER_LEVELMAX_4" | "VOUCHER_SKILL_SPECIALLEVELMAX_6" | "VOUCHER_SKILL_SPECIALLEVELMAX_5" | "VOUCHER_SKILL_SPECIALLEVELMAX_4" | "ACTIVITY_POTENTIAL" | "ITEM_PACK" | "SANDBOX" | "FAVOR_ADD_ITEM" | "CLASSIC_SHD" | "CLASSIC_TKT_GACHA" | "CLASSIC_TKT_GACHA_10" | "LIMITED_BUFF" | "CLASSIC_FES_PICK_TIER_5" | "CLASSIC_FES_PICK_TIER_6" | "RETURN_PROGRESS" | "NEW_PROGRESS" | "MCARD_VOUCHER" | "MATERIAL_ISSUE_VOUCHER" | "CRS_SHOP_COIN_V2" | "HOME_THEME" | "SANDBOX_PERM" | "SANDBOX_TOKEN" | "TEMPLATE_TRAP" | "NAME_CARD_SKIN" | "EMOTICON_SET" | "EXCLUSIVE_TKT_GACHA" | "EXCLUSIVE_TKT_GACHA_10" | "SO_CHAR_EXP" | "GIFTPACKAGE_TKT" | "VOUCHER_SKIN_V2" | "RANDOM_VOUCHER_SKIN" | "ACT1VHALFIDLE_ITEM" | "PLOT_ITEM" | "MAGAZINE_LEAF" | "STICKER" | "ARKHUB" | "LINKAGE_TKT_GACHA";

export type ItemRarity = "TIER_1" | "TIER_2" | "TIER_3" | "TIER_4" | "TIER_5" | "TIER_6" | "E_NUM";

export type OccPer = "ALWAYS" | "ALMOST" | "USUAL" | "OFTEN" | "SOMETIMES" | "NEVER" | "DEFINITELY_BUFF";

export type ItemClassifyType = "NONE" | "CONSUME" | "NORMAL" | "MATERIAL" | "MEMENTO";

export type ItemReslockStatus = "NOT_SUPPORT_RESLOCK" | "MAT_GACHA_RESLOCK_BLACKLIST" | "CHAR_POTENTIAL_BLACKLIST" | "COMMON_BLACKLIST" | "CAN_RESLOCK";

export type ItemDropShopType = "HGGSHD_SHOP" | "LGGSHD_SHOP" | "XSHD_SHOP" | "EPGS_SHOP" | "REP_SHOP" | "CLASSIC_SHOP";

export type VoucherDisplayType = "NONE" | "DIVIDE";

export type LevelData_Difficulty = "NONE" | "NORMAL" | "FOUR_STAR" | "EASY" | "SIX_STAR" | "ALL";

export type TileData_HeightTypeMask = "NONE" | "LOWLAND" | "HIGHLAND" | "ALL";

export type MedalRarity = "T1" | "T1D5" | "T2" | "T2D5" | "T3" | "T3D5";

export type MedalExpireType = "NONE" | "INIT" | "TEMP" | "PERM";

export type CommonUnlockType = "STAGECLEAR" | "HASCHAR" | "NONE";

export type MissionType = "UNKNOWN" | "MAIN" | "DAILY" | "WEEKLY" | "GUIDE" | "SUB" | "ACTIVITY" | "OPENSERVER" | "TOWERSEASON" | "RETRO" | "SPECIAL_OPERATOR" | "SPECIAL_OPERATOR_WEEKLY";

export type MissionItemBgType = "COMMON" | "Equipment" | "Char";

export type CrossAppShareMissionType = "NORMAL" | "ACTIVITY";

export type TemplateMissionBigRewardType = "NONE" | "ILLUST_CHAR_REWARD" | "CUSTOM" | "PIC_REWARD" | "SKIN_REWARD";

export type TemplateMissionTitleType = "COMMON" | "CUSTOM";

export type TemplateMissionCoinInfoType = "COMMON" | "CUSTOM";

export type RetroType = "SIDESTORY" | "BRANCHLINE";

export type ReturnMissionGroupType = "DAILY" | "NORMAL" | "DIFF";

export type ReturnJumpType = "NONE" | "ZONE_GROUP" | "ROGUE" | "CLIMB_TOWER" | "CAMPAIGN" | "BUILDING" | "RECRUIT_BUILD" | "DAILY_MISSION" | "SANDBOX" | "MAIN_SS";

export type ReturnNewsType = "NONE" | "MAIN_SS" | "ROGUE" | "SANDBOX";

export type ReturnAllOpenType = "RESOURCE" | "CAMP";

export type RoguelikeActivityType = "NONE" | "SEED_MODE";

export type RoguelikeItemType = "NONE" | "HP" | "GOLD" | "POPULATION" | "SQUAD_CAPACITY" | "RECRUIT_TICKET" | "UPGRADE_TICKET" | "RELIC" | "TOTEM_EFFECT";

export type RoguelikeItemRarity = "NONE" | "BORN" | "NORMAL" | "RARE" | "SUPER_RARE";

export type SanEffectRank = "SAN_EFFECT_0" | "SAN_EFFECT_1" | "SAN_EFFECT_2" | "SAN_EFFECT_3";

export type DiceResultClass = "VERYBAD" | "BAD" | "NORMAL" | "GOOD" | "GREAT" | "BEST";

export type DiceResultShowType = "RAW_TEXT" | "MUTATION" | "VIRTUE";

export type ChaosEffectRank = "CHAOS_EFFECT_0" | "CHAOS_EFFECT_1" | "CHAOS_EFFECT_2";

export type RoguelikeTotemColorType = "NONE" | "RED" | "GREEN" | "BLUE" | "ALL";

export type RoguelikeTotemPosType = "LOCATION" | "EFFECT";

export type RoguelikeTotemBlurNodeType = "NONE" | "BATTLE" | "NO_BATTLE";

export type RoguelikeVisionModuleData_VisionChoiceCheckType = "LOWER" | "UPPER";

export type RoguelikeFragmentType = "NONE" | "INSPIRATION" | "WISH" | "IDEA";

export type AlchemyPoolRarityType = "NONE" | "NORMAL" | "RARE" | "SUPER_RARE";

export type RoguelikeCopperLuckyLevel = "NONE" | "HIGH" | "MID" | "LOW";

export type RoguelikeCopperBuffType = "NONE" | "REFRESH" | "MOVE";

export type RoguelikeCopperDivineType = "NONE" | "DIVINE" | "EVENT";

export type RoguelikeCopperDivineResultType = "NONE" | "GOOD" | "NORMAL" | "BAD";

export type RoguelikeSkyZoneNodeType = "NONE" | "ORIGIN" | "BATTLE" | "TRIAL_GATE" | "INCIDENT" | "TREASURE" | "SHOP" | "SACRIFICE" | "ENTERTAINMENT" | "MARKET" | "BATTLE_HARD" | "INCIDENT_BOSS" | "INCIDENT_BOSS_ONLY" | "CHOICES" | "BATTLES";

export type RoguelikeScrapType = "ERROR" | "NONE" | "MOVE" | "GOODS" | "PASSIVE";

export type RoguelikeMoveScrapRangeType = "RANGE" | "FULL_MAP";

export type RoguelikeEventType = "NONE" | "BATTLE_NORMAL" | "BATTLE_ELITE" | "BATTLE_BOSS" | "SHOP" | "REST" | "INCIDENT" | "TREASURE" | "ENTERTAINMENT" | "UNKNOWN" | "WISH" | "SACRIFICE" | "EXPEDITION" | "BATTLE_SHOP" | "PORTAL" | "MISSION" | "STORY" | "STORY_HIDDEN" | "ALCHEMY" | "DUEL" | "STASHED_RECRUIT" | "SPECIAL_ZONE" | "SCRAP_SHOP" | "DOOR" | "FINAL" | "EVACUATE" | "EMPLOY" | "LIGHT" | "BATTLE_SAVAGE" | "EMPTY" | "BATTLES" | "CHOICES" | "EVENTS" | "ALL";

export type RoguelikeModuleType = "NONE" | "SANCHECK" | "DICE" | "CHAOS" | "TOTEMBUFF" | "VISION" | "FRAGMENT" | "DISASTER" | "NODE_UPGRADE" | "COPPER" | "WRATH" | "CANDLE" | "SKY" | "GRID_ZONE" | "WEATHER" | "SCRAP";

export type RoguelikeRewardExDropTagSrcType = "NONE" | "TREASURE" | "TOTEM" | "EXPLORE_TOOL" | "COPPER" | "EVIL_TEMPLE" | "TREASURE_MAP" | "LOOP_CHIP" | "STEP" | "GREED" | "GOLDEN_AGE";

export type RoguelikeBankRewardCountType = "HIGHEST_RECORD" | "TOTAL_SUM";

export type RoguelikeEnrollType = "DLC" | "REVIEW";

export type RoguelikeExpStyleConfigParam = "BATTLE_END_HP_LOSE_TEXT";

export type RoguelikeMonthChatTrigType = "NONE" | "TRANSITING" | "DUNGEON";

export type RoguelikeCharState = "NORMAL" | "UPGRADE" | "UPGRADE_BUFF" | "UPGRADE_BONUS" | "FREE" | "ASSIST" | "THIRD" | "MONTHLY" | "THIRD_LOW" | "MERCENARY";

export type RoguelikeTopicDevNodeType = "BRANCH" | "KEY" | "NONE";

export type RL02DevelopmentNodeType = "NONE" | "SMALL" | "NORMAL" | "LARGE_RHODES" | "LARGE_ABYSSAL" | "LARGE_IBERIA";

export type RL02DevelopmentEffectType = "BUFF" | "RAW_TEXT_EFFECT" | "RAW_TEXT_BAND" | "NONE";

export type RoguelikeTopicDevTokenDisplayForm = "ABSOLUTE_VAL" | "PERCENTAGE";

export type RoguelikeTopicDifficultyWarningType = "NONE" | "NORMAL" | "HARD";

export type RoguelikeTopicMode = "NONE" | "EASY" | "NORMAL" | "HARD" | "NORML_END" | "MONTH_TEAM" | "CHALLENGE";

export type RoguelikeChoiceDisplayType = "NONE" | "NORMAL" | "ITEM" | "TASK";

export type RoguelikeChoiceHintType = "NONE" | "ITEM" | "CANDLED_CHAR" | "GUIDED_CHAR" | "SACRIFICE" | "SACRIFICE_TOTEM" | "SACRIFICE_SCRAP" | "EXPEDITION" | "CANDLE" | "GUIDED" | "HP" | "VISION" | "STASHED_RECRUIT" | "SEED_COST" | "ITEM_COST" | "CHAOS" | "FRAGMENT" | "SP_ZONE_AP" | "COPPER_LUCK" | "AP_LEFT";

export type RoguelikeGameCharBuffType = "NONE" | "MUTATION" | "EVOLUTION" | "FROM_RELIC";

export type CustomTicketType = "NONE" | "PURIFY" | "GET_CANDLE";

export type RoguelikeGameItemType = "NONE" | "HP" | "HPMAX" | "GOLD" | "POPULATION" | "EXP" | "SQUAD_CAPACITY" | "RECRUIT_TICKET" | "UPGRADE_TICKET" | "RELIC" | "BP_POINT" | "GROW_POINT" | "BAND" | "ACTIVE_TOOL" | "CAPSULE" | "POOL" | "RL_BP" | "RL_GP" | "KEY_POINT" | "SAN_POINT" | "DICE_POINT" | "DICE_TYPE" | "SHIELD" | "LOCKED_TREASURE" | "CUSTOM_TICKET" | "TOTEM" | "TOTEM_EFFECT" | "FEATURE" | "VISION" | "CHAOS" | "CHAOS_PURIFY" | "CHAOS_LEVEL" | "EXPLORE_TOOL" | "FRAGMENT" | "MAX_WEIGHT" | "DISASTER" | "DISASTER_TYPE" | "ABSTRACT_DISASTER" | "PILL" | "BIGPILL" | "COPPER" | "COPPER_BUFF" | "DIVINATION_KIT" | "WRATH" | "SPECIAL_ZONE_AP" | "COPPER_DRAW_NUM" | "STASH_RECRUIT_LIMIT" | "NODE_BUOY" | "SCRAP" | "LEGACY" | "CHARACTER";

export type RoguelikeGameItemSubType = "NONE" | "CURSE" | "TEMP_TICKET" | "TOTEM_UPPER" | "TOTEM_LOWER" | "SECRET" | "SINGLE_RAND_FREE" | "RED_CAPSULE";

export type RoguelikeGameItemRarity = "NONE" | "BORN" | "NORMAL" | "RARE" | "SUPER_RARE";

export type RoguelikeGameMonthTaskClass = "NONE" | "C" | "B" | "A";

export type RoguelikeTopicBankRewardType = "NONE" | "UNLOCK_ITEM" | "ADD_SHOP_POS" | "UNLOCK_WITHDRAW" | "UNLOCK_SHOP_BATTLE" | "UNLOCK_SHOP_REFRESH";

export type RoguelikeGameChoiceType = "NONE" | "LEAVE" | "NEXT" | "NEXT_PROB" | "TRADE" | "TRADE_PROB" | "SACRIFICE" | "TELEPORT" | "EXPEDITION" | "WISH" | "TRADE_PROB_SHOW" | "SACRIFICE_TOTEM" | "WISH_ALL" | "KILL" | "USE_STASHED_TICKET" | "EXPEDITION_ALL" | "EXPEDITION_RETURN_ALL" | "PACIFY_WRATH" | "GILD_COPPER" | "ITEM_REROLL" | "ITEM_TOP_UP" | "GILD_COPPER_ALL" | "JUMP_PROB" | "JUMP" | "ZONE_END" | "MOVE" | "VISION" | "SCRAP_PAY_SHOW";

export type RoguelikeChoiceLeftDecoType = "NONE" | "TASK" | "TASK_REWARD" | "DICE" | "VISION";

export type RoguelikeGameVariationType = "NONE" | "MAP" | "RES" | "BAT";

export type RoguelikeGameRelicCheckType = "NONE" | "PROFESSION" | "SUB_PROFESSION" | "UPGRADE";

export type RoguelikeTaskRarity = "NORMAL" | "RARE" | "SUPER_RARE";

export type RoguelikeEndingDetailText_Type = "SHOW_CHOICE" | "SHOW_RELIC" | "SHOW_CAPSULE" | "SHOW_ACTIVE_TOOL" | "SHOW_ACCELERATE_CHAR" | "SHOW_NORMAL_RECRUIT" | "SHOW_DIRECT_RECRUIT" | "SHOW_FRIEND_RECRUIT" | "SHOW_FREE_RECRUIT" | "BUY" | "INVEST" | "SHOW_STAGE" | "SHOW_CONST" | "SUM" | "SHOW_BOSS_END" | "SHOW_BATTLE";

export type RL03DevelopmentNodeType = "NONE" | "NORMAL" | "KEY" | "DIFFICULTY";

export type RL03DevelopmentEffectType = "BUFF" | "RAW_TEXT_EFFECT" | "RAW_TEXT_BAND";

export type RoguelikeCommonDevelopmentNodeType = "NONE" | "NORMAL" | "KEY" | "DIFFICULTY";

export type RoguelikeCommonDevelopmentEffectType = "BUFF" | "RAW_TEXT_EFFECT" | "RAW_TEXT_BAND";

export type SandboxFoodAttribute = "NONE" | "SURVIVE" | "COST" | "ATTACK" | "COOLDOWN" | "SKILL_POINT" | "SPECIAL" | "ENHANCED" | "FUNCTION";

export type SandboxFoodMatType = "MAIN" | "SUB";

export type SandboxFoodVariantType = "NONE" | "ALPHA" | "BETA" | "GAMMA";

export type SandboxShopCoinType = "DIMENSION_COIN" | "GOLD" | "BASE_GOLD" | "BASE_GOLDEX";

export type SandboxDevelopmentType = "NONE" | "SURVIVE" | "COLLECT" | "SHOP" | "BATTLE" | "DUNGEON" | "EXPLORE" | "RESOURCE" | "INITIAL";

export type SandboxDevelopmentLineStyle = "EMPTY" | "LEVEL_PASS" | "LEVEL_BLOCK";

export type SandboxArchiveQuestType = "NONE" | "MAIN" | "SIDE";

export type SandboxV2NodeType = "NONE" | "HOME" | "HOME_OUTPOST" | "BATTLE" | "NEST" | "COLLECT" | "HUNT" | "CAVE" | "MINE" | "ENCOUNTER" | "EXPEDITION" | "SHOP" | "GATE" | "MARKET" | "HOME_PORTABLE" | "HOME_PORTABLE_RIFT" | "SELECTION" | "RACING";

export type SandboxV2TrapItemType = "NONE" | "BATTLE" | "TACTICAL" | "FUNCTION" | "ANIMAL";

export type SandboxV2ItemTrapTag = "OUTPUT" | "COLLECTION" | "IMPAIR" | "ENHANCE" | "EXPLORE" | "SPECTACLE" | "DECORATE" | "DEFEND" | "SCOUT";

export type SandboxV2WeatherType = "NORMAL" | "RAINFOREST" | "VOLCANO" | "DESERT";

export type SandboxV2SeasonType = "NONE" | "DRY" | "RAINY" | "CHALLENGE";

export type SandboxV2EnemyRushType = "NORMAL" | "ELITE" | "BOSS" | "BANDIT" | "RALLY" | "THIEF" | "MESSENGER" | "INSECT";

export type SandboxV2RacerTalentType = "BORN" | "LEARNED";

export type SandboxV2RacerNameType = "PREFIX" | "SUFFIX";

export type SandboxV2CraftItemType = "BASE_BUILDING" | "TACTICAL" | "COMBAT_BUILDING";

export type SandboxV2QuestRouteType = "NONE" | "ENEMY_RUSH" | "EVENT" | "NODE" | "NPC";

export type SandboxV2NpcType = "NORMAL" | "FIXED_RIFT" | "RANDOM_RIFT" | "PREY_RIFT";

export type SandboxV2QuestLineType = "NONE" | "MAIN" | "SIDE" | "GUIDE" | "TRAINING";

export type SandboxV2QuestLineBadgeType = "NONE" | "SIDE" | "GUIDE" | "MAIN" | "RIFT";

export type SandboxV2QuestLineScopeType = "MAIN" | "RIFT" | "ALL";

export type SandboxV2EventType = "NONE" | "EVENT" | "MISSION" | "QUEST_EVENT" | "QUEST_MISSION";

export type SandboxV2EventChoiceType = "NONE" | "NEXT" | "LEAVE" | "MISSION";

export type SandboxV2RiftMainTargetType = "NONE" | "FIND" | "BOSS_HUNT" | "WILD_HUNT" | "PROTECT" | "FIGHT" | "CATCH_THIEF" | "PREY_HUNT";

export type SandboxV2BaseUnlockFuncType = "NONE" | "HOME_PUTPOST" | "HOME_PORTABLE" | "REWARDSHOP" | "TECH" | "REAR" | "BUILD" | "SHOP" | "RACING";

export type SandboxV2BaseUnlockFuncDisplayType = "NONE" | "NEW" | "UPDATE" | "NUMBER";

export type SandboxV2ConfirmIconType = "COMMON" | "EMERGENCY" | "QUIT" | "EVACUATE" | "EVACUATELOSS" | "NORMAL" | "COMBAT" | "CONSTRUCT" | "NEXTDAY" | "RIFT_EXIT" | "LOAD_ARCHIVE";

export type SandboxV3MapTileType = "NONE" | "TEXTURE" | "BUILDING";

export type SandboxV3NodeType = "NONE" | "HOME" | "STORY" | "EXPLORE";

export type SandboxV3BasementUnlockFuncType = "NONE" | "HOME_PUTPOST" | "TECH" | "MAP";

export type SandboxV3BasementUnlockFuncDisplayType = "NONE" | "NEW" | "UPDATE" | "NUMBER";

export type SandboxV3NpcType = "NORMAL" | "BASE";

export type SandboxV3QuestLineBadgeType = "NONE" | "MAIN" | "SIDE" | "GUIDE";

export type SandboxV3ShopType = "NONE" | "REST" | "BATTLE";

export type SandboxV3MilestoneStage = "EARLY" | "MIDDLE" | "LATE";

export type SandboxV3TrapType = "PRODUCER" | "INFRASTRUCTURE" | "PROCESSOR" | "SERVICE" | "AESTHETICS" | "TACTICAL";

export type SandboxV3BaseTrapType = "NONE" | "PATH" | "AGRICULTURE" | "SETTLEMENT" | "PDLINE" | "DECORATION" | "OTHER";

export type SandboxV3BaseBuildType = "NONE" | "ROAD" | "CANAL" | "RAILWAY" | "PRODUCTION" | "HOUSE" | "POWER" | "BEAUTY";

export type ScoreGroupType = "WONDER" | "DEBRIS_CLEAN" | "NPC_RECRUIT" | "TRAP_BUILD" | "TRAP_RULE";

export type SandboxV3ElectricTransferType = "NONE" | "FUNCTION" | "SUPPLY" | "ADDITION" | "AMPLIFY";

export type SandboxV3BuildScoreType = "NONE" | "NPC" | "TRAP" | "LEVEL" | "ENPC";

export type SandboxV3BagItemType = "NONE" | "MATERIALBAG" | "RELICBAG";

export type SandboxV3EnemyRewardType = "NONE" | "ITEM" | "POWER" | "LUCKYDROP";

export type SandboxV3TaskDifficultyType = "NONE" | "EASY" | "NORMAL" | "HARD";

export type SandboxV3TaskType = "DEPLOY_TRAP_BY_GROUP" | "CONSTRUCT_TRAP_BY_GROUP" | "OWN_TRAP_BY_GROUP" | "OWN_TRAP_AND_DELIVER" | "OWN_TRAP_BY_TYPE" | "ITEM_DELIVERY" | "GATHER" | "KILL_ENEMY" | "KILL_ENEMY_FILTER_BY_TAG" | "KILL_ENEMY_FILTER_BY_LEVELTYPE" | "UNLOCK_ROOM_BY_MASK" | "UNLOCK_ROOM_CULMULATIVE" | "CATCH_ANIMAL" | "PROSPERITY_KEEP" | "AESTHETICS_REACH" | "PROSPERITY_REACH" | "AESTHETICS_INCREASE" | "PROSPERITY_INCREASE" | "TRADE_IN_SALE" | "CHARACTER_CHECK" | "RAILWAY_CHECK";

export type SandboxPermTemplateType = "NONE" | "SANDBOX_V2" | "SANDBOX_V3";

export type SandboxPermItemType = "NONE" | "TACTICAL" | "BUILDING" | "BUILDINGMAT" | "FOOD" | "FOODMAT" | "SPECIALMAT" | "COIN" | "CRAFT" | "PLACEHOLDER" | "STAMINAPOT" | "ANIMAL" | "INSECT" | "SLUGITEM" | "RELIC" | "RECIPE" | "PRODUCT" | "TOOLKIT" | "RANDRELIC" | "RANDRECIPE" | "CURRENCY" | "COOKBOOK" | "BASEBUILDING" | "BASECOIN" | "BASEANIMAL" | "BASETACTICAL" | "TECHPOINT";

export type ShopUnlockType = "ALWAYS_UNLOCK" | "SKIN_UNLOCK" | "FURN_UNLOCK" | "BOTH_SKIN_FURN";

export type ShopRouteTarget = "RECOMMENDSHOP" | "CASHSHOP" | "GIFTPACKAGE" | "SKINSHOP" | "HQCSHOP" | "LQCSHOP" | "EXQCSHOP" | "SOCAILSHOP" | "FURNSHOP" | "REPSHOP" | "LMGTSSHOP" | "EPGSSHOP" | "CLASSICSHOP" | "NONE";

export type ShopCondTrigPackageType = "NONE" | "RETURN_PROGRESS" | "RETURN_ONCE" | "NEW_PROGRESS" | "CHOOSE_REGISTER_TIME" | "CHOOSE_NEWBIE";

export type RecommendItemTagTips = "ONSALE" | "DEADLINE" | "NONE";

export type ShopRecommendTemplateType = "DEFAULT" | "NORSKIN" | "RETURNSKIN" | "NORFURN" | "NORGIFT";

export type ShopGPTabType = "DEFAULT_ALL" | "MONTH_CARD" | "PERM" | "NEWBIE" | "RETURN" | "RECOMMOND" | "TIMELY";

export type SkinVoiceType = "NONE" | "ILLUST" | "ALL";

export type SpecialOperatorTargetType = "NONE" | "ROGUE";

export type SpecialOperatorDetailNodeType = "NONE" | "EVOLVE" | "SKILL" | "TALENT" | "MASTER" | "UNIEQUIP";

export type SpecialOperatorConditionViewType = "TASK" | "EVOLVEPHASE";

export type StageDropType = "NONE" | "ONCE" | "NORMAL" | "SPECIAL" | "ADDITIONAL" | "APRETURN" | "DIAMOND_MATERIAL" | "FUNITURE_DROP" | "COMPLETE" | "CHARM_DROP" | "OVERRIDE_DROP" | "ITEM_RETURN" | "CONDITION_DROP" | "COMPLETE_ONLY";

export type AppearanceStyle = "MAIN_NORMAL" | "MAIN_PREDEFINED" | "SUB" | "TRAINING" | "HIGH_DIFFICULTY" | "MIST_OPS" | "SPECIAL_STORY";

export type FogType = "ZONE" | "STAGE";

export type StageButtonInFogRenderType = "HIDE" | "SHOW_WITH_FOG_SIX_STAR";

export type StageDiffGroup = "NONE" | "EASY" | "NORMAL" | "TOUGH" | "ALL";

export type StageData_PerformanceStageFlag = "NORMAL_STAGE" | "PERFORMANCE_STAGE";

export type StageData_SpecialStageUnlockProgressType = "ONCE" | "PROGRESS";

export type OverrideGameMode = "NONE" | "ACT27SIDE";

export type SixStarMilestoneRewardType = "UNLOCK_STAGE" | "REWARD";

export type SixStarStageCompatibleDropType = "COMPLETE_ONLY";

export type StoryData_Trigger_TriggerType = "GAME_START" | "BEFORE_BATTLE" | "AFTER_BATTLE" | "SWITCH_TO_SCENE" | "PAGE_LOADED" | "STORY_FINISH" | "CUSTOM_OPERATION" | "STORY_FINISH_OR_PAGE_LOADED" | "ACTIVITY_LOADED" | "ACTIVITY_ANNOUNCE" | "CRISIS_SEASON_LOADED" | "STORY_FINISH_OR_CUSTOM_OPERATION" | "E_NUM";

export type StorylineType = "CONTINUE" | "DISCRETE";

export type StorylineLocationType = "STORY_SET" | "BEFORE" | "AFTER" | "MAINLINE_SPLIT";

export type StorylineStorySetType = "MAINLINE" | "SS" | "COLLECT";

export type StoryReviewUnlockType = "STAGE_CLEAR" | "USE_ITEM" | "BY_START_TIME" | "NOTHING";

export type StoryReviewType = "NONE" | "ACTIVITY_STORY" | "MINI_STORY" | "MAIN_STORY";

export type StoryReviewEntryType = "NONE" | "ACTIVITY" | "MINI_ACTIVITY" | "MAINLINE";

export type MiniActTrialData_RuleType = "NONE" | "TITLE" | "CONTENT";

export type ActArchiveResData_ArchiveNewsLineType = "TextContent" | "ImageContent";

export type ActArchiveType = "NONE" | "TIMELINE" | "MUSIC" | "PIC" | "AVG" | "STORY" | "NEWS" | "BUFF" | "RELIC" | "CAPSULE" | "TRAP" | "CHAT" | "LANDMARK" | "LOG" | "ACTIVITY_ENTRY" | "DYNAMIC_MUSIC" | "DYNAMIC_PIC" | "ENDBOOK" | "DYNAMIC_STORY" | "TOTEM" | "CHAOS" | "CHALLENGE_BOOK" | "ACHIEVEMENT" | "QUEST" | "FRAGMENT" | "DISASTER" | "COPPER" | "WRATH" | "SCRAP" | "WEATHER";

export type ActArchivePicType = "IMAGE" | "BACKGROUND" | "ENDING_IMAGE" | "ROGUE_IMAGE";

export type TipData_Category = "NONE" | "BATTLE" | "UI" | "BUILDING" | "GACHA" | "MISC" | "ALL";

export type UniEquipType = "INITIAL" | "ADVANCED";

export type VoiceLangType = "NONE" | "JP" | "CN_MANDARIN" | "EN" | "KR" | "CN_TOPOLECT" | "LINKAGE" | "ITA" | "GER" | "RUS" | "FRE" | "SPA";

export type VoiceLangGroupType = "NONE" | "CN_MANDARIN" | "JP" | "EN" | "KR" | "CUSTOM" | "LINKAGE";

export type ZoneType = "NONE" | "MAINLINE" | "WEEKLY" | "ACTIVITY" | "GUIDE" | "TRAINING" | "CAMPAIGN" | "SIDESTORY" | "BRANCHLINE" | "ROGUELIKE" | "CLIMB_TOWER" | "MAINLINE_ACTIVITY" | "MAINLINE_RETRO";

export type WeeklyType = "NONE" | "MATERIAL" | "SPECIAL" | "EVOLVE";

export type MainlineZoneData_ZoneReplayBtnType = "NONE" | "RECAP" | "REPLAY";

export type RecordRewardStageDiff = "NONE" | "EASY" | "NORMAL" | "TOUGH" | "PREDEFINED" | "HARD";

export type Battle_SideType = "NONE" | "ALLY" | "ENEMY" | "BOTH_ALLY_AND_ENEMY" | "NEUTRAL" | "ALL";

export type AttributeType = "MAX_HP" | "ATK" | "DEF" | "MAGIC_RESISTANCE" | "COST" | "BLOCK_CNT" | "MOVE_SPEED" | "ATTACK_SPEED" | "BASE_ATTACK_TIME" | "RESERVED_0" | "RESERVED_1" | "RESERVED_2" | "RESERVED_3" | "HP_RECOVERY_PER_SEC" | "SP_RECOVERY_PER_SEC" | "ABILITY_RANGE_FORWARD_EXTEND" | "MAX_DEPLOY_COUNT" | "DEF_PENETRATE" | "MAGIC_RESIST_PENETRATE" | "HP_RECOVERY_PER_SEC_BY_MAX_HP_RATIO" | "TAUNT_LEVEL" | "RESPAWN_TIME" | "MAX_DECK_STACK_CNT" | "MASS_LEVEL" | "BASE_FORCE_LEVEL" | "DEF_PENETRATE_FIXED" | "ONE_MINUS_STATUS_RESISTANCE" | "MAGIC_RESIST_PENETRATE_FIXED" | "MAX_EP" | "EP_RECOVERY_PER_SEC" | "SP_RECOVER_RATIO" | "EP_DAMAGE_RESISTANCE" | "EP_RESISTANCE" | "DAMAGE_HITRATE_PHYSICAL" | "DAMAGE_HITRATE_MAGICAL" | "EP_BREAK_RECOVER_SPEED" | "SLOW_DOWN" | "BLOCK_RADIUS_SCALE" | "E_NUM";

export type AbnormalFlag = "STUNNED" | "SP_RECOVER_STOPPED" | "TARGET_FREE" | "BLOCK_FREE" | "HIDDEN" | "INVINCIBLE" | "UNDEADABLE" | "HEAL_FREE" | "UNBALANCE_IMMUNE" | "INVISIBLE" | "UNUSED_PLACEHOLDER_2" | "ALLY_TARGET_FREE" | "UNUSED_PLACEHOLDER_1" | "DISARMED" | "SILENCED" | "UNMOVABLE" | "FROZEN" | "CAMOUFLAGE" | "FORCE_DISARMED" | "STUNNED_NO_AMPLIFY_DAMAGE" | "DISABLE_COMBAT" | "ELEMENT_FREE_ALL" | "UNMOVABLE_PRIVATE" | "COLD" | "SKILL_NOT_ACTIVATABLE" | "LEVITATE" | "DURANCE" | "NOT_WITHDRAWABLE" | "OUT_OF_GROUND" | "SP_MODIFY_STOPPED" | "ANTI_STATUS_RESISTABLE" | "DISARMED_COMBAT" | "TOWER_TARGET_FREE" | "FEARED" | "SKILL_ACTIVABLE_IN_ABNORMAL" | "MOTION_TARGET_FREE" | "FORCE_LEVITATE" | "BUFF_ADD_CAN_BE_CANCELED_IF_DEFENSE" | "DEFENSE_BUFF_ADD_IF_CANCELABLE_BUFF" | "PALSY" | "PALSYING" | "ATTRACTED" | "FEARED_PRIVATE" | "DOZE" | "TELEPORTED" | "GROUND_BOUND" | "E_NUM";

export type AbnormalCombo = "SLEEPING" | "SHELTERING" | "E_NUM";

export type BuildableType = "NONE" | "MELEE" | "RANGED" | "ALL";

export type PlayerSideMask = "ALL" | "SIDE_A" | "SIDE_B" | "NONE";

export type SourceApplyWay = "NONE" | "MELEE" | "RANGED" | "ALL";

export type MotionMode = "WALK" | "FLY" | "E_NUM";

export type SpType = "NONE" | "INCREASE_WITH_TIME" | "INCREASE_WHEN_ATTACK" | "INCREASE_WHEN_TAKEN_DAMAGE" | "ATTACK_OR_DAMAGE" | "ALL";

export type SkillType = "PASSIVE" | "MANUAL" | "AUTO";

export type SkillDurationType = "NONE" | "AMMO";

export type PlayerStageState = "UNLOCKED" | "PLAYED" | "PASS" | "COMPLETE";

export type PlayerBattleRank = "FAIL" | "PASS" | "COMPLETE";

export type RarityRank = "TIER_1" | "TIER_2" | "TIER_3" | "TIER_4" | "TIER_5" | "TIER_6" | "E_NUM";

export type RarityRankMask = "NONE" | "TIER_1" | "TIER_2" | "TIER_3" | "TIER_4" | "TIER_5" | "TIER_6" | "ALL";

export type EvolvePhase = "PHASE_0" | "PHASE_1" | "PHASE_2" | "PHASE_3" | "E_NUM";

export type ProfessionID = "WARRIOR" | "SNIPER" | "TANK" | "MEDIC" | "SUPPORT" | "CASTER" | "SPECIAL" | "PIONEER" | "TOKEN" | "TRAP";

export type ProfessionCategory = "NONE" | "WARRIOR" | "SNIPER" | "TANK" | "MEDIC" | "SUPPORT" | "CASTER" | "SPECIAL" | "TOKEN" | "TRAP" | "PIONEER";

export type SharedConsts_Direction = "UP" | "RIGHT" | "DOWN" | "LEFT" | "E_NUM" | "INVALID";

export type ArkventAudioMetaFlag = "NONE" | "MUSIC" | "LOOP";

export type ArkventAudioTriggerMode = "NONE" | "ONE_SHOT" | "PERIODIC" | "EXIT";

export type ArkventAudioRollOffType = "LINEAR" | "LOGARITHMIC" | "THIRD_PARTY";

export type ArkventAudioSpatialType = "NONE" | "OFFSET_Z" | "DISTANCE";

export type ArkventRangeType = "NONE" | "CIRCLE" | "RECT";

export interface EPBreakBuffData {
    elementBreakDuration: number;
    enemyElementBreakDuration: number;
    elementBuffs: string[];
}

export interface ExtraBattleLogDataKey {
    description: string;
    sourceId: string;
    sourceMode: string;
    enemyId: string;
    enemyApplyWay: string;
    projectileName: string;
    abilityName: string;
    enemyLevelType: string;
    enemyTag: string[];
    logAlias: string;
}

export interface ExtraBattleLogData {
    data: ExtraBattleLogDataKey[];
    SELECTOR: JsonValue;
    DEATHDETAIL: JsonValue;
    PROJECTILEBORN: JsonValue;
    OUTPUT_DAMAGE_TOTAL: JsonValue;
}

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
    GRID_FOUR_WAYS: GridPosition[];
    GRID_EIGHT_WAYS: GridPosition[];
    ZERO: GridPosition;
    ONE: GridPosition;
    NEGATIVE_ONE: GridPosition;
    row: number;
    col: number;
}

export interface ActArchiveAvgData {
    avgs: { [key: string]: ActArchiveAvgItemData };
}

export interface ActArchiveAvgItemData {
    avgId: string;
    avgSortId: number;
}

export interface ActArchiveBuffData {
    buff: { [key: string]: ActArchiveBuffItemData };
}

export interface ActArchiveBuffItemData {
    buffId: string;
    buffGroupIndex: number;
    innerSortId: number;
    name: string;
    iconId: string;
    usage: string;
    desc: string;
    color: string;
}

export interface ActArchiveCapsuleData {
    capsule: { [key: string]: ActArchiveCapsuleItemData };
}

export interface ActArchiveCapsuleItemData {
    capsuleId: string;
    capsuleSortId: number;
    englishName: string;
    enrollId: string;
}

export interface ActArchiveChallengeBookItemData {
    storyId: string;
    sortId: number;
}

export interface ActArchiveChallengeBookData {
    stories: { [key: string]: ActArchiveChallengeBookItemData };
}

export interface ActArchiveChaosItemData {
    id: string;
    isHidden: boolean;
    enrollId: string;
    sortId: number;
}

export interface ActArchiveChaosData {
    chaos: { [key: string]: ActArchiveChaosItemData };
}

export interface ActArchiveChatData {
    chat: { [key: string]: ActArchiveChatGroupData };
}

export interface ActArchiveChatGroupData {
    sortId: number;
    chatItemList: ActArchiveChatItemData[];
}

export interface ActArchiveChatItemData {
    floor: number;
    chatZoneId: string;
    chatDesc: string;
    chatStoryId: string;
}

export interface ActArchiveCopperData {
    coppers: { [key: string]: ActArchiveCopperItemData };
    copperTypes: { [key: string]: ActArchiveCopperTypeData };
    gilds: { [key: string]: ActArchiveCopperGildData };
    luckyLevels: { [key: string]: ActArchiveCopperLuckyLevelData };
}

export interface ActArchiveCopperItemData {
    id: string;
    displayCopperId: string;
    archiveType: ActArchiveCopperType;
    copperType: RoguelikeCopperType;
    sortId: number;
    enrollId: string;
    coppersInGroup: string[];
}

export interface ActArchiveCopperTypeData {
    copperType: RoguelikeCopperType;
    typeName: string;
    typeIconId: string;
}

export interface ActArchiveCopperGildData {
    gildTypeId: string;
    gildName: string;
    gildDesc: string;
}

export interface ActArchiveCopperLuckyLevelData {
    luckyLevel: RoguelikeCopperLuckyLevel;
    luckyName: string;
    luckyDesc: string;
    luckyUsage: string;
}

export interface ActArchiveDisasterData {
    disasters: { [key: string]: ActArchiveDisasterItemData };
}

export interface ActArchiveDisasterItemData {
    disasterId: string;
    sortId: number;
    enrollConditionId: string;
    picSmallId: string;
    picBigActiveId: string;
    picBigInactiveId: string;
}

export interface ActArchiveEndbookData {
    endbook: { [key: string]: ActArchiveEndbookGroupData };
}

export interface ActArchiveEndbookGroupData {
    endId: string;
    endingId: string;
    sortId: number;
    title: string;
    cgId: string;
    backBlurId: string;
    cardId: string;
    hasAvg: boolean;
    avgId: string;
    clientEndbookItemDatas: ActArchiveEndbookItemData[];
}

export interface ActArchiveEndbookItemData {
    endBookId: string;
    sortId: number;
    enrollId: string;
    isLast: boolean;
    endbookName: string;
    unlockDesc: string;
    textId: string;
}

export interface ActArchiveFragmentData {
    fragment: { [key: string]: ActArchiveFragmentItemData };
}

export interface ActArchiveFragmentItemData {
    fragmentId: string;
    sortId: number;
    enrollConditionId: string;
}

export interface ActArchiveLandmarkItemData {
    landmarkId: string;
    landmarkSortId: number;
}

export interface ActArchiveChapterLogData {
    chapterName: string;
    displayId: string;
    unlockDes: string;
    logs: string[];
    chapterIcon: Act17sideData_ChapterIconType;
}

export interface ActArchiveMusicData {
    musics: { [key: string]: ActArchiveMusicItemData };
}

export interface ActArchiveMusicItemData {
    musicId: string;
    musicSortId: number;
}

export interface ActArchiveNewsData {
    news: { [key: string]: ActArchiveNewsItemData };
}

export interface ActArchiveNewsItemData {
    newsId: string;
    newsSortId: number;
}

export interface ActArchivePicData {
    pics: { [key: string]: ActArchivePicItemData };
}

export interface ActArchivePicItemData {
    picId: string;
    picSortId: number;
}

export interface ActArchiveRelicData {
    relic: { [key: string]: ActArchiveRelicItemData };
}

export interface ActArchiveRelicItemData {
    relicId: string;
    relicSortId: number;
    relicGroupId: number;
    orderId: string;
    isSpRelic: boolean;
    enrollId: string;
}

export interface ActArchiveScrapData {
    scraps: { [key: string]: ActArchiveScrapItemData };
}

export interface ActArchiveScrapItemData {
    scrapId: string;
    sortId: number;
    enrollConditionId: string;
}

export interface ActArchiveStoryData {
    stories: { [key: string]: ActArchiveStoryItemData };
}

export interface ActArchiveStoryItemData {
    storyId: string;
    storySortId: number;
}

export interface ActArchiveTimelineData {
    timelineList: ActArchiveTimelineItemData[];
}

export interface ActArchiveTimelineItemData {
    timelineId: string;
    timelineSortId: number;
    timelineTitle: string;
    timelineDes: string;
    picIdList: string[];
    audioIdList: string[];
    avgIdList: string[];
    storyIdList: string[];
    newsIdList: string[];
}

export interface ActArchiveTotemData {
    totem: { [key: string]: ActArchiveTotemItemData };
}

export interface ActArchiveTotemItemData {
    id: string;
    type: ActArchiveTotemType;
    enrollConditionId: string;
    sortId: number;
}

export interface ActArchiveTrapData {
    trap: { [key: string]: ActArchiveTrapItemData };
}

export interface ActArchiveTrapItemData {
    trapId: string;
    trapSortId: number;
    orderId: string;
    enrollId: string;
}

export interface ActArchiveWeatherData {
    weathers: { [key: string]: ActArchiveWeatherItemData };
}

export interface ActArchiveWeatherItemData {
    weatherId: string;
    sortId: number;
    enrollConditionId: string;
}

export interface ActArchiveWrathData {
    wraths: { [key: string]: ActArchiveWrathItemData };
}

export interface ActArchiveWrathItemData {
    wrathId: string;
    sortId: number;
    picTitleId: string;
    picSmallInactiveId: string;
    picSmallActiveId: string;
    picBigActiveId: string;
    picBigInactiveId: string;
    enrollId: string;
    isSp: boolean;
}

export interface Act12SideData {
    constData: Act12SideData_ConstData;
    zoneAdditionDataList: Act12SideData_ZoneAdditionData[];
    missionDescList: { [key: string]: Act12SideData_MissionDescInfo };
    mileStoneInfoList: Act12SideData_MileStoneInfo[];
    photoList: { [key: string]: Act12SideData_PhotoInfo };
    recycleDialogDict: { [key: string]: Act12SideData_RecycleDialogData[] };
}

export interface Act12SideData_ZoneAdditionData {
    zoneId: string;
    unlockText: string;
    zoneClass: Act12SideData_ActZoneClass;
}

export interface Act12SideData_ConstData {
    recycleRewardThreshold: number;
    charmRepoUnlockStageId: string;
    recycleLowThreshold: number;
    recycleMediumThreshold: number;
    recycleHighThreshold: number;
    autoGetCharmId: string;
    fogStageId: string;
    fogUnlockStageId: string;
    fogUnlockTs: number;
    fogUnlockDesc: string;
}

export interface Act12SideData_MissionDescInfo {
    zoneClass: Act12SideData_ActZoneClass;
    specialMissionDesc: string;
    needLock: boolean;
    unlockHint: string;
    unlockStage: string;
}

export interface Act12SideData_MileStoneInfo {
    mileStoneId: string;
    orderId: number;
    tokenNum: number;
    item: ItemBundle;
    isPrecious: boolean;
    mileStoneStage: number;
}

export interface Act12SideData_PhotoInfo {
    picId: string;
    picName: string;
    mileStoneId: string;
    picDesc: string;
    jumpStageId: string;
}

export interface Act12SideData_RecycleDialogData {
    dialogType: Act12SideData_RecycleDialogType;
    dialog: string;
    dialogExpress: Act12SideData_RecycleAnimationState;
}

export interface Act13SideData {
    constData: Act13SideData_ConstData;
    orgDataMap: { [key: string]: Act13SideData_OrgData };
    principalDataMap: { [key: string]: Act13SideData_PrincipalData };
    longTermMissionDataMap: { [key: string]: Act13SideData_LongTermMissionData };
    dailyMissionDataList: Act13SideData_DailyMissionData[];
    dailyRewardGroupDataMap: { [key: string]: Act13SideData_DailyMissionRewardGroupData };
    archiveItemUnlockData: { [key: string]: Act13SideData_ArchiveItemUnlockData };
    hiddenAreaData: { [key: string]: ActivityTable_ActivityHiddenAreaData };
    zoneAddtionDataMap: { [key: string]: Act13SideData_ZoneAdditionData };
}

export interface Act13SideData_ZoneAdditionData {
    unlockText: string;
    zoneClass: Act13SideData_ActZoneClass;
}

export interface Act13SideData_ConstData {
    prestigeDescList: string[];
    dailyRandomCount: number[][];
    dailyWeightInitial: number;
    dailyWeightComplete: number;
    agendaRecover: number;
    agendaMax: number;
    agendaHint: number;
    missionPoolMax: number;
    missionBoardMax: number;
    itemRandomList: ItemBundle[];
    unlockPrestigeCond: string;
    hotSpotShowFlag: number;
}

export interface Act13SideData_OrgData {
    orgId: string;
    orgName: string;
    orgEnName: string;
    openTime: number;
    principalIdList: string[];
    prestigeList: Act13SideData_PrestigeData[];
    agendaCount2PrestigeItemMap: { [key: number]: ItemBundle };
    orgSectionList: Act13SideData_OrgSectionData[];
    prestigeItem: ItemBundle;
}

export interface Act13SideData_PrincipalData {
    principalId: string;
    principalName: string;
    principalEnName: string;
    avgCharId: string;
    principalDescList: string[];
}

export interface Act13SideData_PrestigeData {
    rank: Act13SideData_PrestigeRank;
    threshold: number;
    reward: ItemBundle;
    newsCount: number;
    archiveCount: number;
    avgCount: number;
}

export interface Act13SideData_OrgSectionData {
    sectionName: string;
    sortId: number;
    groupData: Act13SideData_LongTermMissionGroupData;
}

export interface Act13SideData_LongTermMissionGroupData {
    groupId: string;
    groupName: string;
    orgId: string;
    missionList: string[];
}

export interface Act13SideData_LongTermMissionData {
    missionName: string;
    groupId: string;
    principalId: string;
    finishedDesc: string;
    sectionSortId: number;
    haveStageBtn: boolean;
    jumpStageId: string;
}

export interface Act13SideData_DailyMissionData {
    id: string;
    sortId: number;
    description: string;
    missionName: string;
    template: string;
    templateType: string;
    param: string[];
    rewards: MissionDisplayRewards[];
    orgPool: string[];
    rewardPool: string[];
    jumpStageId: string;
    agendaCount: number;
}

export interface Act13SideData_DailyMissionRewardGroupData {
    groupId: string;
    rewards: ItemBundle[];
}

export interface Act13SideData_ArchiveItemUnlockData {
    itemId: string;
    itemType: ActArchiveType;
    unlockCondition: Act13SideData_UnlockCondition;
    param1: string;
    param2: string;
}

export interface Act17sideData {
    placeDataMap: { [key: string]: Act17sideData_PlaceData };
    nodeInfoDataMap: { [key: string]: Act17sideData_NodeInfoData };
    landmarkNodeDataMap: { [key: string]: Act17sideData_LandmarkNodeData };
    storyNodeDataMap: { [key: string]: Act17sideData_StoryNodeData };
    battleNodeDataMap: { [key: string]: Act17sideData_BattleNodeData };
    treasureNodeDataMap: { [key: string]: Act17sideData_TreasureNodeData };
    eventNodeDataMap: { [key: string]: Act17sideData_EventNodeData };
    techNodeDataMap: { [key: string]: Act17sideData_TechNodeData };
    choiceNodeDataMap: { [key: string]: Act17sideData_ChoiceNodeData };
    eventDataMap: { [key: string]: Act17sideData_EventData };
    archiveItemUnlockDataMap: { [key: string]: Act17sideData_ArchiveItemUnlockData };
    techTreeDataMap: { [key: string]: Act17sideData_TechTreeData };
    techTreeBranchDataMap: { [key: string]: Act17sideData_TechTreeBranchData };
    mainlineChapterDataMap: { [key: string]: Act17sideData_MainlineChapterData };
    mainlineDataMap: { [key: string]: Act17sideData_MainlineData };
    zoneDataList: Act17sideData_ZoneData[];
    constData: Act17sideData_ConstData;
}

export interface Act17sideData_PlaceData {
    placeId: string;
    placeDesc: string;
    lockEventId: string;
    zoneId: string;
    visibleCondType: string;
    visibleParams: string[];
}

export interface Act17sideData_NodeInfoData {
    nodeId: string;
    nodeType: Act17sideData_NodeType;
    sortId: number;
    placeId: string;
    isPointPlace: boolean;
    chapterId: string;
    trackPointType: Act17sideData_TrackPointType;
    unlockCondType: string;
    unlockParams: string[];
}

export interface Act17sideData_LandmarkNodeData {
    nodeId: string;
    landmarkId: string;
    landmarkName: string;
    landmarkPic: string;
    landmarkSpecialPic: string;
    landmarkDesList: string[];
}

export interface Act17sideData_StoryNodeData {
    nodeId: string;
    storyId: string;
    storyKey: string;
    storyName: string;
    storyPic: string;
    confirmDes: string;
    storyDesList: string[];
}

export interface Act17sideData_BattleNodeData {
    nodeId: string;
    stageId: string;
}

export interface Act17sideData_TreasureNodeData {
    nodeId: string;
    treasureId: string;
    treasureName: string;
    treasurePic: string;
    treasureSpecialPic: string;
    endEventId: string;
    confirmDes: string;
    treasureDesList: string[];
    missionIdList: string[];
    rewardList: ItemBundle[];
    treasureType: Act17sideData_TreasureType;
}

export interface Act17sideData_EventNodeData {
    nodeId: string;
    eventId: string;
    endEventId: string;
}

export interface Act17sideData_TechNodeData {
    nodeId: string;
    techTreeId: string;
    techTreeName: string;
    techPic: string;
    techSpecialPic: string;
    endEventId: string;
    confirmDes: string;
    techDesList: string[];
    missionIdList: string[];
}

export interface Act17sideData_ChoiceNodeData {
    nodeId: string;
    choicePic: string;
    isDisposable: boolean;
    choiceSpecialPic: string;
    choiceName: string;
    choiceDesList: string[];
    cancelDes: string;
    choiceNum: number;
    optionList: Act17sideData_ChoiceNodeOptionData[];
}

export interface Act17sideData_ChoiceNodeOptionData {
    canRepeat: boolean;
    eventId: string;
    des: string;
    unlockDes: string;
    unlockCondType: string;
    unlockParams: string[];
}

export interface Act17sideData_EventData {
    eventId: string;
    eventPic: string;
    eventSpecialPic: string;
    eventTitle: string;
    eventDesList: string[];
}

export interface Act17sideData_ArchiveItemUnlockData {
    itemId: string;
    itemType: ActArchiveType;
    unlockCondition: Act17sideData_ArchiveItemUnlockCondition;
    nodeId: string;
    stageParam: Act17sideData_ArchiveItemStageUnlockParam;
    chapterId: string;
}

export interface Act17sideData_TechTreeData {
    techTreeId: string;
    sortId: number;
    techTreeName: string;
    defaultBranchId: string;
    lockDes: string;
}

export interface Act17sideData_TechTreeBranchData {
    techTreeBranchId: string;
    techTreeId: string;
    techTreeBranchName: string;
    techTreeBranchIcon: string;
    techTreeBranchDesc: string;
    runeData: RuneTable_PackedRuneData;
}

export interface Act17sideData_MainlineChapterData {
    chapterId: string;
    chapterDes: string;
    chapterIcon: Act17sideData_ChapterIconType;
    unlockDes: string;
    id: string;
}

export interface Act17sideData_MainlineData {
    mainlineId: string;
    nodeId: string;
    sortId: number;
    missionSort: string;
    zoneId: string;
    mainlineDes: string;
    focusNodeId: string;
}

export interface Act17sideData_ZoneData {
    zoneId: string;
    unlockPlaceId: string;
    unlockText: string;
}

export interface Act17sideData_ConstData {
    techTreeUnlockEventId: string;
}

export interface Act1VHalfIdleItemData {
    actId: string;
    itemId: string;
    itemType: Act1VHalfIdleItemType;
    itemName: string;
    sortId: number;
    iconId: string;
    funcDesc: string;
    flavorDesc: string;
    obtainApproach: string;
    showInInventory: boolean;
}

export interface Act1VHalfIdleGachaPoolData {
    poolId: string;
    itemId: string;
    poolType: Act1VHalfIdleGachaPoolType;
    sortId: number;
    name: string;
    charData: string[];
    consumeData: Act1VHalfIdleGachaPoolData_ConsumeData[];
}

export interface Act1VHalfIdleGachaPoolData_ConsumeData {
    gachaTimes: number;
    consume: number;
}

export interface Act1VHalfIdleGachaCharData {
    charId: string;
    isLinkageChar: boolean;
}

export interface Act1VHalfIdlePlotTypeData {
    plotType: Act1VHalfIdlePlotType;
    typeName: string;
    plotSquadLimit: { [key: string]: number[] };
}

export interface Act1VHalfIdlePlotData {
    plotId: string;
    plotName: string;
    plotType: Act1VHalfIdlePlotType;
    trapId: string;
    initUnlock: boolean;
    rarity: number;
    sortId: number;
    isBasePlot: boolean;
    iconId: string;
    funcDesc: string;
    flavorDesc: string;
    enemyIds: string[];
    enemyDesc: string;
    itemIdShown: string;
    itemDropData: Act1VHalfIdlePlotData_ItemDropData[];
    prevCombineData: Act1VHalfIdlePlotData_PlotCombineData;
    derivedPlots: string[];
}

export interface Act1VHalfIdlePlotData_ItemDropData {
    itemId: string;
    itemDropDesc: string;
}

export interface Act1VHalfIdlePlotData_PlotCombineData {
    combineType: Act1VHalfIdlePlotCombineType;
    plots: Act1VHalfIdlePlotData_PlotCombineData_CombineItemData[];
}

export interface Act1VHalfIdlePlotData_PlotCombineData_CombineItemData {
    plotId: string;
    plotCount: number;
}

export interface Act1VHalfIdleStageProductionData {
    stageId: string;
    fixedProduction: string[];
    productionData: { [key: string]: Act1VHalfIdleStageProductionData_ItemProductionData };
}

export interface Act1VHalfIdleStageProductionData_ItemProductionData {
    itemId: string;
    efficiencyMax: number;
    isFixed: boolean;
    maxDropValue: number;
}

export interface Act1VHalfIdleCharRankData {
    evolvePhase: EvolvePhase;
    expData: Act1VHalfIdleCharRankData_CharRankData[];
}

export interface Act1VHalfIdleCharRankData_CharRankData {
    level: number;
    accumulatedExp: number;
    exp: number;
}

export interface Act1VHalfIdleCharEvolveData {
    rarity: RarityRank;
    professionEvolveData: { [key: string]: Act1VHalfIdleCharEvolveData_ProfessionCharEvolveData };
}

export interface Act1VHalfIdleCharEvolveData_EvolveData {
    evolvePhase: EvolvePhase;
    itemId: string;
    itemCount: number;
    rebateItemId: string;
    rebateItemCount: number;
}

export interface Act1VHalfIdleCharEvolveData_ProfessionCharEvolveData {
    profession: ProfessionCategory;
    evolveData: { [key: string]: Act1VHalfIdleCharEvolveData_EvolveData };
}

export interface Act1VHalfIdleCharMaxRankData {
    rarity: RarityRank;
    maxRankData: { [key: string]: Act1VHalfIdleCharMaxRankData_MaxRankData };
    maxEvolvePhase: EvolvePhase;
}

export interface Act1VHalfIdleCharMaxRankData_MaxRankData {
    evolvePhase: EvolvePhase;
    maxLevel: number;
    maxSkillRank: number;
}

export interface Act1VHalfIdleCharSkillRankData {
    rarity: RarityRank;
    skillRankData: Act1VHalfIdleCharSkillRankData_SkillRankData[];
}

export interface Act1VHalfIdleCharSkillRankData_SkillRankData {
    skillLevel: number;
    cost: number;
    accumulatedCost: number;
}

export interface Act1VHalfIdleConstData {
    incomeProductionItems: string[];
    milestoneId: string;
    discount: number[];
    skillLevels: number[];
    levelExpItemId: string;
    skillExpItemId: string;
    normalStageIds: string[];
    hardStageIds: string[];
    techCostItemId: string;
    assistBaseNum: number;
    preloadEnemy: Act1VHalfIdleEnemyPreloadMeta[];
    preloadTrap: string[];
    defaultMaxDiscountSkillLevel: number;
    npcMaxDiscountSkillLevel: number;
    forbiddenAssistCharIds: string[];
    maxEvolvePhase: number;
    maxSafeEnemyDuration: number;
    overloadLoseLifePoint: number;
    trapModifyBossTriggerTime: number;
    normalEnemyOverloadCnt: number;
    eliteEnemyOverloadCnt: number;
    bossEnemyOverloadCnt: number;
    maxEquipNumInBag: number;
    bossBranchName: string;
    bossPreviewBranchName: string;
    enemyCapacityIdWhiteList: string[];
    unlockStageId: string;
    professionDesc: Act1VHalfIdleConstData_ProfessionDesc[];
    productMaxEfficiencyDict: { [key: string]: number };
    efficiencyDurationMax: number;
    produceCd: number;
    harvestHintThresholdTime: number;
    constRuneDatas: RuneTable_PackedRuneData[];
    milestoneTrackId: string;
    maxDeckCardNum: number;
    tutorialStageId: string;
    predefinedPlotIds: string[];
    predefinedCharIds: string[];
    enemyOverloadWarningRatio: number;
    battleFinishWarningTime: number;
    gachaNumMax: number;
    battleCustomTileHighlightColor: string;
    battleCustomTileEmissionColor: string;
    battleEquipLevelColors: string[];
    battleFailHintStr: string[];
    trapDropWeightStep: number;
    unlockSpecialPlot: string[];
    bossEnterBgmKey: string;
}

export interface Act1VHalfIdleConstData_ProfessionDesc {
    profession: ProfessionCategory;
    desc: string;
}

export interface Act1VHalfIdleEnemyPreloadMeta {
    enemyId: string;
    level: number;
}

export interface Act1VHalfIdleTrapMeta {
    trapType: Act1VHalfIdlePlotType;
    buildType: HalfIdleTrapBuildableType;
    skillIndex: number;
    dropWeight: number;
    defaultPlotId: string;
}

export interface Act1VHalfIdleEquipData {
    equipId: string;
    alias: string;
    iconId: string;
    name: string;
    level: number;
    equipType: Act1VHalfIdleEquipType;
    runeData: RuneTable_PackedRuneData;
}

export interface Act1VHalfIdleEnemyDropBundle {
    exp: number;
    mileStoneCnt: number;
    battleItemDropPool: string;
    resourceItemDropPool: string;
}

export interface Act1VBattleItemDropSlot {
    prob: number;
    itemPools: Act1VWeightedBattleItemPool[];
}

export interface Act1VWeightedResItemBundle {
    weight: number;
    resources: { [key: string]: number };
}

export interface Act1VWeightedBattleItemPool {
    poolKey: string;
    type: Act1VHalfIdleBattleItemType;
    weight: number;
}

export interface Act1VHalfIdleWeightedBattleEquip {
    weight: number;
    equipId: string;
    level: number;
    alias: string;
}

export interface Act1VHalfIdleDiagramData {
    width: number;
    height: number;
    pointPosDataMap: { [key: string]: Act1VHalfIdleDiagramData_PointPosData };
    linePosDataMap: { [key: string]: Act1VHalfIdleDiagramData_LinePosData };
    lineRelationDataMap: { [key: string]: Act1VHalfIdleDiagramData_LineRelationData };
    nodePointDataMap: { [key: string]: Act1VHalfIdleDiagramData_NodePointData };
}

export interface Act1VHalfIdleDiagramData_PointPosData {
    pos: JsonValue;
}

export interface Act1VHalfIdleDiagramData_LinePosData {
    startPos: JsonValue;
    endPos: JsonValue;
}

export interface Act1VHalfIdleDiagramData_LineRelationData {
    startPointList: string[];
    endPointList: string[];
}

export interface Act1VHalfIdleDiagramData_NodePointData {
    nodeId: string;
}

export interface Act1VHalfIdleTechTreeData {
    nodeId: string;
    nodeType: Act1VHalfIdleTechTreeNodeType;
    prevNodeId: string[];
    tokenCost: number;
    name: string;
    iconId: string;
    showPrevLockTips: boolean;
    effect: Act1VHalfIdleTechTreeData_Effect[];
}

export interface Act1VHalfIdleTechTreeData_Effect {
    desc: string;
    title: string;
    iconId: string;
    runeDatas: RuneTable_PackedRuneData[];
}

export interface Act1VHalfIdleMilestoneItemData {
    milestoneId: string;
    orderId: number;
    tokenNum: number;
    reward: ItemBundle;
    availTime: number;
}

export interface Act1VHalfIdleGachaPoolTypeData {
    poolType: Act1VHalfIdleGachaPoolType;
    typeName: string;
    desc: string;
    sortId: number;
}

export interface Act1VHalfIdleCharBuffInfo {
    id: string;
    level: number;
    charCount: number;
    desc: string;
    runeData: RuneTable_PackedRuneData;
}

export interface Act1VHalfIdleCharBuffData {
    prof: ProfessionCategory;
    buffInfos: Act1VHalfIdleCharBuffInfo[];
}

export interface Act1VHalfIdleData {
    gachaPoolData: { [key: string]: Act1VHalfIdleGachaPoolData };
    gachaCharData: { [key: string]: Act1VHalfIdleGachaCharData };
    plotTypeData: { [key: string]: Act1VHalfIdlePlotTypeData };
    plotData: { [key: string]: Act1VHalfIdlePlotData };
    stageProductionData: { [key: string]: Act1VHalfIdleStageProductionData };
    charRankData: { [key: string]: Act1VHalfIdleCharRankData };
    charEvolveData: { [key: string]: Act1VHalfIdleCharEvolveData };
    charMaxRankData: { [key: string]: Act1VHalfIdleCharMaxRankData };
    charSkillRankData: { [key: string]: Act1VHalfIdleCharSkillRankData };
    techTreeData: { [key: string]: Act1VHalfIdleTechTreeData };
    charBuffData: Act1VHalfIdleCharBuffData[];
    milestoneList: Act1VHalfIdleMilestoneItemData[];
    poolTypeData: Act1VHalfIdleGachaPoolTypeData[];
    stageIds: string[];
    zoneId: string;
    constData: Act1VHalfIdleConstData;
    diagramList: Act1VHalfIdleDiagramData[];
    enemyItemDropPoolDict: { [key: string]: Act1VHalfIdleEnemyDropBundle };
    battleItemPoolDict: { [key: string]: Act1VBattleItemDropSlot[] };
    resourceItemPoolDict: { [key: string]: Act1VWeightedResItemBundle[] };
    equipItemPoolDict: { [key: string]: Act1VHalfIdleWeightedBattleEquip[] };
    trapItemPoolDict: { [key: string]: string[] };
    equipItemData: { [key: string]: { [key: number]: Act1VHalfIdleEquipData[] } };
    trapMetaDict: { [key: string]: Act1VHalfIdleTrapMeta };
    plotShowCombineHighlightDict: { [key: string]: string[] };
}

export interface HalfIdleData {
    itemData: { [key: string]: Act1VHalfIdleItemData };
}

export interface CartData {
    carDict: { [key: string]: CartComponents };
    runeDataDict: { [key: string]: RuneTable_PackedRuneData };
    cartStages: string[];
    constData: CartData_CartConstData;
}

export interface CartData_CartConstData {
    carItemUnlockStageId: string;
    carItemUnlockDesc: string;
    spLevelUnlockItemCnt: number;
    mileStoneBaseInterval: number;
    spStageIds: string[];
    carFrameDefaultColor: string;
}

export interface CartComponents {
    compId: string;
    sortId: number;
    type: CartComponents_CartAccessoryType;
    posList: CartComponents_CartAccessoryPos[];
    posIdDict: { [key: string]: string[] };
    name: string;
    icon: string;
    showScores: number;
    itemUsage: string;
    itemDesc: string;
    itemObtain: string;
    rarity: number;
    detailDesc: string;
    price: number;
    specialObtain: string;
    obtainInRandom: boolean;
    additiveColor: string;
}

export interface Act20SideData {
    zoneAdditionDataMap: { [key: string]: string };
    residentCartDatas: { [key: string]: Act20SideData_ResidentCartData };
}

export interface Act20SideData_ResidentCartData {
    residentPic: string;
}

export interface SiracusaData {
    areaDataMap: { [key: string]: SiracusaData_AreaData };
    pointDataMap: { [key: string]: SiracusaData_PointData };
    charCardMap: { [key: string]: SiracusaData_CharCardData };
    taskRingMap: { [key: string]: SiracusaData_TaskRingData };
    taskInfoMap: { [key: string]: SiracusaData_TaskBasicInfoData };
    battleTaskMap: { [key: string]: SiracusaData_BattleTaskData };
    avgTaskMap: { [key: string]: SiracusaData_AVGTaskData };
    itemInfoMap: { [key: string]: SiracusaData_ItemInfoData };
    itemCardInfoMap: { [key: string]: SiracusaData_ItemCardInfoData };
    navigationInfoMap: { [key: string]: SiracusaData_NavigationInfoData };
    optionInfoMap: { [key: string]: SiracusaData_OptionInfoData };
    stagePointList: SiracusaData_StagePointInfoData[];
    storyBriefInfoDataMap: { [key: string]: SiracusaData_StoryBriefInfoData };
    operaInfoMap: { [key: string]: SiracusaData_OperaInfoData };
    operaCommentInfoMap: { [key: string]: SiracusaData_OperaCommentInfoData };
    constData: SiracusaData_ConstData;
}

export interface SiracusaData_ConstData {
    operaDailyNum: number;
    operaAllUnlockTime: number;
    defaultFocusArea: string;
}

export interface SiracusaData_AreaData {
    areaId: string;
    areaName: string;
    areaSubName: string;
    unlockType: SiracusaData_ZoneUnlockType;
    unlockStage: string;
    areaIconId: string;
    pointList: string[];
}

export interface SiracusaData_PointData {
    pointId: string;
    areaId: string;
    pointName: string;
    pointDesc: string;
    pointIconId: string;
    pointItaName: string;
}

export interface SiracusaData_CharCardData {
    charCardId: string;
    sortIndex: number;
    avgChar: string;
    avgCharOffsetY: number;
    charCardName: string;
    charCardItaName: string;
    charCardTitle: string;
    charCardDesc: string;
    fullCompleteDes: string;
    gainDesc: string;
    themeColor: string;
    taskRingList: string[];
    operaItemId: string;
    gainType: SiracusaData_CardGainType;
    gainParamList: string[];
}

export interface SiracusaData_TaskRingData {
    taskRingId: string;
    sortIndex: number;
    charCardId: string;
    logicType: SiracusaData_TaskRingLogicType;
    ringText: string;
    item: ItemBundle;
    isPrecious: boolean;
    taskIdList: string[];
}

export interface SiracusaData_TaskBasicInfoData {
    taskId: string;
    taskRingId: string;
    sortIndex: number;
    placeId: string;
    npcId: string;
    taskType: SiracusaData_TaskType;
}

export interface SiracusaData_BattleTaskData {
    taskId: string;
    stageId: string;
    battleTaskDesc: string;
    targetType: string;
    targetTemplate: string;
    targetParamList: string[];
}

export interface SiracusaData_AVGTaskData {
    taskId: string;
    taskAvg: string;
}

export interface SiracusaData_ItemInfoData {
    itemId: string;
    itemName: string;
    itemItalyName: string;
    itemDesc: string;
    itemIcon: string;
}

export interface SiracusaData_ItemCardInfoData {
    cardId: string;
    cardName: string;
    cardDesc: string;
    optionScript: string;
}

export interface SiracusaData_OptionInfoData {
    optionId: string;
    optionDesc: string;
    optionScript: string;
    optionGoToScript: string;
    isLeaveOption: boolean;
    needCommentLike: boolean;
    requireCardId: string;
}

export interface SiracusaData_NavigationInfoData {
    entryId: string;
    navigationType: SiracusaData_NavigationType;
    entryIcon: string;
    entryName: string;
    entrySubName: string;
}

export interface SiracusaData_StagePointInfoData {
    stageId: string;
    pointId: string;
    sortId: number;
    isTaskStage: boolean;
}

export interface SiracusaData_StoryBriefInfoData {
    storyId: string;
    stageId: string;
    storyInfo: string;
}

export interface SiracusaData_OperaInfoData {
    operaId: string;
    sortId: number;
    operaName: string;
    operaSubName: string;
    operaScore: string;
    unlockTime: number;
}

export interface SiracusaData_OperaCommentInfoData {
    commentId: string;
    referenceOperaId: string;
    columnIndex: number;
    columnSortId: number;
    commentTitle: string;
    score: string;
    commentContent: string;
    commentCharId: string;
}

export interface Act21SideData {
    zoneAdditionDataMap: { [key: string]: Act21SideData_ZoneAddtionData };
    constData: Act21SideData_ConstData;
}

export interface Act21SideData_ZoneAddtionData {
    zoneId: string;
    unlockText: string;
    stageUnlockText: string;
    entryId: string;
}

export interface Act21SideData_ConstData {
    lineConnectZone: string;
}

export interface QuestStageData {
    stageId: string;
    stageRank: number;
    sortId: number;
    isUrgentStage: boolean;
    isDragonStage: boolean;
}

export interface Act24SideData {
    toolDataList: { [key: string]: Act24SideData_ToolData };
    mealDataList: { [key: string]: Act24SideData_MealData };
    meldingDict: { [key: string]: Act24SideData_MeldingItemData };
    meldingGachaBoxDataList: { [key: string]: Act24SideData_MeldingGachaBoxData };
    meldingGachaBoxGoodDataMap: { [key: string]: Act24SideData_MeldingGachaBoxGoodData[] };
    mealWelcomeTxtDataMap: { [key: string]: string };
    zoneAdditionDataMap: { [key: string]: Act24SideData_ZoneAdditionData };
    questStageList: QuestStageData[];
    missionDataList: { [key: string]: Act24SideData_MissionExtraData };
    meldingDropDict: { [key: string]: StageData_StageDropInfo };
    stageMapPreviewDict: { [key: string]: string[] };
    huntDatabaseDict: { [key: string]: Act24SideData_HuntDatabaseData };
    stageIdToUnlockItemIdDict: { [key: string]: string };
    constData: Act24SideData_ConstData;
}

export interface Act24SideData_MeldingItemData {
    meldingId: string;
    bgId: string;
    sortId: number;
    meldingPrice: number;
    rarity: Act24SideData_MeldingItemRarityType;
}

export interface Act24SideData_ZoneAdditionData {
    zoneId: string;
    zoneIcon: string;
    unlockText: string;
    displayTime: string;
}

export interface Act24SideData_HuntDatabaseData {
    id: string;
    name: string;
    sortId: number;
    level: number;
    isBoss: boolean;
    bossPicId: string;
    iconSmallId: string;
    iconLargeId: string;
    basicDesc: string;
    rideIcon: string;
    rideDesc: string;
    secretTaskId: string;
    secretTaskItemId: string;
    secretTaskDesc: string;
    secretContent: string;
}

export interface Act24SideData_ConstData {
    stageUnlockToolDesc: string;
    mealLackMoney: string;
    mealDayTimesLimit: number;
    toolMaximum: number;
    stageCanNotUseToTool: string[];
    hunterGuideRewardItemId: string;
    hunterGuideRewardItemType: string;
    hunterGuideRewardItemCount: number;
    hunterGuideDetailTabPosition: number;
    taskRewardItemNoIconDisplayId: string;
    specialLevelUnlockTaskId: string;
    missionProgressFormat: string;
    gachaDefaultProb: number;
    gachaExtraProb: number;
}

export interface Act24SideData_ToolData {
    toolId: string;
    sortId: number;
    toolName: string;
    toolDesc: string;
    toolIcon1: string;
    toolIcon2: string;
    toolUnlockDesc: string;
    toolBuffId: string;
    runeData: RuneTable_PackedRuneData;
    toolStageId: string;
}

export interface Act24SideData_MealData {
    mealId: string;
    sortId: number;
    mealName: string;
    mealEffectDesc: string;
    mealDesc: string;
    mealIcon: string;
    mealCost: number;
    mealRewardAP: number;
    mealRewardItemInfo: ItemBundle;
}

export interface Act24SideData_MeldingGachaBoxData {
    gachaBoxId: string;
    gachaSortId: number;
    gachaIcon: string;
    gachaBoxName: string;
    gachaCost: number;
    gachaTimesLimit: number;
    themeColor: string;
    remainItemBgColor: string;
}

export interface Act24SideData_MeldingGachaBoxGoodData {
    goodId: string;
    gachaBoxId: string;
    orderId: number;
    itemId: string;
    itemType: ItemType;
    displayType: Act24SideData_MeldingGoodDisplayType;
    perCount: number;
    totalCount: number;
    gachaType: Act24SideData_MeldingGoodGachaType;
    weight: number;
    gachaOrderId: number;
    gachaNum: number;
}

export interface Act24SideData_MissionExtraData {
    taskTypeName: string;
    taskTypeIcon: string;
    taskType: Act24SideData_MissionType;
    taskTitle: string;
    taskClient: string;
    taskClientDesc: string;
}

export interface Act25SideData {
    tokenItemId: string;
    constData: Act25SideData_ConstData;
    zoneDescList: { [key: string]: Act25SideData_ZoneDescInfo };
    archiveItemData: { [key: string]: Act25SideData_ArchiveItemData };
    arcMapInfoData: { [key: string]: Act25SideData_ArchiveMapInfoData };
    areaInfoData: { [key: string]: Act25SideData_AreaInfoData };
    areaMissionData: { [key: string]: Act25SideData_AreaMissionData };
    battlePerformanceData: { [key: string]: Act25SideData_BattlePerformanceData };
    keyData: { [key: string]: Act25SideData_KeyData };
    fogUnlockData: { [key: string]: Act25SideData_FogUnlockData };
    farmList: Act25SideData_DailyFarmData[];
}

export interface Act25SideData_ZoneDescInfo {
    zoneId: string;
    unlockText: string;
    displayStartTime: number;
}

export interface Act25SideData_ArchiveMapInfoData {
    objectId: string;
    type: Act25SideData_Act25SideArchiveItemType;
    numberId: string;
    areaId: string;
    sortId: number;
    position: number;
    hasDot: boolean;
}

export interface Act25SideData_ArchiveItemData {
    itemId: string;
    itemType: Act25SideData_Act25SideArchiveItemType;
    itemUnlockType: Act25SideData_Act25SideArchiveItemUnlockType;
    itemUnlockParam: string;
    unlockDesc: string;
    iconId: string;
    itemName: string;
}

export interface Act25SideData_AreaInfoData {
    areaId: string;
    sortId: number;
    areaIcon: string;
    areaName: string;
    unlockText: string;
    preposedStage: string;
    areaInitialDesc: string;
    areaEndingDesc: string;
    areaEndingAud: string;
    reward: ItemBundle;
    finalId: string;
    areaNewIcon: boolean;
}

export interface Act25SideData_AreaMissionData {
    id: string;
    areaId: string;
    preposedMissionId: string;
    sortId: number;
    isZone: boolean;
    stageId: string;
    costCount: number;
    transform: number;
    progress: number;
    progressPicId: string;
    template: string;
    templateType: number;
    desc: string;
    param: string[];
    rewards: ItemBundle[];
    archiveItems: string[];
}

export interface Act25SideData_BattlePerformanceData {
    itemId: string;
    sortId: number;
    itemName: string;
    itemIcon: string;
    itemDesc: string;
    itemTechType: Act25SideData_Act25sideTechType;
    runeData: RuneTable_PackedRuneData;
}

export interface Act25SideData_KeyData {
    keyId: string;
    keyName: string;
    keyIcon: string;
    toastText: string;
}

export interface Act25SideData_FogUnlockData {
    lockId: string;
    lockedCollectionIconId: string;
    unlockedCollectionIconId: string;
}

export interface Act25SideData_ConstData {
    getDailyCount: number;
    costName: string;
    costDesc: string;
    costLimit: number;
    rewardLimit: number;
    researchUnlockText: string;
    harvestReward: ItemBundle;
    costCount: number;
    costCountLimit: number;
    basicProgress: number;
    harvestDesc: string;
}

export interface Act25SideData_DailyFarmData {
    transform: number;
    unitTime: number;
}

export interface Act27SideData {
    goodDataMap: { [key: string]: Act27SideData_Act27SideGoodData };
    mileStoneList: Act27SideData_Act27SideMileStoneData[];
    goodLaunchDataList: Act27SideData_Act27SideGoodLaunchData[];
    shopDataMap: { [key: string]: Act27SideData_Act27SideShopData };
    inquireDataList: Act27SideData_Act27SideInquireData[];
    dynEntrySwitchData: Act27SideData_Act27SideDynEntrySwitchData[];
    zoneAdditionDataMap: { [key: string]: Act27SideData_Act27sideZoneAdditionData };
    constData: Act27SideData_Act27SideConstData;
}

export interface Act27SideData_Act27SideGoodData {
    id: string;
    name: string;
    typeDesc: string;
    iconId: string;
    launchIconId: string;
    purchasePrice: number[];
    sellingPriceList: number[];
    sellShopList: string[];
    isPermanent: boolean;
}

export interface Act27SideData_Act27SideMileStoneData {
    mileStoneId: string;
    mileStoneLvl: number;
    needPointCnt: number;
    rewardItem: ItemBundle;
}

export interface Act27SideData_Act27SideGoodLaunchData {
    groupId: string;
    startTime: number;
    stageId: string;
    code: string;
    drinkId: string;
    foodId: string;
    souvenirId: string;
}

export interface Act27SideData_Act27SideShopData {
    shopId: string;
    sortId: number;
    name: string;
    iconId: string;
}

export interface Act27SideData_Act27SideInquireData {
    mileStonePt: number;
    inquireCount: number;
}

export interface Act27SideData_Act27SideMileStoneFurniRewardData {
    furniId: string;
    pointNum: number;
}

export interface Act27SideData_Act27SideConstData {
    stageId: string;
    stageCode: string;
    purchasePriceName: string[];
    furniRewardList: Act27SideData_Act27SideMileStoneFurniRewardData[];
    prizeText: string;
    playerShopId: string;
    milestonePointName: string;
    inquirePanelTitle: string;
    inquirePanelDesc: string;
    gain123: number[];
    gain113: number[];
    gain122: number[];
    gain111: number[];
    gain11None: number[];
    gain12None: number[];
    campaignEnemyCnt: number;
}

export interface Act27SideData_Act27SideDynEntrySwitchData {
    entryId: string;
    startHour: number;
    signalId: string;
}

export interface Act27SideData_Act27sideZoneAdditionData {
    zoneId: string;
    unlockText: string;
    displayTime: string;
}

export interface Act29SideData {
    fragDataMap: { [key: string]: Act29SideData_Act29SideFragData };
    orcheDataMap: { [key: string]: Act29SideData_Act29SideOrcheData };
    productGroupDataMap: { [key: string]: Act29SideData_Act29SideProductGroupData };
    productDataMap: { [key: string]: Act29SideData_Act29SideProductData };
    formDataMap: { [key: string]: Act29SideData_Act29SideFormData };
    investResultDataMap: { [key: string]: Act29SideData_Act29SideInvestResultData };
    investDataMap: { [key: string]: Act29SideData_Act29SideInvestData };
    majorInvestIdList: string[];
    rareInvestIdList: string[];
    constData: Act29SideData_Act29SideConstData;
    zoneAdditionDataMap: { [key: string]: Act29SideData_Act29SideZoneAdditionData };
    musicDataMap: Act29SideData_Act29SideMusicData[];
}

export interface Act29SideData_Act29SideFragData {
    fragId: string;
    sortId: number;
    fragName: string;
    fragIcon: string;
    fragStoreIcon: string;
}

export interface Act29SideData_Act29SideOrcheData {
    id: string;
    name: string;
    desc: string;
    icon: string;
    sortId: number;
    orcheType: Act29SideData_Act29SideOrcheType;
}

export interface Act29SideData_Act29SideProductGroupData {
    groupId: string;
    groupName: string;
    groupIcon: string;
    groupDesc: string;
    defaultBgmSignal: string;
    productList: string[];
    groupEngName: string;
    groupSmallName: string;
    groupTypeIcon: string;
    groupStoreIconId: string;
    groupTypeBasePic: string;
    groupTypeEyeIcon: string;
    groupSortId: number;
    formList: string[];
    sheetId: string;
    sheetNum: number;
    sheetRotateSpd: number;
    productType: Act29SideData_Act29SideProductType;
    productDescColor: string;
    playTintColor: string;
    confirmTintColor: string;
    confirmDescColor: string;
    bagThemeColor: string;
}

export interface Act29SideData_Act29SideProductData {
    id: string;
    orcheId: string;
    groupId: string;
    formId: string;
    musicId: string;
}

export interface Act29SideData_Act29SideFormData {
    formId: string;
    fragIdList: string[];
    formDesc: string;
    productIdDict: { [key: string]: string };
    withoutOrcheProductId: string;
    groupId: string;
    formSortId: number;
}

export interface Act29SideData_Act29SideInvestResultData {
    resultId: string;
    resultTitle: string;
    resultDesc1: string;
    resultDesc2: string;
}

export interface Act29SideData_Act29SideInvestData {
    investId: string;
    investType: Act29SideData_Act29SideInvestType;
    investNpcName: string;
    storyId: string;
    investNpcPic: string;
    investNpcAvatarPic: string;
    majorNpcPic: string;
    majorNpcBlackPic: string;
    reward: ItemBundle;
    investSucResultId: string;
    investFailResultId: string;
    investRareResultId: string;
}

export interface Act29SideData_Act29SideConstData {
    majorInvestUnlockItemName: string;
    wrongTipsTriggerTime: number;
    majorInvestCompleteImgId: string;
    majorInvestUnknownAvatarId: string;
    majorInvestDetailDesc1: string;
    majorInvestDetailDesc2: string;
    majorInvestDetailDesc3: string;
    majorInvestDetailDesc4: string;
    hiddenInvestImgId: string;
    hiddenInvestHeadImgId: string;
    hiddenInvestNpcName: string;
    unlockLevelId: string;
    investResultHint: string;
    investUnlockText: string;
    noOrcheDesc: string;
    investTrackId: string;
}

export interface Act29SideData_Act29SideZoneAdditionData {
    zoneId: string;
    unlockText: string;
}

export interface Act29SideData_Act29SideMusicData {
    groupId: string;
    orcheId: string;
    musicId: string;
}

export interface Act35SideData {
    challengeDataMap: { [key: string]: Act35SideData_Act35SideChallengeData };
    roundDataMap: { [key: string]: Act35SideData_Act35SideRoundData };
    taskDataMap: { [key: string]: Act35SideData_Act35SideChallengeTaskData };
    cardDataMap: { [key: string]: Act35SideData_Act35SideCardData };
    materialDataMap: { [key: string]: Act35SideData_Act35SideMaterialData };
    dialogueGroupDataMap: { [key: string]: Act35SideData_Act35SideDialogueGroupData };
    constData: Act35SideData_Act35SideConstData;
    mileStoneList: Act35SideData_Act35SideMileStoneData[];
    zoneAdditionDataMap: { [key: string]: Act35SideData_Act35SideZoneAdditionData };
}

export interface Act35SideData_Act35SideChallengeData {
    challengeId: string;
    challengeName: string;
    challengeDesc: string;
    sortId: number;
    challengePicId: string;
    challengeIconId: string;
    openTime: number;
    preposedChallengeId: string;
    passRound: number;
    passRoundScore: number;
    roundIdList: string[];
}

export interface Act35SideData_Act35SideRoundData {
    roundId: string;
    challengeId: string;
    round: number;
    roundPassRating: number;
    isMaterialRandom: boolean;
    fixedMaterialList: { [key: string]: number };
    passRoundCoin: number;
}

export interface Act35SideData_Act35SideChallengeTaskData {
    taskId: string;
    taskDesc: string;
    materialId: string;
    materialNum: number;
    passTaskCoin: number;
}

export interface Act35SideData_Act35SideCardData {
    cardId: string;
    sortId: number;
    rank: number;
    cardFace: string;
    cardPic: string;
    levelDataList: Act35SideData_Act35SideCardLevelData[];
}

export interface Act35SideData_Act35SideCardLevelData {
    cardLevel: number;
    cardName: string;
    cardDesc: string;
    inputMaterialList: Act35SideData_Act35sideCardMaterialData[];
    outputMaterialList: Act35SideData_Act35sideCardMaterialData[];
}

export interface Act35SideData_Act35sideCardMaterialData {
    materialId: string;
    count: number;
}

export interface Act35SideData_Act35SideMaterialData {
    materialId: string;
    sortId: number;
    materialIcon: string;
    materialName: string;
    materialRating: number;
}

export interface Act35SideData_Act35SideMileStoneGrandRewardInfo {
    itemName: string;
    level: number;
}

export interface Act35SideData_Act35SideConstData {
    campaignStageId: string;
    campaignEnemyCnt: number;
    milestoneGrandRewardInfoList: Act35SideData_Act35SideMileStoneGrandRewardInfo[];
    unlockLevelId: string;
    birdSpineLowRate: number;
    birdSpineHighRate: number;
    cardMaxLevel: number;
    maxSlotCnt: number;
    cardRefreshNum: number;
    initSlotCnt: number;
    bonusMaterialId: string;
    introRoundIdList: string[];
    challengeUnlockText: string;
    slotUnlockText: string;
    estimateRatio: number;
    carvingUnlockToastText: string;
}

export interface Act35SideData_Act35SideZoneAdditionData {
    zoneId: string;
    unlockText: string;
}

export interface Act35SideData_Act35SideMileStoneData {
    mileStoneId: string;
    mileStoneLvl: number;
    needPointCnt: number;
    rewardItem: ItemBundle;
}

export interface Act35SideData_Act35SideDialogueGroupData {
    type: Act35SideData_DialogueType;
    dialogDataList: Act35SideData_Act35SideDialogueData[];
}

export interface Act35SideData_Act35SideDialogueData {
    sortId: number;
    iconId: string;
    name: string;
    content: string;
    bgType: Act35SideData_DialogueNameBgType;
}

export interface Act36SideData {
    zoneAdditionData: { [key: string]: Act36SideData_Act36SideZoneAdditionData };
    enemyHandbookData: { [key: string]: Act36SideData_Act36SideEnemyHandbookData };
    tokenHandbookData: { [key: string]: Act36SideData_Act36SideTokenHandbookData };
    constData: Act36SideData_Act36SideConstData;
}

export interface Act36SideData_Act36SideZoneAdditionData {
    zoneId: string;
    zoneIconId: string;
    unlockText: string;
    displayTime: number;
}

export interface Act36SideData_Act36SideEnemyHandbookData {
    enemyHandbookId: string;
    spriteId: string;
    sortId: number;
    foodTypeId: string;
    foodAmountId: string;
}

export interface Act36SideData_Act36SideTokenHandbookData {
    tokenHandbookId: string;
    spriteId: string;
    sortId: number;
    tokenAbility: string;
    tokenDescrption: string;
}

export interface Act36SideData_Act36SideConstData {
    rewardFailed: string;
    rewardReceiveNumber: number;
}

export interface Act38SideData {
    zoneAdditionDataMap: { [key: string]: Act38SideData_Act38SideZoneAdditionData };
    puzzleInfoMap: { [key: string]: Act38SideData_Act38SidePuzzleInfo };
    npcDialogList: Act38SideData_Act38SideNpcDialogData[];
    constData: Act38SideData_ConstData;
    puzzleGroupFocusDataMap: { [key: string]: Act38SideData_Act38SidePuzzleGroupFocusData };
}

export interface Act38SideData_Act38SideZoneAdditionData {
    zoneId: string;
    unlockText: string;
}

export interface Act38SideData_Act38SidePuzzleInfo {
    puzzleId: string;
    sortId: number;
    startTime: number;
    puzzleGroupId: string;
}

export interface Act38SideData_Act38SideNpcDialogData {
    desc: string;
    dialogType: Act38SideData_NpcDialogType;
    emoSpineName: string;
}

export interface Act38SideData_Act38SidePuzzleGroupFocusData {
    puzzleGroupId: string;
    xAxisFocusPos: number;
}

export interface Act38SideData_ConstData {
    npcIdleSpineName: string;
    puzzleMapAnimGroupId: string;
    puzzleCrossDayTrackId: string;
    puzzleListText: string;
    puzzleRewardNum: number;
}

export interface Act3D0Data {
    campBasicInfo: { [key: string]: Act3D0Data_CampBasicInfo };
    limitedPoolList: { [key: string]: Act3D0Data_LimitedPoolDetailInfo };
    infinitePoolList: { [key: string]: Act3D0Data_InfinitePoolDetailInfo };
    infinitePercent: { [key: string]: Act3D0Data_InfinitePoolPercent };
    campItemMapInfo: { [key: string]: Act3D0Data_CampItemMapInfo };
    clueInfo: { [key: string]: Act3D0Data_ClueInfo };
    mileStoneInfo: Act3D0Data_MileStoneInfo[];
    mileStoneTokenId: string;
    coinTokenId: string;
    etTokenId: string;
    gachaBoxInfo: Act3D0Data_GachaBoxInfo[];
    campInfo: { [key: string]: Act3D0Data_CampInfo };
    zoneDesc: { [key: string]: Act3D0Data_ZoneDescInfo };
    favorUpList: { [key: string]: CommonFavorUpInfo };
}

export interface Act3D0Data_CampBasicInfo {
    campId: string;
    campName: string;
    campDesc: string;
    rewardDesc: string;
}

export interface Act3D0Data_InfinitePoolDetailInfo {
    poolId: string;
    poolItemInfo: Act3D0Data_InfinitePoolDetailInfo_PoolItemInfo[];
}

export interface Act3D0Data_InfinitePoolDetailInfo_PoolItemInfo {
    goodId: string;
    goodType: Act3D0Data_GoodType;
    itemInfo: ItemBundle;
    perCount: number;
    weight: number;
    type: string;
    orderId: number;
}

export interface Act3D0Data_LimitedPoolDetailInfo {
    poolId: string;
    poolItemInfo: Act3D0Data_LimitedPoolDetailInfo_PoolItemInfo[];
}

export interface Act3D0Data_LimitedPoolDetailInfo_PoolItemInfo {
    goodId: string;
    itemInfo: ItemBundle;
    goodType: Act3D0Data_GoodType;
    perCount: number;
    totalCount: number;
    weight: number;
    type: string;
    orderId: number;
}

export interface Act3D0Data_InfinitePoolPercent {
    percentDict: { [key: string]: number };
}

export interface Act3D0Data_GachaBoxInfo {
    gachaBoxId: string;
    boxType: Act3D0Data_GachaBoxType;
    keyGoodId: string;
    tokenId: ItemBundle;
    tokenNumOnce: number;
    unlockImg: string;
    nextGachaBoxInfoId: string;
}

export interface Act3D0Data_CampItemMapInfo {
    goodId: string;
    itemDict: { [key: string]: ItemBundle };
}

export interface Act3D0Data_ZoneDescInfo {
    zoneId: string;
    lockedText: string;
}

export interface Act3D0Data_CampInfo {
    campId: string;
    campChineseName: string;
}

export interface Act3D0Data_ClueInfo {
    itemId: string;
    campId: string;
    orderId: number;
    imageId: string;
}

export interface Act3D0Data_MileStoneInfo {
    mileStoneId: string;
    orderId: number;
    mileStoneType: Act3D0Data_GoodType;
    normalItem: ItemBundle;
    specialItemDict: { [key: string]: ItemBundle };
    tokenNum: number;
}

export interface Act42D0Data {
    areaInfoData: { [key: string]: Act42D0Data_Act42D0AreaInfoData };
    stageInfoData: { [key: string]: Act42D0Data_Act42D0StageInfoData };
    effectGroupInfoData: { [key: string]: Act42D0Data_Act42D0EffectGroupInfoData };
    effectInfoData: { [key: string]: Act42D0Data_Act42D0EffectInfoData };
    challengeInfoData: { [key: string]: Act42D0Data_Act42D0ChallengeInfoData };
    stageRatingInfoData: { [key: string]: Act42D0Data_Act42D0StageRatingInfoData };
    milestoneData: Act42D0Data_Act42D0MilestoneData[];
    constData: Act42D0Data_Act42D0ConstData;
    trackPointPeriodData: number[];
}

export interface Act42D0Data_Act42D0AreaInfoData {
    areaId: string;
    sortId: number;
    areaCode: string;
    areaName: string;
    difficulty: Act42D0Data_Act42D0AreaDifficulty;
    areaDesc: string;
    costLimit: number;
    bossIcon: string;
    bossId: string;
    nextAreaStage: string;
}

export interface Act42D0Data_Act42D0StageInfoData {
    stageId: string;
    areaId: string;
    stageCode: string;
    sortId: number;
    stageDesc: string[];
    levelId: string;
    code: string;
    name: string;
    loadingPicId: string;
}

export interface Act42D0Data_Act42D0EffectGroupInfoData {
    effectGroupId: string;
    sortId: number;
    effectGroupName: string;
}

export interface Act42D0Data_Act42D0EffectInfoData {
    effectId: string;
    effectGroupId: string;
    row: number;
    col: number;
    effectName: string;
    effectIcon: string;
    cost: number;
    effectDesc: string;
    unlockTime: number;
    runeData: RuneTable_PackedRuneData;
}

export interface Act42D0Data_Act42D0ChallengeInfoData {
    stageId: string;
    stageDesc: string;
    startTs: number;
    endTs: number;
    levelId: string;
    code: string;
    name: string;
    loadingPicId: string;
    challengeMissionData: Act42D0Data_Act42D0ChallengeMissionData[];
}

export interface Act42D0Data_Act42D0ChallengeMissionData {
    missionId: string;
    sortId: number;
    stageId: string;
    missionDesc: string;
    milestoneCount: number;
}

export interface Act42D0Data_Act42D0StageRatingInfoData {
    stageId: string;
    areaId: string;
    milestoneData: Act42D0Data_Act42D0RatingInfoData[];
}

export interface Act42D0Data_Act42D0RatingInfoData {
    ratingLevel: number;
    costUpLimit: number;
    achivement: string;
    icon: string;
    milestoneCount: number;
}

export interface Act42D0Data_Act42D0MilestoneData {
    milestoneId: string;
    orderId: number;
    tokenNum: number;
    item: ItemBundle;
}

export interface Act42D0Data_Act42D0ConstData {
    milestoneId: string;
    strifeName: string;
    strifeDesc: string;
    unlockDesc: string;
    rewardDesc: string;
    traumaDesc: string;
    milestoneAreaName: string;
    traumaName: string;
}

export interface Act42SideData {
    trustorData: { [key: string]: Act42SideData_Act42SideTrustorData };
    taskData: { [key: string]: Act42SideData_Act42SideTaskData };
    gunData: { [key: string]: Act42SideData_Act42SideGunData };
    fileData: { [key: string]: Act42SideData_Act42SideFileData };
    dailyRewardList: Act42SideData_Act42SideDailyRewardData[];
    constData: Act42SideData_Act42SideConstData;
    zoneAdditionDataMap: { [key: string]: Act42SideData_Act42SideZoneAdditionData };
}

export interface Act42SideData_Act42SideTrustorData {
    trustorId: string;
    sortId: number;
    trustorName: string;
    trustorIconSmall: string;
    trustorIconLarge: string;
    gunId: string;
    taskList: string[];
}

export interface Act42SideData_Act42SideGunData {
    gunId: string;
    gunName: string;
    trustorName: string;
    gunContent: string;
    gunSmallIcon: string;
    gunWhiteIcon: string;
    gunColorIcon: string;
}

export interface Act42SideData_Act42SideTaskData {
    taskId: string;
    preposedTaskId: string;
    trustorId: string;
    trustorName: string;
    sortId: number;
    taskName: string;
    taskContent: string;
    afterTaskContent: string;
    beforeTaskItemIcon: string;
    afterTaskItemIcon: string;
    stageId: string;
    taskDesc: string;
    rewards: ItemBundle[];
}

export interface Act42SideData_Act42SideFileData {
    contentId: string;
    sortId: number;
}

export interface Act42SideData_Act42SideDailyRewardData {
    completedCnt: number;
    reward: ItemBundle;
}

export interface Act42SideData_Act42SideZoneAdditionData {
    zoneId: string;
    unlockText: string;
}

export interface Act42SideData_Act42SideConstData {
    coffeeName: string;
    dailyCoffee: number;
    coffeeLimit: number;
    coffeeContent: string;
    minGunTaskDisplay: string;
    unlockStageId: string;
    toastGunTaskCompleted: string;
    toastGunTaskLocked: string;
    toastStageBlock: string;
    toastEntryLocked: string;
    toastFileLocked: string;
    toastGunLocked: string;
    toastNoCoffee: string;
    toastOuterUnlock: string;
}

export interface Act44SideData {
    zoneAdditionDataMap: { [key: string]: Act44SideData_Act44SideZoneAdditionData };
    customerDataMap: { [key: string]: Act44SideData_Act44SideCustomerData };
    tagDataMap: { [key: string]: Act44SideData_Act44SideTagData };
    choiceDataMap: { [key: string]: Act44SideData_Act44SideChoiceData };
    customerDialogMap: { [key: string]: string };
    keeperDialogMap: { [key: string]: string };
    newsDataMap: { [key: string]: Act44SideData_Act44SideNewsData };
    insightDescMap: { [key: string]: Act44SideData_Act44SideInsightData };
    mileStoneList: Act44SideData_Act44SideMileStoneData[];
    constData: Act44SideData_Act44SideConstData;
}

export interface Act44SideData_Act44SideZoneAdditionData {
    zoneId: string;
    unlockText: string;
}

export interface Act44SideData_Act44SideCustomerData {
    id: string;
    name: string;
    imgId: string;
    iconId: string;
    isSp: boolean;
    description: string;
}

export interface Act44SideData_Act44SideTagData {
    id: string;
    name: string;
    isSp: boolean;
    description: string;
}

export interface Act44SideData_Act44SideChoiceData {
    id: string;
    imgId: string;
    attentionArrow: number;
    trustArrow: number;
    attentionValue: number;
    trustValue: number;
    patienceValue: number;
}

export interface Act44SideData_Act44SideNewsData {
    id: string;
    title: string;
    desc1: string;
    desc2: string;
    imgId: string;
}

export interface Act44SideData_Act44SideInsightData {
    type: Act44SideData_InsightType;
    lowerDesc: string;
    recommendDesc: string;
    maxDesc: string;
}

export interface Act44SideData_Act44SideMileStoneData {
    mileStoneId: string;
    mileStoneLvl: number;
    needPointCnt: number;
    rewardItem: ItemBundle;
}

export interface Act44SideData_Act44SideMilestoneSpecialRewardInfo {
    itemName: string;
    point: number;
}

export interface Act44SideData_Act44SideConstData {
    informantUnlockStageId: string;
    informantItemId: string;
    informantItemType: ItemType;
    informantItemCount: number;
    milestoneItemId: string;
    attentionMax: number;
    trustMax: number;
    attentionMin: number;
    trustMin: number;
    patienceRCRoundNum: number;
    beginnerPatienceRCRoundNum: number;
    specialCustomerListId: string[];
    milestoneRewardList: Act44SideData_Act44SideMilestoneSpecialRewardInfo[];
    forCountBigSuccess: number;
    outerOpenUnlock: string;
    customerTagFormat: string;
}

export interface Act45SideData {
    charData: { [key: string]: Act45SideData_Act45SideCharData };
    mailData: { [key: string]: Act45SideData_Act45SideMailData };
    constData: Act45SideData_Act45SideConstData;
    zoneAdditionDataMap: { [key: string]: Act45SideData_Act45SideZoneAdditionData };
}

export interface Act45SideData_Act45SideCharData {
    charId: string;
    sortId: number;
    charIllustId: string;
    charCardId: string;
    charName: string;
    unlockStageId: string;
}

export interface Act45SideData_Act45SideMailData {
    mailId: string;
    sortId: number;
    charName: string;
    picId: string;
    mailTitle: string;
    mailContent: string;
    sendTime: number;
    rewards: ItemBundle[];
}

export interface Act45SideData_Act45SideZoneAdditionData {
    zoneId: string;
    unlockText: string;
}

export interface Act45SideData_Act45SideConstData {
    entryStageId: string;
    toastCharUnlock: string;
    toastLivePageUnlock: string;
    toastLivePageLocked: string;
    textCharLocked: string;
    textMailTime: string;
    textBtnMailTime: string;
    gameTVSizeMusicId: string;
    gameFullSizeMusicId: string;
    entryMusicId: string;
}

export interface Act46SideData {
    zoneAdditionDataMap: { [key: string]: Act46SideData_Act46SideZoneAdditionData };
    monopolyStageDataMap: { [key: string]: Act46SideData_Act46SideMonopolyStageData };
    buffDataMap: { [key: string]: Act46SideData_Act46SideMonopolyBuffData };
    settleDialogDataMap: { [key: string]: { [key: string]: Act46SideData_Act46SideSettleDialogData[] } };
    constData: Act46SideData_Act46SideConstData;
    resourceItemDataMap: { [key: string]: Act46SideData_Act46SideMonopolyResourceItemData };
}

export interface Act46SideData_Act46SideZoneAdditionData {
    zoneId: string;
    unlockText: string;
}

export interface Act46SideData_Act46SideMonopolyStageData {
    stageId: string;
    sortId: number;
    startTs: number;
    stageName: string;
    stageDesc: string;
    taskRequiredAmount: number;
    rewardList: ItemBundle[];
    buffIdList: string[];
    bgSpriteId: string;
    maxTurn: number;
    nodeIconStyleIndexList: number[];
    validResourceIdList: string[];
}

export interface Act46SideData_Act46SideConstData {
    trainingStageId: string;
    excellentRate: number[];
    entryRequirement: string;
    businessUnlockText: string;
    mapNodeStartIcon: string;
    comboTaskProgressCount: number;
}

export interface Act46SideData_Act46SideMonopolyBuffData {
    buffId: string;
    buffIconId: string;
    buffName: string;
    buffDesc: string;
}

export interface Act46SideData_Act46SideSettleDialogData {
    characterAvatarId: string;
    dialogText: string;
}

export interface Act46SideData_Act46SideMonopolyResourceItemData {
    resourceId: string;
    sortId: number;
}

export interface Act4D0Data {
    mileStoneItemList: Act4D0Data_MileStoneItemInfo[];
    mileStoneStoryList: Act4D0Data_MileStoneStoryInfo[];
    storyInfoList: Act4D0Data_StoryInfo[];
    stageInfo: Act4D0Data_StageJumpInfo[];
    tokenItem: ItemBundle;
    charStoneId: string;
    apSupplyOutOfDateDict: { [key: string]: number };
    extraDropZones: string[];
}

export interface Act4D0Data_StageJumpInfo {
    stageKey: string;
    zoneId: string;
    stageId: string;
    unlockDesc: string;
    lockDesc: string;
}

export interface Act4D0Data_MileStoneItemInfo {
    mileStoneId: string;
    orderId: number;
    tokenNum: number;
    item: ItemBundle;
}

export interface Act4D0Data_MileStoneStoryInfo {
    mileStoneId: string;
    orderId: number;
    tokenNum: number;
    storyKey: string;
    desc: string;
}

export interface Act4D0Data_StoryInfo {
    storyKey: string;
    storyId: string;
    storySort: string;
    storyName: string;
    lockDesc: string;
    storyDesc: string;
}

export interface Act53SideData {
    zoneAdditionDataMap: { [key: string]: Act53SideData_Act53SideZoneAdditionData };
    actOdcStageIdList: string[];
    constData: Act53SideData_Act53SideConstData;
}

export interface Act53SideData_Act53SideZoneAdditionData {
    zoneId: string;
    unlockText: string;
}

export interface Act53SideData_Act53SideConstData {
    arkOdcTopicId: string;
    arkOdcUnlockStageId: string;
    arkOdcUnlockText: string;
    arkOdcUpdateText: string;
    campaignStageId: string;
    campaignEnemyCnt: number;
    coinItemId: string;
}

export interface Act54SideData {
    cards: { [key: string]: Act54SideData_Act54SideCardData };
    spreads: { [key: string]: Act54SideData_Act54SideSpreadData };
    specialZoneStageInfos: Act54SideData_Act54SideSpecialZoneStageInfo[];
    zoneAdditionDataMap: { [key: string]: Act54SideData_Act54SideZoneAdditionData };
    constData: Act54SideData_Act54SideConstData;
}

export interface Act54SideData_Act54SideCardData {
    cardId: string;
    sortId: number;
    name: string;
    charName: string;
    descUpright: string;
    descReverse: string;
    unlockStageId: string;
}

export interface Act54SideData_Act54SideSpreadItemInfo {
    sortId: number;
    name: string;
    nameEnglish: string;
}

export interface Act54SideData_Act54SideSpreadData {
    spreadId: string;
    sortId: number;
    availTimesDivination: number;
    unlockStageId: string;
    unlockSpreadId: string;
    spreadsToUnlock: string[];
    name: string;
    nameEnglish: string;
    spreadInfoList: Act54SideData_Act54SideSpreadItemInfo[];
    rewards: ItemBundle[];
}

export interface Act54SideData_Act54SideSpecialZoneStageInfo {
    stageId: string;
    sortId: number;
    hasUrgentStage: boolean;
}

export interface Act54SideData_Act54SideZoneAdditionData {
    zoneId: string;
    unlockText: string;
}

export interface Act54SideData_Act54SideConstData {
    divinationUnlockStageId: string;
    finalReward: ItemBundle;
    activityItemId: string;
    divinationEnterDelay: number;
}

export interface Act5D0Data {
    mileStoneInfo: MileStoneInfo[];
    mileStoneTokenId: string;
    zoneDesc: { [key: string]: Act5D0Data_ZoneDescInfo };
    missionExtraList: { [key: string]: Act5D0Data_MissionExtraInfo };
    spReward: string;
}

export interface Act5D0Data_ZoneDescInfo {
    zoneId: string;
    lockedText: string;
}

export interface Act5D0Data_MissionExtraInfo {
    difficultLevel: number;
    levelDesc: string;
    sortId: number;
}

export interface MileStoneInfo {
    mileStoneId: string;
    orderId: number;
    tokenNum: number;
    mileStoneType: MileStoneInfo_GoodType;
    normalItem: ItemBundle;
    IsBonus: number;
}

export interface Act5D1Data {
    stageCommonData: Act5D1Data_RuneStageData[];
    runeStageData: Act5D1Data_RuneRecurrentStateData[];
    runeUnlockDict: { [key: string]: Act5D1Data_RuneUnlockData[] };
    runeReleaseData: Act5D1Data_RuneReleaseData[];
    missionData: MissionData[];
    missionGroup: MissionGroup[];
    useBenefitMissionDict: { [key: string]: boolean };
    shopData: Act5D1Data_ShopData;
    coinItemId: string;
    ptItemId: string;
    stageRune: RuneTable_RuneStageExtraData[];
    showRuneMissionList: string[];
}

export interface Act5D1Data_RuneStageData {
    stageId: string;
    levelId: string;
    code: string;
    name: string;
    loadingPicId: string;
    description: string;
    picId: string;
}

export interface Act5D1Data_RuneRecurrentStateData {
    runeReId: string;
    stageId: string;
    slotId: number;
    startTime: number;
    endTime: number;
    runeList: string[];
    isAvail: boolean;
    warningPoint: number;
}

export interface Act5D1Data_RuneUnlockData {
    runeId: string;
    priceItem: ItemBundle;
    runeName: string;
    bgPic: string;
    runeDesc: string;
    sortId: number;
    iconId: string;
}

export interface Act5D1Data_RuneReleaseData {
    runeId: string;
    stageId: string;
    releaseTime: number;
}

export interface Act5D1Data_ShopGood {
    goodId: string;
    slotId: number;
    price: number;
    availCount: number;
    item: ItemBundle;
    progressGoodId: string;
    goodType: Act5D1Data_GoodType;
    rarity: string;
}

export interface Act5D1Data_ShopData {
    shopGoods: { [key: string]: Act5D1Data_ShopGood };
    progressGoods: { [key: string]: Act5D1Data_ProgessGoodItem[] };
}

export interface Act5D1Data_ProgessGoodItem {
    order: number;
    price: number;
    displayName: string;
    item: ItemBundle;
}

export interface Act9D0Data {
    tokenItemId: string;
    zoneDescList: { [key: string]: Act9D0Data_ZoneDescInfo };
    favorUpList: { [key: string]: Act9D0Data_FavorUpInfo };
    subMissionInfo: { [key: string]: Act9D0Data_SubMissionInfo };
    hasSubMission: boolean;
    apSupplyOutOfDateDict: { [key: string]: number };
    newsInfoList: { [key: string]: Act9D0Data_ActivityNewsInfo };
    newsServerInfoList: { [key: string]: Act9D0Data_ActivityNewsServerInfo };
    miscHub: { [key: string]: string };
    constData: Act9D0Data_Act9D0ConstData;
}

export interface Act9D0Data_ZoneDescInfo {
    zoneId: string;
    unlockText: string;
    displayStartTime: number;
}

export interface Act9D0Data_FavorUpInfo {
    charId: string;
    displayStartTime: number;
    displayEndTime: number;
}

export interface Act9D0Data_SubMissionInfo {
    missionId: string;
    missionTitle: string;
    sortId: number;
    missionIndex: string;
}

export interface Act9D0Data_ActivityNewsInfo {
    newsId: string;
    newsSortId: number;
    styleInfo: Act9D0Data_ActivityNewsStyleInfo;
    preposedStage: string;
    titlePic: string;
    newsTitle: string;
    newsInfShow: number;
    newsFrom: string;
    newsText: string;
    newsParam1: number;
    newsParam2: number;
    newsParam3: number;
    newsLines: Act9D0Data_ActivityNewsLine[];
}

export interface Act9D0Data_ActivityNewsServerInfo {
    newsId: string;
    preposedStage: string;
}

export interface Act9D0Data_ActivityNewsStyleInfo {
    typeId: string;
    typeName: string;
    typeLogo: string;
    typeMainLogo: string;
}

export interface Act9D0Data_ActivityNewsLine {
    lineType: Act9D0Data_ActivityNewsLineType;
    content: string;
}

export interface Act9D0Data_Act9D0ConstData {
    campaignEnemyCnt: number;
    campaignStageId: string;
}

export interface ActArcadeData {
    stageAdditionDataDict: { [key: string]: ActArcadeData_ArcadeStageAdditionalData };
    zoneAdditionalDataDict: { [key: string]: ActArcadeData_ArcadeZoneAdditionalData };
    badgeDataDict: { [key: string]: ActArcadeData_ArcadeBadgeData };
    tireBadgeIdDict: { [key: string]: string };
    badgeTypeDataDict: { [key: string]: ActArcadeData_ArcadeBadgeTypeData };
    milestoneList: ActArcadeData_ArcadeMilestoneItemData[];
    constData: ActArcadeData_ArcadeConstData;
}

export interface ActArcadeData_ArcadeZoneAdditionalData {
    zoneId: string;
    sortId: number;
    zoneName: string;
    zoneEntryPicId: string;
    stageInfoPrefabId: string;
    startTs: number;
    endTs: number;
    stages: string[];
    subModeType: ActArcadeData_SubModeType;
    zoneDesc: string;
}

export interface ActArcadeData_ArcadeStageAdditionalData {
    stageId: string;
    zoneId: string;
    mechDescription: string;
    sortId: number;
    maxSlot: number;
    rankRewardData: ActArcadeData_ArcadeStageRankRewardData;
}

export interface ActArcadeData_ArcadeStageRankRewardData {
    stageId: string;
    maxRewardRank: ActArcadeData_Rank;
    rankRewardLevelDatas: ActArcadeData_ArcadeStageRankRewardLevelData[];
}

export interface ActArcadeData_ArcadeStageRankRewardLevelData {
    rank: ActArcadeData_Rank;
    rankScore: number;
    coinCnt: number;
}

export interface ActArcadeData_ArcadeBadgeTierData {
    badgeTierId: string;
    sortId: number;
    badgeTierIconId: string;
    badgeTierShareIconId: string;
    badgeTierEffectId: string;
    title: string;
    desc: string;
    buffId: string;
    unlockDesc: string;
    runeData: RuneTable_PackedRuneData;
}

export interface ActArcadeData_ArcadeBadgeData {
    badgeId: string;
    badgeType: ActArcadeData_BadgeType;
    sortId: number;
    badgeName: string;
    buffRangeDesc: string;
    hasScore: boolean;
    scoreZone: string;
    tiers: { [key: string]: ActArcadeData_ArcadeBadgeTierData };
}

export interface ActArcadeData_ArcadeBadgeTypeData {
    badgeType: ActArcadeData_BadgeType;
    badgeTypeName: string;
    sortId: number;
    buffRangeDesc: string;
}

export interface ActArcadeData_ArcadeMilestoneItemData {
    mileStoneId: string;
    mileStoneLvl: number;
    needPointCnt: number;
    reward: ItemBundle;
}

export interface ActArcadeData_ArcadeConstData {
    milestoneName: string;
    milestoneNameEN: string;
    milestoneItemId: string;
    rewardHomeThemeId: string;
    rewardHomeThemeText: string;
    rewardAvatarId: string;
    rewardAvatarText: string;
    badgeCollectionName: string;
    collectionEntryRelatedBadge: string;
    zoneEntryUnlockToast: string;
    zoneEntryEndText: string;
    zoneEntryEndToast: string;
    rankUnlockNextStage: string;
    stageScoreDisplayLimit: number;
    zoneUltiScoreDisplayLimit: number;
    enemyHudScore: string[];
    trapNotBuildableInRest: string[];
}

export interface ArkdexModuleData {
    modeData: { [key: string]: ArkdexModeData };
    creatureData: { [key: number]: ArkdexCreatureData };
    advantageTypeData: { [key: string]: ArkdexAdvantageTypeData };
    advantageCounterMap: { [key: string]: string[] };
    npcInfoData: { [key: number]: ArkdexNpcInfoData };
    npcDuelStrategyData: { [key: string]: { [key: string]: ArkdexNpcDuelStrategyData } };
    itemEffectData: { [key: number]: ArkdexItemEffectData };
    traitData: { [key: number]: ArkdexTraitData };
    sceneTypeMap: { [key: number]: string };
    npcBattleParamData: { [key: number]: ArkdexNpcBattleParamData };
    npcPixelData: { [key: string]: ArkdexNpcPixelData };
    captureAreaData: { [key: number]: ArkdexCaptureAreaData };
    dexConstData: ArkdexConstData;
}

export interface ArkdexCaptureAreaData {
    areaId: number;
}

export interface ArkdexNpcPixelData {
    npcPixelId: string;
    npcPixelIcon: string;
    npcPixelName: string;
    npcLockedToast: string;
}

export interface ArkdexModeData {
    modeId: string;
    modeNumId: number;
    isMultiplayer: boolean;
    numMax: number;
    battleNpcCount: number;
    isMatching: boolean;
    maxRoundNumber: number;
    stageTimeMax: number;
    characterLimit: number;
    modeType: ArkdexModeType;
    stageIds: string[];
    modeName: string;
    modeHint: string;
    matchingIconId: string;
}

export interface ArkdexCreatureData {
    creatureNumId: number;
    enemyId: string;
    deployedEnemyId: string;
    trapId: string;
    uiDisplayScale: number;
    followScale: number;
    animSpeedFollow: number;
    rarity: number;
    specialRarity: boolean;
    sortId: number;
    orderId: string;
    name: string;
    creatureIcon: string;
    worldEntityId: string;
    alterNumId: number;
    upWeightTagIsShow: boolean;
    advantageType: string;
    description: string;
    abilities: string[];
    obtainApproach: string;
    hp: number;
    atk: number;
    def: number;
    mag: number;
    moveSpeed: number;
    atkSpeed: number;
    hpPct: number;
    atkPct: number;
    defPct: number;
    magPct: number;
    moveSpeedPct: number;
    atkSpeedPct: number;
}

export interface ArkdexAdvantageTypeData {
    advantageType: string;
    sortId: number;
    name: string;
    typeIcon: string;
    entryEffectKey: string;
    damageScaleMap: { [key: string]: number };
}

export interface ArkdexNpcDuelCreatureData {
    creatureNumId: number;
    traitMask: number;
}

export interface ArkdexNpcInfoData {
    npcId: number;
    strategyGroupId: string;
    name: string;
    avatarId: string;
    npcProb: number;
    avatarType: PlayerAvatarGroupType;
    nameCardSkinId: string;
    nameCardSkinTmplId: number;
}

export interface ArkdexNpcDuelStrategyData {
    strategyGroupId: string;
    strategyId: string;
    tileStrategy: ArkDexNpcTileStrategy;
    cardStrategy: ArkDexNpcCardStrategy;
    creatureData: ArkdexNpcDuelCreatureData[];
    weight: number;
}

export interface ArkdexItemEffectData {
    itemNumId: number;
    buff: string;
    activeDesc: string;
    blackboard: Blackboard;
}

export interface ArkdexTraitData {
    sortId: number;
    traitMask: number;
    traitId: string;
    name: string;
    icon: string;
    description: string;
    color: string;
    buff: Blackboard;
}

export interface ArkdexConstData {
    arkdexCreatureBagMaxNum: number;
    arkdexCreatureBagAlertNum: number;
    operatorTeamSize: number;
    totalSquadCnt: number;
    teamSlots: number;
    teamSize: number;
    maxTeamRarityCount: number;
    soloCharacterLimit: number;
    brawlCharacterLimit: number;
    buildEntryMaxTime: number;
    battleEntryMaxTime: number;
    settleMaxTime: number;
    pingConds: PingCond[];
    maxLoadingTime: number;
    deployPhaseTime: number;
    deployPhaseHintTime: number;
    battlePhaseTimeMax: number;
    modeOperationRankTime: number;
    petFollowPanelScale: number;
    tradeRequestTime: number;
    creaturedDisappearAlert: number;
    creatureInteractRange: ArkventRangeData;
    creatureInteractStyleId: string;
    creatureDisplayNameId: string;
    creatureHeadUpStyleId: string;
}

export interface ArkdexNpcBattleParamData {
    npcBattleId: number;
    modeId: string;
}

export interface ArkpixelModuleData {
    pixelConstData: ArkpixelConstData;
    releaseStageData: { [key: string]: ArkpixelReleaseStageData };
}

export interface ArkpixelConstData {
    arkpixelBagNum: number;
    arkpixelOtherPlayerBagNum: number;
    maxReleaseTimesPerStage: number;
    pixelParamId: string;
    hiddenCreatorName: string;
    scenePixelDisplayRadius: number;
    pixelShowLimitConfigList: number[];
    showCollectIconCount: number;
    maxCollectedCount: number;
    maxCollectedDisplayText: string;
}

export interface ArkpixelReleaseStageData {
    arkpixelStage: string;
    startTime: number;
    arkpixelReleaseTimes: number;
}

export interface ActArkHubModuleData {
    arkdexModule: ArkdexModuleData;
    arkpixelModule: ArkpixelModuleData;
    moduleTypes: ActArkHubModuleType[];
}

export interface ActArkHubInteractiveUnitData {
    editorActorId: number;
    actorInteractPointCount: number;
    displayNameId: string;
    unitId: string;
    assetId: string;
    actorType: ActArkHubActorType;
    actorParam: string;
    avgId: string;
    interactionRequirements: string[];
    position: JsonValue;
    yaw: number;
    blockRange: ArkventRangeData;
    interactRange: ArkventRangeData;
    triggerCameraConfig: string;
    interactCameraConfig: string;
    interactBtnStyleId: string;
    headUpStyleId: string;
    sceneId: number;
    overrideAnimConfig: { [key: string]: string };
    spineFace: ArkventSpineFaceType;
    hasSafePos: boolean;
    safePos: JsonValue;
}

export interface ActArkHubItemData {
    itemId: string;
    itemNumId: number;
    itemType: ActArkHubItemType;
    itemName: string;
    itemUsage: string;
    itemDesc: string;
    obtainApproach: string;
    stackLimit: number;
    maxEffectCount: number;
    rarity: ItemRarity;
    itemSortId: number;
    isUsable: boolean;
    isShow: boolean;
    accumulateDesc: string;
}

export interface ActArkHubConstData {
    maxChannelPlayerLimit: number;
    emojiCD: number;
    emojiTime: number;
    runMaxStableMoveSpeed: number;
    walkMaxStableMoveSpeed: number;
    stableMovementSharpness: number;
    defaultAlpha: number;
    runConfiguredAnimScale: number;
    walkConfiguredAnimScale: number;
    minAnimScale: number;
    maxAnimScale: number;
    defaultMovePreset: string;
    defaultSpineFlip: SpineFlipMode;
    defaultSlideStopThreshold: number;
    reportMaxNum: number;
    invitationSendCd: number;
    invitationValidityPeriod: number;
    storyMachineCameraConfigId: string;
    pingConds: PingCond[];
    btnCancelInteractStyleId: string;
    npcDefaultFx: string;
    npcSelectedFx: string;
    enterLobbyFx: string;
    interactSelectedFx: string;
    spraySummonFx: string;
    sprayFadeFx: string;
    petSummonFx: string;
    followDistance: number;
    stopDistance: number;
    moveSpeed: number;
    followOffset: number;
    colorSpineOutline: string;
    highQualityPetSpineCount: number;
    lowQualityPetSpineCount: number;
    midQualityPetSpineCount: number;
}

export interface ActArkHubMoveFixData {
    skinId: string;
    runMaxStableMoveSpeed: number;
    walkMaxStableMoveSpeed: number;
    alpha: number;
    runConfiguredAnimScale: number;
    walkConfiguredAnimScale: number;
    slideStopThreshold: number;
    spineFlip: SpineFlipMode;
}

export interface ActArkHubMenuData {
    type: ActArkHubMenuType;
    name: string;
    iconId: string;
    isPermanent: boolean;
    sortId: number;
    unlockToast: string;
    bannedToast: string;
}

export interface ActArkHubPlayerStateInfoData {
    state: ActArkHubNameCardState;
    iconId: string;
    name: string;
}

export interface ActArkHubRewardItem {
    itemId: string;
    count: number;
    itemType: ActArkHubItemType;
}

export interface ActArkHubRewardData {
    rewardId: string;
    itemList: ActArkHubRewardItem[];
}

export interface ActArkhubLoadingTipData {
    tip: string;
    weight: number;
}

export interface ActArkHubData {
    moduleData: ActArkHubModuleData;
    interactiveUnitData: { [key: number]: ActArkHubInteractiveUnitData };
    enabledEmoticonThemeIdList: string[];
    reportPlayerDataList: CommonReportPlayerData[];
    menuData: { [key: string]: ActArkHubMenuData };
    constData: ActArkHubConstData;
    moveFixData: { [key: string]: ActArkHubMoveFixData };
    movePresetData: { [key: string]: ArkventMovePresetData };
    skinPresetDict: { [key: string]: string };
    playerStateInfoData: { [key: string]: ActArkHubPlayerStateInfoData };
    rewardDataDict: { [key: string]: ActArkHubRewardData };
    spawnFxDurationDict: { [key: string]: number };
    loadingTipList: ActArkhubLoadingTipData[];
}

export interface ArkhubData {
    itemData: { [key: string]: ActArkHubItemData };
}

export interface ActAutoChessData {
    modeDataDict: { [key: string]: ActAutoChessData_ActAutoChessModeData };
    baseRewardDataList: ActAutoChessData_ActAutoChessBaseRewardData[];
    bandDataListDict: { [key: string]: ActAutoChessData_ActAutoChessBandData };
    charChessDataDict: { [key: string]: ActAutoChessData_ActAutoChessCharChessData };
    chessNormalIdLookupDict: { [key: string]: string };
    diyChessDict: { [key: string]: RarityRank };
    shopLevelDataDict: { [key: string]: { [key: number]: ActAutoChessData_ActAutoChessShopLevelData } };
    shopLevelDisplayDataDict: { [key: number]: ActAutoChessData_ActAutoChessShopLevelDisplayData };
    charShopChessDatas: { [key: string]: ActAutoChessData_ActAutoChessCharShopChessData };
    trapChessDataDict: { [key: string]: ActAutoChessData_ActAutoChessTrapChessData };
    trapShopChessDatas: { [key: string]: ActAutoChessData_ActAutoChessTrapShopChessData };
    stageDatasDict: { [key: string]: ActAutoChessData_ActAutoChessStageData };
    battleDataDict: { [key: string]: { [key: number]: ActAutoChessData_ActAutoChessBattleData[] } };
    bondInfoDict: { [key: string]: ActAutoChessData_ActAutoChessBondInfo };
    garrisonDataDict: { [key: string]: ActAutoChessData_ActAutoChessGarrisonData };
    effectInfoDataDict: { [key: string]: ActAutoChessData_ActAutoChessEffectInfoData };
    effectBuffInfoDataDict: { [key: string]: ActAutoChessData_ActAutoChessBuffInfoData[] };
    effectChoiceInfoDict: { [key: string]: ActAutoChessData_ActAutoChessEffectChoiceInfoData };
    bossInfoDict: { [key: string]: ActAutoChessData_ActAutochessBossEntry };
    specialEnemyInfoDict: { [key: string]: ActAutoChessData_ActAutochessSpecialEnemyEntry };
    enemyInfoDict: { [key: string]: string[] };
    specialEnemyRandomTypeDict: { [key: string]: ActAutoChessData_ActAutochessSpecialEnemyTypeEntry };
    trainingNpcList: ActAutoChessData_ActAutoChessTrainingNpcData[];
    milestoneList: ActivityCommonMilestoneData[];
    modeFactorInfo: { [key: string]: number };
    difficultyFactorInfo: { [key: string]: number };
    playerTitleDataDict: { [key: string]: ActAutoChessData_ActAutoChessPlayerTitleData };
    shopCharChessInfoData: { [key: number]: ActAutoChessData_ActAutoChessShopCharChessInfoData[] };
    constData: ActAutoChessData_ActAutoChessConstData;
}

export interface ActAutoChessData_ActAutoChessModeData {
    modeId: string;
    name: string;
    code: string;
    sortId: number;
    backgroundId: string;
    desc: string;
    effectDescList: string[];
    preposedMode: string;
    unlockText: string;
    loadingPicId: string;
    modeType: ActAutoChessModeType;
    modeDifficulty: ActAutoChessModeDifficultyType;
    modeIconId: string;
    modeColor: string;
    specialPhaseTime: number;
    activeBondIdList: string[];
    inactiveBondIdList: string[];
    inactiveEnemyKey: string[];
    startTime: number;
}

export interface ActAutoChessData_ActAutoChessBondInfo {
    bondId: string;
    name: string;
    desc: string;
    iconId: string;
    activeCount: number;
    activeCondition: ActAutoChessBondActiveConditionType;
    activeConditionTemplate: string;
    activeParamList: string[];
    effectId: string;
    activeType: ActAutoChessBondActiveType;
    identifier: number;
    weight: number;
    isActiveInDeck: boolean;
    maxInactiveBondCount: number;
    descParamBaseList: string[];
    descParamPerStackList: string[];
    noStack: boolean;
    chessIdList: string[];
}

export interface ActAutoChessData_ActAutoChessGarrisonData {
    garrisonDesc: string;
    eventType: string;
    eventTypeDesc: string;
    eventTypeIcon: string;
    eventTypeSmallIcon: string;
    effectType: string;
    charLevel: number;
    battleRuneKey: string;
    blackboard: Blackboard;
    description: string;
}

export interface ActAutoChessData_ActAutoChessBandData {
    bandId: string;
    sortId: number;
    modeTypeList: string[];
    bandDesc: string;
    totalHp: number;
    effectId: string;
    victorCount: number;
    bandRewardModulus: number;
    updateTime: number;
}

export interface ActAutoChessData_ActAutoChessCharChessStatusData {
    evolvePhase: EvolvePhase;
    charLevel: number;
    skillLevel: number;
    favorPoint: number;
    equipLevel: number;
}

export interface ActAutoChessData_ActAutoChessCharChessData {
    chessId: string;
    identifier: number;
    isGolden: boolean;
    status: ActAutoChessData_ActAutoChessCharChessStatusData;
    upgradeChessId: string;
    upgradeNum: number;
    bondIds: string[];
    garrisonIds: string[];
}

export interface ActAutoChessData_ActAutoChessShopLevelData {
    shopLevel: number;
    initialUpgradePrice: number;
    charChessCount: number;
    itemCount: number;
    levelTagBgColor: string;
}

export interface ActAutoChessData_ActAutoChessShopCharChessInfoData {
    chessLevel: number;
    isGolden: boolean;
    evolvePhase: EvolvePhase;
    charLevel: number;
    skillLevel: number;
    favorPoint: number;
    equipLevel: number;
    purchasePrice: number;
    chessSoldPrice: number;
    eliteIconId: string;
}

export interface ActAutoChessData_ActAutoChessShopLevelDisplayData {
    shopLevel: number;
    levelTagBgColor: string;
    isLevelCharChessEmpty: boolean;
    isLevelTrapChessEmpty: boolean;
    charChessDiySlotIdList: string[];
}

export interface ActAutoChessData_ActAutoChessCharShopChessData {
    chessId: string;
    goldenChessId: string;
    chessLevel: number;
    shopLevelSortId: number;
    chessType: AutoChessChessType;
    charId: string;
    tmplId: string;
    defaultSkillIndex: number;
    defaultUniEquipId: string;
    backupCharId: string;
    backupTmplId: string;
    backupCharSkillIndex: number;
    backupCharUniEquipId: string;
    backupCharPotRank: number;
    isHidden: boolean;
}

export interface ActAutoChessData_AutoChessTrapChessStatusData {
    evolvePhase: EvolvePhase;
    trapLevel: number;
    skillIndex: number;
    skillLevel: number;
}

export interface ActAutoChessData_ActAutoChessTrapChessData {
    chessId: string;
    identifier: number;
    charId: string;
    isGolden: boolean;
    purchasePrice: number;
    status: ActAutoChessData_AutoChessTrapChessStatusData;
    upgradeChessId: string;
    upgradeNum: number;
    trapDuration: number;
    effectId: string;
    giveBondId: string;
    givePowerId: string;
    canGiveBond: boolean;
    itemType: AutoChessItemType;
}

export interface ActAutoChessData_ActAutoChessTrapShopChessData {
    itemId: string;
    goldenItemId: string;
    hideInShop: boolean;
    itemLevel: number;
    iconLevel: number;
    shopLevelSortId: number;
    itemType: AutoChessItemType;
    trapId: string;
}

export interface ActAutoChessData_ActAutoChessStageData {
    stageId: string;
    mode: string[];
    weight: number;
}

export interface ActAutoChessData_ActAutoChessBattleData {
    bossId: string;
    levelId: string;
    isSpPrepare: boolean;
}

export interface ActAutoChessData_ActAutoChessEffectInfoData {
    effectId: string;
    effectType: AutoChessEffectType;
    effectCounterType: AutoChessEffectCounterType;
    continuedRound: number;
    effectName: string;
    effectDesc: string;
    effectDecoIconId: string;
    enemyPrice: number;
}

export interface ActAutoChessData_ActAutoChessBuffInfoData {
    key: string;
    blackboard: Blackboard;
    countType: AutoChessCountType;
}

export interface ActAutoChessData_ActAutoChessEffectChoiceInfoData {
    choiceEventId: string;
    choiceType: AutoChessEffectChoiceType;
    effectType: AutoChessEffectType;
    name: string;
    desc: string;
    typeTxtColor: string;
}

export interface ActAutoChessData_ActAutoChessPlayerTitleData {
    id: string;
    picId: string;
    txt: string;
}

export interface ActAutoChessData_ActAutochessBossEntry {
    bossId: string;
    sortId: number;
    weight: number;
    bloodPoint: number;
    bloodPointNormal: number;
    bloodPointHard: number;
    bloodPointAbyss: number;
    isHidingBoss: boolean;
}

export interface ActAutoChessData_ActAutochessSpecialEnemyEntry {
    type: string;
    specialEnemyKey: string;
    randomWeight: number;
    isInFirstHalf: boolean;
    attachedNormalEnemyKeys: string[];
    attachedEliteEnemyKeys: string[];
}

export interface ActAutoChessData_ActAutochessSpecialEnemyTypeEntry {
    count: number;
    weight: number;
}

export interface ActAutoChessData_ActAutoChessBaseRewardData {
    round: number;
    item: ItemBundle;
    dailyMissionPoint: number;
}

export interface ActAutoChessData_ActAutoChessTrainingNpcData {
    npcId: string;
    charId: string;
    nameCardSkinId: string;
    medalCount: number;
    bandId: string;
}

export interface ActAutoChessData_ActAutoChessConstData {
    shopRefreshPrice: number;
    maxDeckChessCnt: number;
    maxBattleChessCnt: number;
    fallbackBondId: string;
    storeCntMax: number;
    costPlayerHpLimit: number;
    milestoneId: string;
    borrowCount: number;
    dailyMissionParam: number;
    dailyMissionName: string;
    dailyMissionRule: string;
    trstageBandId: string;
    trstageBossId: string;
    trStageId: string;
    trainingModeId: string;
    trSpecialEnemyTypes: string[];
    trBondIds: string[];
    trBannedBondIds: string[];
    milestoneTrackId: string;
    escapedBattleTemplateMapSinglePlayer: string;
    escapedBattleTemplateMapMultiPlayer: string;
    webBusType: string;
}

export interface AutoChessData {
    versionInfoDict: { [key: string]: AutoChessData_AutoChessVersionInfoData };
    bandDataDict: { [key: string]: AutoChessData_AutoChessBandData };
    cultivateEffectList: AutoChessData_AutoChessCultivateRelationData[];
    effectTypeDataDict: { [key: string]: AutoChessData_AutoChessEffectTypeData };
    bondInfoDict: { [key: string]: AutoChessData_AutoChessBondInfoData };
    bossInfoDict: { [key: string]: AutoChessData_AutoChessBossInfoData };
    enemyTypeDatas: { [key: string]: AutoChessData_AutoChessEnemyTypeData };
    enterStepList: AutoChessData_AutoChessEnterStepData[];
    shopStateTokenDict: { [key: string]: AutoChessData_AutoChessShopStateTokenData };
    skillTriggerDataList: AutoChessData_AutoChessSkillTriggerData[];
    skillRangeDict: { [key: string]: string };
    prepareStateDict: { [key: string]: AutoChessData_AutoChessPrepareStateData };
    randomEnemyAttributeDict: { [key: string]: AutoChessData_AutoChessRandomEnemyAttributeData };
    enabledEmoticonThemeIdList: string[];
    gameTipsList: AutoChessData_AutoChessGameTipData[];
    medalDataList: AutoChessData_AutoChessMedalData[];
    turnInfoDataDict: { [key: string]: { [key: number]: AutoChessData_AutoChessTurnInfoData } };
    roundScoreDataList: AutoChessData_AutoChessRoundScoreData[];
    reportPlayerDataList: CommonReportPlayerData[];
    broadcastList: AutoChessData_AutoChessBroadcastData[];
    constData: AutoChessData_AutoChessConstData;
}

export interface AutoChessData_AutoChessVersionInfoData {
    versionId: string;
    activityId: string;
    seasonName: string;
    startTime: number;
}

export interface AutoChessData_AutoChessBandData {
    bandId: string;
    bandName: string;
    bandIconId: string;
    unlockDesc: string;
}

export interface AutoChessData_AutoChessBroadcastData {
    id: string;
    desc: string;
    priority: number;
    type: AutoChessBroadcastType;
    paramList: string[];
}

export interface AutoChessData_AutoChessCultivateRelationData {
    TRANS_NUM: number;
    cultivateNum: number;
    effectId: string;
    evolvePhase: EvolvePhase;
    charLevel: number;
    atkPer: number;
    defPer: number;
    hpPer: number;
}

export interface AutoChessData_AutoChessEffectTypeData {
    description: string;
}

export interface AutoChessData_AutoChessBondInfoData {
    bondId: string;
    bondType: AutoChessBondType;
    powerIdList: string[];
    name: string;
    icon: string;
    isPower: boolean;
    bondOrder: number;
    isHiddenCharList: boolean;
}

export interface AutoChessData_AutoChessBossInfoData {
    bossId: string;
    enemyId: string;
    handbookEnemyId: string;
}

export interface AutoChessData_AutoChessEnemyTypeData {
    type: string;
    sortId: number;
    name: string;
    description: string;
    icon: string;
    typeIdentifier: number;
    involveRandom: boolean;
}

export interface AutoChessData_AutoChessEnterStepData {
    stepType: AutoChessPrepareStepType;
    sortId: number;
    time: number;
    hintTime: number;
    title: string;
    desc: string;
}

export interface AutoChessData_AutoChessShopStateTokenData {
    tokenId: string;
    tokenDisplayType: AutoChessShopTokenDisplayType;
}

export interface AutoChessData_AutoChessSkillTriggerData {
    profession: ProfessionCategory;
    subProfessionId: string;
    charId: string;
    skillIndex: number;
    skillTriggerType: AutoChessSkillTriggerType;
}

export interface AutoChessData_AutoChessPrepareStateData {
    effectId: string;
    buff: string;
    blackBoard: Blackboard;
}

export interface AutoChessData_AutoChessRandomEnemyAttributeData {
    enemyKey: string;
    level: number;
    extraEnemyIdentifier: number;
    extraEnemyKeyList: string[];
    isFlyEnemy: boolean;
    enemyBattleEffectivenessFactor: number;
}

export interface AutoChessData_AutoChessConstData {
    pingConds: PingCond[];
    matchingTipRotateInterval: number;
    minReplacedEnemyCount: number;
    maxReplacedEnemyCount: number;
    templateEnemyNormal: string;
    templateEnemyElite: string;
    templateEnemySpecial: string;
    templateEnemyNormalFly: string;
    templateEnemyEliteFly: string;
    templateEnemySpecialFly: string;
    templateEnemyToken: string;
    templateEnemyTokenFly: string;
    maxLevelCnt: number;
    specialEnemyNum: number;
    enemyTypeIdentifierToFillRandom: number;
    enemyMaxHpFactor: number;
    enemyAtkFactor: number;
    enemyDefFactor: number;
    enemyMagicResistanceFactor: number;
    singleReconnectTime: number;
    specialPhaseStayTime: number;
    hintTimeSpecialPhase: number;
    hintTimeNormalPhase: number;
    hintTimeFightPhase: number;
    hintTimeDotPhase: number;
    invitationSendCd: number;
    discountColor: string;
    premiumColor: string;
    normalColor: string;
    reportMaxNum: number;
    chatCd: number;
    chatTime: number;
    broadcastBeginDelay: number;
    noMoneyTipsBand: string[];
    bossTrailerStartRound: number;
    singleClosureStayTime: number;
    matchTimeMax: number;
    enemyDataLevelId: string;
}

export interface AutoChessData_AutoChessTurnInfoData {
    round: number;
    normalPhaseTime: number;
    isBossTurn: boolean;
    bossTurnHpReduceTime: number;
}

export interface AutoChessData_AutoChessMedalData {
    medalCount: number;
    medalIconId: string;
}

export interface AutoChessData_AutoChessGameTipData {
    tip: string;
    weight: number;
}

export interface AutoChessData_AutoChessRoundScoreData {
    round: number;
    score: number;
}

export interface ActFootballData {
    zoneAdditionDataMap: { [key: string]: ActFootballData_ActFootballZoneAdditionData };
    stageAdditionDataMap: { [key: string]: ActFootballData_ActFootballStageAdditionData };
    milestoneList: ActFootballData_ActFootballMilestoneItemData[];
    npcCharDataDict: { [key: number]: ActFootballData_ActFootballNPCCharData };
    constData: ActFootballData_ActFootballConstData;
}

export interface ActFootballData_ActFootballZoneAdditionData {
    zoneId: string;
    unlockText: string;
}

export interface ActFootballData_ActFootballStageAdditionData {
    stageId: string;
    selfTeamIcon: string;
    selfTeamName: string;
    enemyTeamIcon: string;
    enemyTeamName: string;
    unlockBuffId: string;
    unlockBuffIcon: string;
    unlockBuffName: string;
    unlockBuffDesc: string;
    firstCompletePoint: number;
    completePoint: number;
}

export interface ActFootballData_ActFootballMilestoneItemData {
    milestoneId: string;
    orderId: number;
    tokenNum: number;
    reward: ItemBundle;
    availTime: number;
}

export interface ActFootballData_ActFootballNPCCharData {
    instId: number;
    charId: string;
    level: number;
    evolvePhase: EvolvePhase;
    mainSkillLevel: number;
    specializeLevel: number;
    potentialRank: number;
    favorPoint: number;
    skinId: string;
    getTime: number;
}

export interface ActFootballData_ActFootballConstData {
    milestonePointId: string;
    milestoneTrackId: string;
}

export interface ActivityBossRushData {
    zoneAdditionDataMap: { [key: string]: ActivityBossRushData_ZoneAdditionData };
    stageGroupMap: { [key: string]: ActivityBossRushData_BossRushStageGroupData };
    stageAdditionDataMap: { [key: string]: ActivityBossRushData_BossRushStageAdditionData };
    stageDropDataMap: { [key: string]: { [key: number]: ActivityBossRushData_BossRushDropInfo } };
    missionAdditionDataMap: { [key: string]: ActivityBossRushData_BossRushMissionAdditionData };
    teamDataMap: { [key: string]: ActivityBossRushData_BossRushTeamData };
    relicList: ActivityBossRushData_RelicData[];
    relicLevelInfoDataMap: { [key: string]: ActivityBossRushData_RelicLevelInfoData };
    mileStoneList: ActivityBossRushData_BossRushMileStoneData[];
    bestWaveRuneList: RuneTable_PackedRuneData[];
    constData: ActivityBossRushData_ConstData;
}

export interface ActivityBossRushData_ZoneAdditionData {
    unlockText: string;
    displayStartTime: number;
}

export interface ActivityBossRushData_BossRushStageGroupData {
    stageGroupId: string;
    sortId: number;
    stageGroupName: string;
    stageIdMap: { [key: string]: string };
    waveBossInfo: string[][];
    normalStageCount: number;
    isHardStageGroup: boolean;
    unlockCondtion: string;
}

export interface ActivityBossRushData_BossRushStageAdditionData {
    stageId: string;
    stageType: ActivityBossRushData_BossRushStageType;
    stageGroupId: string;
    teamIdList: string[];
    unlockText: string;
}

export interface ActivityBossRushData_BossRushDropInfo {
    clearWaveCount: number;
    displayDetailRewards: ActivityBossRushData_DisplayDetailRewards[];
    firstPassRewards: ItemBundle[];
    passRewards: ItemBundle[];
}

export interface ActivityBossRushData_DisplayDetailRewards {
    type: ItemType;
    id: string;
    dropType: StageDropType;
    occPercent: OccPer;
    GetPercent: number;
    CannotGetPercent: number;
    dropCount: number;
}

export interface ActivityBossRushData_BossRushMissionAdditionData {
    missionId: string;
    isRelicTask: boolean;
}

export interface ActivityBossRushData_BossRushTeamData {
    teamId: string;
    teamName: string;
    charIdList: string[];
    teamBuffName: string;
    teamBuffDes: string;
    teamBuffId: string;
    maxCharNum: number;
    runeData: RuneTable_PackedRuneData;
}

export interface ActivityBossRushData_RelicData {
    relicId: string;
    sortId: number;
    name: string;
    icon: string;
    relicTaskId: string;
}

export interface ActivityBossRushData_RelicLevelInfo {
    level: number;
    effectDesc: string;
    runeData: RuneTable_PackedRuneData;
    needItemCount: number;
}

export interface ActivityBossRushData_RelicLevelInfoData {
    relicId: string;
    levelInfos: { [key: number]: ActivityBossRushData_RelicLevelInfo };
}

export interface ActivityBossRushData_BossRushMileStoneData {
    mileStoneId: string;
    mileStoneLvl: number;
    needPointCnt: number;
    rewardItem: ItemBundle;
}

export interface ActivityBossRushData_ConstData {
    maxProvidedCharNum: number;
    textMilestoneItemLevelDesc: string;
    milestonePointId: string;
    relicUpgradeItemId: string;
    defaultRelictList: string[];
    rewardSkinId: string;
}

export interface DefaultCheckInData {
    checkInList: { [key: number]: DefaultCheckInData_CheckInDailyInfo };
    apSupplyOutOfDateDict: { [key: string]: number };
    dynCheckInData: DefaultCheckInData_DynamicCheckInData;
    extraCheckinList: DefaultCheckInData_ExtraCheckinDailyInfo[];
}

export interface DefaultCheckInData_CheckInDailyInfo {
    itemList: ItemBundle[];
    order: number;
    color: number;
    keyItem: number;
    showItemOrder: number;
    isDynItem: boolean;
}

export interface DefaultCheckInData_DynCheckInDailyInfo {
    questionDesc: string;
    preOption: string;
    optionList: string[];
    showDay: number;
    spOrderIconId: string;
    spOrderDesc: string;
    spOrderCompleteDesc: string;
}

export interface DefaultCheckInData_OptionInfo {
    optionDesc: string;
    showImageId1: string;
    showImageId2: string;
    optionCompleteDesc: string;
    isStart: boolean;
}

export interface DefaultCheckInData_ExtraCheckinDailyInfo {
    order: number;
    blessing: string;
    absolutData: number;
    adTip: string;
    relativeData: number;
    itemList: ItemBundle[];
}

export interface DefaultCheckInData_DynamicCheckInData {
    dynCheckInDict: { [key: string]: DefaultCheckInData_DynCheckInDailyInfo };
    dynOptionDict: { [key: string]: DefaultCheckInData_OptionInfo };
    dynItemDict: { [key: string]: ItemBundle[] };
    constData: DefaultCheckInData_DynamicCheckInConsts;
    initOption: string;
}

export interface DefaultCheckInData_DynamicCheckInConsts {
    firstQuestionDesc: string;
    firstQuestionTipsDesc: string;
    expirationDesc: string;
    firstQuestionConfirmDesc: string;
}

export interface VersusCheckInData {
    checkInDict: { [key: number]: VersusCheckInData_DailyInfo };
    voteTasteList: VersusCheckInData_VoteData[];
    tasteInfoDict: { [key: number]: VersusCheckInData_TasteInfoData };
    tasteRewardDict: { [key: string]: VersusCheckInData_TasteRewardData };
    apSupplyOutOfDateDict: { [key: string]: number };
    versusTotalDays: number;
    ruleText: string;
}

export interface VersusCheckInData_DailyInfo {
    rewardList: ItemBundle[];
    order: number;
}

export interface VersusCheckInData_VoteData {
    plSweetNum: number;
    plSaltyNum: number;
    plTaste: number;
}

export interface VersusCheckInData_TasteInfoData {
    plTaste: number;
    tasteType: VersusCheckInData_TasteType;
    tasteText: string;
}

export interface VersusCheckInData_TasteRewardData {
    tasteType: VersusCheckInData_TasteType;
    rewardItem: ItemBundle;
}

export interface AllPlayerCheckinData {
    checkInList: { [key: number]: AllPlayerCheckinData_DailyInfo };
    apSupplyOutOfDateDict: { [key: string]: number };
    pubBhvs: { [key: string]: AllPlayerCheckinData_PublicBehaviour };
    personalBhvs: { [key: string]: AllPlayerCheckinData_PersonalBehaviour };
    constData: AllPlayerCheckinData_ConstData;
}

export interface AllPlayerCheckinData_DailyInfo {
    itemList: ItemBundle[];
    order: number;
    keyItem: boolean;
    showItemOrder: number;
}

export interface AllPlayerCheckinData_PublicBehaviour {
    sortId: number;
    allBehaviorId: string;
    displayOrder: number;
    allBehaviorDesc: string;
    requiringValue: number;
    requireRepeatCompletion: boolean;
    rewardReceivedDesc: string;
    rewards: ItemBundle[];
}

export interface AllPlayerCheckinData_PersonalBehaviour {
    sortId: number;
    personalBehaviorId: string;
    displayOrder: number;
    requireRepeatCompletion: boolean;
    desc: string;
}

export interface AllPlayerCheckinData_ConstData {
    characterName: string;
    skinName: string;
}

export interface ActivityCollectionData {
    collections: ActivityCollectionData_CollectionInfo[];
    apSupplyOutOfDateDict: { [key: string]: number };
    consts: ActivityCollectionData_Consts;
}

export interface ActivityCollectionData_CollectionInfo {
    id: number;
    itemType: ItemType;
    itemId: string;
    itemCnt: number;
    pointId: string;
    pointCnt: number;
    isBonus: boolean;
    pngName: string;
    pngSort: number;
    isShow: boolean;
    showInList: boolean;
    showIconBG: boolean;
    isBonusShow: boolean;
}

export interface ActivityCollectionData_Consts {
    showJumpBtn: boolean;
    jumpBtnType: ActivityCollectionData_JumpType;
    jumpBtnParam1: string;
    jumpBtnParam2: string;
    dailyTaskDisabled: boolean;
    dailyTaskStartTime: number;
    isSimpleMode: boolean;
}

export interface ActivityEnemyDuelData {
    milestoneList: ActivityEnemyDuelMilestoneItemData[];
    modeData: { [key: string]: ActivityEnemyDuelModeData };
    roundData: { [key: string]: ActivityEnemyDuelRoundData };
    poolData: { [key: string]: ActivityEnemyDuelPoolData };
    npcData: { [key: string]: ActivityEnemyDuelNpcData };
    npcSelectorData: { [key: string]: ActivityEnemyDuelNpcSelectorGroupData };
    enemyData: { [key: string]: ActivityEnemyDuelEnemyData };
    extraScoreData: { [key: string]: ActivityEnemyDuelExtraScoreGroupData };
    basicScores: number[];
    announceData: ActivityEnemyDuelAnnounceData[];
    commentData: { [key: string]: { [key: string]: ActivityEnemyDuelSingleCommentData } };
    constData: ActivityEnemyDuelConstData;
    constToastData: ActivityEnemyDuelConstToastData;
    tipsData: ActivityEnemyDuelTipsData[];
    enabledEmoticonThemeIdList: string[];
}

export interface ActivityEnemyDuelMilestoneItemData {
    milestoneId: string;
    orderId: number;
    tokenNum: number;
    reward: ItemBundle;
    availTime: number;
}

export interface ActivityEnemyDuelModeData {
    modeId: string;
    isMultiPlayer: boolean;
    isRoom: boolean;
    modeType: EnemyDuelModeType;
    stageIds: string[];
    pageId: number;
    innerSortId: number;
    modeName: string;
    modeShortName: string;
    modeEnName: string;
    maxPlayer: number;
    preposedMode: string;
    startTs: number;
    endTs: number;
    entryPicId: string;
    titlePics: string[];
    modeTarget: string;
    modeDesc: string;
    modeRecordDesc: string;
    extraTag: boolean;
    modeAvatarPicId: string;
    modeAvatarName: string;
    modeAvatarText: string;
    hasUnlockToast: boolean;
}

export interface ActivityEnemyDuelRoundData {
    roundId: string;
    modeId: string;
    guessTime: number;
    round: number;
    enemyPredefined: boolean;
    roundScore: number;
    enemyScore: number;
    enemyScoreRandom: number;
    enemySideMinLeft: number;
    enemySideMaxLeft: number;
    enemySideMinRight: number;
    enemySideMaxRight: number;
    enemyPoolLeft: string;
    enemyPoolRight: string;
    canSkip: boolean;
    canAllIn: boolean;
}

export interface ActivityEnemyDuelPoolData {
    enemyId: string;
    poolNormal: number;
    poolSmallEnemy: number;
    poolBoss: number;
    poolMusic: number;
    poolNoSurpriseEnemy: number;
    poolGiantBoss: number;
    poolAntiGiantBoss: number;
}

export interface ActivityEnemyDuelNpcData {
    npcId: string;
    avatarId: string;
    name: string;
    priority: number;
    specialStrategy: EnemyDuelBetStrategy;
    npcProb: number;
    defaultEnemyScore: number;
    allinProb: number;
}

export interface ActivityEnemyDuelNpcSelectorData {
    enemyId: string;
    score: number;
}

export interface ActivityEnemyDuelNpcSelectorGroupData {
    npcId: string;
    data: ActivityEnemyDuelNpcSelectorData[];
}

export interface ActivityEnemyDuelEnemyData {
    enemyId: string;
    originalEnemyId: string;
    tagType: string;
}

export interface ActivityEnemyDuelExtraScoreData {
    rankMin: number;
    rankMax: number;
    tokenNum: number;
}

export interface ActivityEnemyDuelExtraScoreGroupData {
    modeId: string;
    data: ActivityEnemyDuelExtraScoreData[];
}

export interface ActivityEnemyDuelAnnounceData {
    startTs: number;
    endTs: number;
    announceText: string;
    showNew: boolean;
}

export interface ActivityEnemyDuelSingleCommentData {
    commentId: string;
    priority: number;
    template: string;
    param: string[];
    commentText: string;
}

export interface ActivityEnemyDuelConstData {
    maxLoadingTime: number;
    maxRetryTimeInBattle: number;
    maxMatchTime: number;
    maxRoomTime: number;
    maxRetryTimeInTeamRoom: number;
    roomReserveTime: number;
    minRoomNum: number;
    roomFinishWaitingTime: number;
    roomMasterRestartWaitingTime: number;
    pingConds: ActivityEnemyDuelConstData_PingCond[];
    chatCd: number;
    chatTime: number;
    dailyMissionParam: number;
    dailyMissionReward: ItemBundle;
    dailyMissionName: string;
    dailyMissionDesc: string;
    maxOperatorDelay: number;
    maxPlaySpeed: number;
    delayTimeNeedTip: number;
    netBlockTimeNeedTip: number;
    stageTimeMax: number;
    npcCorrectProb: number;
    winStreakRoundNum: number;
    settlementPicNum: number;
    timeBeforeSelectAfterRoundBegin: number;
    npcMaxCorrectCountInStand: number;
    battlePhaseTimeMax: number;
    battleFinishToSettleTimeMax: number;
    minBetCd: number;
    defaultEmoticonItemId: string;
    defaultEmoticonPicId: string;
    defaultEnemyTag: string;
    modeOperationRoundNumber: number;
    modeOperationInitialScore: number;
    modeOperationMaxScore: number;
    modeOperationSelectTime: number;
    modeOperationSelectTimeLast: number;
    modeOperationSkipParam: number;
    modeOperationBetParam: number;
    modeOperationAllinParam: number;
    modeOperationTopRank: number;
    modeOperationRankTime: number;
    modeSoloOperationRankTime: number;
    modeOperationRewardMultiplier: number;
    modeOperationRewardMultiplierAllin: number;
    modeOperationHotRoundNumber: number;
    modeSoloOperationSelectTime: number;
    modeStandRoundNumber: number;
    modeStandShieldTurn: number;
    modeStandSelectTime: number;
    modeStandSelectTimeLast: number;
    modeStandAllinParam: number;
    modeStandTopRank: number;
    modeStandRankTime: number;
    modeStandHotRoundNumber: number;
    milestoneName: string;
    milestoneItemId: string;
    milestoneItemName: string;
    milestoneItemText: string;
    milestoneTrackId: string;
    entryVideoId: string;
    entryTabText: string;
    matchTabText: string;
    modeOperationId: string;
    modeStandId: string;
    multiPreposedModeId: string;
    entryMusicName: string;
    milestonePlanName: string;
    modeCondLockText: string;
    modeTimeLockText: string;
    titlePicRotateTime: number;
    titlePicId: string;
}

export interface ActivityEnemyDuelConstData_PingCond {
    cond: number;
    txt: string;
}

export interface ActivityEnemyDuelConstToastData {
    createRoomAliveFailed: string;
    joinRoomAliveFailed: string;
    roomIdFormatError: string;
    emptyRoomId: string;
    noRoom: string;
    continuousClicks: string;
    matchAliveFailed: string;
    serverOverloaded: string;
    matchTimeout: string;
    unlockMultiMode: string;
    unlockRoomMode: string;
    addFriendInRoom: string;
    roomIdCopySuccess: string;
    entryModeLock: string;
}

export interface ActivityEnemyDuelTipsData {
    id: string;
    txt: string;
    weight: number;
    modeIds: string[];
}

export interface DefaultShopData {
    goodId: string;
    slotId: number;
    price: number;
    availCount: number;
    overrideName: string;
    item: ItemBundle;
}

export interface DefaultZoneData {
    zoneId: string;
    zoneIndex: string;
    zoneName: string;
    zoneDesc: string;
    itemDropList: string[];
}

export interface DefaultFirstData {
    zoneList: DefaultZoneData[];
    shopList: DefaultShopData[];
}

export interface ActivityFloatParadeData {
    constData: ActivityFloatParadeData_ConstData;
    dailyDataDic: ActivityFloatParadeData_DailyData[];
    rewardPools: { [key: string]: { [key: string]: ActivityFloatParadeData_RewardPool } };
    tacticList: ActivityFloatParadeData_Tactic[];
    groupInfos: { [key: string]: ActivityFloatParadeData_GroupData };
}

export interface ActivityFloatParadeData_ConstData {
    cityName: string;
    cityNamePic: string;
    lowStandard: number;
    variationTitle: string;
    ruleDesc: string;
}

export interface ActivityFloatParadeData_DailyData {
    dayIndex: number;
    dateName: string;
    placeName: string;
    placeEnName: string;
    placePic: string;
    eventGroupId: string;
    extReward: ItemBundle;
}

export interface ActivityFloatParadeData_GroupData {
    groupId: string;
    name: string;
    startDay: number;
    endDay: number;
    extRewardDay: number;
    extRewardCount: number;
}

export interface ActivityFloatParadeData_RewardPool {
    grpId: string;
    id: string;
    type: string;
    name: string;
    desc: string;
    reward: ItemBundle;
}

export interface ActivityFloatParadeData_Tactic {
    id: number;
    name: string;
    packName: string;
    briefName: string;
    rewardVar: { [key: string]: number };
}

export interface ActivityInterlockData {
    stageAdditionInfoMap: { [key: string]: ActivityInterlockData_StageAdditionData };
    treasureMonsterMap: { [key: string]: ActivityInterlockData_TreasureMonsterData };
    specialAssistData: SharedCharData;
    mileStoneItemList: ActivityInterlockData_MileStoneItemInfo[];
    finalStageProgressMap: { [key: string]: ActivityInterlockData_FinalStageProgressData[] };
}

export interface ActivityInterlockData_StageAdditionData {
    stageId: string;
    stageType: ActivityInterlockData_InterlockStageType;
    lockStageKey: string;
    lockSortIndex: number;
}

export interface ActivityInterlockData_MileStoneItemInfo {
    mileStoneId: string;
    orderId: number;
    tokenNum: number;
    item: ItemBundle;
}

export interface ActivityInterlockData_TreasureMonsterData {
    lockStageKey: string;
    enemyId: string;
    enemyName: string;
    enemyIcon: string;
    enemyDescription: string;
}

export interface ActivityInterlockData_FinalStageProgressData {
    stageId: string;
    killCnt: number;
    apCost: number;
    favor: number;
    exp: number;
    gold: number;
}

export interface ActivityLoginData {
    description: string;
    itemList: ItemBundle[];
    apSupplyOutOfDateDict: { [key: string]: number };
}

export interface ActivityMainlineBuffData {
    missionGroupList: { [key: string]: ActivityMainlineBuffData_MissionGroupData };
    periodDataList: ActivityMainlineBuffData_PeriodData[];
    apSupplyOutOfDateDict: { [key: string]: number };
    constData: ActivityMainlineBuffData_ConstData;
}

export interface ActivityMainlineBuffData_MissionGroupData {
    id: string;
    bindBanner: string;
    sortId: number;
    zoneId: string;
    missionIdList: string[];
}

export interface ActivityMainlineBuffData_PeriodData {
    id: string;
    startTime: number;
    endTime: number;
    favorUpCharDesc: string;
    favorUpImgName: string;
    newChapterImgName: string;
    newChapterZoneId: string;
    stepDataList: ActivityMainlineBuffData_PeriodData_StepData[];
}

export interface ActivityMainlineBuffData_PeriodData_StepData {
    isBlock: boolean;
    favorUpDesc: string;
    unlockDesc: string;
    bindStageId: string;
    blockDesc: string;
}

export interface ActivityMainlineBuffData_ConstData {
    favorUpStageRange: string;
}

export interface ActivityMiniStoryData {
    tokenItemId: string;
    zoneDescList: { [key: string]: ActivityMiniStoryData_ZoneDescInfo };
    favorUpList: { [key: string]: ActivityMiniStoryData_FavorUpInfo };
    extraDropZoneList: string[];
}

export interface ActivityMiniStoryData_ZoneDescInfo {
    zoneId: string;
    unlockText: string;
}

export interface ActivityMiniStoryData_FavorUpInfo {
    charId: string;
    displayStartTime: number;
    displayEndTime: number;
}

export interface ActivityRoguelikeData {
    outBuffInfos: { [key: string]: ActivityRoguelikeData_OuterBuffUnlockInfoData };
    apSupplyOutOfDateDict: { [key: string]: number };
    outerBuffToken: string;
    shopToken: string;
    relicUnlockTime: number;
    milestoneTokenRatio: number;
    outerBuffTokenRatio: number;
    relicTokenRatio: number;
    relicOuterBuffTokenRatio: number;
    reOpenCoolDown: number;
    tokenItem: ItemBundle;
    charStoneId: string;
    milestone: ActivityRoguelikeData_MileStoneItemInfo[];
    unlockConds: ActivityTable_CustomUnlockCond[];
}

export interface ActivityRoguelikeData_OuterBuffUnlockInfoData {
    buffId: string;
    buffUnlockInfos: { [key: number]: ActivityRoguelikeData_OuterBuffUnlockInfo };
}

export interface ActivityRoguelikeData_OuterBuffUnlockInfo {
    buffLevel: number;
    name: string;
    iconId: string;
    description: string;
    usage: string;
    itemId: string;
    itemType: ItemType;
    cost: number;
}

export interface ActivityRoguelikeData_MileStoneItemInfo {
    mileStoneId: string;
    orderId: number;
    tokenNum: number;
    item: ItemBundle;
}

export interface ActivitySwitchCheckinData {
    constData: ActivitySwitchCheckinConstData;
    rewards: { [key: string]: ItemBundle[] };
    rewardShowDatas: { [key: string]: ActivitySwitchCheckinRewardShowData };
    apSupplyOutOfDateDict: { [key: string]: number };
    sortIdDict: { [key: string]: number };
}

export interface ActivitySwitchCheckinConstData {
    activityTime: string;
    activityRule: string;
}

export interface ActivitySwitchCheckinRewardShowData {
    checkinId: string;
    rewardsTitle: string;
    rewardShowItemDatas: ActivitySwitchCheckinRewardItemShowData[];
    mainRewardShowData: ActivitySwitchCheckinMainRewardShowData;
}

export interface ActivitySwitchCheckinMainRewardShowData {
    mainRewardPicId: string;
    mainRewardName: string;
    mainRewardCount: number;
    hasTip: boolean;
    tipItemBundle: ItemBundle;
}

export interface ActivitySwitchCheckinRewardItemShowData {
    itemBundle: ItemBundle;
    isMainReward: boolean;
}

export interface ActivityYear5GeneralData {
    constData: ActivityYear5GeneralConstData;
    unlimitedApRewards: ActivityYear5GeneralUnlimitedApRewardData[];
}

export interface ActivityYear5GeneralUnlimitedApRewardData {
    rewardIndex: number;
    rewardItem: ItemBundle;
}

export interface ActivityYear5GeneralConstData {
    rewPoint: number;
    rewMainDesc: string;
    rewApDesc: string;
    rewEndDesc: string;
    actPrimaryDesc: string;
    actEntryDesc: string;
    actSecondaryDesc: string;
    actRewardDesc: string;
    missionArchiveTopicId: string;
    missionArchiveUnlockDesc: string;
}

export interface ActMainlineBpExtraData {
    periodDataList: ActMainlineBpExtraData_ActMainlineBpExtraPeriodData[];
}

export interface ActMainlineBpExtraData_ActMainlineBpExtraPeriodData {
    periodId: string;
    startTs: number;
    endTs: number;
}

export interface ActMainSSZoneAdditionData {
    unlockTip: string;
    unlockTipAfterRetro: string;
}

export interface ActMainSSData {
    zoneAdditionDataMap: { [key: string]: ActMainSSZoneAdditionData };
}

export interface ActMultiV3Data {
    selectStepDataList: ActMultiV3SelectStepData[];
    squadInfoList: ActMultiV3SquadInfoData[];
    identityDataList: ActMultiV3IdentityData[];
    squadEffectList: ActMultiV3SquadEffectData[];
    targetMissionDataDict: { [key: string]: ActMultiV3TargetMissionData };
    mapTypeDataDict: { [key: string]: ActMultiV3MapTypeData };
    mapDataDict: { [key: string]: ActMultiV3MapData };
    mapModeDataDict: { [key: string]: ActMultiV3MapModeData };
    mapDiffDataDict: { [key: string]: ActMultiV3MapDiffData };
    missionTitleDict: { [key: string]: string };
    titleDataDict: { [key: string]: ActMultiV3TitleData };
    photoTypeDataDict: { [key: string]: ActMultiV3PhotoTypeData };
    photoWeeklyRewardDataDict: { [key: string]: ActMultiV3WeeklyPhotoRewardData };
    matchPosDataDict: { [key: string]: ActMultiV3MatchPosData };
    enabledEmoticonThemeIdList: string[];
    diffStarRewardDict: { [key: string]: ActMultiV3DiffStarRewardData };
    milestoneList: ActMultiV3MilestoneData[];
    tipsDataList: ActMultiV3TipsData[];
    reportDataList: CommonReportPlayerData[];
    tempCharDataList: ActMultiV3TempCharData[];
    constToastData: ActMultiV3ConstToastData;
    constData: ActMultiV3ConstData;
    sailBoatLevelPoolDict: { [key: string]: ActMultiV3SailBoatLevelPoolData };
    sailBoatBlockPoolDict: { [key: string]: ActMultiV3SailBoatBlockPoolData[] };
    sailBoatBlockInfoList: { [key: string]: ActMultiV3SailBoatBlockInfoData };
}

export interface ActMultiV3SelectStepData {
    stepType: ActMultiV3PrepareStepType;
    sortId: number;
    time: number;
    hintTime: number;
    title: string;
    desc: string;
}

export interface ActMultiV3IdentityData {
    id: string;
    sortId: number;
    picId: string;
    type: ActMultiV3IdentityType;
    maxNum: number;
    color: string;
}

export interface ActMultiV3SquadInfoData {
    id: string;
    sortId: number;
    name: string;
    modeType: ActMultiV3MapModeType;
}

export interface ActMultiV3SquadEffectData {
    id: string;
    iconId: string;
    sortId: number;
    name: string;
    themeColor: string;
    buffDesc: string;
    debuffDesc: string;
    token: ActMultiV3SquadEffectData_Token;
    runeData: RuneTable_PackedRuneData;
    isInitial: boolean;
}

export interface ActMultiV3SquadEffectData_Token {
    name: string;
    desc: string;
    iconId: string;
}

export interface ActMultiV3TargetMissionData {
    id: string;
    sortId: number;
    title: string;
    battleDesc: string;
    description: string;
}

export interface ActMultiV3MapTypeData {
    modeId: string;
    mode: ActMultiV3MapModeType;
    difficulty: ActMultiV3MapDiffType;
    isDefaultSelectInQuickMatch: boolean;
    squadMax: number;
    matchUnlockModeId: string;
    matchUnlockParam: number;
    stageIdInModeList: string[];
    unlockHint: string;
}

export interface ActMultiV3MatchPosUnlockCond {
    diff: ActMultiV3MapDiffType;
    completeMapCount: number;
    requireMapStar: number;
    unlockHint: string;
}

export interface ActMultiV3MatchPosData {
    matchPos: ActMultiV3MatchPosType;
    sortId: number;
    name: string;
    desc: string;
    posToast: string;
    matchDesc: string;
    unlockCond: ActMultiV3MatchPosUnlockCond;
}

export interface ActMultiV3MapData {
    stageId: string;
    modeId: string;
    sortId: number;
    missionIdList: string[];
    displayEnemyIdList: string[];
    previewIconId: string;
}

export interface ActMultiV3MapModeData {
    modeType: ActMultiV3MapModeType;
    name: string;
    iconId: string;
    color: string;
    quickMatchSortId: number;
    stageOverviewSortId: number;
    unlockTs: number;
    unlockPageTitle: string;
    unlockPageDesc: string;
}

export interface ActMultiV3MapDiffData {
    diffType: ActMultiV3MapDiffType;
    name: string;
}

export interface ActMultiV3TitleData {
    order: number;
    titleDesc: string;
    isBack: boolean;
}

export interface ActMultiV3PhotoSlotData {
    slotPosX: number;
    slotPosY: number;
    slotRotZ: number;
    slotScale: number;
    slotAnimName: string;
}

export interface ActMultiV3PhotoTypeData {
    photoTypeName: string;
    sortId: number;
    background: string;
    photoDesc: string;
    slots: ActMultiV3PhotoSlotData[];
}

export interface ActMultiV3WeeklyPhotoRewardData {
    order: number;
    titleDesc: string;
    unlockTime: number;
    rewards: ItemBundle[];
}

export interface ActMultiV3StarRewardData {
    starNum: number;
    rewards: ItemBundle[];
    dailyMissionPoint: number;
}

export interface ActMultiV3DiffStarRewardData {
    diffType: ActMultiV3MapDiffType;
    starRewardDatas: ActMultiV3StarRewardData[];
}

export interface ActMultiV3MilestoneData {
    id: string;
    level: number;
    needPointCnt: number;
    rewardItem: ItemBundle;
    availTime: number;
}

export interface ActMultiV3TipsData {
    id: string;
    txt: string;
    weight: number;
}

export interface ActMultiV3TempCharData {
    charId: string;
    level: number;
    evolvePhase: EvolvePhase;
    mainSkillLevel: number;
    specializeLevel: number;
    potentialRank: number;
    favorPoint: number;
    skinId: string;
}

export interface ActMultiV3SailBoatLevelPoolData {
    stageId: string;
    startBlockPool: string;
    midBlockPool: string;
    endBlockPool: string;
}

export interface ActMultiV3SailBoatBlockPoolData {
    blockPool: string;
    blockId: string;
    startDirType: ActMultiV3BlockDirType;
    endDirType: ActMultiV3BlockDirType;
    weight: number;
}

export interface ActMultiV3SailBoatBlockInfoData {
    blockId: string;
    blockLevelId: string;
    startDirType: ActMultiV3BlockDirType;
    endDirType: ActMultiV3BlockDirType;
    blockType: ActMultiV3BlockType;
}

export interface ActMultiV3InverseUnlockCond {
    diff: ActMultiV3MapDiffType;
    requireStarCnt: number;
}

export interface ActMultiV3ConstToastData {
    noRoom: string;
    fullRoom: string;
    roomIdFormatError: string;
    roomIdCopySuccess: string;
    banned: string;
    serverOverload: string;
    matchAliveFailed: string;
    createRoomAliveFailed: string;
    joinRoomAliveFailed: string;
    roomOwnerReviseMap: string;
    roomCollaboratorReviseMap: string;
    roomCollaboratorJoinRoom: string;
    roomCollaboratorExitRoom: string;
    roomOwnerReviseMode: string;
    roomCollaboratorReviseMode: string;
    continuousClicks: string;
    matchNoProject: string;
    otherModeTrainingLock: string;
    teamLock: string;
    mentorLockTips: string;
    unlockMentorInMatch: string;
    unlockInverseMode: string;
    unlockNewMapType: string;
    teamFullLow: string;
    teamFullHigh: string;
    difficultUnlock: string;
    weeklyAlbumTimeUnlock: string;
    weeklyAlbumCommitUnlock: string;
    squadLockHint: string;
    squadEffectEditHint: string;
    inverseModeUnlockHint: string;
    noPhotoInTemplateHint: string;
    cannotResubmitHint: string;
    cannotSaveTitleChange: string;
    matchPrepareRoomClose: string;
    stageListViewTimeLockToast: string;
}

export interface ActMultiV3ConstData {
    milestoneId: string;
    roomNumCopyDesc: string;
    noMapRoomNumCopyDesc: string;
    randomMapRoomNumCopyDesc: string;
    targetCd: number;
    squadMinNum: number;
    squadMaxNum: number;
    defenseTraMax: number;
    defenseOrdMax: number;
    defenseDifMax: number;
    stageChooseAnimRandomStageIdList: string[];
    requireStarsPerBuffKey: number;
    maxUnlockNum: number;
    mapUnlockDesc1: string;
    mapUnlockDesc2: string;
    mapUnlockDesc3: string;
    mapUnlockDesc4: string;
    mapUnlockDesc5: string;
    mapUnlockDesc6: string;
    mapUnlockDesc7: string;
    difUnlockCond: number;
    ordRewardStageId: string;
    difRewardStageId: string;
    maxMatchTime: number;
    tipsSwitchTime: number;
    pingConds: ActMultiV3ConstData_PingCond[];
    chatCd: number;
    chatTime: number;
    markCd: number;
    markCond1: number;
    markCond2: number;
    dailyMissionParam: number;
    dailyMissionName: string;
    dailyMissionDesc: string;
    dailyMissionRule: string;
    missionDesc: string;
    dailyMissionRewardItem: ItemBundle;
    normalGreatVoiceStar: number;
    footballGreatVoiceNum: number;
    defenceGreatVoiceWave: number;
    reportMaxNum: number;
    reward1Id: string;
    reward1Text: string;
    reward2Id: string;
    reward2Text: string;
    maxRetryTimeInTeamRoom: number;
    maxRetryTimeInMatchRoom: number;
    maxRetryTimeInBattle: number;
    maxOperatorDelay: number;
    maxPlaySpeed: number;
    delayTimeNeedTip: number;
    settleRetryTime: number;
    playerDisplayTimeMax: number;
    isMatchDefaultInverse: boolean;
    inverseUnlockCond: ActMultiV3InverseUnlockCond;
    inverseModeHint: string;
    teamUnlockStageId: string;
    teamUnlockParam: number;
    trainPartnerCharId: string;
    trainPartnerCharSkinId: string;
    trainPartnerPlayerName: string;
    trainPartnerPlayerLevel: number;
    trainPartnerBuffId: string;
    trainPartnerAvatarGroupType: PlayerAvatarGroupType;
    trainPartnerAvatarId: string;
    trainPartnerTitleList: string[];
    trainPartnerNameCardSkinId: string;
    trainPartnerNameCardSkinTmpl: number;
    maxPhotoPerType: number;
    checkFriendStateTime: number;
    photoCharacterDefaultAct: string;
    trainingStageConfirmDesc: string;
    joinRoomLongTimeThreshold: number;
    invitationSendCd: number;
    boatMapReachableSize: number;
    boatMapSizeMax: number;
    boatExitMapOffset: number;
    boatEnterTranOffset: number;
    boatCollisionLossSpeedFactor: number;
    boatAirFactor: number;
    boatFrictionFactor: number;
    boatForceInterval: number;
    boatExchangeDamageMax: number;
    boatExchangeDamageMin: number;
    boatExchangeForceMax: number;
    boatExchangeForceMin: number;
    waterSpeedFactor: number;
}

export interface ActMultiV3ConstData_PingCond {
    cond: number;
    txt: string;
}

export interface ActRecruitOnlyData {
    recruitData: ActRecruitOnlyData_RecruitOnlyItemData;
    previewData: ActRecruitOnlyData_RecruitOnlyItemData;
}

export interface ActRecruitOnlyData_RecruitOnlyItemData {
    id: string;
    phaseNum: number;
    tagId: number;
    tagTimes: number;
    startTime: number;
    endTime: number;
    startTimeDesc: string;
    endTimeDesc: string;
    desc1: string;
    desc2: string;
}

export interface ActVasebreakerData {
    zoneAdditionDataMap: { [key: string]: ActVasebreakerData_ActVasebreakerZoneAdditionData };
    stageAdditionDataMap: { [key: string]: ActVasebreakerData_ActVasebreakerStageAdditionData };
    stageUnlockToastMap: { [key: string]: ActVasebreakerData_ActVasebreakerStageUnlockToastData };
    stageDropDataMap: { [key: string]: ActVasebreakerData_ActVasebreakerStageDropData };
    milestoneList: ActVasebreakerData_ActVasebreakerMilestoneItemData[];
    stickerList: ActVasebreakerData_ActVasebreakerStickerData[];
    constData: ActVasebreakerData_ActVasebreakerConstData;
}

export interface ActVasebreakerData_ActVasebreakerZoneAdditionData {
    zoneId: string;
    unlockText: string;
}

export interface ActVasebreakerData_ActVasebreakerStageAdditionData {
    stageId: string;
    firstCost: number;
    formationMostNum: number;
    formationLeastNum: number;
}

export interface ActVasebreakerData_ActVasebreakerStageUnlockToastData {
    stageId: string;
    unlockToast: string;
}

export interface ActVasebreakerData_ActVasebreakerStageDropData {
    stageId: string;
    itemType: ItemType;
    itemId: string;
    retryCount: number;
    firstCount: number;
    completeCount: number;
    onceCompleteCount: number;
    isDisplay: boolean;
}

export interface ActVasebreakerData_ActVasebreakerMilestoneItemData {
    milestoneId: string;
    orderId: number;
    tokenNum: number;
    reward: ItemBundle;
    availTime: number;
}

export interface ActVasebreakerData_ActVasebreakerStickerData {
    stickerId: string;
    stickerIcon: string;
    template: string;
    stickerName: string;
    param: string[];
}

export interface ActVasebreakerData_ActVasebreakerConstData {
    milestonePointId: string;
    milestoneTrackId: string;
    levelEntranceText: string;
    rewardFurnitureId: string;
    rewardFurnitureText: string;
    rewardAvatarId: string;
    rewardAvatarText: string;
}

export interface ActVecBreakV2Data {
    offenseStageDict: { [key: string]: ActVecBreakV2OffenseStageData };
    hardStageDict: { [key: string]: ActVecBreakV2HardStageData };
    defenseBasicDict: { [key: string]: ActVecBreakV2DefenseBasicData };
    defenseDetailDict: { [key: string]: ActVecBreakV2DefenseDetailData };
    zoneDict: { [key: string]: ActVecBreakV2ZoneData };
    defenseGroupDict: { [key: string]: ActVecBreakV2DefenseGroupData };
    battleBuffDict: { [key: string]: ActVecBreakV2BattleBuffData };
    milestoneList: ActVecBreakV2MilestoneItemData[];
    stageRewardDict: { [key: string]: ActVecBreakV2StageRewardData };
    constData: ActVecBreakV2ConstData;
    squadBuffAvailStageList: string[];
    scheduleBlockList: ActVecBreakV2ScheduleBlockData[];
    defenseZoneId: string;
    offenseZoneId: string;
    hardZoneId: string;
    firstDefenseStageId: string;
}

export interface ActVecBreakV2OffenseStageData {
    stageId: string;
    level: number;
    levelLayout: string;
    storyDesc: string;
    particleType: ActVecBreakV2ParticleType;
    bossData: ActVecBreakV2BossData;
}

export interface ActVecBreakV2ZoneData {
    zoneId: string;
    stageLockHint: string;
}

export interface ActVecBreakV2HardStageData {
    stageId: string;
    orderType: ActVecBreakV2StageOrderType;
    storyDesc: string;
    bossData: ActVecBreakV2BossData;
}

export interface ActVecBreakV2ScheduleBlockData {
    startTs: number;
    endTs: number;
}

export interface ActVecBreakV2BossData {
    enemyId: string;
    name: string;
    desc: string;
    level: number;
    iconId: string;
    levelDecoFigureId: string;
    levelDecoSignId: string;
    decoId: string;
}

export interface ActVecBreakV2DefenseBasicData {
    stageId: string;
    groupId: string;
    sortId: number;
    startTs: number;
}

export interface ActVecBreakV2DefenseDetailData {
    stageId: string;
    buffId: string;
    defenseCharLimit: number;
    bossIconId: string;
}

export interface ActVecBreakV2DefenseGroupData {
    groupId: string;
    sortId: number;
    orderedStageList: string[];
}

export interface ActVecBreakV2BattleBuffData {
    buffId: string;
    name: string;
    desc: string;
    iconId: string;
    runeData: RuneTable_PackedRuneData;
}

export interface ActVecBreakV2MilestoneItemData {
    milestoneId: string;
    orderId: number;
    tokenNum: number;
    reward: ItemBundle;
    availTime: number;
}

export interface ActVecBreakV2StageRewardData {
    stageId: string;
    completeRewardCnt: number;
    normalRewardCnt: number;
    limitReward: ActVecBreakV2StageRewardData_LimitedRewardData;
}

export interface ActVecBreakV2StageRewardData_LimitedRewardData {
    startTs: number;
    endTs: number;
    rewardCnt: number;
}

export interface ActVecBreakV2ConstData {
    defenseDesc: string;
    defenseOverviewName: string;
    milestoneName: string;
    milestoneItemId: string;
    bossDescTitle: string;
    defenseUnlockRequireStageId: string;
    offenseNavLockToastStageId: string;
    offenseNavLockToastStr: string;
    offenseHardUnlockToast: string;
    hardUnlockStageId: string;
    defenseRetreatSingleText: string;
    defenseRetreatMultipleText: string;
    defenseReplaceText: string;
    defenseEquipBuffLimit: number;
    displayMedalId: string;
    defenseAddBuffToast: string;
    defenseRemoveBuffToast: string;
    defenseReplaceBuffToast: string;
    defenseBuffExceedToast: string;
    defendSameGroupHint: string;
    defendOtherHint: string;
    defenseBuffLockToast: string;
    offenseBuffSelectUnsaveHint: string;
    defenceBattleFinishEquipText: string;
    defenceBattleFinishActivateText: string;
    defenceBattleFinishSquadText: string;
    milestoneTrackId: string;
    themeColor: string;
    subTitleName: string;
}

export interface FireworkData {
    plateData: { [key: string]: FireworkData_PlateData };
    animalData: { [key: string]: FireworkData_AnimalData };
    levelData: { [key: string]: FireworkData_LevelData };
    constData: FireworkData_ConstData;
}

export interface FireworkData_PlateContent {
    plateContent: GridPosition[];
}

export interface FireworkData_PlateData {
    plateId: string;
    sortId: number;
    directionType: FireworkData_FireworkDirectionType;
    unlockLevel: string;
    plateRank: number;
    plateContents: FireworkData_PlateContent[];
    isCraft: boolean;
}

export interface FireworkData_AnimalData {
    animalId: string;
    sortId: number;
    animalName: string;
    animalBuffDesc1: string;
    animalBuffDesc2: string;
    unlockLevel: string;
    type: FireworkData_FireworkType;
    noneOutlineUnselectIconId: string[];
    outlineIconId: string[];
    noneOutlineSelectIconId: string[];
    unlockToast: string;
    unlockToastIconId: string;
    changedToast: string;
    fireworkAnimalNameIconId: string;
}

export interface FireworkData_LevelData {
    levelId: string;
    sortId: number;
    trapPosX: number;
    trapPosY: number;
    isSplevel: boolean;
}

export interface FireworkData_ConstData {
    maxFireworkNum: number;
    maxFireworkPlateRowCount: number;
    unlockStageCode: string;
    dontDisplayFireworkPluginStageList: string[];
}

export interface CommonFavorUpInfo {
    charId: string;
    displayStartTime: number;
    displayEndTime: number;
}

export interface KVSwitchInfo {
    isDefault: boolean;
    displayTime: number;
    stageId: string;
    passState: PlayerStageState;
}

export interface DynEntrySwitchInfo {
    entryId: string;
    sortId: number;
    stageId: string;
    signalId: string;
}

export interface ActivityKVSwitchData {
    kvSwitchInfo: { [key: string]: KVSwitchInfo };
}

export interface ActivityDynEntrySwitchData {
    entrySwitchInfo: { [key: string]: DynEntrySwitchInfo };
    randomEntrySwitchInfo: { [key: string]: DynEntrySwitchInfo };
    entryAnimationInfo: { [key: string]: DynEntryAnimationInfo };
}

export interface DynEntryAnimationInfo {
    animationId: string;
    sortId: number;
    isDefaultAnimation: boolean;
    stageId: string;
    signalId: string;
}

export interface ActivityStageRewardData {
    stageRewardsDict: { [key: string]: StageData_DisplayDetailRewards[] };
}

export interface ActivityThemeData {
    id: string;
    type: ActivityThemeType;
    funcId: string;
    endTs: number;
    sortId: number;
    itemId: string;
    timeNodes: ActivityThemeData_TimeNode[];
    picGroups: ActivityThemeData_PicGroup[];
    startTs: number;
}

export interface ActivityThemeData_TimeNode {
    title: string;
    ts: number;
}

export interface ActivityThemeData_PicGroup {
    sortIndex: number;
    picId: string;
    availCheck: CommonAvailCheck;
}

export interface ActivityCommonMilestoneData {
    milestoneId: string;
    milestoneLvl: number;
    tokenNum: number;
    rewardItem: ItemBundle;
    availableTime: number;
}

export interface ActivityTable {
    basicInfo: { [key: string]: ActivityTable_BasicData };
    homeActConfig: { [key: string]: ActivityTable_HomeActivityConfig };
    zoneToActivity: { [key: string]: string };
    actTimeTrackPoint: { [key: string]: number };
    missionData: MissionData[];
    missionGroup: MissionGroup[];
    replicateMissions: { [key: string]: string };
    activity: ActivityTable_ActivityDetailTable;
    extraData: ActivityTable_ActivityExtraData;
    activityItems: { [key: string]: string[] };
    syncPoints: { [key: string]: number[] };
    dynActs: { [key: string]: JsonValue };
    stageRewardsData: { [key: string]: ActivityStageRewardData };
    actThemes: ActivityThemeData[];
    actFunData: AprilFoolTable;
    carData: CartData;
    siracusaData: SiracusaData;
    fireworkData: FireworkData;
    halfIdleData: HalfIdleData;
    kvSwitchData: { [key: string]: ActivityKVSwitchData };
    dynEntrySwitchData: { [key: string]: ActivityDynEntrySwitchData };
    hiddenStageData: ActivityTable_ActivityHiddenStageData[];
    missionArchives: { [key: string]: MissionArchiveData };
    fifthAnnivExploreData: FifthAnnivExploreData;
    anniv7thData: Anniv7thMainlineData;
    autoChessData: AutoChessData;
    arkhubData: ArkhubData;
    stringRes: { [key: string]: { [key: string]: string } };
    activityTraps: { [key: string]: ActivityTable_ActivityTrapsData };
    activityTrapMissions: { [key: string]: ActivityTable_ActivityTrapMissionsData };
    trapRuneDataDict: { [key: string]: RuneTable_PackedRuneData };
    activityTemplateMissionStyles: { [key: string]: TemplateMissionStyleData };
    activityCrossDayTrackTypeDataDict: { [key: string]: CrossDayTrackTypeData };
    activityCrossDayTrackTypeMap: { [key: string]: string[] };
    activityStoryReadTipsDatas: { [key: string]: StoryReadTipsData };
}

export interface ActivityTable_PicGroup {
    sortIndex: number;
    picId: string;
    availCheck: CommonAvailCheck;
}

export interface ActivityTable_BasicData {
    id: string;
    type: ActivityType;
    displayType: ActivityDisplayType;
    name: string;
    startTime: number;
    endTime: number;
    rewardEndTime: number;
    displayOnHome: boolean;
    hasStage: boolean;
    templateShopId: string;
    medalGroupId: string;
    ungroupedMedalIds: string[];
    isReplicate: boolean;
    needFixedSync: boolean;
    trapDomainId: string;
    recType: ActivityCompleteType;
    isPageEntry: boolean;
    isMagnify: boolean;
    picGroup: ActivityTable_PicGroup[];
    usePicGroup: boolean;
}

export interface ActivityTable_HomeActivityConfig {
    actId: string;
    isPopupAfterCheckin: boolean;
    showTopBarMenu: boolean;
    actTopBarColor: string;
    actTopBarText: string;
}

export interface ActivityTable_CustomUnlockCond {
    actId: string;
    stageId: string;
}

export type ActivityTable_ActivityDetailTable = { [key: string]: JsonValue };

export interface ActivityTable_ActivityExtraData {
    typeMainlineBpData: { [key: string]: ActMainlineBpExtraData };
    MAINLINE_BP: JsonValue;
}

export interface ActivityTable_ActivityHiddenAreaData {
    name: string;
    desc: string;
    preposedStage: ActivityTable_ActHiddenAreaPreposeStageData[];
    preposedTime: number;
}

export interface ActivityTable_ActHiddenAreaPreposeStageData {
    stageId: string;
    unlockRank: PlayerBattleRank;
}

export interface ActivityTable_ActivityHiddenStageUnlockConditionData {
    unlockStageId: string;
    unlockTemplate: string;
    unlockParams: string[];
    missionStageId: string;
    unlockedName: string;
    lockedName: string;
    lockCode: string;
    unlockedDes: string;
    templateDesc: string;
    desc: string;
    riddle: string;
}

export interface ActivityTable_ActivityHiddenStageData {
    stageId: string;
    encodedName: string;
    showStageId: string;
    rewardDiamond: boolean;
    missions: ActivityTable_ActivityHiddenStageUnlockConditionData[];
}

export interface ActivityTable_ActivityTrapsData {
    templateTraps: { [key: string]: ActivityTable_TemplateTrapData };
    trapConstData: ActivityTable_ActivityTrapConstData;
}

export interface ActivityTable_ActivityTrapMissionsData {
    trapMissions: { [key: string]: ActivityTable_TrapMissionData };
}

export interface ActivityTable_TemplateTrapData {
    trapId: string;
    sortId: number;
    trapName: string;
    trapDesc: string;
    trapText: string;
    trapIcon1: string;
    trapIcon2: string;
    trapTaskId: string;
    trapUnlockDesc: string;
    trapBuffId: string;
    availableCount: number;
}

export interface ActivityTable_TrapMissionData {
    id: string;
    description: string;
    type: MissionType;
    rewards: MissionDisplayRewards[];
}

export interface ActivityTable_ActivityTrapConstData {
    stageUnlockTrapDesc: string;
    trapMaximum: number;
    stageCanNotUseTrap: string[];
    mustSelectTrap: boolean;
    systemUnlockToast: string;
    squadSaveSuccessToast: string;
    lockedToast: string;
    showBtnBack: boolean;
    useSpecialToast: boolean;
}

export interface Anniv7thClueGroupData {
    clueGroupId: string;
    sortId: number;
    clueGroupName: string;
    clueGroupSubName: string;
    clueGroupBg: string;
}

export interface Anniv7thClueData {
    clueId: string;
    clueGroupId: string;
    sortId: number;
    clueLink: string[];
    clueName: string;
    clueOwner: string;
    clueDesc: string;
    unlockDesc: string;
    clueOwnerPic: string;
    pageRes: string;
}

export interface Anniv7thClueRewardData {
    clueRecordId: string;
    clueRecord: number;
    clueRecordDesc: string;
    rewards: ItemBundle[];
}

export interface Anniv7thClueConstData {
    unlockStageId: string;
    unlockToast: string;
}

export interface Anniv7thDisplayData {
    sortId: number;
    charId: string;
    voiceId: string;
}

export interface Anniv7thDisplayNodeData {
    nodeType: Anniv7thDisplayNodeType;
    displayData: Anniv7thDisplayData[];
}

export interface Anniv7thMainlineData {
    clueGroupData: { [key: string]: Anniv7thClueGroupData };
    clueData: { [key: string]: Anniv7thClueData };
    clueRewardData: Anniv7thClueRewardData[];
    displayNodeData: Anniv7thDisplayNodeData[];
    constData: Anniv7thClueConstData;
}

export interface AprilFoolTable {
    stages: { [key: string]: AprilFoolStageData };
    scoreDict: { [key: string]: AprilFoolScoreData[] };
    constant: AprilFoolConst;
    act4FunData: Act4funData;
    act5FunData: Act5FunData;
    act6FunData: Act6FunData;
    act7FunData: Act7FunData;
}

export interface AprilFoolStageData {
    stageId: string;
    levelId: string;
    code: string;
    name: string;
    appearanceStyle: AppearanceStyle;
    loadingPicId: string;
    difficulty: LevelData_Difficulty;
    unlockCondition: StageData_ConditionDesc[];
    stageDropInfo: ItemBundle[];
}

export interface AprilFoolScoreData {
    stageId: string;
    sortId: number;
    playerName: string;
    playerScore: number;
}

export interface AprilFoolConst {
    battleFinishLoseDes: string;
    killEnemyDes: string;
    killBossDes: string;
    totalTime: string;
}

export interface Act4funData {
    performGroupInfoDict: { [key: string]: Act4funPerformGroupInfo };
    performInfoDict: { [key: string]: Act4funPerformInfo };
    normalMatDict: { [key: string]: Act4funLiveMatInfoData };
    spMatDict: { [key: string]: Act4funSpLiveMatInfoData };
    valueEffectInfoDict: { [key: string]: Act4funValueEffectInfoData };
    liveValueInfoDict: { [key: string]: Act4funLiveValueInfoData };
    superChatInfoDict: { [key: string]: Act4funSuperChatInfo };
    cmtGroupInfoDict: { [key: string]: Act4funCmtGroupInfo };
    cmtUsers: string[];
    endingDict: { [key: string]: Act4funEndingInfo };
    tokenLevelInfos: { [key: string]: Act4funTokenInfoData };
    missionDatas: { [key: string]: Act4funMissionData };
    constant: Act4funConst;
    stageExtraDatas: { [key: string]: Act4funStageExtraData };
    randomMsgText: string[];
    randomUserIconId: string[];
}

export interface Act4funPerformGroupInfo {
    performGroupId: string;
    performIds: string[];
}

export interface Act4funPerformInfo {
    performId: string;
    performFinishedPicId: string;
    fixedCmpGroup: string;
    cmpGroups: string[];
    words: Act4funPerformWordData[];
}

export interface Act4funPerformWordData {
    text: string;
    picId: string;
    backgroundId: string;
}

export interface Act4funLiveMatInfoData {
    liveMatId: string;
    stageId: string;
    name: string;
    picId: string;
    tagTxt: string;
    emojiIcon: string;
    selectedPerformId: string;
    effectInfos: { [key: string]: Act4funLiveMatEffectInfo };
}

export interface Act4funLiveMatEffectInfo {
    liveMatEffectId: string;
    valueId: string;
    performGroup: string;
}

export interface Act4funSpLiveMatInfoData {
    spLiveMatId: string;
    spLiveEveId: string;
    stageId: string;
    name: string;
    picId: string;
    tagTxt: string;
    emojiIcon: string;
    accordingPerformId: string;
    selectedPerformId: string;
    valueEffectId: string;
    accordingSuperChatId: string;
}

export interface Act4funValueEffectInfoData {
    valueEffectId: string;
    effectParams: { [key: string]: number };
}

export interface Act4funLiveValueInfoData {
    liveValueId: string;
    name: string;
    stageId: string;
    iconId: string;
    highEndingId: string;
    lowEndingId: string;
    increaseToastTxt: string;
    decreaseToastTxt: string;
}

export interface Act4funSuperChatInfo {
    superChatId: string;
    chatType: Act4funSuperChatType;
    userName: string;
    iconId: string;
    valueEffectId: string;
    performId: string;
    superChatTxt: string;
}

export interface Act4funCmtGroupInfo {
    cmtGroupId: string;
    cmtList: Act4funCmtInfo[];
}

export interface Act4funCmtInfo {
    iconId: string;
    name: string;
    cmtTxt: string;
}

export interface Act4funEndingInfo {
    endingId: string;
    endingAvg: string;
    endingDesc: string;
    stageId: string;
    isGoodEnding: boolean;
}

export interface Act4funTokenInfoData {
    tokenLevelId: string;
    levelDesc: string;
    skillDesc: string;
    tokenLevelNum: number;
    levelIconId: string;
}

export interface Act4funMissionData {
    missionId: string;
    sortId: string;
    missionDes: string;
    rewardIconIds: string[];
    rewards: ItemBundle[];
}

export interface Act4funStageExtraData {
    description: string;
    valueIconId: string;
}

export interface Act4funConst {
    liveMatAmtLowerLimit: number;
    liveTurnUpperLimit: number;
    superChatCountDownNum: number;
    badEndingPerformEffectTitle: string;
    performEffectTitle: string;
    defaultPerformPicId: string;
    defaultTxtBackground: string;
    openingPerformGroup: string;
    forgetPerformGroup: string;
    runPerformGroup: string;
    liveMatDefaultUserIcon: string;
    liveMatAttributeIcon: string;
    liveMatAttribIconDiffNum: number;
    liveValueAbsLimit: number;
    cmtAppearTimeLowerLimit: number;
    cmtAppearTimeUpperLimit: number;
    subtitleIntervalTime: number;
    mainPageEventDes: string;
    spStageEndingTip: string;
    noLiveEndingTip: string;
    notEnoughEndingTip: string;
    enoughEndingTip: string;
    mainPagePersonal: string;
    mainPageJobDes: string;
    endingPageConfirmTxt: string;
    runConfirmTxt: string;
    mainPageDiamondMissionId: string;
    reconnectConfirmTxt: string;
    studyStageId: string;
    goodEndingToastTxt: string;
    tokenLevelUpToastTxt: string;
    studyStageToastTxt: string;
    matNotEnoughToastTxt: string;
    formalLevelUnlockToastTxt: string;
}

export interface Act5FunRoundData {
    roundId: string;
    stageId: string;
    enemyPredefined: boolean;
    round: number;
    enemyPoint: number;
    enemyScoreRandom: number;
    minType: number;
    maxType: number;
    choiceCount: number;
    choiceId1: string;
    choiceId2: string;
    choiceId3: string;
    choiceId4: string;
    enableSideTarget: boolean;
}

export interface Act5FunNpcData {
    npcId: string;
    avatarId: string;
    name: string;
    priority: number;
    specialStrategy: NpcStrategy;
    npcProb: number;
    defaultEnemyScore: number;
}

export interface Act5FunNpcSelectorData {
    npcId: string;
    enemyId: string;
    score: number;
}

export interface Act5FunChoiceRewardData {
    choiceId: string;
    name: string;
    percentage: number;
    isSpecialStyle: boolean;
}

export interface Act5FunEnemyIdMappingData {
    enemyId: string;
    originalEnemyId: string;
}

export interface Act5funConst {
    storyStageId: string;
    betStageId: string;
    storyRoundnumber: number;
    betRoundnumber: number;
    initialFundStory: number;
    initialFundBet: number;
    minFundDrop: number;
    maxFund: number;
    selectTime: number;
    npcCountInRound: number;
    selectDescription: string;
    selectLeftDescription: string;
    selectRightDescription: string;
    fundDescription: string;
    confirmDescription: string;
    loadingDescription: string;
}

export interface Act5funBasicConst {
    storyStageId: string;
    betStageId: string;
    storyRoundNumber: number;
    betRoundNumber: number;
    minFundDrop: number;
    maxFund: number;
}

export interface Act5FunBasicNpcData {
    npcId: string;
    avatarId: string;
    name: string;
}

export interface Act5FunSettleRatingData {
    minRating: number;
    maxRating: number;
    ratingDesc: string;
}

export interface Act5FunSettleStreakData {
    count: number;
    desc: string;
}

export interface Act5FunSettleSuccessData {
    count: number;
    desc: string;
}

export interface Act5FunData {
    battleData: Act5FunData_BattleData;
    constData: Act5funBasicConst;
    npcData: { [key: string]: Act5FunBasicNpcData };
    ratingData: Act5FunSettleRatingData[];
    streakData: Act5FunSettleStreakData[];
    successData: Act5FunSettleSuccessData[];
}

export interface Act5FunData_BattleData {
    battleConstData: Act5funConst;
    roundData: { [key: string]: Act5FunRoundData };
    npcData: { [key: string]: Act5FunNpcData };
    npcSelectorData: Act5FunNpcSelectorData[];
    choiceRewardData: { [key: string]: Act5FunChoiceRewardData };
    enemyIdMappingData: { [key: string]: Act5FunEnemyIdMappingData };
    battleStreak: number[];
}

export interface Act6FunStageAdditionData {
    description: string;
    npcDialogText: string;
    previewCharPicId: string;
    feverCoinNum: number;
    isHiddenStage: boolean;
}

export interface Act6FunAchievementData {
    achievementId: string;
    sortId: number;
    achievementType: Act6FunAchievementType;
    description: string;
    coverDesc: string;
}

export interface Act6FunAchievementRewardData {
    reward: ItemBundle;
    sortId: number;
    achievementCount: number;
}

export interface Act6FunConst {
    defaultStage: string;
    achievementMaxNumber: number;
    specialNumber: number;
    characterTipToast: string;
    functionToastList: string[];
}

export interface Act6FunData {
    stageAdditionMap: { [key: string]: Act6FunStageAdditionData };
    stageAchievementMap: { [key: string]: Act6FunAchievementData[] };
    achievementRewardList: { [key: string]: Act6FunAchievementRewardData };
    constData: Act6FunConst;
}

export interface Act7FunStageAdditionData {
    homepageSpineGroupId: string;
    battleSpineGroupId: string;
    settleWinSpineGroupId: string;
    settleLoseSpineGroupId: string;
    trapMaxNum: number;
    trapTargetNum: number;
}

export interface Act7FunEasterEggData {
    eastereggId: string;
    charId: string;
    newsDesc: string;
}

export interface Act7FunCharAnimData {
    charId: string;
    failAnimId: string;
    normalAnimIds: string[];
}

export interface Act7FunSpineGroupData {
    spineGroupId: string;
    holderData: Act7FunSpineHolderData[];
}

export interface Act7FunSpineHolderData {
    holderId: number;
    charId: string;
    direction: boolean;
}

export interface Act7FunConstData {
    defaultStage: string;
    homepageSwitchStageId: string;
}

export interface Act7FunData {
    stageAdditionMap: { [key: string]: Act7FunStageAdditionData };
    easterEggData: { [key: string]: Act7FunEasterEggData };
    spineGroupData: { [key: string]: Act7FunSpineGroupData };
    charAnimData: { [key: string]: Act7FunCharAnimData };
    stageRewardList: string[];
    constData: Act7FunConstData;
}

export interface ArkOdcMoveConstData {
    runMaxStableMoveSpeed: number;
    walkMaxStableMoveSpeed: number;
    stableMovementSharpness: number;
    defaultAlpha: number;
    runConfiguredAnimScale: number;
    walkConfiguredAnimScale: number;
    minAnimScale: number;
    maxAnimScale: number;
    spineFlip: SpineFlipMode;
    defaultSlideStopThreshold: number;
    presetData: ArkventMovePresetData;
}

export interface ArkOdcTaskTrackingConstData {
    taskTrackerHeightThreshold: number;
    distanceUnitScale: number;
    taskTrackerYOffset: number;
}

export interface ArkOdcLoadingData {
    loadingId: string;
    weight: number;
}

export interface ArkOdcConstData {
    defaultSceneId: string;
    defaultLoadingId: string;
    playerSpineName: string;
    idleSpecialAnimName: string;
    idleSpecialAnimInterval: number;
    resetExpIds: string[];
    npcSelectedFx: string;
    interactSelectedFx: string;
    sceneValidPositionY: number;
}

export interface ArkOdcBasicData {
    topicId: string;
    rewardGroups: { [key: string]: ItemBundle[] };
    moveConstData: ArkOdcMoveConstData;
    loadingData: { [key: string]: ArkOdcLoadingData };
    constData: ArkOdcConstData;
    taskTrackingConstData: ArkOdcTaskTrackingConstData;
    clientTrackingData: ArkOdcTaskTrackingData;
}

export interface ArkOdcTable {
    odcDataMap: { [key: string]: ArkOdcBasicData };
    arkventDataMap: { [key: string]: ArkventData };
}

export interface ArkOdcTaskTrackingData {
    mainDataDict: { [key: string]: ArkOdcTaskTrackingMainData };
}

export interface ArkOdcTaskTrackingMainData {
    questId: string;
    priority: number;
    title: string;
    startBannerDesc: string;
    completeBannerDesc: string;
    entryDict: { [key: string]: ArkOdcTaskTrackingEntryData };
}

export interface ArkOdcTaskTrackingEntryData {
    trackEntryId: string;
    questId: string;
    stage: number;
    slot: number;
    slotOrder: number;
    description: string;
    trackActorId: string;
    enableCompass: boolean;
    triggerCondIds: string[];
    completeCondId: string;
    progressCompleteFlags: string[];
    progressCount: number;
}

export interface ArkventSceneData {
    sceneId: string;
    sceneIdHash: number;
    sceneName: string;
    assetId: string;
    spawnPos: JsonValue;
    spawnRadius: number;
    moveCameraConfigId: string;
    idleCameraConfigId: string;
}

export interface ArkventData {
    taskData: ArkventTaskData;
    sceneDataMap: { [key: number]: ArkventSceneData };
    nameMappingData: ArkventNameMappingData;
    interactBtnStyleDict: { [key: string]: ArkventInteractBtnStyleData };
    headUIData: { [key: string]: ArkventHeadUIData };
    barkData: ArkventBarkData;
    animMixData: ArkventAnimMixData;
    sceneAudioMap: { [key: number]: ArkventAudioSourceData[] };
}

export interface ArkventTaskShowCondition {
    conditionType: string;
    varSeqList: string[];
    type: ArkventTaskVarSeqCompareOperation;
    value: number;
}

export interface ArkventTaskActorTriggerOperation {
    operationId: string;
    operationTemplate: string;
    operationParams: { [key: string]: string };
    finishOperation: boolean;
    preserveBlackout: boolean;
}

export interface ArkventCameraPlatformConfig {
    blendDuration: number;
    blendStyle: ArkventCameraBlendStyle;
    pitch: number;
    cameraDistance: number;
    lookAheadTime: number;
    lookAheadSmoothing: number;
    screenX: number;
    screenY: number;
    trackedObjectOffset: JsonValue;
    deadZoneWidth: number;
    deadZoneHeight: number;
    deadZoneDepth: number;
    softZoneWidth: number;
    softZoneHeight: number;
    biasX: number;
    biasY: number;
    xDamping: number;
    yDamping: number;
    zDamping: number;
}

export interface ArkventCameraConfigData {
    pcConfig: ArkventCameraPlatformConfig;
    mobileConfig: ArkventCameraPlatformConfig;
}

export interface ArkventTaskActorData {
    actorId: string;
    actorNameId: string;
    actorEnvLineId: string;
    sceneId: number;
    isGlobal: boolean;
    charId: string;
    skinId: string;
    arkventSpineId: string;
    npcSpineType: ArkventNPCSpineType;
    overrideAnimConfig: { [key: string]: string };
    furnitureAssetId: string;
    actorType: ArkventTaskActorType;
    actorPosition: JsonValue;
    actorYaw: number;
    actorShowCondition: ArkventTaskShowCondition[];
    actorTriggerType: ArkventTaskActorTriggerType;
    actorTriggerOperations: { [key: string]: ArkventTaskActorTriggerOperation[] };
    triggerRange: ArkventRangeData;
    colliderRange: ArkventRangeData;
    interactRange: ArkventRangeData;
    triggerCameraConfig: string;
    interactCameraConfig: string;
    sceneStatusDriverId: string;
    sceneObjectStatus: string;
    effectId: string;
    effectOffsetY: number;
    interactBtnStyleId: string;
    interactingBtnStyleId: string;
    interactSoundFx: string;
    headUpStyleId: string;
    spineFace: ArkventSpineFaceType;
    persistFaceWhenInteract: boolean;
    hasSafePos: boolean;
    safePos: JsonValue;
}

export interface ArkventTaskData {
    topicId: string;
    actorData: { [key: string]: ArkventTaskActorData };
    varSeqData: string[];
    cameraConfigData: { [key: string]: ArkventCameraConfigData };
}

export interface ArkventNameMappingData {
    displayNameMap: { [key: string]: string };
}

export interface ArkventBarkItemData {
    content: string;
    weight: number;
    duration: number;
    cooldown: number;
}

export interface ArkventBarkPoolData {
    barkItemData: ArkventBarkItemData[];
}

export interface ArkventBarkData {
    barkAreaRadius: number;
    showAreaRadius: number;
    barkPoolData: { [key: string]: ArkventBarkPoolData };
}

export interface ArkventInteractBtnStyleData {
    id: string;
    icon: string;
    bgStyle: string;
    displayText: string;
    textColorStr: string;
}

export interface ArkventHeadUIData {
    id: string;
    icon: string;
    bgStyle: string;
}

export interface ArkventAnimMixData {
    mixDurationMap: { [key: string]: number };
}

export interface ArkventMovePresetData {
    presetId: string;
    accelEasingType: EasingType;
    accelDuration: number;
    accPower: number;
    decEasingType: EasingType;
    decDuration: number;
    decPower: number;
    turningMode: TurningMode;
    momentumTurnSpeed: number;
    momentumTurnSpeedLow: number;
}

export interface AttributeModifierData {
    abnormalFlags: AbnormalFlag[];
    abnormalImmunes: AbnormalFlag[];
    abnormalAntis: AbnormalFlag[];
    abnormalCombos: AbnormalCombo[];
    abnormalComboImmunes: AbnormalCombo[];
    attributeModifiers: AttributeModifierData_AttributeModifier[];
}

export interface AttributeModifierData_AttributeModifier {
    attributeType: AttributeType;
    formulaItem: AttributeModifierData_AttributeModifier_FormulaItemType;
    value: number;
    loadFromBlackboard: boolean;
    fetchBaseValueFromSourceEntity: boolean;
}

export type Blackboard = Blackboard_DataPair[];

export interface Blackboard_DataPair {
    key: string;
    value: number;
    valueStr: string;
}

export interface BuildingData {
    CONTROL_STOREY_ID: string;
    controlSlotId: string;
    meetingSlotId: string;
    initMaxLabor: number;
    laborRecoverTime: number;
    manufactInputCapacity: number;
    shopCounterCapacity: number;
    comfortLimit: number;
    creditInitiativeLimit: number;
    creditPassiveLimit: number;
    creditComfortFactor: number;
    creditGuaranteed: number;
    creditCeiling: number;
    manufactUnlockTips: string;
    shopUnlockTips: string;
    manufactStationBuff: number;
    comfortManpowerRecoverFactor: number;
    manpowerDisplayFactor: number;
    shopOutputRatio: { [key: string]: number };
    shopStackRatio: { [key: string]: number };
    basicFavorPerDay: number;
    humanResourceLimit: number;
    tiredApThreshold: number;
    processedCountRatio: number;
    tradingStrategyUnlockLevel: number;
    tradingReduceTimeUnit: number;
    tradingLaborCostUnit: number;
    manufactReduceTimeUnit: number;
    manufactLaborCostUnit: number;
    laborAssistUnlockLevel: number;
    apToLaborUnlockLevel: number;
    apToLaborRatio: number;
    socialResourceLimit: number;
    socialSlotNum: number;
    furniDuplicationLimit: number;
    assistFavorReport: number;
    manufactManpowerCostByNum: number[];
    tradingManpowerCostByNum: number[];
    trainingBonusMax: number;
    betaRemoveTime: number;
    furniHighlightTime: number;
    canNotVisitToast: string;
    meetingMessageBoardEmoteTime: number;
    musicPlayerOpenTime: number;
    roomsWithoutRemoveStaff: string[];
    privateFavorLevelThresholds: number[];
    roomUnlockConds: { [key: string]: BuildingData_RoomUnlockCond };
    rooms: { [key: string]: BuildingData_RoomData };
    layouts: { [key: string]: BuildingData_LayoutData };
    prefabs: { [key: string]: BuildingData_PrefabInfo };
    controlData: BuildingData_ControlRoomBean;
    manufactData: BuildingData_ManufactRoomBean;
    shopData: BuildingData_RoomBean;
    hireData: BuildingData_HireRoomBean;
    dormData: BuildingData_RoomBean;
    privateRoomData: BuildingData_RoomBean;
    meetingData: BuildingData_MeetingRoomBean;
    tradingData: BuildingData_TradingRoomBean;
    workshopData: BuildingData_RoomBean;
    trainingData: BuildingData_TrainingBean;
    powerData: BuildingData_PowerRoomBean;
    chars: { [key: string]: BuildingData_BuildingCharacter };
    buffs: { [key: string]: BuildingData_BuildingBuff };
    workshopBonus: { [key: string]: string[] };
    customData: BuildingData_CustomData;
    manufactFormulas: { [key: string]: BuildingData_ManufactFormula };
    shopFormulas: { [key: string]: BuildingData_ShopFormula };
    workshopFormulas: { [key: string]: BuildingData_WorkshopFormula };
    creditFormula: BuildingData_CreditFormula;
    goldItems: { [key: string]: number };
    assistantUnlock: number[];
    workshopRarities: BuildingData_WorkshopRarityInfo[];
    todoItemSortPriorityDict: { [key: string]: number };
    slotPrequeDatas: { [key: string]: BuildingData_SlotPrequeData };
    dormitoryPrequeDatas: { [key: string]: BuildingData_DormitoryPrequeData };
    workshopTargetDesDict: { [key: string]: string };
    tradingOrderDesDict: { [key: string]: string };
    stationManageConstData: BuildingData_StationManageConstData;
    stationManageFilterInfos: { [key: number]: BuildingData_StationManageFilterInfo };
    musicData: BuildingData_MusicData;
    emojis: string[];
    categoryNames: { [key: string]: string };
    buffSortData: { [key: string]: BuildingData_BuildingRoomTypeBuffSortData };
    tradingRoomInfoData: BuildingData_TradingRoomInfoData;
}

export interface BuildingData_PrefabInfo {
    id: string;
    blueprintRoomOverrideId: string;
    size: GridPosition;
    floorGridSize: GridPosition;
    backWallGridSize: GridPosition;
    obstacleId: string;
}

export interface BuildingData_RoomUnlockCond {
    id: string;
    number: { [key: number]: BuildingData_RoomUnlockCond_CondItem };
}

export interface BuildingData_RoomUnlockCond_CondItem {
    type: BuildingData_RoomType;
    level: number;
    count: number;
}

export interface BuildingData_RoomData {
    id: BuildingData_RoomType;
    name: string;
    description: string;
    defaultPrefabId: string;
    canLevelDown: boolean;
    maxCount: number;
    category: BuildingData_RoomCategory;
    size: GridPosition;
    phases: BuildingData_RoomData_PhaseData[];
}

export interface BuildingData_RoomData_BuildCost {
    items: ItemBundle[];
    time: number;
    labor: number;
}

export interface BuildingData_RoomData_PhaseData {
    overrideName: string;
    overridePrefabId: string;
    unlockCondId: string;
    buildCost: BuildingData_RoomData_BuildCost;
    electricity: number;
    maxStationedNum: number;
    manpowerCost: number;
}

export interface BuildingData_LayoutData {
    DEFAULT_LAYOUT_ID: string;
    id: string;
    slots: { [key: string]: BuildingData_LayoutData_RoomSlot };
    cleanCosts: { [key: string]: BuildingData_LayoutData_SlotCleanCost };
    storeys: { [key: string]: BuildingData_LayoutData_StoreyData };
}

export interface BuildingData_LayoutData_RoomSlot {
    id: string;
    cleanCostId: string;
    costLabor: number;
    provideLabor: number;
    size: GridPosition;
    offset: GridPosition;
    category: BuildingData_RoomCategory;
    storeyId: string;
}

export interface BuildingData_LayoutData_SlotCleanCost {
    id: string;
    number: { [key: number]: BuildingData_LayoutData_SlotCleanCost_CountCost };
}

export interface BuildingData_LayoutData_SlotCleanCost_CountCost {
    items: ItemBundle[];
}

export interface BuildingData_LayoutData_StoreyData {
    id: string;
    yOffset: number;
    unlockControlLevel: number;
    type: BuildingData_LayoutData_StoreyData_Type;
}

export interface BuildingData_BuildingCharacter {
    charId: string;
    maxManpower: number;
    buffChar: BuildingData_BuildingBuffCharSlot[];
}

export interface BuildingData_BuildingBuffCharSlot {
    buffData: BuildingData_BuildingBuffCharSlot_SlotItem[];
}

export interface BuildingData_BuildingBuffCharSlot_SlotItem {
    buffId: string;
    cond: CharacterData_UnlockCondition;
}

export interface BuildingData_BuildingBuff {
    buffId: string;
    buffName: string;
    buffIcon: string;
    skillIcon: string;
    sortId: number;
    buffColor: string;
    textColor: string;
    buffCategory: BuildingData_BuffCategory;
    roomType: BuildingData_RoomType;
    description: string;
    efficiency: number;
    targetGroupSortId: number;
    targets: string[];
}

export interface BuildingData_BuildingRoomTypeBuffSortData {
    hasEfficiencySort: boolean;
    defaultGroupSortId: number;
    efficiencyTargetDict: { [key: string]: BuildingData_BuildingRoomTypeBuffSortData_buffGroupInfo };
}

export interface BuildingData_BuildingRoomTypeBuffSortData_buffGroupInfo {
    targets: string[];
    sortId: number;
}

export interface BuildingData_RoomBean {
    phases: { buildCost?: { items?: { id: string; count: number; type: string }[]; time?: number; labor?: number }; maxStationedNum?: number; electricity?: number; manpowerRecover?: number | string; unlockCondId?: string }[];
}

export interface BuildingData_ControlRoomBean {
    phases: JsonValue[];
    basicCostBuff: number;
}

export interface BuildingData_ManufactRoomBean {
    phases: { speed?: number; outputCapacity?: number }[];
    basicSpeedBuff: number;
}

export interface BuildingData_ShopPhase {
    counterNum: number;
    speed: number;
    moneyCapacity: number;
}

export interface BuildingData_HireRoomBean {
    phases: { economizeRate?: number; resSpeed?: number; refreshTimes?: number }[];
    basicSpeedBuff: number;
}

export interface BuildingData_DormPhase {
    manpowerRecover: number;
    decorationLimit: number;
}

export interface BuildingData_PrivatePhase {
    decorationLimit: number;
}

export interface BuildingData_MeetingRoomBean {
    phases: { friendSlotInc?: number; maxVisitorNum?: number; gatheringSpeed?: number }[];
    basicSpeedBuff: number;
}

export interface BuildingData_TradingRoomBean {
    phases: JsonValue[];
    basicSpeedBuff: number;
}

export interface BuildingData_WorkshopPhase {
    manpowerFactor: number;
}

export interface BuildingData_TrainingBean {
    phases: JsonValue[];
    basicSpeedBuff: number;
}

export interface BuildingData_PowerRoomBean {
    phases: JsonValue[];
    basicSpeedBuff: number;
}

export interface BuildingData_CustomData {
    furnitures: { [key: string]: BuildingData_CustomData_FurnitureData };
    themes: { [key: string]: BuildingData_CustomData_ThemeData };
    groups: { [key: string]: BuildingData_CustomData_GroupData };
    types: { [key: string]: BuildingData_CustomData_FurnitureTypeData };
    subTypes: { [key: string]: BuildingData_CustomData_FurnitureSubTypeData };
    defaultFurnitures: { [key: string]: BuildingData_CustomData_DormitoryDefaultFurnitureItem[] };
    interactGroups: { [key: string]: BuildingData_CustomData_InteractItem[] };
    diyUISortTemplates: { [key: string]: { [key: string]: BuildingData_CustomData_DiyUISortTemplateListData } };
}

export interface BuildingData_CustomData_FurnitureData {
    id: string;
    sortId: number;
    name: string;
    iconId: string;
    interactType: BuildingData_FurnitureInteract;
    musicId: string;
    type: BuildingData_FurnitureType;
    subType: BuildingData_FurnitureSubType;
    location: BuildingData_FurnitureLocation;
    category: BuildingData_FurnitureCategory;
    validOnRotate: boolean;
    enableRotate: boolean;
    rarity: number;
    themeId: string;
    groupId: string;
    width: number;
    depth: number;
    height: number;
    comfort: number;
    usage: string;
    description: string;
    obtainApproach: string;
    processedProductId: string;
    processedProductCount: number;
    processedByProductPercentage: number;
    processedByProductGroup: BuildingData_WorkshopExtraWeightItem[];
    canBeDestroy: boolean;
    isOnly: number;
    enableRoomType: number;
    quantity: number;
}

export interface BuildingData_CustomData_ThemeData {
    id: string;
    enableRoomType: number;
    sortId: number;
    name: string;
    themeType: string;
    desc: string;
    quickSetup: BuildingData_CustomData_ThemeQuickSetupItem[];
    groups: string[];
    furnitures: string[];
}

export interface BuildingData_CustomData_GroupData {
    id: string;
    sortId: number;
    name: string;
    themeId: string;
    comfort: number;
    count: number;
    furniture: string[];
}

export interface BuildingData_CustomData_ThemeQuickSetupItem {
    furnitureId: string;
    pos0: number;
    pos1: number;
    dir: number;
}

export interface BuildingData_CustomData_FurnitureTypeData {
    type: BuildingData_FurnitureType;
    name: string;
    enableRoomType: number;
}

export interface BuildingData_CustomData_FurnitureSubTypeData {
    subType: BuildingData_FurnitureSubType;
    name: string;
    type: BuildingData_FurnitureType;
    sortId: number;
    countLimit: number;
    enableRoomType: number;
}

export interface BuildingData_CustomData_DormitoryDefaultFurnitureItem {
    furnitureId: string;
    xOffset: number;
    yOffset: number;
    defaultPrefabId: string;
}

export interface BuildingData_CustomData_InteractItem {
    skinId: string;
}

export interface BuildingData_CustomData_DiyUISortTemplateListData {
    diySortType: BuildingData_DiySortType;
    expandState: string;
    defaultTemplateIndex: number;
    defaultTemplateOrder: BuildingData_DiyUISortOrder;
    templates: BuildingData_CustomData_DiyUISortTemplateListData_DiyUISortTemplateData[];
}

export interface BuildingData_CustomData_DiyUISortTemplateListData_DiyUISortTemplateData {
    name: string;
    sequences: string[];
    stableSequence: string;
    stableSequenceOrder: BuildingData_DiyUISortOrder;
}

export interface BuildingData_ManufactFormula {
    formulaId: string;
    itemId: string;
    count: number;
    weight: number;
    costPoint: number;
    formulaType: BuildingData_FormulaItemType;
    buffType: string;
    costs: ItemBundle[];
    requireRooms: BuildingData_ManufactFormula_UnlockRoom[];
    requireStages: BuildingData_ManufactFormula_UnlockStage[];
}

export interface BuildingData_ManufactFormula_UnlockRoom {
    roomId: BuildingData_RoomType;
    roomLevel: number;
    roomCount: number;
}

export interface BuildingData_ManufactFormula_UnlockStage {
    stageId: string;
    rank: number;
}

export interface BuildingData_WorkshopExtraWeightItem {
    weight: number;
    itemId: string;
    itemCount: number;
}

export interface BuildingData_WorkshopFormula {
    sortId: number;
    formulaId: string;
    rarity: number;
    itemId: string;
    count: number;
    goldCost: number;
    apCost: number;
    formulaType: BuildingData_FormulaItemType;
    buffType: string;
    extraOutcomeRate: number;
    extraOutcomeGroup: BuildingData_WorkshopExtraWeightItem[];
    costs: ItemBundle[];
    requireRooms: BuildingData_WorkshopFormula_UnlockRoom[];
    requireStages: BuildingData_WorkshopFormula_UnlockStage[];
}

export interface BuildingData_WorkshopFormula_UnlockRoom {
    roomId: BuildingData_RoomType;
    roomLevel: number;
    roomCount: number;
}

export interface BuildingData_WorkshopFormula_UnlockStage {
    stageId: string;
    rank: number;
}

export interface BuildingData_ShopFormula {
    formulaId: string;
    itemId: string;
    formulaType: BuildingData_FormulaItemType;
    costPoint: number;
    gainItem: ItemBundle;
    requireRooms: BuildingData_ShopFormula_UnlockRoom[];
}

export interface BuildingData_ShopFormula_UnlockRoom {
    roomId: BuildingData_RoomType;
    roomLevel: number;
}

export interface BuildingData_CreditFormula {
    initiative: { [key: number]: BuildingData_CreditFormula_ValueModel };
    passive: { [key: number]: BuildingData_CreditFormula_ValueModel };
}

export interface BuildingData_CreditFormula_ValueModel {
    basic: number;
    addition: number;
}

export interface BuildingData_SlotPrequeData {
    roomType: BuildingData_RoomType;
    name: string;
    typeSortId: number;
    isPreque: boolean;
    prequeNum: number;
}

export interface BuildingData_DormitoryPrequeData {
    roomType: BuildingData_RoomType;
    name: string;
}

export interface BuildingData_StationManageConstData {
    cantWorkToastNoTiredChar: string;
    cantWorkToastNoAvailQueue: string;
    cantWorkToastNoNeed: string;
    cantRestToastNoTiredChar: string;
    cantRestToastNoAvailDorm: string;
    workBatchToast: string;
    restBatchToast: string;
    roomNoAvailQueueToast: string;
    cantUseNoPerson: string;
    cantUseWorking: string;
    queueCleared: string;
    updateTime: number;
    dormLockUpdateTime: number;
}

export interface BuildingData_WorkshopRarityInfo {
    name: string;
    order: number;
    rarityList: ItemRarity[];
    color: string;
}

export interface BuildingData_StationManageFilterInfo {
    charStationFilterType: BuildingData_CharStationFilterType;
    name: string;
}

export interface BuildingData_MusicData {
    defaultMusic: string;
    musicDatas: { [key: string]: BuildingData_MusicSingleData };
}

export interface BuildingData_MusicSingleData {
    bgmId: string;
    bgmSortId: number;
    bgmStartTime: number;
    bgmName: string;
    gameMusicId: string;
    obtainApproach: string;
    bgmDescUnlocked: string;
    unlockType: string;
    unlockParams: string[];
}

export interface BuildingData_TradingRoomSpecialOrderInfo {
    charId: string;
    iconId: string;
    title: string;
}

export interface BuildingData_TradingRoomInfoData {
    tradingRoomSpecialOrderData: { [key: string]: BuildingData_TradingRoomSpecialOrderInfo };
}

export interface CampaignStageMapData {
    position: JsonValue;
}

export interface CampaignData {
    stageId: string;
    isSmallScale: number;
    breakLadders: CampaignData_BreakRewardLadder[];
    isCustomized: boolean;
    dropGains: { [key: string]: CampaignData_DropGainInfo };
}

export interface CampaignData_CampaignDropInfo {
    firstPassRewards: ItemBundle[];
    passRewards: WeightItemBundle[][];
    displayDetailRewards: StageData_DisplayDetailRewards[];
}

export interface CampaignData_BreakRewardLadder {
    DEFAULT: CampaignData_BreakRewardLadder;
    killCnt: number;
    breakFeeAdd: number;
    rewards: ItemBundle[];
}

export interface CampaignData_DropLadder {
    DEFAULT: CampaignData_DropLadder;
    killCnt: number;
    dropInfo: CampaignData_CampaignDropInfo;
}

export interface CampaignData_GainLadder {
    DEFAULT: CampaignData_GainLadder;
    killCnt: number;
    apFailReturn: number;
    favor: number;
    expGain: number;
    goldGain: number;
    displayDiamondShdNum: number;
}

export interface CampaignData_DropGainInfo {
    dropLadders: CampaignData_DropLadder[];
    gainLadders: CampaignData_GainLadder[];
    displayRewards: StageData_DisplayRewards[];
    displayDetailRewards: StageData_DisplayDetailRewards[];
}

export interface CampaignGroupData {
    groupId: string;
    activeCamps: string[];
    startTs: number;
    endTs: number;
}

export interface CampaignRegionData {
    id: string;
    isUnknwon: number;
}

export interface CampaignZoneData {
    id: string;
    name: string;
    regionId: string;
    templateId: string;
}

export interface CampaignRotateOpenTimeData {
    groupId: string;
    stageId: string;
    mapId: string;
    unknownRegions: string[];
    duration: number;
    startTs: number;
    endTs: number;
}

export interface CampaignTrainingOpenTimeData {
    groupId: string;
    stages: string[];
    startTs: number;
    endTs: number;
}

export interface CampaignTrainingAllOpenTimeData {
    groupId: string;
    startTs: number;
    endTs: number;
}

export interface CampaignMissionData {
    id: string;
    sortId: number;
    param: string[];
    description: string;
    breakFeeAdd: number;
}

export interface CampaignConstTable {
    systemPreposedStage: string;
    rotateStartTime: number;
    rotatePreposedStage: string;
    zoneUnlockStage: string;
    firstRotateRegion: string;
    sweepStartTime: number;
}

export interface CampaignTable {
    campaigns: { [key: string]: CampaignData };
    campaignGroups: { [key: string]: CampaignGroupData };
    campaignRegions: { [key: string]: CampaignRegionData };
    campaignZones: { [key: string]: CampaignZoneData };
    campaignMissions: { [key: string]: CampaignMissionData };
    stageIndexInZoneMap: { [key: string]: number };
    campaignConstTable: CampaignConstTable;
    campaignRotateStageOpenTimes: CampaignRotateOpenTimeData[];
    campaignTrainingStageOpenTimes: CampaignTrainingOpenTimeData[];
    campaignTrainingAllOpenTimes: CampaignTrainingAllOpenTimeData[];
    campaignZoneMapData: { [key: string]: { [key: string]: CampaignStageMapData } };
}

export interface CGGalleryGroupData {
    storySetId: string;
    storylineId: string;
    locationId: string;
    displays: string[];
}

export interface CGGalleryDisplayData {
    displayId: string;
    cgList: string[];
    cgSource: CGGalleryCGSource;
    displayName: string;
    displayDesc: string;
    storySetId: string;
    sortId: number;
    relatedStoryId: string;
    relatedStageId: string;
}

export interface CGGalleryCGData {
    cgId: string;
    sortId: number;
    compositeType: CGGalleryCGCompositeType;
    compositeList: CGGalleryCGCompositeData[];
    storySetId: string;
}

export interface CGGalleryCGCompositeData {
    cgId: string;
    width: number;
    height: number;
}

export interface ChapterData {
    chapterId: string;
    chapterName: string;
    chapterName2: string;
    chapterIndex: number;
    preposedChapterId: string;
    startZoneId: string;
    endZoneId: string;
    chapterEndStageId: string;
}

export type CharacterData = {
    name: string;
    description: string;
    sortIndex: number;
    spTargetType: SpecialOperatorTargetType;
    spTargetId: string;
    canUseGeneralPotentialItem: boolean;
    canUseActivityPotentialItem: boolean;
    potentialItemId: string;
    activityPotentialItemId: string;
    classicPotentialItemId: string;
    nationId: string;
    groupId: string;
    teamId: string;
    mainPower: CharacterData_PowerData;
    subPower: CharacterData_PowerData[];
    displayNumber: string;
    appellation: string;
    position: BuildableType;
    tagList: string[];
    itemUsage: string;
    itemDesc: string;
    itemObtainApproach: string;
    isNotObtainable: boolean;
    isSpChar: boolean;
    maxPotentialLevel: number;
    rarity: RarityRank;
    profession: ProfessionCategory;
    subProfessionId: string;
    trait: CharacterData_TraitDataBundle;
    phases: CharacterData_PhaseData[];
    skills: CharacterData_MainSkill[];
    displayTokenDict: { [key: string]: boolean };
    talents: CharacterData_TalentDataBundle[];
    potentialRanks: CharacterData_PotentialRank[];
    favorKeyFrames: CharacterData_AttributesDeltaKeyFrame;
    allSkillLvlup: CharacterData_SkillLevelCost[];
} & { [key: string]: JsonValue };

export type CharacterData_AttributesKeyFrame = KeyFrames_KeyFrame[];

export type CharacterData_AttributesDeltaKeyFrame = KeyFrames_KeyFrame[];

export interface CharacterData_UnlockCondition {
    phase: EvolvePhase;
    level: number;
}

export interface CharacterData_TalentDataBundle {
    candidates: TalentData[];
}

export interface CharacterData_EquipTalentDataBundle {
    candidates: EquipTalentData[];
}

export interface CharacterData_TraitData {
    unlockCondition: CharacterData_UnlockCondition;
    requiredPotentialRank: number;
    blackboard: Blackboard;
    overrideDescripton: string;
    prefabKey: string;
    rangeId: string;
}

export interface CharacterData_EquipTraitData {
    unlockCondition: CharacterData_UnlockCondition;
    requiredPotentialRank: number;
    blackboard: Blackboard;
    overrideDescripton: string;
    prefabKey: string;
    rangeId: string;
    additionalDescription: string;
}

export interface CharacterData_TraitDataBundle {
    candidates: CharacterData_TraitData[];
}

export interface CharacterData_EquipTraitDataBundle {
    candidates: CharacterData_EquipTraitData[];
}

export interface CharacterData_PhaseData {
    characterPrefabKey: string;
    rangeId: string;
    maxLevel: number;
    attributesKeyFrames: CharacterData_AttributesKeyFrame;
    evolveCost: ItemBundle[];
}

export interface CharacterData_MainSkill {
    skillId: string;
    overridePrefabKey: string;
    overrideTokenKey: string;
    specializeLevelUpData: CharacterData_MainSkill_SpecializeLevelData[];
    initialUnlockCond: CharacterData_UnlockCondition;
}

export interface CharacterData_MainSkill_SpecializeLevelData {
    unlockCond: CharacterData_UnlockCondition;
    lvlUpTime: number;
    levelUpCost: ItemBundle[];
}

export interface CharacterData_PotentialRank {
    type: CharacterData_PotentialRank_TypeEnum;
    description: string;
    buff: ExternalBuff;
    equivalentCost: ItemBundle[];
}

export interface CharacterData_SkillLevelCost {
    unlockCond: CharacterData_UnlockCondition;
    lvlUpCost: ItemBundle[];
}

export interface CharacterData_PowerData {
    nationId: string;
    groupId: string;
    teamId: string;
}

export interface CharmItemData {
    id: string;
    sort: number;
    name: string;
    icon: string;
    itemUsage: string;
    itemDesc: string;
    itemObtainApproach: string;
    rarity: CharmRarity;
    desc: string;
    price: number;
    specialObtainApproach: string;
    charmType: string;
    obtainInRandom: boolean;
    dropStages: string[];
    runeData: RuneTable_PackedRuneData;
}

export interface CharmData {
    charmList: CharmItemData[];
}

export interface SpCharMissionData {
    charId: string;
    missionId: string;
    sortId: number;
    condType: SpCharMissionCondType;
    param: string[];
    rewards: ItemBundle[];
}

export interface CharMasterLevelData {
    level: number;
    name: string;
    description: string;
    conditionDesc: string;
}

export interface CharMasterBasicData {
    charId: string;
    masterId: string;
    sortId: number;
    masterType: CharMasterType;
    levelList: CharMasterLevelData[];
    candidates: JsonValue[];
}

export interface CharMetaTable {
    spCharGroups: { [key: string]: string[] };
    spCharMissions: { [key: string]: { [key: string]: SpCharMissionData } };
    spCharVoucherSkinTime: { [key: string]: number };
    charIdMasterListMap: { [key: string]: string[] };
    charMasterDataMap: { [key: string]: CharMasterBasicData };
}

export interface CharPatchData {
    infos: { [key: string]: CharPatchData_PatchInfo };
    patchChars: { [key: string]: CharacterData };
    unlockConds: { [key: string]: CharPatchData_UnlockCond };
    patchDetailInfoList: { [key: string]: CharPatchData_PatchDetailInfo };
}

export interface CharPatchData_PatchInfo {
    tmplIds: string[];
    defaultPatch: string;
    default: JsonValue;
}

export interface CharPatchData_UnlockCond {
    conds: CharPatchData_UnlockCond_Item[];
}

export interface CharPatchData_UnlockCond_Item {
    stageId: string;
    completeState: PlayerBattleRank;
    unlockTs: number;
}

export interface CharPatchData_PatchDetailInfo {
    patchId: string;
    sortId: number;
    infoParam: string;
    transSortId: number;
}

export interface CharWordTable {
    charWords: { [key: string]: CharWordData };
    charExtraWords: { [key: string]: CharExtraWordData };
    voiceLangDict: { [key: string]: VoiceLangData };
    defaultLangType: VoiceLangType;
    newTagList: string[];
    voiceLangTypeDict: { [key: string]: VoiceLangTypeData };
    voiceLangGroupTypeDict: { [key: string]: VoiceLangGroupData };
    charDefaultTypeDict: { [key: string]: VoiceLangType };
    startTimeWithTypeDict: { [key: string]: NewVoiceTimeData[] };
    displayGroupTypeList: VoiceLangGroupType[];
    displayTypeList: VoiceLangType[];
    playVoiceRange: CharWordShowType;
    fesVoiceData: { [key: string]: FestivalVoiceData };
    fesVoiceWeight: { [key: string]: FestivalVoiceWeightData };
    extraVoiceConfigData: { [key: string]: ExtraVoiceConfigData };
}

export interface CharWordData {
    ILLUST_SHOW_TYPES: CharWordShowType[];
    charWordId: string;
    wordKey: string;
    charId: string;
    voiceId: string;
    voiceText: string;
    voiceTitle: string;
    voiceIndex: number;
    voiceType: CharWordVoiceType;
    unlockType: DataUnlockType;
    unlockParam: CharWordUnlockParam[];
    lockDescription: string;
    placeType: CharWordShowType;
    voiceAsset: string;
}

export interface CharExtraWordData {
    wordKey: string;
    charId: string;
    voiceId: string;
    voiceText: string;
}

export interface CharWordUnlockParam {
    valueStr: string;
    valueInt: number;
}

export interface FestivalTimeInterval {
    startTs: number;
    endTs: number;
}

export interface FestivalTimeData {
    timeType: FestivalVoiceTimeType;
    interval: FestivalTimeInterval;
}

export interface FestivalVoiceData {
    showType: CharWordShowType;
    timeData: FestivalTimeData[];
}

export interface FestivalVoiceWeightData {
    showType: CharWordShowType;
    weight: number;
    priority: number;
}

export interface MonthlySignInData {
    itemId: string;
    itemType: ItemType;
    count: number;
}

export interface MonthlySignInGroupData {
    groupId: string;
    title: string;
    description: string;
    signStartTime: number;
    signEndTime: number;
    items: MonthlySignInData[];
}

export interface MonthlyDailyBonusGroup {
    groupId: string;
    startTime: number;
    endTime: number;
    items: ItemBundle[];
    imgId: string;
    backId: string;
}

export interface CheckInTable {
    groups: { [key: string]: MonthlySignInGroupData };
    monthlySubItem: { [key: string]: MonthlyDailyBonusGroup[] };
    currentMonthlySubId: string;
}

export interface ClimbTowerDropDisplayInfo {
    itemId: string;
    type: ItemType;
    maxCount: number;
    minCount: number;
}

export interface ClimbTowerLevelDropInfo {
    passRewards: WeightItemBundle[][];
    displayRewards: StageData_DisplayRewards[];
    displayDetailRewards: StageData_DisplayDetailRewards[];
    displayDropInfo: { [key: string]: ClimbTowerDropDisplayInfo };
}

export interface ClimbTowerTable {
    towers: { [key: string]: ClimbTowerSingleTowerData };
    levels: { [key: string]: ClimbTowerSingleLevelData };
    tacticalBuffs: { [key: string]: ClimbTowerTacticalBuffData };
    mainCards: { [key: string]: ClimbTowerMainCardData };
    subCards: { [key: string]: ClimbTowerSubCardData };
    curseCards: { [key: string]: ClimbTowerCurseCardData };
    seasonInfos: { [key: string]: ClimbTowerSeasonInfoData };
    detailConst: ClimbTowerDetailConst;
    rewardInfoList: ClimbTowerRewardInfo[];
    rewardInfoListHardMode: ClimbTowerRewardInfo[];
    missionData: { [key: string]: ClimbTowerMissionData };
    missionGroup: { [key: string]: MissionGroup };
}

export interface ClimbTowerSingleTowerData {
    id: string;
    sortId: number;
    stageNum: number;
    name: string;
    subName: string;
    desc: string;
    towerType: ClimbTowerTowerType;
    levels: string[];
    hardLevels: string[];
    taskInfo: ClimbTowerSingleTowerData_ClimbTowerTaskRewardData[];
    preTowerId: string;
    medalId: string;
    hiddenMedalId: string;
    hardModeMedalId: string;
    bossId: string;
    cardId: string;
    curseCardIds: string[];
    dangerDesc: string;
    hardModeDesc: string;
}

export interface ClimbTowerSingleTowerData_ClimbTowerTaskRewardData {
    levelNum: number;
    rewards: ItemBundle[];
}

export interface ClimbTowerSingleLevelData {
    id: string;
    levelId: string;
    towerId: string;
    layerNum: number;
    code: string;
    name: string;
    desc: string;
    levelType: ClimbTowerLevelType;
    loadingPicId: string;
    dropInfo: ClimbTowerLevelDropInfo;
}

export interface ClimbTowerTacticalBuffData {
    id: string;
    desc: string;
    profession: ProfessionCategory;
    isDefaultActive: boolean;
    sortId: number;
    buffType: ClimbTowerTaticalBuffType;
}

export interface ClimbTowerMainCardData {
    id: string;
    type: ClimbTowerCardType;
    linkedTowerId: string;
    sortId: number;
    name: string;
    desc: string;
    subCardIds: string[];
    runeData: RuneTable_PackedRuneData;
    trapIds: string[];
}

export interface ClimbTowerSubCardData {
    id: string;
    mainCardId: string;
    sortId: number;
    name: string;
    desc: string;
    runeData: RuneTable_PackedRuneData;
    trapIds: string[];
}

export interface ClimbTowerCurseCardData {
    id: string;
    towerIdList: string[];
    name: string;
    desc: string;
    trapId: string;
}

export interface ClimbTowerMissionData {
    id: string;
    sortId: number;
    description: string;
    type: MissionType;
    itemBgType: MissionItemBgType;
    preMissionIds: string[];
    template: string;
    templateType: string;
    param: string[];
    unlockCondition: string;
    unlockParam: string[];
    missionGroup: string;
    toPage: string;
    periodicalPoint: number;
    rewards: MissionDisplayRewards[];
    backImagePath: string;
    foldId: string;
    haveSubMissionToUnlock: boolean;
    countEndTs: number;
    bindGodCardId: string;
    bindTowerId: string;
}

export interface ClimbTowerSeasonInfoData {
    id: string;
    name: string;
    seasonNum: number;
    startTs: number;
    endTs: number;
    towers: string[];
    seasonCards: string[];
    replicatedTowers: string[];
}

export interface ClimbTowerDetailConst {
    unlockLevelId: string;
    unlockModuleNumRequirement: number;
    lowerItemId: string;
    lowerItemLimit: number;
    higherItemId: string;
    higherItemLimit: number;
    initCharCount: number;
    charRecruitTimes: number;
    charRecruitChoiceCount: number;
    subcardStageSort: number;
    assistCharLimit: number;
    firstClearTaskDesc: string;
    subCardObtainDesc: string;
    subGodCardUnlockDesc: string;
    sweepStartTime: number;
    sweepOpenOrdinaryLayer: number;
    sweepOpenDifficultLayer: number;
    sweepCostCount: number;
    squadMemStartTime: number;
    recordNoResetStartTime: number;
}

export interface ClimbTowerRewardInfo {
    stageSort: number;
    lowerItemCount: number;
    higherItemCount: number;
}

export interface KeyFrames_KeyFrame {
    level: number;
    data: JsonValue;
}

export interface PingCond {
    cond: number;
    txt: string;
}

export interface CommonReportPlayerData {
    id: string;
    sortId: number;
    txt: string;
    desc: string;
}

export interface CrisisClientData {
    seasonInfo: CrisisClientData_SeasonInfo[];
    meta: string;
    unlockCoinLv3: number;
    hardPointPerm: number;
    hardPointTemp: number;
    voiceGrade: number;
    crisisRuneCoinUnlockItemTitle: string;
    crisisRuneCoinUnlockItemDesc: string;
}

export interface CrisisClientData_SeasonInfo {
    seasonId: string;
    startTs: number;
    endTs: number;
    name: string;
    crisisRuneCoinUnlockItem: ItemBundle;
    permBgm: string;
    medalGroupId: string;
    bgmHardPoint: number;
    permBgmHard: string;
}

export interface CrisisV2AppraiseWrap {
    appraiseType: CrisisV2AppraiseType;
}

export interface CrisisV2SeasonInfo {
    seasonId: string;
    name: string;
    startTs: number;
    endTs: number;
    medalGroupId: string;
    medalId: string;
    themeColor1: string;
    themeColor2: string;
    themeColor3: string;
    seasonBgm: string;
    seasonBgmChallenge: string;
    crisisV2SeasonCode: string;
}

export interface CrisisV2ConstData {
    sysStartTime: number;
    blackScoreThreshold: number;
    redScoreThreshold: number;
    detailBkgRedThreshold: number;
    voiceGrade: number;
    seasonButtonUnlockInfo: number;
    shopCoinId: string;
    hardBgmSwitchScore: number;
    stageId: string;
    hideTodoWhenStageFinish: boolean;
}

export interface CrisisV2SharedData {
    seasonInfoDataMap: { [key: string]: CrisisV2SeasonInfo };
    scoreLevelToAppraiseDataMap: { [key: number]: CrisisV2AppraiseWrap };
    constData: CrisisV2ConstData;
    battleCommentRuneData: { [key: string]: RuneData[] };
    recalRuneData: RecalRuneSharedData;
}

export interface CrossDayTrackData {
    updateEndTs: number;
    id: string;
}

export interface CrossDayTrackTypeData {
    type: string;
    startTs: number;
    expireTs: number;
    dataDict: { [key: string]: CrossDayTrackData };
}

export interface ArtGalleryItemData {
    id: string;
    groupType: string;
    sortId: number;
}

export interface ArtGalleryGroupData {
    type: string;
    title: string;
    sortId: number;
    items: ArtGalleryItemData[];
}

export interface AVGDialogPresetData {
    id: number;
    name: string;
    nameFontSize: number;
    messageFontSize: number;
    messageMinHeight: number;
}

export interface AVGDialogSettingData {
    defaultPresetId: number;
    presetList: AVGDialogPresetData[];
}

export interface DisplayMetaData {
    playerAvatarData: PlayerAvatarData;
    homeBackgroundData: HomeBackgroundData;
    nameCardV2Data: NameCardV2Data;
    mailArchiveData: MailArchiveData;
    mailSenderData: MailSenderData;
    emoticonData: EmoticonData;
    storyVariantData: { [key: string]: StoryVariantData };
    guidebookGroupDatas: { [key: string]: GuidebookGroupData };
    pcKeyData: PCKeyData;
    resolutionSettingList: ResolutionSettingItemData[];
    artGalleryCollectData: ArtGalleryCollectData;
    magazineLeafData: MagazineLeafData;
    stickerData: StickerData;
    avgDialogSettingData: AVGDialogSettingData;
    pixelMapData: PixelMapData;
}

export interface PlayerAvatarPerData {
    ASSISTANT_GROUP_TYPE: PlayerAvatarGroupType;
    avatarId: string;
    avatarType: PlayerAvatarGroupType;
    avatarDesc: string;
    isSecret: boolean;
    avatarStartTs: number;
    avatarLimit: boolean;
    avatarIdSort: number;
    avatarIdDesc: string;
    avatarItemName: string;
    avatarItemDesc: string;
    avatarItemUsage: string;
    obtainApproach: string;
    dynAvatarId: string;
    limitDatas: PlayerAvatarLimitData[];
}

export interface PlayerAvatarLimitData {
    avatarId: string;
    descShowTs: number;
    descHideTs: number;
}

export interface PlayerAvatarGroupData {
    avatarType: PlayerAvatarGroupType;
    typeName: string;
    sortId: number;
    avatarIdList: string[];
}

export interface PlayerAvatarData {
    defaultAvatarId: string;
    avatarList: PlayerAvatarPerData[];
    avatarTypeData: { [key: string]: PlayerAvatarGroupData };
    constData: AvatarConstData;
}

export interface AvatarConstData {
    approachHideText: string;
}

export interface HomeBackgroundSingleData {
    bgId: string;
    bgType: string;
    bgSortId: number;
    bgStartTime: number;
    isSecret: boolean;
    bgName: string;
    bgDes: string;
    bgUsage: string;
    isMultiForm: boolean;
    changeRule: HomeMultiFormChangeRule;
    multiFormList: HomeBackgroundMultiFormData[];
    obtainApproach: string;
    unlockDesList: string[];
    multiPicId: string;
}

export interface HomeBackgroundLimitData {
    bgId: string;
    limitInfos: HomeBackgroundLimitInfoData[];
}

export interface HomeBackgroundMultiFormData {
    multiFormBgId: string;
    sortId: number;
    bgMusicId: string;
}

export interface HomeBackgroundLimitInfoData {
    limitInfoId: string;
    startTime: number;
    endTime: number;
    invalidObtainDesc: string;
    displayAfterEndTime: boolean;
}

export interface HomeBackgroundData {
    defaultBackgroundId: string;
    defaultThemeId: string;
    homeBgDataList: HomeBackgroundSingleData[];
    backgroundGroupDatas: ArtGalleryGroupData[];
    themeList: HomeThemeDisplayData[];
    themeGroupDatas: ArtGalleryGroupData[];
    backgroundLimitData: { [key: string]: HomeBackgroundLimitData };
    themeLimitData: { [key: string]: HomeThemeLimitData };
    multiFormInfoData: HomeMultiFormInfoData[];
    timeRuleData: { [key: string]: HomeMultiFormTimeRuleData[] };
    defaultBgMusicId: string;
    themeStartTime: number;
}

export interface HomeThemeDisplayData {
    id: string;
    type: string;
    sortId: number;
    startTime: number;
    isSecret: boolean;
    tmName: string;
    tmDes: string;
    tmUsage: string;
    isMultiForm: boolean;
    changeRule: HomeMultiFormChangeRule;
    multiFormList: HomeThemeMultiFormData[];
    obtainApproach: string;
    unlockDesList: string[];
    isLimitObtain: boolean;
    hideWhenLimit: boolean;
    rarity: ItemRarity;
    multiPicId: string;
}

export interface HomeThemeLimitData {
    id: string;
    limitInfos: HomeThemeLimitInfoData[];
}

export interface HomeThemeLimitInfoData {
    startTime: number;
    endTime: number;
    invalidObtainDesc: string;
}

export interface HomeThemeMultiFormData {
    multiFormTmId: string;
    sortId: number;
}

export interface HomeMultiFormInfoData {
    changeRule: HomeMultiFormChangeRule;
    bgDesc: string;
    tmDesc: string;
}

export interface HomeMultiFormTimeRuleData {
    id: string;
    startHour: number;
}

export interface NameCardV2ModuleData {
    id: string;
    type: NameCardV2ModuleType;
}

export interface NameCardV2RemovableModuleData {
    id: string;
    type: NameCardV2ModuleType;
    sortId: number;
    subType: NameCardV2ModuleSubType;
    name: string;
}

export interface NameCardV2TimeLimitInfo {
    limitId: string;
    id: string;
    availStartTime: number;
    availEndTime: number;
}

export interface NameCardV2SkinData {
    id: string;
    name: string;
    type: NameCardV2SkinType;
    isSecret: boolean;
    sortId: number;
    isSpTheme: boolean;
    defaultShowDetail: boolean;
    themeName: string;
    themeEnName: string;
    skinStartTime: number;
    skinDesc: string;
    usageDesc: string;
    skinApproach: string;
    unlockConditionCnt: number;
    unlockDescList: string[];
    fixedModuleList: string[];
    rarity: ItemRarity;
    skinTmplCnt: number;
    canChangeTmpl: boolean;
    isTimeLimit: boolean;
    timeLimitInfoList: { [key: string]: NameCardV2TimeLimitInfo };
}

export interface NameCardV2Consts {
    defaultNameCardSkinId: string;
    canUidHide: boolean;
    removableModuleMaxCount: number;
    approachHideText: string;
}

export interface NameCardV2Data {
    fixedModuleData: { [key: string]: NameCardV2ModuleData };
    removableModuleData: { [key: string]: NameCardV2RemovableModuleData };
    skinData: { [key: string]: NameCardV2SkinData };
    skinGroupDatas: ArtGalleryGroupData[];
    consts: NameCardV2Consts;
}

export interface MailArchiveItemData {
    id: string;
    type: MailArchiveItemType;
    sortId: number;
    displayReceiveTs: number;
    year: number;
    dateDelta: number;
    senderId: string;
    title: string;
    content: string;
    rewardList: ItemBundle[];
}

export interface MailArchiveConstData {
    funcOpenTs: number;
}

export interface MailArchiveData {
    mailArchiveInfoDict: { [key: string]: MailArchiveItemData };
    constData: MailArchiveConstData;
}

export interface MailSenderData {
    senderDict: { [key: string]: MailSenderSingleInfo };
}

export interface MailSenderSingleInfo {
    senderId: string;
    senderName: string;
    avatarId: string;
}

export interface EmoticonData {
    emojiDataDict: { [key: string]: EmoticonData_EmojiData };
    emoticonThemeDataDict: { [key: string]: string[] };
    emoticonThemeTypeDict: { [key: string]: EmoticonData_EmoticonThemeTypeData };
    emoticonThemeReverseDict: { [key: string]: string[] };
}

export interface EmoticonData_EmojiData {
    id: string;
    type: EmojiSceneType;
    sortId: number;
    picId: string;
    desc: string;
}

export interface EmoticonData_EmoticonThemeTypeData {
    itemId: string;
    sortId: number;
    isBasic: boolean;
    isDyn: boolean;
    picSceneList: EmojiSceneType[];
}

export interface GuidebookGroupData {
    groupId: string;
    guideTarget: UIGuideTarget;
    subSignal: string;
    configList: GuidebookConfigData[];
}

export interface GuidebookConfigData {
    configId: string;
    sortId: number;
    pageIdList: string[];
}

export interface StoryVariantData {
    plotTaskId: string;
    spStoryId: string;
    storyId: string;
    priority: number;
    startTime: number;
    endTime: number;
    template: string;
    param: string[];
}

export interface KeyItem {
    keyId: string;
    keyName: string;
    useIcon: boolean;
    keyCodeType: KeyCodeType;
    keyCodes: number[];
    canBeSetted: boolean;
}

export interface ResolutionSettingItemData {
    sortId: number;
    resolutionWidth: number;
    resolutionHeight: number;
    resolutionText: string;
    isFullScreen: boolean;
    isBorderless: boolean;
}

export interface KeySettingGroupData {
    groupId: string;
    name: string;
    funcType: KeySettingGroup;
    keyEffectGroup: KeyEffectGroup;
    isHidden: boolean;
    relatedActTypes: ActivityType[];
    gameModeTag: string;
    sortId: number;
    startTs: number;
    itemList: KeySettingItemData[];
}

export interface KeySettingItemData {
    funcId: string;
    funcName: string;
    canBeSet: boolean;
    defaultKeyId: string;
    sortId: number;
}

export interface PCKeyConstData {
    cannotSetKeyNotice: string;
    resetKeyNotice: string;
}

export interface PCKeyData {
    keyList: { [key: string]: KeyItem };
    keySettingData: { [key: string]: KeySettingGroupData };
    constData: PCKeyConstData;
}

export interface ArtGalleryCollectData {
    collectionSets: { [key: string]: ArtGalleryCollectSetData };
    collectionTypes: { [key: string]: ArtGalleryCollectTypeData };
    constData: ArtGalleryCollectConstData;
}

export interface ArtGalleryCollectSetData {
    setId: string;
    setName: string;
    setType: CollectType;
    sortId: number;
    startTime: number;
    completeTime: number;
    items: ArtGalleryCollectItemData[];
    displayMaxCount: number;
    missionList: { [key: string]: ArtGalleryCollectSetMissionData };
}

export interface ArtGalleryCollectTypeData {
    setType: CollectType;
    typeName: string;
    typeEngNameFilterPic: string;
    typeEngNamePic: string;
    typeFilterSelectIcon: string;
    typeFilterUnselectIcon: string;
    setIdList: string[];
    sortId: number;
}

export interface ArtGalleryCollectItemData {
    itemId: string;
    itemType: ItemType;
    collectionSetId: string;
    sortId: number;
}

export interface ArtGalleryCollectSetMissionData {
    missionId: string;
    requireItemCount: number;
    rewardList: ItemBundle[];
}

export interface ArtGalleryCollectConstData {
    collectTypeFilterAll: string;
    collectTypeFilterAllUnselect: string;
}

export interface ArtMagazineLeafElementData {
    id: string;
    type: ItemType;
    sub: number;
    pos: number[];
    scale: number;
}

export interface ArtMagazineLeafData {
    leafId: string;
    decorList: ArtMagazineLeafElementData[];
    charSkin: ArtMagazineLeafElementData;
}

export interface MagazineLeafData {
    leafMap: { [key: string]: MagazineLeafItemData };
    leafDecorTypeMap: { [key: string]: MagazineLeafDecorTypeData };
    leafTypeMap: { [key: string]: MagazineLeafTypeData };
    leafTemplateMap: { [key: string]: ArtMagazineLeafData };
    constData: MagazineLeafConst;
    blackListInDiy: { [key: string]: { [key: string]: number } };
}

export interface MagazineLeafItemData {
    leafId: string;
    leafType: MagazineLeafType;
    sortId: number;
    startTime: number;
    name: string;
    desc: string;
    usage: string;
    approach: string;
    rarity: ItemRarity;
    templateId: string;
    templateStartTime: number;
    templateColor: string;
    templateColor2: string;
    skinDefaultPos: JsonValue;
    skinDefaultScale: number;
    leafDecorMaxNumMap: { [key: string]: number };
}

export interface MagazineLeafDecorTypeData {
    minScale: number;
    maxScale: number;
    defaultScale: number;
    engName: string;
    smallIconId: string;
    bigIconId: string;
    templateUseCardPosBias: JsonValue;
    templateUseCardScale: number;
}

export interface MagazineLeafTypeData {
    engName: string;
    typeIconId: string;
}

export interface MagazineLeafConst {
    sysUnlockRewards: ItemBundle[];
    leafDisplayMaxNum: number;
    skinDefaultGainTime: number;
    defaultLeafId: string;
}

export interface StickerData {
    stickerMap: { [key: string]: StickerItemData };
}

export interface StickerItemData {
    id: string;
    name: string;
    stickerType: StickerType;
    sortId: number;
    desc: string;
    usage: string;
    approach: string;
    rarity: ItemRarity;
}

export interface PixelMapData {
    paramMap: { [key: string]: PixelMapParamData };
    constData: PixelMapConstData;
}

export interface PixelMapParamData {
    width: number;
    height: number;
    initColor: string;
    htmlColors: string[];
}

export interface PixelMapConstData {
    uidWaterMark: boolean;
}

export interface EnemyDatabase {
    enemies: { Key: string; Value: EnemyDatabase_EnemyLevel[] }[];
}

export interface EnemyDatabase_EnemyData {
    name: string;
    description: string;
    prefabKey: string;
    attributes: EnemyDatabase_AttributesData;
    applyWay: SourceApplyWay;
    motion: MotionMode;
    enemyTags: string[];
    lifePointReduce: number;
    levelType: EnemyLevelType;
    rangeRadius: number;
    numOfExtraDrops: number;
    viewRadius: number;
    notCountInTotal: boolean;
    talentBlackboard: Blackboard;
    skills: LevelData_EnemyData_ESkillData[];
    spData: LevelData_EnemyData_ESpData;
}

export interface EnemyDatabase_EnemyLevel {
    level: number;
    enemyData: EnemyDatabase_EnemyData;
}

export interface EnemyDatabase_AttributesData {
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
    massLevel: number;
    baseForceLevel: number;
    tauntLevel: number;
    epDamageResistance: number;
    epResistance: number;
    damageHitratePhysical: number;
    damageHitrateMagical: number;
    epBreakRecoverSpeed: number;
    stunImmune: boolean;
    silenceImmune: boolean;
    sleepImmune: boolean;
    frozenImmune: boolean;
    levitateImmune: boolean;
    disarmedCombatImmune: boolean;
    fearedImmune: boolean;
    palsyImmune: boolean;
    attractImmune: boolean;
    teleportImmune: boolean;
    groundBoundImmune: boolean;
}

export interface EnemyHandbookLevelInfoData {
    classLevel: string;
    attack: EnemyHandbookLevelInfoData_RangePair;
    def: EnemyHandbookLevelInfoData_RangePair;
    magicRes: EnemyHandbookLevelInfoData_RangePair;
    maxHP: EnemyHandbookLevelInfoData_RangePair;
    moveSpeed: EnemyHandbookLevelInfoData_RangePair;
    attackSpeed: EnemyHandbookLevelInfoData_RangePair;
    enemyDamageRes: EnemyHandbookLevelInfoData_RangePair;
    enemyRes: EnemyHandbookLevelInfoData_RangePair;
}

export interface EnemyHandbookLevelInfoData_RangePair {
    min: number;
    max: number;
}

export interface EnemyHandbookRaceData {
    id: string;
    raceName: string;
    sortId: number;
}

export interface BattleUniEquipData {
    resKey: string;
    target: UniEquipTarget;
    isToken: boolean;
    validInGameTag: string;
    validInMapTag: string;
    addOrOverrideTalentDataBundle: CharacterData_EquipTalentDataBundle;
    overrideTraitDataBundle: CharacterData_EquipTraitDataBundle;
}

export interface BattleEquipPerLevelPack {
    equipLevel: number;
    parts: BattleUniEquipData[];
    attributeBlackboard: Blackboard;
    tokenAttributeBlackboard: { [key: string]: Blackboard };
}

export interface BattleEquipPack {
    phases: BattleEquipPerLevelPack[];
}

export interface ExternalBuff {
    attributes: AttributeModifierData;
}

export type FavorDataFrames = KeyFrames_KeyFrame[];

export interface FavorTable {
    maxFavor: number;
    favorFrames: FavorDataFrames;
}

export interface FifthAnnivExploreGroupData {
    id: string;
    name: string;
    desc: string;
    code: string;
    iconId: string;
    initialValues: { [key: string]: number };
    heritageValueType: FifthAnnivExploreValueType;
}

export interface FifthAnnivExploreStageData {
    id: string;
    name: string;
    desc: string;
    nextStageId: string;
    eventCount: number;
    prevNodeCount: number;
    stageNum: number;
    stageEventNum: number;
    stageDisplayNum: string;
    stageFailureDescription: string;
}

export interface FifthAnnivExploreTargetData {
    id: string;
    linkStageId: string;
    targetValues: { [key: string]: number };
    requireEventId: string;
    lockedLevelId: string;
    isEnd: boolean;
    name: string;
    endName: string;
    desc: string;
    successDesc: string;
    successIconId: string;
}

export interface FifthAnnivExploreEventChoiceData {
    id: string;
    eventId: string;
    name: string;
    desc: string;
    successDesc: string;
    failureDesc: string;
}

export interface FifthAnnivExploreEventData {
    id: string;
    name: string;
    typeName: string;
    iconId: string;
    desc: string;
    choiceIds: string[];
}

export interface FifthAnnivExploreBroadcastData {
    id: string;
    eventCount: number;
    stageId: string;
    content: string;
}

export interface FifthAnnivExploreConst {
    prevRecordNum: number;
    maxBoard: number;
    valueMin: number;
    valueMax: number;
    targetStuckDesc: string;
    stageStuckDesc: string;
    missionName: string;
    missionDesc: string;
    choiceValueOrder: string[];
    teamPassTargeDesc: string;
    teamPassEndDesc: string;
}

export interface FifthAnnivExploreMissionData {
    id: string;
    sortId: number;
    description: string;
    type: MissionType;
    itemBgType: MissionItemBgType;
    preMissionIds: string[];
    template: string;
    templateType: string;
    param: string[];
    unlockCondition: string;
    unlockParam: string[];
    missionGroup: string;
    toPage: string;
    periodicalPoint: number;
    rewards: MissionDisplayRewards[];
    backImagePath: string;
    foldId: string;
    haveSubMissionToUnlock: boolean;
    countEndTs: number;
    progressUpLimit: number;
}

export interface FifthAnnivExploreData {
    exploreGroupData: { [key: string]: FifthAnnivExploreGroupData };
    exploreStageData: { [key: string]: FifthAnnivExploreStageData };
    exploreTargetData: { [key: string]: FifthAnnivExploreTargetData };
    exploreEventData: { [key: string]: FifthAnnivExploreEventData };
    exploreChoiceData: { [key: string]: FifthAnnivExploreEventChoiceData };
    broadcastData: { [key: string]: FifthAnnivExploreBroadcastData };
    exploreConst: FifthAnnivExploreConst;
    missionData: { [key: string]: FifthAnnivExploreMissionData };
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

export interface SharedCharData_SharedCharSkillData {
    skillId: string;
    specializeLevel: number;
}

export interface SharedCharData_TmplData {
    skillIndex: number;
    skinId: string;
    skills: SharedCharData_SharedCharSkillData[];
    selectEquip: string;
    equips: { [key: string]: SharedCharData_CharEquipInfo };
    overrideSkillIndex: number;
    overrideEquipId: string;
}

export interface SharedCharData_CharEquipInfo {
    locked: boolean;
    level: number;
}

export interface GachaTag {
    tagId: number;
    tagName: string;
    tagGroup: number;
}

export interface GachaPoolClientData {
    gachaPoolId: string;
    gachaIndex: number;
    openTime: number;
    endTime: number;
    gachaPoolName: string;
    gachaPoolSummary: string;
    gachaPoolDetail: string;
    guaranteeName: string;
    guarantee5Avail: number;
    guarantee5Count: number;
    lMTGSID: string;
    cDPrimColor: string;
    cDSecColor: string;
    freeBackColor: string;
    gachaRuleType: GachaRuleType;
    dynMeta: JsonValue;
    linkageRuleId: string;
    linkageParam: JsonValue;
    limitParam: JsonValue;
}

export interface NewbeeGachaPoolClientData {
    gachaPoolId: string;
    gachaIndex: number;
    gachaPoolName: string;
    gachaPoolDetail: string;
    gachaPrice: number;
    gachaTimes: number;
    gachaOffset: string;
}

export interface BasedRecruitPool_RecruitConstants {
    tagPriceList: { [key: number]: number };
    maxRecruitTime: number;
}

export interface RecruitPool {
    recruitConstants: BasedRecruitPool_RecruitConstants;
    recruitTimeTable: RecruitPool_RecruitTime[];
}

export interface RecruitPool_RecruitTime {
    timeLength: number;
    recruitPrice: number;
}

export interface SpecialRecruitPool {
    recruitConstants: BasedRecruitPool_RecruitConstants;
    recruitId: string;
    tagName: string;
    tagId: number;
    order: number;
    startDateTime: number;
    endDateTime: number;
    recruitTimeTable: SpecialRecruitPool_SpecialRecruitCostData[];
}

export interface SpecialRecruitPool_SpecialRecruitCostData {
    timeLength: number;
    recruitPrice: number;
    itemCosts: ItemBundle[];
}

export interface PotentialMaterialConverterConfig {
    items: { [key: number]: ItemBundle };
}

export interface GachaData {
    gachaPoolClient: GachaPoolClientData[];
    newbeeGachaPoolClient: NewbeeGachaPoolClientData[];
    specialRecruitPool: SpecialRecruitPool[];
    gachaTags: GachaTag[];
    recruitPool: RecruitPool;
    potentialMaterialConverter: PotentialMaterialConverterConfig;
    classicPotentialMaterialConverter: PotentialMaterialConverterConfig;
    recruitRarityTable: { [key: number]: GachaData_RecruitRange };
    specialTagRarityTable: { [key: number]: number[] };
    recruitDetail: string;
    showGachaLogEntry: boolean;
    carousel: GachaData_CarouselData[];
    freeGacha: GachaData_FreeLimitGachaData[];
    limitTenGachaItem: GachaData_LimitTenGachaTkt[];
    linkageGachaItem: GachaData_LinkageGachaTkt[];
    normalGachaItem: GachaData_NormalGachaTkt[];
    fesGachaPoolRelateItem: { [key: string]: GachaData_FesGachaPoolRelateItem };
    dicRecruit6StarHint: { [key: string]: string };
    specialGachaPercentDict: { [key: number]: number };
}

export interface GachaData_RecruitRange {
    rarityStart: number;
    rarityEnd: number;
}

export interface GachaData_CarouselData {
    poolId: string;
    index: number;
    startTime: number;
    endTime: number;
    spriteId: string;
}

export interface GachaData_FreeLimitGachaData {
    poolId: string;
    openTime: number;
    endTime: number;
    freeCount: number;
}

export interface GachaData_LimitTenGachaTkt {
    itemId: string;
    endTime: number;
}

export interface GachaData_FesGachaPoolRelateItem {
    rarityRank5ItemId: string;
    rarityRank6ItemId: string;
}

export interface GachaData_LinkageGachaTkt {
    itemId: string;
    endTime: number;
    gachaPoolId: string;
    isTen: boolean;
}

export interface GachaData_NormalGachaTkt {
    itemId: string;
    endTime: number;
    gachaPoolId: string;
    isTen: boolean;
}

export interface GameDataConsts {
    maxPlayerLevel: number;
    playerExpMap: number[];
    playerApMap: number[];
    maxLevel: number[][];
    characterExpMap: number[][];
    characterUpgradeCostMap: number[][];
    evolveGoldCost: number[][];
    completeGainBonus: number;
    playerApRegenSpeed: number;
    maxPracticeTicket: number;
    advancedGachaCrystalCost: number;
    completeCrystalBonus: number;
    initPlayerGold: number;
    initPlayerDiamondShard: number;
    initCampaignTotalFee: number;
    initRecruitTagList: number[];
    initCharIdList: string[];
    attackMax: number;
    defMax: number;
    hpMax: number;
    reMax: number;
    diamondToShdRate: number;
    requestSameFriendCd: number;
    baseMaxFriendNum: number;
    maxStarFriendNum: number;
    maxSquadAssistDisplayNum: number;
    friendStarEditTrackTs: number;
    hardDiamondDrop: number;
    instFinDmdShdCost: number;
    easyCrystalBonus: number;
    diamondMaterialToShardExchangeRatio: number;
    diamondHandbookStageGain: number;
    apBuyCost: number;
    apBuyThreshold: number;
    creditLimit: number;
    monthlySubRemainTimeLimitDays: number;
    friendAssistRarityLimit: number[];
    mainlineCompatibleDesc: string;
    mainlineToughDesc: string;
    mainlineEasyDesc: string;
    mainlineNormalDesc: string;
    rejectSpCharMission: number;
    addedRewardDisplayZone: string;
    oneDiamondAp: number;
    charRotationPresetMaxCnt: number;
    charRotationSkinListMaxCnt: number;
    defaultCrpresetCharId: string;
    defaultCrpresetCharSkinId: string;
    defaultCrpresetBgid: string;
    defaultCrpresetThemeId: string;
    defaultCrpresetName: string;
    charRotationPresetTrackTs: number;
    uniequipArchiveSysTrackTs: number;
    manufactPromptTime: number;
    mainGuideActivedStageId: string;
    richTextStyles: { [key: string]: string };
    charAssistRefreshTime: GameDataConsts_CharAssistRefreshTimeState[];
    normalRecruitLockedString: string[];
    commonPotentialLvlUpCount: number;
    weeklyOverrideDesc: string;
    voucherDiv: number;
    recruitPoolVersion: number;
    v006RecruitTimeStep1Refresh: number;
    v006RecruitTimeStep2Check: number;
    v006RecruitTimeStep2Flush: number;
    buyApTimeNoLimitFlag: boolean;
    isLmgtsenabled: boolean;
    legacyTime: number;
    legacyItemList: ItemBundle[];
    useAssistSocialPt: number;
    useAssistSocialPtMaxCount: number;
    assistBeUsedSocialPt: { [key: number]: number };
    pushForces: number[];
    pushForceZeroIndex: number;
    normalGachaUnlockPrice: number[];
    pullForces: number[];
    pullForceZeroIndex: number;
    multiInComeByRank: string[];
    lmtgstoEpgsratio: number;
    newBeeGiftEpgs: number;
    lMtgsdescConstOne: string;
    lMtgsdescConstTwo: string;
    defCdprimColor: string;
    defCdsecColor: string;
    mailBannerType: string[];
    monthlySubWarningTime: number;
    unlimitSkinOutOfTime: number;
    replicateShopStartTime: number;
    operatorRecordsStartTime: number;
    isDynIllustEnabled: boolean;
    isDynIllustStartEnabled: boolean;
    isClassicQcshopEnabled: boolean;
    isRoguelikeTopicFuncEnabled: boolean;
    isSandboxPermFuncEnabled: boolean;
    isRoguelikeAvgAchieveFuncEnabled: boolean;
    isClassicPotentialItemFuncEnabled: boolean;
    isClassicGachaPoolFuncEnabled: boolean;
    isSpecialGachaPoolFuncEnabled: boolean;
    isVoucherClassicItemDistinguishable: boolean;
    isRecalRuneFuncEnabled: boolean;
    voucherSkinRedeem: number;
    voucherSkinDesc: string;
    charmEquipCount: number;
    termDescriptionDict: { [key: string]: TermDescriptionData };
    storyReviewUnlockItemLackTip: string;
    dataVersion: string;
    resPrefVersion: string;
    announceWebBusType: string;
    videoPlayerWebBusType: string;
    gachaLogBusType: string;
    defaultMinMultipleBattleTimes: number;
    defaultMaxMultipleBattleTimes: number;
    multipleActionOpen: boolean;
    subProfessionDamageTypePairs: { [key: string]: SubProfessionAttackType };
    classicProtectChar: string[];
    feverGameData: GameDataConsts_FeverGameData;
    birthdaySettingDesc: string;
    birthdaySettingConfirmDesc: string;
    birthdaySettingLeapConfirmDesc: string;
    leapBirthdayRewardMonth: number;
    leapBirthdayRewardDay: number;
    birthdaySettingShowStageId: string;
    isBirthdayFuncEnabled: boolean;
    isSoCharEnabled: boolean;
    avgReaderModeDefaultSetting: GameDataConsts_AVGReaderModeDefaultSetting;
    tso: number;
}

export interface GameDataConsts_CharAssistRefreshTimeState {
    hour: number;
    minute: number;
}

export interface GameDataConsts_FeverGameData {
    feverDuration: number;
    feverNeed: number;
}

export interface GameDataConsts_AVGReaderModeDefaultSetting {
    defaultReaderFontsize: number;
    defaultReaderLinespace: number;
    defaultReaderBackgroundAlpha: number;
    defaultNameReaderFontsize: number;
}

export interface HandbookUnlockParam {
    unlockType: DataUnlockType;
    unlockParam1: string;
    unlockParam2: string;
    unlockParam3: string;
}

export interface HandbookStoryStageData {
    charID: string;
    stageId: string;
    levelId: string;
    zoneId: string;
    code: string;
    name: string;
    loadingPicId: string;
    description: string;
    unlockParam: HandbookUnlockParam[];
    rewardItem: ItemBundle[];
    stageGetTime: number;
}

export interface HandbookAvgData {
    storyId: string;
    storySetId: string;
    storySort: number;
    storyCanShow: boolean;
    storyIntro: string;
    storyInfo: string;
    storyTxt: string;
}

export interface HandbookAvgGroupData {
    storySetId: string;
    storySetName: string;
    sortId: number;
    storyGetTime: number;
    rewardItem: ItemBundle[];
    unlockParam: HandbookUnlockParam[];
    avgList: HandbookAvgData[];
    charID: string;
}

export interface HandBookStoryViewData {
    stories: HandBookStoryViewData_StoryText[];
    storyTitle: string;
    unLockorNot: boolean;
}

export interface HandBookStoryViewData_StoryText {
    storyText: string;
    unLockType: DataUnlockType;
    unLockParam: string;
    showType: DataUnlockType;
    showParam: string;
    unLockString: string;
    patchIdList: string[];
}

export interface HandbookInfoData {
    charID: string;
    infoName: string;
    isLimited: boolean;
    storyTextAudio: HandBookStoryViewData[];
    handbookAvgList: HandbookAvgGroupData[];
}

export interface HandbookTeamMission {
    id: string;
    sort: number;
    powerId: string;
    powerName: string;
    item: ItemBundle;
    favorPoint: number;
}

export interface HandbookStageTimeData {
    timestamp: number;
    charSet: string[];
}

export interface HandbookDisplayCondition {
    charID: string;
    conditionCharId: string;
    type: HandbookDisplayCondition_DisplayType;
}

export interface HandbookInfoTable {
    handbookDict: { [key: string]: HandbookInfoData };
    npcDict: { [key: string]: NPCData };
    teamMissionList: { [key: string]: HandbookTeamMission };
    handbookDisplayConditionList: { [key: string]: HandbookDisplayCondition };
    handbookStageData: { [key: string]: HandbookStoryStageData };
    handbookStageTime: HandbookStageTimeData[];
}

export type HandbookTeamData = { [key: string]: JsonValue };

export interface HotUpdateMetaMovieData {
    videoId: string;
    videoPath: string;
    endTime: number;
    sortId: number;
}

export interface HotUpdateMetaPicData {
    picId: string;
    groupId: number;
    sortId: number;
    startTime: number;
    endTime: number;
    textList: string[];
    picType: HotUpdateMetaPicData_PicType;
    logoId: string;
    color: string;
    videoId: string;
    videoPath: string;
}

export interface HotUpdateMetaTable {
    picList: HotUpdateMetaPicData[];
    movieInfo: HotUpdateMetaMovieData;
}

export interface InventoryData {
    items: { [key: string]: ItemData };
    expItems: { [key: string]: ExpItemFeature };
    potentialItems: { [key: number]: { [key: string]: string } };
    apSupplies: { [key: string]: ApSupplyFeature };
    charVoucherItems: { [key: string]: CharVoucherItemFeature };
    uniqueInfo: { [key: string]: number };
    itemTimeLimit: { [key: string]: number };
    uniCollectionInfo: { [key: string]: UniCollectionInfo };
    itemPackInfos: { [key: string]: ItemPackInfo };
    fullPotentialCharacters: { [key: string]: FullPotentialCharacterInfo };
    activityPotentialCharacters: { [key: string]: ActivityPotentialCharacterInfo };
    favorCharacters: { [key: string]: FavorCharacterInfo };
    itemShopNameDict: { [key: string]: string };
}

export interface FullPotentialCharacterInfo {
    itemId: string;
    ts: number;
}

export interface UniCollectionInfo {
    uniCollectionItemId: string;
    uniqueItem: ItemBundle[];
}

export interface ItemPackInfo {
    packId: string;
    content: ItemBundle[];
}

export interface ActivityPotentialCharacterInfo {
    charId: string;
}

export interface FavorCharacterInfo {
    itemId: string;
    charId: string;
    favorAddAmt: number;
}

export interface ItemData {
    itemId: string;
    name: string;
    description: string;
    rarity: ItemRarity;
    iconId: string;
    overrideBkg: string;
    stackIconId: string;
    sortId: number;
    usage: string;
    obtainApproach: string;
    hideInItemGet: boolean;
    reslockStatus: ItemReslockStatus;
    canReslock: boolean;
    classifyType: ItemClassifyType;
    itemType: ItemType;
    stageDropList: ItemData_StageDropInfo[];
    buildingProductList: ItemData_BuildingProductInfo[];
    voucherRelateList: ItemData_VoucherRelateInfo[];
    shopRelateInfoList: ItemData_ShopRelateInfo[];
}

export interface ItemData_StageDropInfo {
    stageId: string;
    occPer: OccPer;
    sortId: number;
    expectPerAp: number;
}

export interface ItemData_BuildingProductInfo {
    roomType: BuildingData_RoomType;
    formulaId: string;
}

export interface ItemData_VoucherRelateInfo {
    voucherId: string;
    voucherItemType: ItemType;
}

export interface ItemData_ShopRelateInfo {
    shopType: ItemDropShopType;
    shopGroup: number;
    startTs: number;
}

export interface ItemBundle {
    id: string;
    count: number;
    type: ItemType;
}

export interface WeightItemBundle {
    id: string;
    type: ItemType;
    dropType: StageDropType;
    count: number;
    weight: number;
}

export interface ExpItemFeature {
    id: string;
    gainExp: number;
}

export interface ApSupplyFeature {
    id: string;
    ap: number;
    hasTs: boolean;
}

export interface CharVoucherItemFeature {
    id: string;
    displayType: VoucherDisplayType;
}

export interface LevelData_EnemyData_ESkillData {
    prefabKey: string;
    priority: number;
    cooldown: number;
    initCooldown: number;
    spCost: number;
    blackboard: Blackboard;
}

export interface LevelData_EnemyData_ESpData {
    spType: SpType;
    maxSp: number;
    initSp: number;
    increment: number;
}

export interface LongTermCheckInGroupData {
    groupId: string;
    sortId: number;
    startTs: number;
    level: number;
    days: number;
    bkgImgId: string;
    titleImgId: string;
    tipText: string;
    bottomText: string;
    rewardList: ItemBundle[];
}

export interface LongTermCheckInConstData {
    startTs: number;
    detailTitle: string;
    detailDesc: string;
}

export interface LongTermCheckInData {
    groupList: LongTermCheckInGroupData[];
    constData: LongTermCheckInConstData;
}

export interface MedalRewardGroupData {
    groupId: string;
    slotId: number;
    itemList: ItemBundle[];
}

export interface MedalPerData {
    medalId: string;
    medalName: string;
    medalType: string;
    slotId: number;
    preMedalIdList: string[];
    rarity: MedalRarity;
    template: string;
    unlockParam: string[];
    getMethod: string;
    description: string;
    advancedMedal: string;
    originMedal: string;
    displayTime: number;
    expireTimes: MedalExpireTime[];
    medalRewardGroup: MedalRewardGroupData[];
    isHidden: boolean;
    playerMedal: JsonValue;
    stageMedal: JsonValue;
    campMedal: JsonValue;
    towerMedal: JsonValue;
    growthMedal: JsonValue;
    storyMedal: JsonValue;
    buildMedal: JsonValue;
    activityMedal: JsonValue;
    rogueMedal: JsonValue;
    hiddenMedal: JsonValue;
}

export interface MedalTypeData {
    medalGroupId: string;
    sortId: number;
    medalName: string;
    groupData: MedalGroupData[];
}

export interface MedalGroupData {
    groupId: string;
    groupName: string;
    groupDesc: string;
    medalId: string[];
    sortId: number;
    groupBackColor: string;
    groupGetTime: number;
    sharedExpireTimes: MedalExpireTime[];
}

export interface MedalExpireTime {
    start: number;
    end: number;
    type: MedalExpireType;
}

export interface MedalData {
    medalList: MedalPerData[];
    medalTypeData: { [key: string]: MedalTypeData };
}

export interface StageUnlockParam {
    stageId: string;
}

export interface CharUnlockParam {
    charId: string;
}

export interface CommonAvailCheck {
    startTs: number;
    endTs: number;
    type: CommonUnlockType;
    rate: number;
    stageUnlockParam: StageUnlockParam;
    charUnlockParam: CharUnlockParam;
}

export interface TipsMetaDisplayItem {
    tipsId: string;
    loadingPic: string;
    availCheck: CommonAvailCheck;
    relateActId: string;
    isAllStageActive: boolean;
    stageIdList: string[];
    zoneIdList: string[];
    tips: TipData[];
}

export interface MapPreviewDisplayMetaItem {
    mapPreviewPicId: string;
    availCheck: CommonAvailCheck;
    relateActId: string;
    isAllStageActive: boolean;
    stageIdList: string[];
}

export interface FlashAlertAfterStageDisplayMetaItem {
    flashAlertId: string;
    availCheck: CommonAvailCheck;
    isAllStageActive: boolean;
    stageIdList: string[];
    relateActId: string;
    detailText: string;
    isBasicInfo: boolean;
    times: number;
}

export interface BattleLoadingDisplayMetaItem {
    isAllStageActive: boolean;
    stageIdList: string[];
    battleLoadingPicId: string;
    relateActId: string;
    availCheck: CommonAvailCheck;
}

export interface BattleAutoBattleMetaItem {
    battleAutoBattleDisplayKey: string;
    isAllStageActive: boolean;
    relateActId: string;
    stageIdList: string[];
    availCheck: CommonAvailCheck;
}

export interface BattleFinishDisplayMetaItem {
    battleFinishDisplayKey: string;
    isAllStageActive: boolean;
    stageIdList: string[];
    availCheck: CommonAvailCheck;
    relateActId: string;
    overrideStageName: string;
    signal: string;
    overrideCharWord: string;
}

export interface MetaUIDisplayTable {
    tipsMetaList: TipsMetaDisplayItem[];
    flashAlertAfterStageItemList: FlashAlertAfterStageDisplayMetaItem[];
    mapPreviewDisplayMetaItemList: MapPreviewDisplayMetaItem[];
    battleFinishDisplayMetaItemList: BattleFinishDisplayMetaItem[];
    battleLoadingDisplayMetaItemList: BattleLoadingDisplayMetaItem[];
    battleAutoBattleMetaItemList: BattleAutoBattleMetaItem[];
}

export interface MissionArchiveData {
    topicId: string;
    zones: string[];
    nodes: MissionArchiveNodeData[];
    hiddenClips: MissionArchiveVoiceClipData[];
    unlockDesc: string;
}

export interface MissionArchiveNodeData {
    nodeId: string;
    title: string;
    unlockDesc: string;
    clips: MissionArchiveVoiceClipData[];
}

export interface MissionArchiveVoiceClipData {
    charId: string;
    voiceId: string;
    index: number;
}

export interface MissionTable {
    missions: { [key: string]: MissionData };
    missionGroups: { [key: string]: MissionGroup };
    periodicalRewards: { [key: string]: MissionDailyRewardConf };
    weeklyRewards: { [key: string]: MissionWeeklyRewardConf };
    soCharMissionGroupInfo: { [key: string]: SOCharMissionGroup };
    dailyMissionGroupInfo: { [key: string]: DailyMissionGroupInfo };
    dailyMissionPeriodInfo: DailyMissionGroupInfo[];
    mainlineMissionEndImageDataList: MainlineMissionEndImageData[];
    crossAppShareMissions: { [key: string]: CrossAppShareMission };
    crossAppShareMissionConst: CrossAppShareMissionConst;
    guideMissionGroupInfo: { [key: string]: GuideMissionGroupInfo };
}

export interface MissionData {
    id: string;
    sortId: number;
    description: string;
    type: MissionType;
    itemBgType: MissionItemBgType;
    preMissionIds: string[];
    template: string;
    templateType: string;
    param: string[];
    unlockCondition: string;
    unlockParam: string[];
    missionGroup: string;
    toPage: string;
    periodicalPoint: number;
    rewards: MissionDisplayRewards[];
    backImagePath: string;
    foldId: string;
    haveSubMissionToUnlock: boolean;
    countEndTs: number;
}

export interface DailyMissionGroupInfo {
    startTime: number;
    endTime: number;
    tagState: string;
    periodList: DailyMissionGroupInfo_periodInfo[];
}

export interface DailyMissionGroupInfo_periodInfo {
    missionGroupId: string;
    rewardGroupId: string;
    period: number[];
}

export interface GuideMissionGroupInfo {
    groupId: string;
    sortId: number;
    shortName: string;
    unlockDesc: string;
}

export interface MissionGroup {
    id: string;
    title: string;
    type: MissionType;
    preMissionGroup: string;
    period: number[];
    rewards: MissionDisplayRewards[];
    missionIds: string[];
    startTs: number;
    endTs: number;
}

export interface MissionDailyRewardConf {
    groupId: string;
    id: string;
    periodicalPointCost: number;
    type: MissionType;
    sortIndex: number;
    rewards: MissionDisplayRewards[];
}

export interface MissionWeeklyRewardConf {
    groupId: string;
    id: string;
    periodicalPointCost: number;
    type: MissionType;
    sortIndex: number;
    rewards: MissionDisplayRewards[];
    beginTime: number;
    endTime: number;
}

export interface MissionDisplayRewards {
    type: ItemType;
    id: string;
    count: number;
}

export interface SOCharMissionGroup {
    groupId: string;
    missionIds: string[];
    startTs: number;
    endTs: number;
}

export interface MainlineMissionEndImageData {
    imageId: string;
    priority: number;
}

export interface CrossAppShareMission {
    shareMissionId: string;
    missionType: CrossAppShareMissionType;
    relateActivityId: string;
    startTime: number;
    endTime: number;
    limitCount: number;
    condTemplate: string;
    condParam: string[];
    rewardsList: MissionDisplayRewards[];
}

export interface CrossAppShareMissionConst {
    nameCardShareMissionId: string;
}

export interface TemplateMissionStyleData {
    isMissionBgCustomType: boolean;
    bigRewardType: TemplateMissionBigRewardType;
    bigRewardParamList: string[];
    isMissionListCommonType: boolean;
    isMissionItemCommonType: boolean;
    missionItemMainColor: string;
    isMissionItemCompleteUseMainColor: boolean;
    missionItemCompleteColor: string;
    isMissionRewardItemCommonType: boolean;
    isClaimAllBtnCommonType: boolean;
    claimAllBtnMainColor: string;
    claimAllBtnTips: string;
    titleType: TemplateMissionTitleType;
    coinType: TemplateMissionCoinInfoType;
    coinBackColor: string;
}

export interface NPCUnlock {
    unLockType: DataUnlockType;
    unLockParam: string;
    unLockString: string;
}

export interface NPCData {
    npcId: string;
    name: string;
    appellation: string;
    profession: ProfessionCategory;
    illustList: string[];
    designerList: string[];
    cv: string;
    displayNumber: string;
    nationId: string;
    groupId: string;
    teamId: string;
    resType: IllustNPCResType;
    npcShowAudioInfoFlag: boolean;
    unlockDict: { [key: string]: NPCUnlock };
}

export interface OpenServerItemData {
    itemId: string;
    itemType: ItemType;
    count: number;
    name: string;
}

export interface ChainLoginData {
    order: number;
    item: OpenServerItemData;
    colorId: number;
}

export interface TotalCheckinData {
    order: number;
    item: OpenServerItemData;
    colorId: number;
}

export interface OpenServerData {
    openServerMissionGroup: MissionGroup;
    openServerMissionData: MissionData[];
    checkInData: TotalCheckinData[];
    chainLoginData: ChainLoginData[];
    totalCheckinCharData: string[];
    chainLoginCharData: string[];
}

export interface OpenServerScheduleItem {
    id: string;
    versionId: string;
    startTs: number;
    endTs: number;
    totalCheckinDescption: string;
    chainLoginDescription: string;
    charImg: string;
    constData: JsonValue;
    openseverTaskGroup1: JsonValue;
    openseverTaskGroup2: JsonValue;
    firstDiamondShardMailCount: number;
    initApMailEndTs: number;
    resFullOpenUnlockStageId: string;
    resFullOpenDuration: number;
    resFullOpenTitle: string;
    resFullOpenDesc: string;
    resFullOpenGuideGroupThreshold: number;
    resFullOpenStartTime: number;
    groupDataMap: JsonValue;
    onceDataMap: JsonValue;
    checkinDataMap: JsonValue;
    priceDataMap: JsonValue;
    missionDataMap: JsonValue;
    checkinGpData: JsonValue;
    newsDataMap: JsonValue;
    giftPackagePicDataMap: JsonValue;
    openStyleData: JsonValue;
    groupList: JsonValue;
}

export interface OpenServerConst {
    firstDiamondShardMailCount: number;
    initApMailEndTs: number;
    resFullOpenUnlockStageId: string;
    resFullOpenDuration: number;
    resFullOpenTitle: string;
    resFullOpenDesc: string;
    resFullOpenGuideGroupThreshold: string;
    resFullOpenStartTime: number;
}

export interface NewbieCheckInPackageData {
    groupId: string;
    startTime: number;
    endTime: number;
    bindGPGoodId: string;
    checkInDuration: number;
    compensateEndDay: number;
    totalCheckInDay: number;
    iconId: string;
    checkInRewardDict: { [key: number]: NewbieCheckInPackageRewardData[] };
    trigStartTime: number;
    trigEndTime: number;
}

export interface NewbieCheckInPackageRewardData {
    orderNum: number;
    itemBundle: ItemBundle;
}

export interface OpenServerSchedule {
    schedule: OpenServerScheduleItem[];
    dataMap: { [key: string]: OpenServerData };
    constant: OpenServerConst;
    playerReturn: ReturnData;
    newbieCheckInPackageList: NewbieCheckInPackageData[];
    longTermCheckInData: LongTermCheckInData;
}

export interface RangeData {
    RANGE_STANDARD_DIRECTION: SharedConsts_Direction;
    id: string;
    direction: number | string;
    grids: GridPosition[];
    boundingBoxes: ObscuredRect[];
}

export interface ObscuredRect {}

export interface RecalRuneSharedData {
    seasons: { [key: string]: RecalRuneSeasonData };
    constData: RecalRuneConstData;
}

export interface RecalRuneSeasonData {
    seasonId: string;
    sortId: number;
    startTs: number;
    seasonCode: string;
    juniorReward: ItemBundle;
    seniorReward: ItemBundle;
    seniorRewardHint: string;
    mainMedalId: string;
    picId: string;
    stages: { [key: string]: RecalRuneStageData };
}

export interface RecalRuneStageData {
    stageId: string;
    levelId: string;
    juniorMedalId: string;
    seniorMedalId: string;
    juniorMedalScore: number;
    seniorMedalScore: number;
    runes: { [key: string]: RecalRuneRuneData };
    sourceName: string;
    sourceType: string;
    useName: boolean;
    levelName: string;
    levelCode: string;
    levelDesc: string;
    fixedRuneSeriesName: string;
    logoId: string;
    mainPicId: string;
    loadingPicId: string;
}

export interface RecalRuneRuneData {
    runeId: string;
    score: number;
    sortId: number;
    essential: boolean;
    exclusiveGroupId: string;
    runeIcon: string;
    packedRune: RuneTable_PackedRuneData;
}

export interface RecalRuneConstData {
    stageCountPerSeason: number;
    juniorRewardMedalCount: number;
    seniorRewardMedalCount: number;
    unlockLevelIds: string[];
}

export interface ReplicateTable {
    replicateList: ReplicateData[];
}

export interface ReplicateData {
    item: ItemBundle;
    replicateTokenItem: ItemBundle;
}

export interface RetroStageOverrideInfo {
    dropInfo: StageData_StageDropInfo;
    zoneId: string;
    apCost: number;
    apFailReturn: number;
    expGain: number;
    goldGain: number;
    passFavor: number;
    completeFavor: number;
    canMultipleBattle: boolean;
}

export interface RetroTrailRewardItem {
    trailRewardId: string;
    starCount: number;
    rewardItem: ItemBundle;
}

export interface RetroActData {
    retroId: string;
    type: RetroType;
    linkedActId: string[];
    startTime: number;
    trailStartTime: number;
    index: number;
    name: string;
    haveTrail: boolean;
    customActId: string;
    customActType: ActivityType;
    trapDomainId: string;
}

export interface RetroTrailData {
    retroId: string;
    trailStartTime: number;
    trailRewardList: RetroTrailRewardItem[];
    stageList: string[];
    relatedChar: string;
    relatedFullPotentialItemId: string;
    themeColor: string;
    fullPotentialItemId: string;
}

export interface RetroTrailRuleData {
    title: string[];
    desc: string[];
}

export type ActivityCustomData = { [key: string]: JsonValue };

export interface ActivityCustomData_Act25sideCustomData {
    battlePerformanceData: { [key: string]: Act25SideData_BattlePerformanceData };
}

export interface RetroStageTable {
    zoneToRetro: { [key: string]: string };
    stageValidInfo: { [key: string]: StageValidInfo };
    stages: { [key: string]: RetroStageOverrideInfo };
    retroActList: { [key: string]: RetroActData };
    retroTrailList: { [key: string]: RetroTrailData };
    stageList: { [key: string]: StageData };
    ruleData: RetroTrailRuleData;
    customData: ActivityCustomData;
    initRetroCoin: number;
    retroCoinPerWeek: number;
    retroCoinMaxOfLevels: { [key: number]: number };
    retroUnlockCost: number;
    retroDetail: string;
    retroPreShowTime: number;
}

export interface ReturnData {
    groupDataMap: { [key: string]: ReturnGroupData };
    onceDataMap: { [key: string]: ReturnOnceRewardData };
    checkinDataMap: { [key: string]: ReturnCheckinGroupData };
    priceDataMap: { [key: string]: ReturnPriceGroupData };
    missionDataMap: { [key: string]: ReturnMissionGroupData };
    checkinGpData: { [key: string]: ReturnCheckinGpRewardData };
    newsDataMap: { [key: string]: ReturnNewsData };
    giftPackagePicDataMap: { [key: string]: ReturnGiftPackagePicData };
    openStyleData: { [key: string]: ReturnOpenStyleData };
    constData: ReturnConstData;
}

export interface ReturnGroupData {
    groupId: string;
    taskDays: number;
    onceGroupId: string;
    missionGroupId: string[];
    checkinGroupId: string;
    priceGroupId: string;
    newsGroupId: string[];
    giftPackageIdList: string[];
    checkinGpId: string;
    gachaPoolId: string;
    allOpenDays: number;
    campAllOpenDays: number;
    allOpenData: ReturnOpenData[];
}

export interface ReturnOnceRewardData {
    groupId: string;
    rewardList: ReturnItemData[];
}

export interface ReturnItemData {
    id: string;
    count: number;
    type: ItemType;
    sortId: number;
}

export interface ReturnCheckinGroupData {
    groupId: string;
    checkinItemList: ReturnCheckinItemData[];
}

export interface ReturnCheckinItemData {
    order: number;
    isKeyItem: boolean;
    rewardList: ItemBundle[];
}

export interface ReturnPriceGroupData {
    groupId: string;
    content: ReturnPriceItemData[];
}

export interface ReturnPriceItemData {
    contentId: string;
    sortId: number;
    pointRequire: number;
    desc: string;
    displayReward: ReturnItemData;
    rewardList: ReturnItemData[];
}

export interface ReturnMissionGroupData {
    groupId: string;
    sortId: number;
    type: ReturnMissionGroupType;
    missionList: ReturnMissionItemData[];
}

export interface ReturnMissionItemData {
    missionId: string;
    sortId: number;
    uncompleteBgIcon: string;
    completeBgIcon: string;
    desc: string;
    jumpType: ReturnJumpType;
    jumpPlace: string;
    rewardList: ItemBundle[];
}

export interface ReturnCheckinGpRewardData {
    groupId: string;
    getTime: number;
    bindGPGoodId: string;
    totalCheckInDay: number;
    iconId: string;
    rewardDict: { [key: number]: ReturnItemData[] };
}

export interface ReturnNewsData {
    groupId: string;
    sortId: number;
    tabTitle: string;
    tabIcon: string;
    title: string;
    desc: string;
    imgId: string;
    iconId: string;
    jumpType: ReturnNewsType;
    jumpPlace: string;
}

export interface ReturnOpenData {
    allOpenType: ReturnAllOpenType;
    allOpenTime: number;
    desc: string;
}

export interface ReturnOpenStyleData {
    sortId: number;
    imgBkgId: string;
    imgEntryId: string;
    imgIconId: string;
    pauseDesc: string;
    title: string;
    name: string;
}

export interface ReturnConstData {
    pointItemId: string;
    returnPriceDesc: string;
    oldReturnGroupId: string;
}

export interface ReturnGiftPackagePicData {
    giftPackageId: string;
    giftPackagePic: string;
    sortId: number;
}

export interface RoguelikeActivityData {
    basicDatas: { [key: string]: RoguelikeActivityBasicData };
    activityTable: RoguelikeActivityTable;
}

export interface RoguelikeActivityBasicData {
    id: string;
    type: RoguelikeActivityType;
    startTime: number;
    endTime: number;
    isPresentSeedMode: boolean;
    isUnlockBadge: boolean;
    validMode: RoguelikeTopicMode;
}

export type RoguelikeActivityTable = { [key: string]: JsonValue };

export interface RoguelikeActivitySeedModeData {
    officialSeedDataList: RoguelikeActivitySeedModeData_RoguelikeActivityOfficialSeedData[];
    constData: RoguelikeActivitySeedModeData_RoguelikeActivitySeedModeConstData;
}

export interface RoguelikeActivitySeedModeData_RoguelikeActivityOfficialSeedData {
    seed: string;
    sortId: number;
    desc: string;
}

export interface RoguelikeActivitySeedModeData_RoguelikeActivitySeedModeConstData {
    seedModeIntro: string;
    emptyTextHint: string;
    errorTextHint: string;
    legitimateTextHint: string;
    seedModeConfirmReplacement: string;
    difficultyLevelTextHint: string;
    lockedDifficultyLevelTextHint: string;
    setDifficultyLevelTextHint: string;
    notEnabledTextHint: string;
    enabledTextHint: string;
    useSucceededTextHint: string;
    officialUseSucceededTextHint: string;
    seedModeLockedTextHint: string;
}

export interface RoguelikeTable {
    constTable: RoguelikeConstTable;
    itemTable: RoguelikeItemTable;
    stages: { [key: string]: RoguelikeStageData };
    zones: { [key: string]: RoguelikeZoneData };
    choices: { [key: string]: RoguelikeChoiceData };
    choiceScenes: { [key: string]: RoguelikeChoiceSceneData };
    modes: { [key: string]: RoguelikeModeData };
    endings: { [key: string]: RoguelikeEndingData };
    outBuffs: { [key: string]: RoguelikeOutBuffData };
    playerLevelTable: JsonValue;
    recruitPopulationTable: JsonValue;
    charUpgradeTable: JsonValue;
    eventTypeTable: JsonValue;
    shopDialogs: JsonValue;
    shopRelicDialogs: JsonValue;
    eventTypeDialogs: JsonValue;
    shopTicketDialogs: JsonValue;
    mimicEnemyIds: string[];
    clearZoneScores: JsonValue;
    moveToNodeScore: number;
    clearNormalBattleScore: number;
    clearEliteBattleScore: number;
    clearBossBattleScore: number;
    upgradeRarityScore: number;
    collectEndingScore: number;
    eventTypeIcons: JsonValue;
}

export interface RoguelikeConstTable {
    playerLevelTable: { [key: number]: RoguelikeConstTable_PlayerLevelData };
    recruitPopulationTable: { [key: number]: RoguelikeConstTable_RecruitData };
    charUpgradeTable: { [key: number]: RoguelikeConstTable_CharUpgradeData };
    eventTypeTable: { [key: string]: RoguelikeConstTable_EventTypeData };
    shopDialogs: string[];
    shopRelicDialogs: string[];
    shopTicketDialogs: string[];
    mimicEnemyIds: string[];
    clearZoneScores: number[];
    moveToNodeScore: number;
    clearNormalBattleScore: number;
    clearEliteBattleScore: number;
    clearBossBattleScore: number;
    gainRelicScore: number;
    gainCharacterScore: number;
    unlockRelicSpecialScore: number;
    squadCapacityMax: number;
    bossIds: string[];
}

export interface RoguelikeConstTable_PlayerLevelData {
    exp: number;
    populationUp: number;
    squadCapacityUp: number;
    battleCharLimitUp: number;
}

export interface RoguelikeConstTable_RecruitData {
    recruitPopulation: number;
    upgradePopulation: number;
}

export interface RoguelikeConstTable_CharUpgradeData {
    evolvePhase: number | string;
    skillLevel: number;
    skillSpecializeLevel: number;
}

export interface RoguelikeConstTable_EventTypeData {
    name: string;
    description: string;
}

export interface RoguelikeItemTable {
    items: { [key: string]: RoguelikeItemData };
    recruitTickets: { [key: string]: RoguelikeRecruitTicketFeature };
    upgradeTickets: { [key: string]: RoguelikeUpgradeTicketFeature };
    relics: { [key: string]: RoguelikeRelicFeature };
}

export interface RoguelikeItemData {
    id: string;
    name: string;
    description: string;
    usage: string;
    obtainApproach: string;
    iconId: string;
    type: RoguelikeItemType;
    rarity: RoguelikeItemRarity;
    value: number;
    sortId: number;
    unlockCond: string;
    unlockCondDesc: string;
    unlockCondParams: string[];
    stableUnlockCond: RelicStableUnlockParam;
}

export interface RelicStableUnlockParam {
    unlockCondDetail: string;
    unlockCnt: number;
}

export interface RoguelikeRecruitTicketFeature {
    id: string;
    profession: number | string;
    rarity: number | string;
    professionList: ProfessionID[];
    rarityList: (number | string)[];
    extraEliteNum: number;
    extraFreeRarity: (number | string)[];
    extraCharIds: string[];
}

export interface RoguelikeUpgradeTicketFeature {
    id: string;
    profession: number | string;
    rarity: number | string;
    professionList: ProfessionID[];
    rarityList: (number | string)[];
}

export interface RoguelikeRelicFeature {
    id: string;
    buffs: RoguelikeBuff[];
}

export interface RoguelikeStageData {
    id: string;
    linkedStageId: string;
    levelId: string;
    code: string;
    name: string;
    loadingPicId: string;
    description: string;
    eliteDesc: string;
    isBoss: number;
    isElite: number;
    difficulty: LevelData_Difficulty;
}

export interface RoguelikeZoneData {
    id: string;
    name: string;
    description: string;
    endingDescription: string;
    backgroundId: string;
    subIconId: string;
}

export interface RoguelikeChoiceData {
    id: string;
    title: string;
    description: string;
    type: string;
    nextSceneId: string;
    icon: string;
    param: { [key: string]: JsonValue };
}

export interface RoguelikeChoiceSceneData {
    id: string;
    title: string;
    description: string;
    background: string;
}

export interface RoguelikeModeData {
    id: string;
    name: string;
    canUnlockItem: number;
    scoreFactor: number;
    itemPools: string[];
    difficultyDesc: string;
    ruleDesc: string;
    sortId: number;
    unlockMode: string;
    color: string;
}

export interface RoguelikeEndingData {
    id: string;
    backgroundId: string;
    name: string;
    description: string;
    priority: number;
    unlockItemId: string;
    changeEndingDesc: string;
}

export interface RoguelikeOutBuffData {
    id: string;
    buffs: { [key: number]: RoguelikeOuterBuff };
}

export interface RoguelikeOuterBuff {
    key: string;
    blackboard: Blackboard;
    buffId: string;
    level: number;
    name: string;
    iconId: string;
    description: string;
    usage: string;
}

export interface RoguelikeSanCheckModuleData {
    sanRanges: RoguelikeSanRangeData[];
    moduleConsts: RoguelikeSanCheckConsts;
}

export interface RoguelikeSanCheckConsts {
    sanDecreaseToast: string;
}

export interface RoguelikeSanRangeData {
    sanMax: number;
    diceGroupId: string;
    description: string;
    sanDungeonEffect: SanEffectRank;
    sanEffectRank: SanEffectRank;
    sanEndingDesc: string;
}

export interface RoguelikeDiceModuleData {
    dice: { [key: string]: RoguelikeDiceData };
    diceEvents: { [key: string]: RoguelikeDiceRuleData };
    diceChoices: { [key: string]: string };
    diceRuleGroups: { [key: string]: RoguelikeDiceRuleGroupData };
    dicePredefines: RoguelikeDicePredefineData[];
}

export interface RoguelikeDiceData {
    diceId: string;
    description: string;
    isUpgradeDice: number;
    upgradeDiceId: string;
    diceFaceCount: number;
    battleDiceId: string;
}

export interface RoguelikeDiceRuleGroupData {
    ruleGroupId: string;
    minGoodNum: number;
}

export interface RoguelikeDiceRuleData {
    dicePointMax: number;
    diceResultClass: DiceResultClass;
    diceGroupId: string;
    diceEventId: string;
    resultDesc: string;
    showType: DiceResultShowType;
    canReroll: boolean;
    diceEndingScene: string;
    diceEndingDesc: string;
    sound: string;
}

export interface RoguelikeDicePredefineData {
    modeId: RoguelikeTopicMode;
    modeGrade: number;
    predefinedId: string;
    initialDiceCount: number;
}

export interface RoguelikeChaosModuleData {
    chaosDatas: { [key: string]: RoguelikeChaosData };
    chaosRanges: RoguelikeChaosRangeData[];
    levelInfoDict: { [key: string]: { [key: number]: RoguelikeChaosPredefineLevelInfo } };
    moduleConsts: RoguelikeChaosModuleConsts;
}

export interface RoguelikeChaosData {
    chaosId: string;
    level: number;
    nextChaosId: string;
    prevChaosId: string;
    iconId: string;
    name: string;
    functionDesc: string;
    desc: string;
    sound: string;
    sortId: number;
}

export interface RoguelikeChaosModuleConsts {
    maxChaosLevel: number;
    maxChaosSlot: number;
    chaosNotMaxDescription: string;
    chaosMaxDescription: string;
    chaosPredictDescription: string;
}

export interface RoguelikeChaosPredefineLevelInfo {
    chaosLevelBeginNum: number;
    chaosLevelEndNum: number;
}

export interface RoguelikeChaosRangeData {
    chaosMax: number;
    chaosDungeonEffect: ChaosEffectRank;
}

export interface RoguelikeTotemModuleConsts {
    totemPredictDescription: string;
    colorCombineDesc: { [key: string]: string };
    bossCombineDesc: string;
    battleNoPredictDescription: string;
    shopNoGoodsDescription: string;
}

export interface RoguelikeTotemBuffModuleData {
    totemBuffDatas: { [key: string]: RoguelikeTotemBuffData };
    subBuffs: { [key: string]: RoguelikeTotemSubBuffData };
    moduleConsts: RoguelikeTotemModuleConsts;
}

export interface RoguelikeTotemBuffData {
    totemId: string;
    color: RoguelikeTotemColorType;
    pos: RoguelikeTotemPosType;
    rhythm: string;
    normalDesc: string;
    synergyDesc: string;
    archiveDesc: string;
    combineGroupName: string;
    bgIconId: string;
    isManual: boolean;
    linkedNodeTypeData: RoguelikeTotemLinkedNodeTypeData;
    distanceMin: number;
    distanceMax: number;
    vertPassable: boolean;
    expandLength: number;
    onlyForVert: boolean;
    portalLinkedNodeTypeData: RoguelikeTotemLinkedNodeTypeData;
}

export interface RoguelikeTotemLinkedNodeTypeData {
    effectiveNodeTypes: RoguelikeEventType[];
    blurNodeTypes: RoguelikeTotemBlurNodeType[];
}

export interface RoguelikeTotemSubBuffData {
    subBuffId: string;
    name: string;
    desc: string;
    combinedDesc: string;
    info: string;
}

export interface RoguelikeVisionModuleData {
    visionDatas: { [key: number]: RoguelikeVisionData };
    visionChoices: { [key: string]: RoguelikeVisionModuleData_VisionChoiceConfig };
    moduleConsts: RoguelikeVisionModuleConsts;
}

export interface RoguelikeVisionModuleData_VisionChoiceConfig {
    value: number;
    type: RoguelikeVisionModuleData_VisionChoiceCheckType;
}

export interface RoguelikeVisionData {
    sightNum: number;
    level: number;
    canForesee: boolean;
    dividedDis: number;
    status: string;
    clr: string;
    desc1: string;
    desc2: string;
    icon: string;
}

export interface RoguelikeVisionModuleConsts {
    maxVision: number;
    totemBottomDescription: string;
    chestBottomDescription: string;
    goodsBottomDescription: string;
}

export interface RoguelikeFragmentModuleData {
    fragmentData: { [key: string]: RoguelikeFragmentData };
    fragmentTypeData: { [key: string]: RoguelikeFragmentTypeData };
    moduleConsts: RoguelikeFragmentModuleConsts;
    fragmentBuffData: { [key: string]: RoguelikeFragmentBuffData };
    alchemyData: { [key: string]: RoguelikeAlchemyData };
    alchemyFormulaData: { [key: string]: RoguelikeAlchemyFormulationData };
    fragmentLevelData: { [key: number]: RoguelikeFragmentLevelRelatedData };
}

export interface RoguelikeFragmentLevelRelatedData {
    weightUp: number;
}

export interface RoguelikeFragmentData {
    id: string;
    type: RoguelikeFragmentType;
    value: number;
    weight: number;
}

export interface RoguelikeFragmentTypeData {
    type: RoguelikeFragmentType;
    typeName: string;
    typeDesc: string;
    typeIconId: string;
}

export interface RoguelikeFragmentModuleConsts {
    weightStatusSafeDesc: string;
    weightStatusLimitDesc: string;
    weightStatusOverweightDesc: string;
    charWeightSlot: number;
    limitWeightThresholdValue: number;
    overWeightThresholdValue: number;
    maxAlchemyField: number;
    maxAlchemyCount: number;
    fragmentBagWeightLimitTips: string;
    fragmentBagWeightOverWeightTips: string;
    weightUpgradeToastFormat: string;
}

export interface RoguelikeFragmentBuffData {
    itemId: string;
    maskType: RoguelikeEventType;
    desc: string;
}

export interface RoguelikeAlchemyData {
    fragmentTypeList: RoguelikeFragmentType[];
    fragmentSquareSum: number;
    poolRarity: AlchemyPoolRarityType;
    relicProp: number;
    shieldProp: number;
    populationProp: number;
    overrideConditionBandIds: string[];
    overrideRecipeId: string;
}

export interface RoguelikeAlchemyFormulationData {
    fragmentIds: string[];
    rewardId: string;
    rewardCount: number;
    rewardItemType: RoguelikeGameItemType;
}

export interface RoguelikeDisasterModuleData {
    disasterData: { [key: string]: RoguelikeDisasterData };
}

export interface RoguelikeDisasterData {
    id: string;
    iconId: string;
    toastIconId: string;
    level: number;
    name: string;
    levelName: string;
    type: string;
    functionDesc: string;
    desc: string;
    sound: string;
}

export interface RoguelikeNodeUpgradeModuleData {
    nodeUpgradeDataMap: { [key: string]: RoguelikeNodeUpgradeData };
}

export interface RoguelikeNodeUpgradeData {
    nodeType: RoguelikeEventType;
    sortId: number;
    permItemList: RoguelikePermNodeUpgradeItemData[];
    tempItemList: RoguelikeTempNodeUpgradeItemData[];
}

export interface RoguelikePermNodeUpgradeItemData {
    upgradeId: string;
    nodeType: RoguelikeEventType;
    nodeLevel: number;
    costItemId: string;
    costItemCount: number;
    desc: string;
    nodeName: string;
}

export interface RoguelikeTempNodeUpgradeItemData {
    upgradeId: string;
    nodeType: RoguelikeEventType;
    sortId: number;
    costItemId: string;
    costItemCount: number;
    desc: string;
}

export interface RoguelikeCopperModuleData {
    copperData: { [key: string]: RoguelikeCopperData };
    copperDivineData: { [key: string]: RoguelikeCopperDivineData };
    copperGildTypeData: { [key: string]: RoguelikeCopperGildTypeData };
    changeCopperMap: { [key: string]: string };
    moduleConsts: RoguelikeCopperModuleConsts;
}

export interface RoguelikeCopperData {
    id: string;
    groupId: string;
    gildTypeId: string;
    luckyLevel: RoguelikeCopperLuckyLevel;
    buffType: RoguelikeCopperBuffType;
    layerCntDesc: string;
    poemList: string[];
    alwaysShowCountDown: boolean;
    buffItemIdList: string[];
    isAllLuckyLevel: boolean;
}

export interface RoguelikeCopperDivineData {
    eventId: string;
    groupId: string;
    showDesc: string;
    divineType: RoguelikeCopperDivineType;
    resultType: RoguelikeCopperDivineResultType;
}

export interface RoguelikeCopperGildTypeData {
    gildTypeId: string;
    gildName: string;
    gildDesc: string;
}

export interface RoguelikeCopperModuleConsts {
    copperDrawMaxNum: number;
    copperDrawMinNum: number;
    copperAllLuckyLevelGildId: string;
    copperDrawFreezeCostItemId: string;
    copperDrawFreezeCostCount: number[];
}

export interface RoguelikeWrathModuleData {
    wrathData: { [key: string]: RoguelikeWrathData };
    moduleConsts: RoguelikeWrathModuleConsts;
}

export interface RoguelikeWrathData {
    id: string;
    group: string;
    level: number;
    name: string;
    levelName: string;
    functionDesc: string;
    desc: string;
    isPacified: boolean;
}

export interface RoguelikeWrathModuleConsts {
    getWrathTransition: string;
    getWrathToast: string;
    hiddenWrathType: string;
    pacifiedWrathLevel: number;
}

export interface RoguelikeCandleModuleData {
    candleTicketIdList: string[];
    moduleConsts: RoguelikeCandleModuleConsts;
    candleBattleStageIdList: string[];
}

export interface RoguelikeCandleModuleConsts {
    candleHolderBuffId: string;
}

export interface RoguelikeSkyModuleData {
    nodeData: { [key: string]: RoguelikeSkyNodeData };
    subTypeData: RoguelikeSkyNodeSubTypeData[];
    moduleConsts: RoguelikeSkyModuleConsts;
}

export interface RoguelikeSkyNodeData {
    evtType: RoguelikeSkyZoneNodeType;
    name: string;
    iconId: string;
    effId: string;
    desc: string;
    nameBkgClr: string;
    selectClr: string;
    isRepeatedly: boolean;
}

export interface RoguelikeSkyNodeSubTypeData {
    evtType: RoguelikeSkyZoneNodeType;
    subTypeId: number;
    desc: string;
}

export interface RoguelikeSkyModuleConsts {
    skyApItemId: string;
    skyMaxColumns: number;
    skySacrificeChoiceDynamicKey: string;
}

export interface RoguelikeGridZoneModuleData {
    zoneMissionBannerData: { [key: string]: RoguelikeGridZoneMissionBannerData };
    scrapSideBarStepZeroHintBannerData: { [key: string]: RoguelikeGridZoneFocusViewHintData };
    buoyItemDatas: { [key: string]: RoguelikeBuoyItemData };
    moduleConsts: RoguelikeGridZoneModuleConsts;
}

export interface RoguelikeGridZoneMissionBannerData {
    zoneId: string;
    bannerText: string;
    bannerIcon: string;
}

export interface RoguelikeGridZoneFocusViewHintData {
    zoneId: string;
    hintText: string;
}

export interface RoguelikeBuoyItemData {
    itemId: string;
    isVisible: boolean;
}

export interface RoguelikeGridZoneModuleConsts {
    savageBubble: string;
    secretZoneDisableBuff: string;
    maxBannerDifficulty: number;
    focusViewBossHintStageId: { [key: string]: boolean };
}

export interface RoguelikeWeatherModuleData {
    mainWeatherData: { [key: string]: RoguelikeMainWeatherData };
    subWeatherData: { [key: string]: RoguelikeSubWeatherData };
}

export interface RoguelikeMainWeatherData {
    id: string;
    iconId: string;
    iconBigId: string;
    isPositive: boolean;
    level: number;
    name: string;
    levelName: string;
    type: string;
    functionDesc: string;
    desc: string;
    sound: string;
}

export interface RoguelikeSubWeatherData {
    id: string;
    iconId: string;
    isPositive: boolean;
    name: string;
    type: string;
    functionDesc: string;
    desc: string;
    sound: string;
}

export interface RoguelikeScrapModuleData {
    scrapItemToType: { [key: string]: RoguelikeScrapType };
    scrapTypeData: { [key: string]: RoguelikeScrapTypeData };
    moveScrapData: { [key: string]: RoguelikeScrapMoveData };
    goodsScrapData: { [key: string]: RoguelikeScrapGoodsData };
    passiveScrapData: { [key: string]: RoguelikeScrapPassiveData };
    moveScrapRangeData: { [key: string]: RangeData };
    moduleConsts: RoguelikeScrapModuleConsts;
}

export interface RoguelikeScrapMoveData {
    scrapId: string;
    scrapDesc: string;
    sellPrice: number;
    count: number;
    range: string;
    rangeType: RoguelikeMoveScrapRangeType;
    node: string[];
    step: number;
    isRandomMove: boolean;
}

export interface RoguelikeScrapGoodsData {
    scrapId: string;
    scrapDesc: string;
    sellPrice: number;
}

export interface RoguelikeScrapPassiveData {
    scrapId: string;
    scrapDesc: string;
    sellPrice: number;
    node: RoguelikeEventType;
    buffStack: number;
}

export interface RoguelikeScrapTypeData {
    type: RoguelikeScrapType;
    typeName: string;
    typeDesc: string;
    typeIconId: string;
}

export interface RoguelikeScrapModuleConsts {
    identifyScrapId: string;
}

export interface RoguelikeTopicTable {
    topics: { [key: string]: RoguelikeTopicBasicData };
    constant: RoguelikeTopicConst;
    details: { [key: string]: RoguelikeTopicDetail };
    modules: { [key: string]: RoguelikeModule };
    customizeData: RoguelikeTopicCustomizeData;
}

export interface RoguelikeTopicBasicData {
    id: string;
    name: string;
    startTime: number;
    disappearTimeOnMainScreen: number;
    sort: number;
    showMedalId: string;
    medalGroupId: string;
    fullStoredTime: number;
    lineText: string;
    homeEntryDisplayData: RoguelikeTopicBasicData_HomeEntryDisplayData[];
    moduleTypes: RoguelikeModuleType[];
    config: RoguelikeTopicConfig;
}

export interface RoguelikeTopicBasicData_HomeEntryDisplayData {
    topicId: string;
    displayId: string;
    startTs: number;
    endTs: number;
}

export interface RoguelikeTopicConfig {
    loadCharCardPlugin: boolean;
    webBusType: string;
    monthChatTrigType: RoguelikeMonthChatTrigType;
    loadRewardHpDecoPlugin: boolean;
    loadRewardExtraInfoPlugin: boolean;
}

export interface RoguelikeTopicConst {
    milestoneTokenRatio: number;
    outerBuffTokenRatio: number;
    relicTokenRatio: number;
    rogueSystemUnlockStage: string;
    ordiModeReOpenCoolDown: number;
    monthModeReOpenCoolDown: number;
    monthlyTaskUncompletedTime: number;
    monthlyTaskManualRefreshLimit: number;
    monthlyTeamUncompletedTime: number;
    bpPurchaseSystemUnlockTime: number;
    predefinedChars: { [key: string]: RoguelikeTopicConst_PredefinedChar };
}

export interface RoguelikeTopicConst_PredefinedChar {
    charId: string;
    canBeFree: boolean;
    uniEquipId: string;
    recruitType: RoguelikeCharState;
}

export interface RoguelikeTopicDetail {
    updates: RoguelikeTopicUpdate[];
    enrolls: { [key: string]: RoguelikeTopicEnroll };
    milestones: RoguelikeTopicBP[];
    milestoneUpdates: RoguelikeTopicMilestoneUpdateData[];
    grandPrizes: RoguelikeTopicBPGrandPrize[];
    monthMission: RoguelikeTopicMonthMission[];
    monthSquad: { [key: string]: RoguelikeTopicMonthSquad };
    challenges: { [key: string]: RoguelikeTopicChallenge };
    difficulties: RoguelikeTopicDifficulty[];
    bankRewards: RoguelikeTopicBankReward[];
    archiveComp: RoguelikeArchiveComponentData;
    archiveUnlockCond: RoguelikeArchiveUnlockCondData;
    detailConst: RoguelikeTopicDetailConst;
    init: RoguelikeGameInitData[];
    stages: { [key: string]: RoguelikeGameStageData };
    zones: { [key: string]: RoguelikeGameZoneData };
    variation: { [key: string]: RoguelikeZoneVariationData };
    traps: { [key: string]: RoguelikeGameTrapData };
    recruitTickets: { [key: string]: RoguelikeGameRecruitTicketData };
    upgradeTickets: { [key: string]: RoguelikeGameUpgradeTicketData };
    customTickets: { [key: string]: RoguelikeGameCustomTicketData };
    stashableTickets: { [key: string]: RoguelikeGameStashableTicketData };
    relics: { [key: string]: RoguelikeGameRelicData };
    relicParams: { [key: string]: RoguelikeGameRelicParamData };
    recruitGrps: { [key: string]: RoguelikeGameRecruitGrpData };
    choices: { [key: string]: RoguelikeGameChoiceData };
    choiceScenes: { [key: string]: RoguelikeGameChoiceSceneData };
    nodeTypeData: { [key: string]: RoguelikeGameNodeTypeData };
    subTypeData: RoguelikeGameNodeSubTypeData[];
    variationData: { [key: string]: RoguelikeGameVariationData };
    fusionData: { [key: string]: RoguelikeGameFusionData };
    charBuffData: { [key: string]: RoguelikeGameCharBuffData };
    squadBuffData: { [key: string]: RoguelikeGameSquadBuffData };
    taskData: { [key: string]: RoguelikeTaskData };
    gameConst: RoguelikeGameConst;
    shopDialogData: RoguelikeGameShopDialogData;
    capsuleDict: { [key: string]: RoguelikeTopicCapsule };
    endings: { [key: string]: RoguelikeGameEndingData };
    failEndings: { [key: string]: RoguelikeGameFailEndingData };
    battleSummeryDescriptions: { [key: string]: RoguelikeBattleSummeryDescriptionData };
    battleLoadingTips: TipData[];
    items: { [key: string]: RoguelikeGameItemData };
    bandRef: { [key: string]: RoguelikeBandRefData };
    endingDetailList: RoguelikeEndingDetailText[];
    endingRelicDetailList: RoguelikeEndingRelicDetailText[];
    treasures: { [key: string]: RoguelikeGameTreasureData[] };
    difficultyUpgradeRelicGroups: { [key: string]: RoguelikeDifficultyUpgradeRelicGroupData };
    styles: { [key: string]: RoguelikePredefinedStyleData };
    styleConfig: RoguelikePredefinedConstStyleData;
    exploreTools: { [key: string]: RoguelikeGameExploreToolData };
    rollNodeData: { [key: string]: RoguelikeRollNodeData };
    relicTipsData: { [key: string]: RoguelikeRelicTipsData };
    legacyItems: { [key: string]: RoguelikeLegacyItemData };
    activity: RoguelikeActivityData;
}

export type RoguelikeTopicCustomizeData = { [key: string]: JsonValue };

export interface RL01CustomizeData {
    developments: { [key: string]: RoguelikeTopicDev };
    developmentTokens: { [key: string]: RoguelikeTopicDevToken };
    endingText: RL01EndingText;
    difficulties: RL01DifficultyExt[];
}

export interface RL02CustomizeData {
    developments: { [key: string]: RL02Development };
    developmentTokens: { [key: string]: RoguelikeTopicDevToken };
    developmentRawTextGroup: RL02DevRawTextBuffGroup[];
    developmentLines: RL02DevelopmentLine[];
    endingText: RL02EndingText;
    difficulties: RL02DifficultyExt[];
}

export interface RL03CustomizeData {
    developments: { [key: string]: RL03Development };
    developmentsTokens: { [key: string]: RoguelikeTopicDevToken };
    developmentRawTextGroup: RL03DevRawTextBuffGroup[];
    developmentsDifficultyNodeInfos: { [key: string]: RL03DevDifficultyNodeInfo };
    endingText: RL03EndingText;
    difficulties: RL03DifficultyExt[];
}

export interface RoguelikeCommonDevelopmentData {
    developments: { [key: string]: RoguelikeCommonDevelopment };
    developmentsTokens: { [key: string]: RoguelikeTopicDevToken };
    developmentRawTextGroup: RoguelikeCommonDevRawTextBuffGroup[];
    developmentsDifficultyNodeInfos: { [key: string]: RoguelikeCommonDevDifficultyNodeInfo };
}

export interface RL04CustomizeData {
    commonDevelopment: RoguelikeCommonDevelopmentData;
    difficulties: RL04DifficultyExt[];
    endingText: RL04EndingText;
}

export interface RL05CustomizeData {
    commonDevelopment: RoguelikeCommonDevelopmentData;
    difficulties: RL05DifficultyExt[];
    specialShopDialog: RoguelikeGameShopDialogData;
    endingText: RL05EndingText;
}

export interface RL06CustomizeData {
    commonDevelopment: RoguelikeCommonDevelopmentData;
    difficulties: RL06DifficultyExt[];
    endingText: RL06EndingText;
    scrapShopDialogData: RoguelikeGameShopDialogData;
    employShopDialogData: RoguelikeGameShopDialogData;
}

export interface RoguelikeModule {
    moduleTypes: RoguelikeModuleType[];
    sanCheck: RoguelikeSanCheckModuleData;
    dice: RoguelikeDiceModuleData;
    chaos: RoguelikeChaosModuleData;
    totemBuff: RoguelikeTotemBuffModuleData;
    vision: RoguelikeVisionModuleData;
    fragment: RoguelikeFragmentModuleData;
    disaster: RoguelikeDisasterModuleData;
    nodeUpgrade: RoguelikeNodeUpgradeModuleData;
    copper: RoguelikeCopperModuleData;
    wrath: RoguelikeWrathModuleData;
    candle: RoguelikeCandleModuleData;
    sky: RoguelikeSkyModuleData;
    weather: RoguelikeWeatherModuleData;
    gridZone: RoguelikeGridZoneModuleData;
    scrap: RoguelikeScrapModuleData;
}

export interface RoguelikeTopicDetailConst {
    playerLevelTable: { [key: number]: RoguelikeTopicDetailConst_PlayerLevelData };
    charUpgradeTable: { [key: number]: RoguelikeTopicDetailConst_CharUpgradeData };
    difficultyUpgradeRelicDescTable: { [key: number]: string };
    predefinedLevelTable: { [key: string]: RoguelikeTopicDetailConst_PredefinedPlayerLevelData };
    tokenBpId: string;
    tokenOuterBuffId: string;
    spOperatorLockedMessage: string;
    previewedRewardsAccordingUpdateId: string;
    tipButtonName: string;
    collectButtonName: string;
    bpSystemName: string;
    autoSetKV: string;
    bpPurchaseActiveEnroll: string;
    defaultExpeditionSelectDesc: string;
    gotCharMutationBuffToast: string;
    gotCharEvolutionBuffToast: string;
    gotSquadBuffToast: string;
    loseCharBuffToast: string;
    monthTeamSystemName: string;
    battlePassUpdateName: string;
    monthCharCardTagName: string;
    monthTeamDescTagName: string;
    outerBuffCompleteText: string;
    outerProgressTextColor: string;
    challengeTaskTargetName: string;
    challengeTaskConditionName: string;
    challengeTaskRewardName: string;
    challengeTaskModeName: string;
    challengeTaskName: string;
    outerBuffTokenSum: number;
    needAllFrontNode: boolean;
    showBlurBack: boolean;
    endingIconBorderDifficulty: number;
    endingIconBorderCount: number;
    copySeedModeInfo: string;
    copySucceededTextHint: string;
    historicalRecordsCount: number;
    historicalRecordsStartTime: number;
    historicalRecordsMode: RoguelikeTopicMode;
}

export interface RoguelikeTopicDetailConst_PlayerLevelData {
    exp: number;
    populationUp: number;
    squadCapacityUp: number;
    battleCharLimitUp: number;
    maxHpUp: number;
}

export interface RoguelikeTopicDetailConst_CharUpgradeData {
    evolvePhase: EvolvePhase;
    skillLevel: number;
    skillSpecializeLevel: number;
}

export interface RoguelikeTopicDetailConst_PredefinedPlayerLevelData {
    levels: { [key: number]: RoguelikeTopicDetailConst_PlayerLevelData };
}

export interface RoguelikeTopicUpdate {
    updateId: string;
    topicUpdateTime: number;
    topicEndTime: number;
}

export interface RoguelikeTopicEnroll {
    enrollId: string;
    enrollTime: number;
    enrollType: RoguelikeEnrollType;
    enrollNoticeEndTime: number;
}

export interface RoguelikeTopicMilestoneUpdateData {
    updateTime: number;
    endTime: number;
    maxBpLevel: number;
    maxBpCount: number;
    maxDisplayBpCount: number;
}

export interface RoguelikeTopicCapsule {
    itemID: string;
    maskType: RoguelikeEventType;
    innerColor: string;
}

export interface RoguelikeTopicBP {
    id: string;
    level: number;
    tokenNum: number;
    nextTokenNum: number;
    itemID: string;
    itemType: ItemType;
    itemCount: number;
    isGoodPrize: boolean;
    isGrandPrize: boolean;
    isReturnDisplay: boolean;
    returnSortId: number;
}

export interface RoguelikeTopicBPGrandPrize {
    grandPrizeDisplayId: string;
    sortId: number;
    displayUnlockYear: number;
    displayUnlockMonth: number;
    acquireTitle: string;
    purchaseTitle: string;
    displayName: string;
    displayDiscription: string;
    bpLevelId: string;
    itemBundle: ItemBundle;
    detailAnnounceTime: string;
    picIdAftrerUnlock: string;
}

export interface RoguelikeTopicMonthMission {
    id: string;
    taskName: string;
    taskClass: RoguelikeGameMonthTaskClass;
    innerClassWeight: number;
    template: string;
    paramList: string[];
    desc: string;
    tokenRewardNum: number;
}

export interface RoguelikeTopicDisplayItem {
    displayType: string;
    displayNum: number;
    displayForm: RoguelikeTopicDevTokenDisplayForm;
    tokenDesc: string;
    sortId: number;
}

export interface RoguelikeTopicDev {
    buffId: string;
    sortId: number;
    nodeType: RoguelikeTopicDevNodeType;
    nextNodeId: string[];
    frontNodeId: string[];
    tokenCost: number;
    buffName: string;
    buffIconId: string;
    buffTypeName: string;
    buffDisplayInfo: RoguelikeTopicDisplayItem[];
}

export interface RL02Development {
    buffId: string;
    nodeType: RL02DevelopmentNodeType;
    frontNodeId: string[];
    nextNodeId: string[];
    positionP: number;
    positionR: number;
    tokenCost: number;
    buffName: string;
    buffIconId: string;
    effectType: RL02DevelopmentEffectType;
    rawDesc: string;
    buffDisplayInfo: RoguelikeTopicDisplayItem[];
    enrollId: string;
}

export interface RL02DevRawTextBuffGroup {
    nodeIdList: string[];
    useLevelMark: boolean;
    groupIconId: string;
    useUpBreak: boolean;
    sortId: number;
}

export interface RL02DevelopmentLine {
    fromNode: string;
    toNode: string;
    fromNodeP: number;
    fromNodeR: number;
    toNodeP: number;
    toNodeR: number;
    enrollId: string;
}

export interface RoguelikeTopicDevToken {
    sortId: number;
    displayForm: RoguelikeTopicDevTokenDisplayForm;
    tokenDesc: string;
}

export interface RoguelikeTopicMonthSquadTeamChar {
    teamCharId: string;
    teamTmplId: string;
}

export interface RoguelikeTopicMonthSquad {
    id: string;
    teamName: string;
    teamSubName: string;
    teamFlavorDesc: string;
    teamDes: string;
    teamColor: string;
    teamMonth: string;
    teamYear: string;
    teamIndex: string;
    teamChars: RoguelikeTopicMonthSquadTeamChar[];
    zoneId: string;
    chatId: string;
    tokenRewardNum: number;
    items: ItemBundle[];
    startTime: number;
    endTime: number;
    taskDes: string;
}

export interface RoguelikeTopicChallengeTask {
    taskId: string;
    taskDes: string;
    completionClass: string;
    completionParams: string[];
}

export interface RoguelikeTopicChallenge {
    challengeId: string;
    sortId: number;
    challengeName: string;
    challengeGroup: number;
    challengeGroupSortId: number;
    challengeGroupName: string;
    challengeUnlockDesc: string;
    challengeUnlockToastDesc: string;
    challengeDes: string;
    challengeConditionDes: string[];
    challengeTasks: { [key: string]: RoguelikeTopicChallengeTask };
    defaultTaskId: string;
    rewards: ItemBundle[];
    challengeStoryId: string;
}

export interface RoguelikeTopicDifficulty {
    modeDifficulty: RoguelikeTopicMode;
    grade: number;
    name: string;
    nameImage: string;
    subName: string;
    enrollId: string;
    haveInitialRelicIcon: boolean;
    scoreFactor: number;
    canUnlockItem: boolean;
    doMonthTask: boolean;
    ruleDesc: string;
    ruleDescReplacements: RoguelikeTopicDifficulty_RuleDescReplacement[];
    failTitle: string;
    failImageId: string;
    failForceDesc: string;
    sortId: number;
    equivalentGrade: number;
    color: string;
    bpValue: number;
    bossValue: number;
    addDesc: string;
    warningType: RoguelikeTopicDifficultyWarningType;
    unlockText: string;
    displayIconId: string;
    hideEndingStory: boolean;
    haveLegacy: boolean;
}

export interface RoguelikeTopicDifficulty_RuleDescReplacement {
    enrollId: string;
    ruleDesc: string;
}

export interface RL01DifficultyExt {
    modeDifficulty: RoguelikeTopicMode;
    grade: number;
    buffDesc: string[];
}

export interface RL02DifficultyExt {
    modeDifficulty: RoguelikeTopicMode;
    grade: number;
    buffDesc: string[];
}

export interface RL03DifficultyExt {
    modeDifficulty: RoguelikeTopicMode;
    grade: number;
    totemProb: number;
    relicDevLevel: string;
    buffs: string[];
    buffDesc: string[];
}

export interface RL04DifficultyExt {
    modeDifficulty: RoguelikeTopicMode;
    grade: number;
    leftDisasterDesc: string;
    leftOverweightDesc: string;
    relicDevLevel: string;
    weightStatusLimitDesc: string;
    buffs: string[];
    buffDesc: string[];
}

export interface RL05DifficultyExt {
    modeDifficulty: RoguelikeTopicMode;
    grade: number;
    buffs: string[];
    buffDesc: string[];
    leftWrathDesc: string;
    relicDevLevel: string;
    gildProbDisplay: string;
    skyStepDescription: string;
}

export interface RL06DifficultyExt {
    modeDifficulty: RoguelikeTopicMode;
    grade: number;
    buffs: string[];
    buffDesc: string[];
    leftWeatherDesc: string;
    relicDevLevel: string;
}

export interface RoguelikeTopicBankReward {
    rewardId: string;
    unlockGoldCnt: number;
    rewardType: RoguelikeTopicBankRewardType;
    desc: string;
}

export interface RoguelikeArchiveComponentData {
    relic: ActArchiveRelicData;
    capsule: ActArchiveCapsuleData;
    trap: ActArchiveTrapData;
    chat: ActArchiveChatData;
    endbook: ActArchiveEndbookData;
    buff: ActArchiveBuffData;
    totem: ActArchiveTotemData;
    chaos: ActArchiveChaosData;
    fragment: ActArchiveFragmentData;
    disaster: ActArchiveDisasterData;
    wrath: ActArchiveWrathData;
    copper: ActArchiveCopperData;
    scrap: ActArchiveScrapData;
    weather: ActArchiveWeatherData;
}

export interface RoguelikeArchiveUnlockCondData {
    unlockCondDesc: { [key: string]: RoguelikeArchiveUnlockCondDesc };
    enroll: { [key: string]: RoguelikeArchiveEnroll };
}

export interface RoguelikeArchiveUnlockCondDesc {
    archiveType: ActArchiveType;
    description: string;
}

export interface RoguelikeArchiveEnroll {
    archiveType: ActArchiveType;
    enrollId: string;
}

export interface RoguelikeGameConst {
    initSceneName: string;
    failSceneName: string;
    hpItemId: string;
    goldItemId: string;
    populationItemId: string;
    squadCapacityItemId: string;
    expItemId: string;
    initialBandShowGradeFlag: boolean;
    bankMaxGold: number;
    bankCostId: string;
    bankDrawCount: number;
    bankDrawLimit: number;
    bankRewardCountType: RoguelikeBankRewardCountType;
    spZoneShopBgmSignal: string;
    mimicEnemyIds: string[];
    bossIds: string[];
    goldChestTrapId: string;
    normBoxTrapId: string;
    rareBoxTrapId: string;
    badBoxTrapId: string;
    toolBoxTrapId: string;
    maxHpItemId: string;
    shieldItemId: string;
    keyItemId: string;
    divinationKitItemId: string;
    chestKeyCnt: number;
    chestKeyItemId: string;
    keyColorId: string;
    onceNodeTypeList: RoguelikeEventType[];
    vertNodeCostDialogUseItemIconType: boolean;
    gpScoreRatio: number;
    overflowUsageSquadBuff: string;
    specialTrapId: string;
    trapRewardRelicId: string;
    unlockRouteItemId: string;
    unlockRouteItemCount: number;
    hideBattleNodeName: string;
    hideBattleNodeDescription: string;
    hideNonBattleNodeName: string;
    hideNonBattleNodeDescription: string;
    charSelectExpeditionConflictToast: string;
    charSelectNoUpgradeConflictToast: string;
    itemDropTagDict: { [key: string]: string };
    shopRefreshCostId: string;
    expeditionLeaveToastFormat: string;
    expeditionReturnDescCureUpgrade: string;
    expeditionReturnDescUpgrade: string;
    expeditionReturnDescCure: string;
    expeditionReturnDesc: string;
    expeditionSelectDescFormat: string;
    expeditionReturnDescItem: string;
    expedEndingRelic: string;
    expedEndingRelicDesc: string;
    expeditionReturnRewardBlackList: string[];
    travelLeaveToastFormat: string;
    charSelectTravelConflictToast: string;
    travelReturnDescUpgrade: string;
    travelReturnDesc: string;
    travelReturnDescItem: string;
    traderReturnTitle: string;
    traderReturnDesc: string;
    candleReturnDescCandleUpgrade: string;
    candleReturnDescCandle: string;
    charSelectCandleConflictToast: string;
    charSelectGuidedConflictToast: string;
    charSelectNonGuidedConflictToast: string;
    gainBuffDiffGrade: number;
    dsPredictTips: string;
    dsBuffActiveTips: string;
    totemDesc: string;
    copperGildDesc: string;
    relicDesc: string;
    buffDesc: string;
    refreshNodeItemId: string;
    storingRecruitDesc: string;
    storingRecruitSucceedToast: string;
    specialRecruitReductionDesc: string;
    specialRecruitFuncDesc: string;
    specialRecruitDetailDesc: string;
    portalZones: string[];
    treasureBuffs: string[];
    diffDisplayZoneId: string;
    exploreExpOnKill: string;
    fusionName: string;
    fusionNotifyToast: string;
    haveCustomZone: boolean;
    gotCharCandleBuffToast: string;
    gotCharsCandleBuffToast: string;
    stashedRecruitNodeDescription: string;
    stashedRecruitEmptyNodeDescription: string;
    recruitStashMaxNum: number;
    recruitStashMinNum: number;
    hasTopicCharSelectMenuButton: boolean;
}

export interface RoguelikeGameShopDialogData {
    types: { [key: string]: RoguelikeGameShopDialogTypeData };
}

export interface RoguelikeGameShopDialogTypeData {
    groups: { [key: string]: RoguelikeGameShopDialogGroupData };
}

export interface RoguelikeGameShopDialogGroupData {
    content: string[];
}

export interface RoguelikeGameStageData {
    id: string;
    linkedStageId: string;
    levelId: string;
    levelReplaceIds: string[];
    code: string;
    name: string;
    loadingPicId: string;
    description: string;
    eliteDesc: string;
    isBoss: number;
    isElite: number;
    difficulty: LevelData_Difficulty;
    capsulePool: string;
    capsuleProb: number;
    vutresProb: number[];
    boxProb: number[];
    specialNodeId: string;
    redCapsulePool: string;
    redCapsuleProb: number;
}

export interface RoguelikeGameZoneData {
    id: string;
    name: string;
    clockPerformance: string;
    displayTime: string;
    description: string;
    buffDescription: string;
    endingDescription: string;
    backgroundId: string;
    zoneIconId: string;
    isHiddenZone: boolean;
    bgmSignal: string;
    bgmSignalWithLowSan: string;
    transitionEffectId: string;
}

export interface RoguelikeZoneVariationData {}

export interface RoguelikeGameRecruitGrpData {
    id: string;
    iconId: string;
    name: string;
    desc: string;
    unlockDesc: string;
}

export interface RoguelikeChoiceDisplayData {
    type: RoguelikeChoiceDisplayType;
    costHintType: RoguelikeChoiceHintType;
    effectHintType: RoguelikeChoiceHintType;
    funcIconId: string;
    itemID: string;
    difficultyUpgradeRelicGroupId: string;
    taskId: string;
    instId: string;
}

export interface RoguelikeGameChoiceData {
    id: string;
    title: string;
    description: string;
    lockedCoverDesc: string;
    type: RoguelikeGameChoiceType;
    leftDecoType: RoguelikeChoiceLeftDecoType;
    nextSceneId: string;
    icon: string;
    displayData: RoguelikeChoiceDisplayData;
    forceShowWhenOnlyLeave: boolean;
    isHiddenChoice: boolean;
    sortId: number;
}

export interface RoguelikeGameChoiceSceneData {
    id: string;
    title: string;
    description: string;
    background: string;
    titleIcon: string;
    subTypeId: number;
    useHiddenMusic: boolean;
}

export interface RoguelikeGameNodeTypeData {
    name: string;
    subName: string;
    description: string;
}

export interface RoguelikeGameNodeSubTypeData {
    eventType: RoguelikeEventType;
    subTypeId: number;
    iconId: string;
    name: string;
    description: string;
}

export interface RoguelikeGameInitData {
    modeId: RoguelikeTopicMode;
    modeGrade: number;
    predefinedId: string;
    predefinedStyle: string;
    initialBandRelic: string[];
    initialRecruitGroup: string[];
    initialHp: number;
    initialPopulation: number;
    initialGold: number;
    initialSquadCapacity: number;
    initialShield: number;
    initialMaxHp: number;
    initialKey: number;
}

export interface RoguelikePredefinedStyleData {
    styleId: string;
    styleConfig: number;
}

export interface RoguelikePredefinedConstStyleData {
    expStyleConfig: RoguelikePredefinedExpStyleConfigData;
}

export interface RoguelikePredefinedExpStyleConfigData {
    paramDict: { [key: string]: string };
}

export interface RoguelikeGameVariationData {
    id: string;
    type: RoguelikeGameVariationType;
    outerName: string;
    innerName: string;
    functionDesc: string;
    desc: string;
    iconId: string;
    sound: string;
}

export interface RoguelikeGameFusionData {
    id: string;
    type: RoguelikeGameVariationType;
    name: string;
    functionDesc: string;
    desc: string;
}

export interface RoguelikeGameCharBuffData {
    id: string;
    buffType: RoguelikeGameCharBuffType;
    iconId: string;
    relatedItemId: string;
    outerName: string;
    innerName: string;
    functionDesc: string;
    desc: string;
    buffs: RoguelikeBuff[];
}

export interface RoguelikeGameSquadBuffData {
    id: string;
    iconId: string;
    outerName: string;
    innerName: string;
    functionDesc: string;
    desc: string;
    buffs: RoguelikeBuff[];
}

export interface RoguelikeTaskData {
    taskId: string;
    taskName: string;
    taskDesc: string;
    rewardSceneId: string;
    taskRarity: RoguelikeTaskRarity;
}

export interface RoguelikeGameTrapData {
    itemID: string;
    trapId: string;
    trapDesc: string;
}

export interface RoguelikeGameExploreToolData {
    itemId: string;
    trapId: string;
    trapDesc: string;
}

export interface RoguelikeGameItemData {
    id: string;
    name: string;
    description: string;
    usage: string;
    obtainApproach: string;
    iconId: string;
    itemIconGroupId: string;
    type: RoguelikeGameItemType;
    subType: RoguelikeGameItemSubType;
    rarity: RoguelikeGameItemRarity;
    sortId: number;
    canSacrifice: boolean;
    tinyIconColor: string;
    unlockCondDesc: string;
    shortUsage: string;
    value: number;
}

export interface RoguelikeBandRefData {
    itemID: string;
    bandLevel: number;
    normalBandId: string;
}

export interface RoguelikeGameRecruitTicketData {
    id: string;
    profession: number | string;
    rarity: number | string;
    professionList: ProfessionID[];
    rarityList: RarityRank[];
    extraEliteNum: number;
    extraFreeRarity: RarityRank[];
    extraCharIds: string[];
}

export interface RoguelikeGameUpgradeTicketData {
    id: string;
    profession: number | string;
    rarity: number | string;
    professionList: ProfessionID[];
    rarityList: RarityRank[];
}

export interface RoguelikeGameCustomTicketData {
    id: string;
    subType: CustomTicketType;
    discardText: string;
}

export interface RoguelikeGameStashableTicketData {
    ticketId: string;
    stashedTicketId: string;
}

export interface RoguelikeGameRelicParamData {
    id: string;
    checkCharBoxTypes: RoguelikeGameRelicCheckType[];
    checkCharBoxParams: RoguelikeGameRelicCheckParam[];
}

export interface RoguelikeBuff {
    key: string;
    blackboard: Blackboard;
}

export interface RoguelikeGameRelicData {
    id: string;
    buffs: RoguelikeBuff[];
}

export interface RoguelikeGameTreasureData {
    treasureId: string;
    groupId: string;
    subIndex: number;
    name: string;
    usage: string;
}

export interface RoguelikeGameEndingData {
    id: string;
    familyId: number;
    name: string;
    desc: string;
    bgId: string;
    icons: RoguelikeGameEndingData_LevelIcon[];
    priority: number;
    changeEndingDesc: string;
    bossIconId: string;
}

export interface RoguelikeGameEndingData_LevelIcon {
    level: number;
    iconId: string;
}

export interface RoguelikeGameFailEndingData {
    id: string;
    name: string;
    desc: string;
    iconId: string;
    priority: number;
}

export interface RoguelikeBattleSummeryDescriptionData {
    randomDescriptionList: string[];
}

export interface RoguelikeGameRelicCheckParam {
    valueProfessionMask: ProfessionCategory;
    valueStrs: string[];
    valueInt: number;
}

export interface RoguelikeDifficultyUpgradeRelicGroupData {
    relicData: RoguelikeDifficultyUpgradeRelicData[];
}

export interface RoguelikeDifficultyUpgradeRelicData {
    relicId: string;
    equivalentGrade: number;
}

export interface RoguelikeRollNodeGroupData {
    nodeType: RoguelikeEventType;
}

export interface RoguelikeRollNodeData {
    zoneId: string;
    groups: { [key: string]: RoguelikeRollNodeGroupData };
}

export interface RoguelikeRelicTipsData {
    itemId: string;
    toastText: string;
}

export interface RoguelikeLegacyItemData {
    legacyId: string;
    hideLegacyItem: boolean;
    legacyGroupId: string;
}

export interface RL01EndingText {
    summaryVariation: string;
    summaryFusion: string;
    summaryCapsule: string;
}

export interface RL02EndingText {
    summaryMutation: string;
    summaryDice: string;
    summaryDiceResultGood: string;
    summaryDiceResultNormal: string;
    summaryDiceResultBad: string;
    summaryDiceResultDesc: string;
    summaryCommuDesc: string;
    summaryHiddenDesc: string;
    summaryKnightDesc: string;
    summaryGoldDesc: string;
    summaryPracticeDesc: string;
    summaryCommuEmptyDesc: string;
    summaryCommuNotEmptyDesc: string;
    summaryHiddenPassedDesc: string;
    summaryHiddenNotPassedDesc: string;
    summaryKnightPassedDesc: string;
    summaryKnightNotPassedDesc: string;
    summaryGoldThreshold: number;
    summaryGoldHighDesc: string;
    summaryGoldLowDesc: string;
    summaryPracticeThreshold: number;
    summaryPracticeHighDesc: string;
    summaryPracticeLowDesc: string;
}

export interface RL03EndingText {
    summaryGetTotem: string;
    summaryDemoPointUp: string;
    summaryDemoPointDown: string;
    summaryDemoGradeUp: string;
    summaryDemoGradeDown: string;
    summaryVisionPointUp: string;
    summaryVisionPointDown: string;
    summaryVisionGradeUp: string;
    summaryVisionGradeDown: string;
    summaryFightWin: string;
    summaryFightFail: string;
    summaryExchangeTotem: string;
    summaryUseTotem: string;
    summaryVisionGrade: string;
}

export interface RL04EndingText {
    summaryGetFragment: string;
    summaryUseIdea: string;
    summaryUseFood: string;
    summaryDropFragment: string;
    summaryMeetDisaster: string;
    summaryLeaveDisaster: string;
    summaryEnterAlchemy: string;
    summaryAlchemyOthers: string;
    summaryAlchemyFragment: string;
    summaryWeightOverweight: string;
    summaryWeightLimit: string;
    summaryWeightSafe: string;
    summaryPermUpgrade: string;
    summaryTempUpgrade: string;
    summarySellFragment: string;
}

export interface RL05EndingText {
    summaryGetCopper: string;
    summaryLostCopper: string;
    summaryDrawCopper: string;
    summaryCopperResultGood: string;
    summaryCopperResultBad: string;
    summaryCopperResultNormal: string;
    summaryCopperCheckSuccess: string;
    summaryCopperCheckFail: string;
    summaryCopperCheckNormal: string;
    summaryMeetWrath: string;
    summaryExpeditionGoEndingFour: string;
    summaryExpeditionBackEndingFour: string;
    summaryExpeditionBackCandle: string;
    summaryExpeditionGoEnding: string;
    summaryExpeditionBackEnding: string;
    summaryHoldCandle: string;
    summaryHoldCandleRecruit: string;
    summaryHoldCandleUpgrade: string;
    summaryExpeditionEndingFourToFive: string;
    summaryExchangeSpZoneGet: string;
    summaryMeetShopSpZone: string;
    summaryBattleFailSpZone: string;
    summaryMeetEventLock: string;
    summaryTreasureSpZone: string;
    summaryMeetExchangeSpZone: string;
    summaryMeetTradeSpZone: string;
}

export interface RL06EndingText {
    summaryScrapGot: string;
    summaryScrapSold: string;
    summaryScrapLost: string;
    summaryScrapMove: string;
    summaryScrapBuff: string;
    summaryScrapLegacy: string;
    summaryMeetWeather: string;
    summaryWeatherClear: string;
    summaryBubbleBandit: string;
    summaryBubbleTreasure: string;
    summaryBubbleEvent: string;
    summarySavageCamp: string;
    summaryScrapShop: string;
    summaryScrapShopBuy: string;
    summaryScrapShopIdentify: string;
    summaryDoor: string;
    summaryTreeHole: string;
    summaryEvacuate: string;
    summaryEmployCamp: string;
    summaryEmployRecruit: string;
    summaryMercenaryLeave: string;
    summaryEncounterBattleWin: string;
    summaryEncounterBattleLose: string;
    summaryExchangeScrap: string;
    summaryExpeditionGoEnding: string;
    summaryExpeditionBackEnding: string;
}

export interface RoguelikeEndingDetailText {
    textId: string;
    text: string;
    eventType: RoguelikeEventType;
    spZoneEvtType: string;
    showType: RoguelikeEndingDetailText_Type;
    choiceSceneId: string;
    paramList: string[];
    otherPara1: string;
}

export interface RoguelikeEndingRelicDetailText {
    relicId: string;
    summaryEventText: string;
}

export interface RL03Development {
    buffId: string;
    nodeType: RL03DevelopmentNodeType;
    frontNodeId: string[];
    nextNodeId: string[];
    positionRow: number;
    positionOrder: number;
    tokenCost: number;
    buffName: string;
    buffIconId: string;
    effectType: RL03DevelopmentEffectType;
    rawDesc: string[];
    buffDisplayInfo: RoguelikeTopicDisplayItem[];
    groupId: string;
    enrollId: string;
}

export interface RL03DevRawTextBuffGroup {
    nodeIdList: string[];
    useLevelMark: boolean;
    groupIconId: string;
    sortId: number;
}

export interface RL03DevDifficultyNodeInfo {
    buffId: string;
    nodeMap: RL03DevDifficultyNodePairInfo[];
    enableGrade: number;
}

export interface RL03DevDifficultyNodePairInfo {
    frontNode: string;
    nextNode: string;
}

export interface RoguelikeCommonDevelopment {
    buffId: string;
    nodeType: RoguelikeCommonDevelopmentNodeType;
    frontNodeId: string[];
    nextNodeId: string[];
    positionRow: number;
    positionOrder: number;
    tokenCost: number;
    buffName: string;
    activeIconId: string;
    inactiveIconId: string;
    bottomIconId: string;
    effectType: RoguelikeCommonDevelopmentEffectType;
    rawDesc: string[];
    buffDisplayInfo: RoguelikeTopicDisplayItem[];
    groupId: string;
    enrollId: string;
}

export interface RoguelikeCommonDevRawTextBuffGroup {
    nodeIdList: string[];
    groupIconId: string;
    sortId: number;
}

export interface RoguelikeCommonDevDifficultyNodeInfo {
    buffId: string;
    nodeMap: RoguelikeCommonDevDifficultyNodePairInfo[];
    enableGrade: number;
    enableDesc: string;
    lightId: string;
    decoId: string;
}

export interface RoguelikeCommonDevDifficultyNodePairInfo {
    frontNodes: string[];
    nextNode: string;
}

export interface LegacyInLevelRuneData {
    difficultyMask: LevelData_Difficulty;
    SIX_STAR_RUNE_NAMES: string[][];
    key: string;
    professionMask: ProfessionCategory;
    buildableMask: BuildableType;
    blackboard: Blackboard;
}

export interface RuneData {
    key: string;
    selector: RuneData_Selector;
    blackboard: Blackboard;
}

export interface RuneData_Selector {
    professionMask: number | ProfessionCategory;
    buildableMask: BuildableType;
    playerSideMask: PlayerSideMask;
    sideType: Battle_SideType;
    charIdFilter: string[];
    charIdExcludeFilter: string[];
    enemyIdFilter: string[];
    enemyIdExcludeFilter: string[];
    enemyLevelTypeFilter: string[];
    enemyActionHiddenGroupFilter: string[];
    skillIdFilter: string[];
    tileKeyFilter: string[];
    groupTagFilter: string[];
    filterTagFilter: string[];
    filterTagExcludeFilter: string[];
    subProfessionExcludeFilter: string[];
    mapTagFilter: string[];
    heightTypeMask: TileData_HeightTypeMask;
}

export interface RuneTable_PackedRuneData {
    id: string;
    points: number;
    mutexGroupKey: string;
    description: string;
    runes: RuneData[];
}

export interface RuneTable_RuneStageExtraData {
    stageId: string;
    runes: RuneTable_PackedRuneData[];
}

export interface SandboxBuildingItemData {
    itemId: string;
    itemRarity: number;
}

export interface SandboxFoodMatData {
    id: string;
    type: SandboxFoodMatType;
    attribute: SandboxFoodAttribute;
    variantType: SandboxFoodVariantType;
    bonusDuration: number;
    buffDesc: string;
    sortId: number;
}

export interface SandboxFoodRecipeData {
    foodId: string;
    mats: string[];
}

export interface SandboxFoodVariantData {
    type: SandboxFoodVariantType;
    name: string;
    usage: string;
}

export interface SandboxFoodData {
    id: string;
    attributes: SandboxFoodAttribute[];
    recipes: SandboxFoodRecipeData[];
    variants: SandboxFoodVariantData[];
    duration: number;
    sortId: number;
}

export interface SandboxShopGoodData {
    goodId: string;
    itemId: string;
    count: number;
    coinType: SandboxShopCoinType;
    value: number;
    itemPoolId: string;
    stock: number;
    weight: number;
}

export interface SandboxShopSlotData {
    slotId: number;
    sortId: number;
    itemPoolId: string;
    priceModifier: number;
}

export interface SandboxShopCoinTypeData {
    coinTye: SandboxShopCoinType;
    itemId: string;
    coinIcon: string;
    coinColorStr: string;
}

export interface SandboxPermShopGoodData {
    goodId: string;
    itemId: string;
    count: number;
    coinType: SandboxShopCoinType;
    value: number;
    stock: number;
}

export interface SandboxPermShopSellData {
    itemId: string;
    countInUnit: number;
    sellCoinType: SandboxShopCoinType;
    sellVal: number;
}

export interface SandboxDevelopmentData {
    techId: string;
    techType: SandboxDevelopmentType;
    positionX: number;
    positionY: number;
    frontNodeId: string;
    nextNodeIds: string[];
    limitBaseLevel: number;
    tokenCost: number;
    techName: string;
    techIconId: string;
    nodeTitle: string;
    rawDesc: string;
    canBuffReserch: boolean;
}

export interface SandboxDevelopmentLineSegmentData {
    fromNodeId: string;
    passingNodeIds: string[];
    fromAxisPosX: number;
    fromAxisPosY: number;
    toAxisPosX: number;
    toAxisPosY: number;
    lineStyle: SandboxDevelopmentLineStyle;
    unlockBasementLevel: number;
}

export interface SandboxArchiveQuestTypeData {
    type: SandboxArchiveQuestType;
    name: string;
    iconId: string;
}

export interface SandboxArchiveQuestAvgData {
    avgId: string;
    avgName: string;
}

export interface SandboxArchiveQuestCgData {
    cgId: string;
    cgTitle: string;
    cgDesc: string;
    cgPath: string;
}

export interface SandboxArchiveQuestZoneData {
    zoneId: string;
    zoneName: string;
    zoneBgPicId: string;
    zoneNameIdEn: string;
}

export interface SandboxArchiveQuestData {
    id: string;
    sortId: number;
    questType: SandboxArchiveQuestType;
    name: string;
    desc: string;
    avgDataList: SandboxArchiveQuestAvgData[];
    cgDataList: SandboxArchiveQuestCgData[];
    npcPicIdList: string[];
    zoneData: SandboxArchiveQuestZoneData;
}

export interface SandboxArchiveAchievementData {
    id: string;
    achievementType: string[];
    raritySortId: number;
    sortId: number;
    name: string;
    desc: string;
}

export interface SandboxArchiveAchievementTypeData {
    achievementType: string;
    name: string;
    sortId: number;
}

export interface SandboxArchiveMusicUnlockData {
    musicId: string;
    unlockCondDesc: string;
}

export interface SandboxV2MapZoneData {
    zoneId: string;
    center: JsonValue;
    vertices: JsonValue[];
    triangles: number[][];
    hasBorder: boolean;
}

export interface SandboxV2MapConfig {
    DEFAULT: SandboxV2MapConfig;
    RIFT_DEFAULT: SandboxV2MapConfig;
    isRift: boolean;
    isGuide: boolean;
    cameraBoundMin: JsonValue;
    cameraBoundMax: JsonValue;
    cameraMaxNormalizedZoom: number;
    backgroundId: string;
}

export interface SandboxV2NodeData {
    minDistance: number;
}

export interface SandboxV2MapData {
    nodes: { [key: string]: SandboxV2NodeData };
    zones: { [key: string]: SandboxV2MapZoneData };
    mapConfig: SandboxV2MapConfig;
    centerNodeId: string;
    monthModeNodeId: string;
}

export interface SandboxV2RewardItemConfigData {
    rewardItem: string;
    rewardType: SandboxPermItemType;
}

export interface SandboxV2RewardData {
    rewardList: SandboxV2RewardItemConfigData[];
}

export interface SandboxV2RewardCommonConfig {
    rewardItemId: string;
    rewardItemType: SandboxPermItemType;
    count: number;
}

export interface SandboxV2RewardConfigGroupData {
    stageMapPreviewRewardDict: { [key: string]: SandboxV2RewardData };
    stageDetailPreviewRewardDict: { [key: string]: SandboxV2RewardData };
    trapRewardDict: { [key: string]: SandboxV2RewardCommonConfig };
    enemyRewardDict: { [key: string]: SandboxV2RewardCommonConfig };
    unitPreviewRewardDict: { [key: string]: SandboxV2RewardData };
    stageRewardDict: { [key: string]: SandboxV2RewardData };
    rushPreviewRewardDict: { [key: string]: SandboxV2RewardData };
}

export interface SandboxV2NodeTypeData {
    nodeType: SandboxV2NodeType;
    name: string;
    iconId: string;
}

export interface SandboxV2NodeUpgradeData {
    nodeUpgradeId: string;
    name: string;
    description: string;
    upgradeDesc: string;
    upgradeTips: string;
    itemType: SandboxPermItemType;
    itemTag: SandboxV2ItemTrapTag;
    itemCnt: number;
    itemRarity: number;
}

export interface SandboxV2WeatherData {
    weatherId: string;
    name: string;
    weatherLevel: number;
    weatherType: SandboxV2WeatherType;
    weatherTypeName: string;
    weatherIconId: string;
    functionDesc: string;
    description: string;
    buffId: string;
}

export interface SandboxV2LivestockData {
    livestockItemId: string;
    shinyLivestockItemId: string;
    livestockEnemyId: string;
    targetFenceId: string;
}

export interface SandboxV2SeasonData {
    seasonType: SandboxV2SeasonType;
    name: string;
    functionDesc: string;
    description: string;
    color: string;
}

export interface SandboxV2StageData {
    stageId: string;
    levelId: string;
    code: string;
    name: string;
    description: string;
    actionCost: number;
    actionCostEnemyRush: number;
}

export interface SandboxV2ZoneData {
    zoneId: string;
    zoneName: string;
    displayName: boolean;
    appellation: string;
}

export interface SandboxV2NodeBuffData {
    runeId: string;
    name: string;
    description: string;
    extra: string;
    iconId: string;
}

export interface SandboxV2EnemyRushTypeData {
    type: SandboxV2EnemyRushType;
    description: string;
    sortId: number;
}

export interface SandboxV2ItemTrapData {
    itemId: string;
    trapId: string;
    trapPhase: number;
    trapLevel: number;
    skillIndex: number;
    skillLevel: number;
    buildingLevel: number;
    updatedItemId: string;
    minLevelItemId: string;
    baseItemName: string;
    itemType: SandboxV2TrapItemType;
    itemTag: SandboxV2ItemTrapTag;
    buffId: string;
}

export interface SandboxV2ItemTrapTagData {
    tag: SandboxV2ItemTrapTag;
    tagName: string;
    tagPic: string;
    sortId: number;
}

export interface SandboxV2CraftItemData {
    itemId: string;
    type: SandboxV2CraftItemType;
    buildingUnlockDesc: string;
    materialItems: { [key: string]: number };
    upgradeItems: { [key: string]: number };
    outputRatio: number;
    withdrawRatio: number;
    repairCost: number;
    isHidden: boolean;
    craftGroupId: string;
    recipeLevel: number;
}

export interface SandboxV2CraftGroupData {
    items: string[];
}

export interface SandboxV2AlchemyMaterialData {
    itemId: string;
    count: number;
}

export interface SandboxV2AlchemyRecipeData {
    recipeId: string;
    materials: SandboxV2AlchemyMaterialData[];
    itemId: string;
    onceAlchemyRatio: number;
    recipeLevel: number;
    unlockDesc: string;
}

export interface SandboxV2DrinkMatData {
    id: string;
    type: SandboxPermItemType;
    count: number;
}

export interface SandboxV2DiffModeData {
    title: string;
    desc: string;
    buffList: string[];
    detailList: string;
    sortId: number;
}

export interface SandboxV2GameConst {
    mainMapId: string;
    baseTrapId: string;
    portableTrapId: string;
    doorTrapId: string;
    mineTrapId: string;
    neutralBossEnemyId: string[];
    nestTrapId: string;
    shopNpcName: string;
    daysBetweenAssessment: number;
    portableConstructUnlockLevel: number;
    outpostConstructUnlockLevel: number;
    maxEnemyCountSameTimeInRush: number;
    maxPreDelayTimeInRush: number;
    maxSaveCnt: number;
    firstSeasonDuration: number;
    seasonTransitionLoop: SandboxV2SeasonType[];
    seasonDurationLoop: number[];
    firstSeasonStartAngle: number;
    seasonTransitionAngleLoop: number[];
    seasonAngle: number;
    battleItemDesc: string;
    foodDesc: string;
    multipleSurvivalDayDesc: string;
    multipleTips: string;
    techProgressScore: number;
    otherEnemyRushName: string;
    surviveDayText: string;
    survivePeriodText: string;
    surviveScoreText: string;
    actionPointScoreText: string;
    nodeExploreDesc: string;
    dungeonExploreDesc: string;
    nodeCompleteDesc: string;
    noRiftDungeonDesc: string;
    baseRushedDesc: string;
    riftBaseDesc: string;
    riftBaseRushedDesc: string;
    dungeonTriggeredGuideQuestList: string[];
    noLogInEnemyStatsEnemyId: string[];
}

export interface SandboxV2BasicConst {
    staminaItemId: string;
    goldItemId: string;
    dimensioncoinItemId: string;
    alwaysShowItemIdsConstruct: string[];
    alwaysShowItemIds: string[];
    bagBottomBarResType: string[];
    failedCookFood: string;
    maxFoodDuration: number;
    drinkCostOnce: number;
    drinkMakeLimit: number;
    specialMatWater: string;
    workbenchMakeLimit: number;
    logisticsPosLimit: number;
    logisticsUnlockLevel: number;
    logisticsDrinkCost: number;
    logisticsEvacuateTips: string;
    logisticsEvacuateWarning: string;
    baseRepairCost: number;
    portRepairCost: number;
    unitFenceLimit: number;
    unitRareFenceLimit: number;
    cageId: string;
    fenceId: string;
    rareFenceId: string;
    monthlyRushEntryText1: string;
    monthlyEntryUnlockText: string;
    monthlyEntryRiftText: string;
    monthlyRushIntro: string;
    monthlyCoin: ItemBundle;
    charRarityColorList: string[];
    squadCharCapacity: number;
    totalSquadCnt: number;
    toolboxCapacity: number;
    toolCntLimitInSquad: number;
    miniSquadCharCapacity: number;
    miniSquadDrinkCost: number;
    normalSquadDrinkCost: number;
    emptySquadDrinkCost: number;
    achieveTypeAll: string;
    constructModeBgmHome: string;
    battleBgmCollect: string;
    battleBgmHunt: string;
    battleBgmEnemyRush: string;
    battleBgmBossRush: string;
    imgLoadingNormalName: string;
    imgLoadingBaseName: string;
    imgUnloadingBaseName: string;
    isChallengeOpen: boolean;
    isRacingOpen: boolean;
    hasExploreMode: boolean;
    exploreModeBuffDescs: string[];
    modeSelectTips: string;
    stringRes: { [key: string]: string };
    diffList: SandboxV2DiffModeData[];
    battlePreloadEnemies: string[];
    battleExcludedTrapsInRush: string[];
}

export interface SandboxV2RiftConst {
    refreshRate: number;
    randomDungeonId: string;
    huntDungeonId: string;
    subTargetRewardId: string;
    preyQuestRewardId: string;
    dungeonSeasonId: SandboxV2SeasonType;
    fixedDungeonTypeName: string;
    randomDungeonTypeName: string;
    preyDungeonTypeName: string;
    noTeamDescription: string;
    noTeamName: string;
    noTeamBackgroundId: string;
    noTeamSmallIconId: string;
    noTeamBigIconId: string;
    messengerEnemyId: string;
    riftRushEnemyGroupLimit: number;
    riftRushSpawnCd: number;
}

export interface SandboxV2BattleRushEnemyConfig {
    enemyKey: string;
    branchId: string;
    count: number;
    interval: number;
    preDelay: number;
}

export interface SandboxV2BattleRushEnemyGroupConfig {
    enemyGroupKey: string;
    enemy: SandboxV2BattleRushEnemyConfig[];
    dynamicEnemy: string[];
}

export interface SandboxV2BattleRushEnemyData {
    rushEnemyGroupConfigs: { [key: string]: SandboxV2BattleRushEnemyGroupConfig[] };
    rushEnemyDbRef: SandboxV2BattleRushEnemyData_RushEnemyDBRef[];
}

export interface SandboxV2BattleRushEnemyData_RushEnemyDBRef {
    id: string;
    level: number;
}

export interface SandboxV2FloatIconData {
    picId: string;
    picName: string;
}

export interface SandboxV2QuestData {
    questId: string;
    questLine: string;
    questTitle: string;
    questDesc: string;
    questTargetDesc: string;
    isDisplay: boolean;
    questRouteType: SandboxV2QuestRouteType;
    questLineType: SandboxV2QuestLineType;
    questRouteParam: string;
    showProgressIndex: number;
}

export interface SandboxV2NpcData {
    npcId: string;
    trapId: string;
    npcType: SandboxV2NpcType;
    dialogIds: { [key: string]: string };
    npcLocation: number[];
    npcOrientation: SharedConsts_Direction;
    picId: string;
    picName: string;
    showPic: boolean;
    reactSkillIndex: number;
}

export interface SandboxV2DialogData {
    dialogId: string;
    avgId: string;
}

export interface SandboxV2QuestLineData {
    questLineId: string;
    questLineTitle: string;
    questLineType: SandboxV2QuestLineType;
    questLineBadgeType: SandboxV2QuestLineBadgeType;
    questLineScopeType: SandboxV2QuestLineScopeType;
    questLineDesc: string;
    sortId: number;
}

export interface SandboxV2GuideQuestData {
    questId: string;
    storyId: string;
    triggerKey: string;
}

export interface SandboxV2DevelopmentConst {
    techPointsTotal: number;
}

export interface SandboxV2EventData {
    eventId: string;
    type: SandboxV2EventType;
    iconId: string;
    iconName: string;
    enterSceneId: string;
}

export interface SandboxV2EventSceneData {
    eventSceneId: string;
    title: string;
    desc: string;
    choiceIds: string[];
}

export interface SandboxV2EventChoiceData {
    choiceId: string;
    type: SandboxV2EventChoiceType;
    costAction: number;
    title: string;
    desc: string;
    expeditionId: string;
}

export interface SandboxV2ExpeditionData {
    expeditionId: string;
    desc: string;
    effectDesc: string;
    costAction: number;
    costDrink: number;
    charCnt: number;
    profession: ProfessionCategory;
    professions: ProfessionID[];
    minEliteRank: number;
    duration: number;
}

export interface SandboxV2EventEffectData {
    eventEffectId: string;
    buffId: string;
    duration: number;
    desc: string;
}

export interface SandboxV2ShopDialogData {
    seasonDialogs: { [key: string]: string[] };
    afterBuyDialogs: string[];
    shopEmptyDialogs: string[];
}

export interface SandboxV2LogisticsData {
    id: string;
    desc: string;
    noBuffDesc: string;
    iconId: string;
    profession: ProfessionCategory;
    sortId: number;
    levelParams: string[];
}

export interface SandboxV2LogisticsCharData {
    levelUpperLimit: number;
    charUpperLimit: number;
}

export interface SandboxV2MonthRushData {
    monthlyRushId: string;
    startTime: number;
    endTime: number;
    isLast: boolean;
    sortId: number;
    rushGroupKey: string;
    monthlyRushName: string;
    monthlyRushDes: string;
    weatherId: string;
    nodeId: string;
    conditionGroup: string;
    conditionDesc: string;
    rewardItemList: ItemBundle[];
}

export interface SandboxV2RiftParamData {
    id: string;
    desc: string;
    iconId: string;
    bkColor: string;
}

export interface SandboxV2RiftMainTargetData {
    id: string;
    title: string;
    desc: string;
    storyDesc: string;
    targetDayCount: number;
    targetType: SandboxV2RiftMainTargetType;
    questIconId: string;
    questIconName: string;
}

export interface SandboxV2RiftSubTargetData {
    id: string;
    name: string;
    desc: string;
}

export interface SandboxV2RiftGlobalEffectData {
    id: string;
    desc: string;
}

export interface SandboxV2FixedRiftData {
    riftId: string;
    riftName: string;
    rewardGroupId: string;
}

export interface SandboxV2RiftTeamBuffData {
    teamId: string;
    teamName: string;
    buffLevel: number;
    buffDesc: string;
    teamSmallIconId: string;
    teamBigIconId: string;
    teamDesc: string;
    teamBgId: string;
}

export interface SandboxV2RiftDifficultyData {
    id: string;
    riftId: string;
    desc: string;
    difficultyLevel: number;
    rewardGroupId: string;
}

export interface SandboxV2BuildingNodeScoreData {
    nodeId: string;
    sortId: number;
    limitScore: number;
}

export interface SandboxV2BaseUpdateData {
    baseLevelId: string;
    baseLevel: number;
    conditions: SandboxV2BaseUpdateCondition[];
    items: { [key: string]: number };
    previewDatas: SandboxV2BaseFunctionPreviewData[];
    scoreFactor: string;
    portableRepairCost: number;
    entryCount: number;
    repairCost: number;
}

export interface SandboxV2BaseUpdateCondition {
    desc: string;
    limitCond: string;
    param: string[];
}

export interface SandboxV2BaseFunctionPreviewData {
    previewId: string;
    previewValue: number;
    detailData: SandboxV2BaseUpdateFunctionPreviewDetailData;
}

export interface SandboxV2BaseUpdateFunctionPreviewDetailData {
    funcId: string;
    unlockType: SandboxV2BaseUnlockFuncType;
    typeTitle: string;
    desc: string;
    icon: string;
    darkMode: boolean;
    sortId: number;
    displayType: SandboxV2BaseUnlockFuncDisplayType;
}

export interface SandboxV2ConfirmIconData {
    iconType: SandboxV2ConfirmIconType;
    iconPicId: string;
}

export interface SandboxV2TutorialRepoCharData {
    instId: number;
    charId: string;
    evolvePhase: EvolvePhase;
    level: number;
    favorPoint: number;
    potentialRank: number;
    mainSkillLv: number;
    specSkillList: number[];
}

export interface SandboxV2TutorialBasicConst {
    trainingQuestList: string[];
}

export interface SandboxV2TutorialData {
    charRepoData: { [key: number]: SandboxV2TutorialRepoCharData };
    questData: { [key: string]: SandboxV2QuestData };
    guideQuestData: { [key: string]: SandboxV2GuideQuestData };
    questLineData: { [key: string]: SandboxV2QuestLineData };
    basicConst: SandboxV2TutorialBasicConst;
}

export interface SandboxV2RacerBasicInfo {
    racerId: string;
    sortId: number;
    racerTypeName: string;
    itemId: string;
    attributeMaxValue: number[];
}

export interface SandboxV2RacerTalentInfo {
    talentId: string;
    talentType: SandboxV2RacerTalentType;
    talentIconId: string;
    desc: string;
}

export interface SandboxV2RacerNameInfo {
    nameId: string;
    nameType: SandboxV2RacerNameType;
    nameDesc: string;
}

export interface SandboxV2RacingConstData {
    attributeNameList: string[];
    racerMaxValue: number[];
    bagFullHintPercent: number;
    tempBagFullHintPercent: number;
    bagName: string;
    tempBagName: string;
    bagEmptyLeftDesc: string;
    bagEmptyRightDesc: string;
    tempBagEmptyLeftDesc: string;
    tempBagEmptyRightDesc: string;
    bornTalentIconId: string;
    bornTalentTitle: string;
    learnedTalentIconId: string;
    learnedTalentTitle: string;
    talentEmptyDesc: string;
    slugItemId: string;
    racingHpFactor: number;
    racingSpeedFactor: number;
    racingAccelerationFactor: number;
    recoverMoveSpeed: number;
    recoverHpFactor: number;
    bleedingFactor: number;
    maxSteeringFactor: number;
    steeringMassLevelFactor: number;
    steeringMoveSpeedFactor: number;
    safeAngleCos: number;
    safeCollisionForceLevel: number;
    tileCollisionFactor: number;
    collisionForceSector: number[];
    collisionForceLevel: number[];
    collisionSpeedLoss: number[];
    collisionHpLoss: number[];
    tileCollisionSpeedLoss: number[];
    tileCollisionHpLoss: number[];
    autoUseItemTimeRange: number[];
    recoverAcceleration: number;
}

export interface SandboxV2RacerMedalInfo {
    medalId: string;
    sortId: number;
    name: string;
    desc: string;
    iconId: string;
    smallIconId: string;
}

export interface SandboxV2RacingItemInfo {
    racerItemId: string;
    name: string;
    iconId: string;
    blackboard: Blackboard;
}

export interface SandboxV2RacingData {
    racerBasicInfo: { [key: string]: SandboxV2RacerBasicInfo };
    racerTalentInfo: { [key: string]: SandboxV2RacerTalentInfo };
    racerNameInfo: { [key: string]: SandboxV2RacerNameInfo };
    racerMedalInfo: { [key: string]: SandboxV2RacerMedalInfo };
    enemyItemMap: { [key: string]: string };
    racingItemInfo: { [key: string]: SandboxV2RacingItemInfo };
    constData: SandboxV2RacingConstData;
}

export interface SandboxV2ChallengeModeUnlockData {
    unlockId: string;
    sortId: number;
    conditionDesc: string;
}

export interface SandboxV2ChallengeModeRewardData {
    rewardId: string;
    sortId: number;
    rewardDay: number;
    rewardItemList: ItemBundle[];
}

export interface SandboxV2ChallengeModeDifficultyData {
    challengeDay: number;
    diffDesc: string;
}

export interface SandboxV2ChallengeConst {
    challengeModeDesc: string;
    dailyTitleDesc: string;
    debuffCountdownDesc: string;
    gainAllDebuffDesc: string;
    dailyUpAttributeDesc: string;
}

export interface SandboxV2ChallengeModeData {
    challengeConst: SandboxV2ChallengeConst;
    challengeModeUnlockData: { [key: string]: SandboxV2ChallengeModeUnlockData };
    challengeModeRewardData: { [key: string]: SandboxV2ChallengeModeRewardData };
    challengeModeDifficultyData: SandboxV2ChallengeModeDifficultyData[];
}

export interface SandboxV2Data {
    mapData: { [key: string]: SandboxV2MapData };
    itemTrapData: { [key: string]: SandboxV2ItemTrapData };
    itemTrapTagData: { [key: string]: SandboxV2ItemTrapTagData };
    buildingItemData: { [key: string]: SandboxBuildingItemData };
    craftItemData: { [key: string]: SandboxV2CraftItemData };
    livestockProduceData: { [key: string]: SandboxV2LivestockData };
    craftGroupData: { [key: string]: SandboxV2CraftGroupData };
    alchemyRecipeData: { [key: string]: SandboxV2AlchemyRecipeData };
    drinkMatData: { [key: string]: SandboxV2DrinkMatData };
    foodMatData: { [key: string]: SandboxFoodMatData };
    foodData: { [key: string]: SandboxFoodData };
    nodeTypeData: { [key: string]: SandboxV2NodeTypeData };
    nodeUpgradeData: { [key: string]: SandboxV2NodeUpgradeData };
    weatherData: { [key: string]: SandboxV2WeatherData };
    stageData: { [key: string]: SandboxV2StageData };
    zoneData: { [key: string]: SandboxV2ZoneData };
    nodeBuffData: { [key: string]: SandboxV2NodeBuffData };
    rewardConfigData: SandboxV2RewardConfigGroupData;
    floatIconData: { [key: string]: SandboxV2FloatIconData };
    enemyRushTypeData: { [key: string]: SandboxV2EnemyRushTypeData };
    rushEnemyData: SandboxV2BattleRushEnemyData;
    gameConst: SandboxV2GameConst;
    basicConst: SandboxV2BasicConst;
    riftConst: SandboxV2RiftConst;
    developmentConst: SandboxV2DevelopmentConst;
    battleLoadingTips: TipData[];
    runeDatas: { [key: string]: RuneTable_PackedRuneData };
    itemRuneList: { [key: string]: LegacyInLevelRuneData[] };
    questData: { [key: string]: SandboxV2QuestData };
    npcData: { [key: string]: SandboxV2NpcData };
    dialogData: { [key: string]: SandboxV2DialogData };
    questLineData: { [key: string]: SandboxV2QuestLineData };
    questLineStoryData: { [key: string]: string };
    guideQuestData: { [key: string]: SandboxV2GuideQuestData };
    developmentData: { [key: string]: SandboxDevelopmentData };
    eventData: { [key: string]: SandboxV2EventData };
    eventSceneData: { [key: string]: SandboxV2EventSceneData };
    eventChoiceData: { [key: string]: SandboxV2EventChoiceData };
    expeditionData: { [key: string]: SandboxV2ExpeditionData };
    eventEffectData: { [key: string]: SandboxV2EventEffectData };
    shopGoodData: { [key: string]: SandboxShopGoodData };
    shopDialogData: SandboxV2ShopDialogData;
    logisticsData: SandboxV2LogisticsData[];
    logisticsCharMapping: { [key: number]: { [key: number]: SandboxV2LogisticsCharData[] } };
    materialKeywordData: { [key: string]: string };
    monthRushData: SandboxV2MonthRushData[];
    riftTerrainParamData: { [key: string]: SandboxV2RiftParamData };
    riftClimateParamData: { [key: string]: SandboxV2RiftParamData };
    riftEnemyParamData: { [key: string]: SandboxV2RiftParamData };
    riftSubTargetData: { [key: string]: SandboxV2RiftSubTargetData };
    riftMainTargetData: { [key: string]: SandboxV2RiftMainTargetData };
    riftGlobalEffectData: { [key: string]: SandboxV2RiftGlobalEffectData };
    fixedRiftData: { [key: string]: SandboxV2FixedRiftData };
    riftTeamBuffData: { [key: string]: SandboxV2RiftTeamBuffData[] };
    riftDifficultyData: { [key: string]: SandboxV2RiftDifficultyData };
    riftRewardDisplayData: { [key: string]: string[] };
    enemyReplaceData: { [key: string]: { [key: string]: string } };
    archiveQuestData: { [key: string]: SandboxArchiveQuestData };
    achievementData: { [key: string]: SandboxArchiveAchievementData };
    achievementTypeData: { [key: string]: SandboxArchiveAchievementTypeData };
    archiveQuestTypeData: { [key: string]: SandboxArchiveQuestTypeData };
    archiveMusicUnlockData: { [key: string]: SandboxArchiveMusicUnlockData };
    baseUpdate: SandboxV2BaseUpdateData[];
    developmentLineSegmentDatas: SandboxDevelopmentLineSegmentData[];
    buildingNodeScoreData: { [key: string]: SandboxV2BuildingNodeScoreData };
    seasonData: { [key: string]: SandboxV2SeasonData };
    confirmIconData: SandboxV2ConfirmIconData[];
    shopUpdateTimeData: number[];
    tutorialData: SandboxV2TutorialData;
    racingData: SandboxV2RacingData;
    challengeModeData: SandboxV2ChallengeModeData;
}

export interface SandboxV3MapGridPos {
    X: number;
    Y: number;
}

export interface SandboxV3ModeData {
    modeId: string;
    modeName: string;
    sortId: number;
    modeDescription: string;
    modeDescriptionDetail: string;
    difficultyFactor: number;
    runeIdList: string[];
}

export interface SandboxV3NodeTypeData {
    nodeType: SandboxV3NodeType;
    name: string;
}

export interface SandboxV3StageData {
    stageId: string;
    code: string;
    name: string;
    description: string;
    maxDay: number;
    maxPlayTime: number;
    jumpTime: number;
    targetPowerValue: number;
    dayTargetValues: number[];
    taskPool: string[];
    questPoolByDifficulty: number;
    statParams: string;
    milestones: { [key: string]: SandboxV3PowerMilestoneData };
    taskSlots: string[];
    initialItemData: SandboxV3StageInitialItemData[];
    squadMax: number;
    initialRecruitNum: number;
    dayPassRecruitNum: number;
    levelRune: string;
    firstDayDescription: string;
    levelBgm: string;
    isFormationSaved: boolean;
}

export interface SandboxV3StoryStageData {
    stageId: string;
    subStageIdList: string[];
    initialSubStageIndexList: number[];
}

export interface SandboxV3ExploreStageData {
    stageId: string;
    subStagePoolId: string;
    stageDifficultyMax: number;
    displayEnemyIdList: string[];
}

export interface SandboxV3ExploreStageDifficultyData {
    difficultyId: string;
    difficultyLevel: number;
    unlockCondDescList: string[];
    difficultyDesc: string;
    difficultyFactor: number;
    runeIdList: string[];
}

export interface SandboxV3SubStageData {
    subStageId: string;
    levelId: string;
    typeMask: number;
    mapPreviewId: string;
}

export interface SandboxV3StageDropData {
    stageId: string;
    rewardFirstItems: { [key: string]: number };
    rewardNormalItems: { [key: string]: number };
    rewardHardItems: { [key: string]: number };
}

export interface SandboxV3MapData {
    tiles: { [key: string]: SandboxV3MapTileData };
    nodes: { [key: string]: SandboxV3MapNodeData };
    zones: { [key: string]: SandboxV3ZoneData };
    mapConfig: SandboxV3MapConfig;
}

export interface SandboxV3MapTileData {
    tileId: string;
    tileType: SandboxV3MapTileType;
    gridPos: SandboxV3MapGridPos;
    tileResId: string;
    tileResRotateZ: number;
    tileDecoId: string;
    tileDecoRotateZ: number;
    height: number;
    nodeId: string;
}

export interface SandboxV3MapNodeData {
    nodeId: string;
    nodeType: SandboxV3NodeType;
    stageId: string;
    zoneId: string;
    frontNodeId: string;
    unlockTileIdList: string[];
    gridPos: SandboxV3MapGridPos;
    onTileId: string;
    height: number;
}

export interface SandboxV3ZoneData {
    zoneId: string;
    name: string;
    sortId: number;
    displayName: boolean;
    appellation: string;
    gridPos: SandboxV3MapGridPos;
}

export interface SandboxV3MapConfig {
    maxSpringBackRadius: number;
    minSpringBackRadius: number;
}

export interface SandboxV3BandLevelData {
    level: number;
    effectDesc: string;
    unlockCondDesc: string;
}

export interface SandboxV3BandData {
    bandId: string;
    name: string;
    sortId: number;
    bandIcon: string;
    levelList: SandboxV3BandLevelData[];
}

export interface SandboxV3DefendScoreData {
    rarity: number;
    evolvePhase: number;
    level: number;
    grade: number;
}

export interface SandboxV3ZoneDefendData {
    zoneId: string;
    iconId: string;
    titleIconId: string;
    rewardDataList: SandboxV3ZoneDefendRewardData[];
}

export interface SandboxV3ZoneDefendRewardData {
    grade: number;
    rewards: { [key: string]: number };
}

export interface SandboxV3BasementUpdateData {
    baseLevelId: string;
    baseLevel: number;
    baseDesc: string;
    levelId: string;
    wonderId: string;
    conditions: SandboxV3BasementUpdateCondition[];
    items: { [key: string]: number };
    previewDatas: SandboxV3BasementFunctionPreviewData[];
    rewards: ItemBundle[];
}

export interface SandboxV3BasementUpdateCondition {
    desc: string;
    limitCond: string;
    param: string[];
}

export interface SandboxV3BasementFunctionPreviewData {
    previewId: string;
    previewValue: number;
}

export interface SandboxV3BasementUpdateFunctionPreviewDetailData {
    funcId: string;
    unlockType: SandboxV3BasementUnlockFuncType;
    typeTitle: string;
    desc: string;
    icon: string;
    darkMode: boolean;
    sortId: number;
    displayType: SandboxV3BasementUnlockFuncDisplayType;
}

export interface SandboxV3WonderData {
    wonderId: string;
    wonderName: string;
    sortId: number;
}

export interface SandboxV3QuestData {
    questId: string;
    questLine: string;
    sortId: number;
    questTitle: string;
    questDesc: string;
    questTargetDesc: string;
    isDisplay: boolean;
    questRouteParam: string;
    showProgressIndex: number;
}

export interface SandboxV3DialogData {
    dialogId: string;
    avgId: string;
}

export interface SandboxV3NpcData {
    npcId: string;
    trapId: string;
    sortId: number;
    npcType: SandboxV3NpcType;
    dialogIds: { [key: string]: string };
    npcLocation: number[];
    npcOrientation: SharedConsts_Direction;
    picId: string;
    picName: string;
    showPic: boolean;
    reactSkillIndex: number;
}

export interface SandboxV3EnemyNpcData {
    npcId: string;
    battleRuneId: string;
}

export interface SandboxV3QuestLineData {
    questLineId: string;
    questLineTitle: string;
    questLineBadgeType: SandboxV3QuestLineBadgeType;
    questLineDesc: string;
    sortId: number;
}

export interface SandboxV3GuideQuestData {
    questId: string;
    storyId: string;
    triggerKey: string;
}

export interface SandboxV3BaseShopGoodExtraData {
    unlockDesc: string;
}

export interface SandboxV3ShopGoodPoolData {
    itemPoolId: string;
    normalItemList: SandboxV3ShopGoodPoolItemData[];
    guaranteeItemList: SandboxV3ShopGoodPoolItemData[];
}

export interface SandboxV3ShopGoodPoolItemData {
    goodId: string;
    weight: number;
}

export interface SandboxV3StageShopData {
    shopId: string;
    stageId: string;
    shopType: SandboxV3ShopType;
    priority: number;
    canRefresh: boolean;
    displaySlot: number;
}

export interface SandboxV3ShopDetailData {
    slotDataList: SandboxShopSlotData[];
}

export interface SandboxV3CookbookData {
    itemId: string;
    attrList: string[];
    mainMatList: string[];
    itemUsage: string;
    itemName: string;
    runeData: RuneTable_PackedRuneData;
}

export interface SandboxV3CookSpiceData {
    itemId: string;
    buffDesc: string;
    attrType: SandboxFoodAttribute;
    runeData: RuneTable_PackedRuneData;
}

export interface SandboxV3EventSceneData {
    sceneId: string;
    title: string;
    desc: string;
    choiceIdList: string[];
}

export interface SandboxV3EventChoiceData {
    choiceId: string;
    title: string;
    desc: string;
    expeditionId: string;
}

export interface SandboxV3EventExpeditionData {
    expeditionId: string;
    charCount: number;
    requiredProfession: ProfessionCategory;
    minEliteRank: number;
}

export interface SandboxV3PowerMilestoneData {
    milestoneId: string;
    stage: SandboxV3MilestoneStage;
    targetPowerValue: number;
    choiceSlotCnt: number;
    allowRefresh: boolean;
    allowGiveUpChoice: boolean;
    defaultPool: string;
    refreshPool: string;
}

export interface SandboxV3ProsParam {
    threshold: number;
    plusValue: number;
    level: number;
}

export interface SandboxV3StatParamData {
    statId: string;
    prosParams: SandboxV3ProsParam[];
    aesthParams: { [key: number]: number };
}

export interface SandboxV3WeatherData {
    weatherId: string;
    name: string;
    runeId: string;
    exRuneId: string;
    funcDesc: string;
    desc: string;
    enableFog: boolean;
    screenEffectId: string;
}

export interface SandboxV3LivestockData {
    enemyId: string;
    livestockItemId: string;
    livestockEnemyId: string;
    shinyLivestockItemId: string;
    shinyLivestockEnemyId: string;
    shinyRate: number;
    isLegend: boolean;
}

export interface SandboxV3RelicData {
    relicId: string;
    parts: SandboxV3RelicPart[];
}

export interface SandboxV3RelicPart {
    key: string;
    selector: string;
    allowMultiple: boolean;
    blackboard: Blackboard;
}

export interface SandboxV3StageInitialItemData {
    itemId: string;
    count: number;
}

export interface SandboxV3TrapData {
    trapCfgId: string;
    trapId: string;
    trapPhase: number;
    trapLevel: number;
    skillIndex: number;
    skillLevel: number;
    itemId: string;
    trapType: SandboxV3TrapType;
    trapIcon: string;
    prosperity: number;
    aesthetics: number;
    trapGroup: string;
    overrideMaxDeployCnt: number;
    handCoverItemId: string;
}

export interface SandboxV3ElectricTransferData {
    itemId: string;
    calType: SandboxV3ElectricTransferType;
    attackRange: string;
    attackRangeData: RangeData;
    skillParam: string;
    supplyType: string[];
    powerOutput: { [key: string]: number };
}

export interface SandboxV3BuildRuleData {
    buildType1: SandboxV3BaseBuildType;
    buildType2: string[];
    extraBuildScore: number;
    extraScoreDesc: string;
    sortId: number;
}

export interface SandboxV3BuildScoreData {
    itemId: string;
    paramType: SandboxV3BuildScoreType;
    buildScore: number;
    sortId: number;
}

export interface SandboxV3BuildScoreGroupData {
    sortId: number;
    scoreGroupType: ScoreGroupType;
}

export interface SandboxV3BaseTrapData {
    trapCfgId: string;
    trapId: string;
    trapPhase: number;
    trapLevel: number;
    skillIndex: number;
    skillLevel: number;
    itemId: string;
    upgradeItemId: string;
    trapType: SandboxV3BaseTrapType;
    buildType: SandboxV3BaseBuildType;
    buildScore: number;
    derivedBuildType: string[];
    derivedItemNMaxCnt: { [key: string]: number };
}

export interface SandboxV3BuildRecipeData {
    recipeCfgId: string;
    recipeItemId: string;
    materials: { [key: string]: number };
    outputItemId: string;
    outputTrapType: SandboxV3TrapType;
    withdrawRatio: number;
    outputCnt: number;
}

export interface SandboxV3ProcessRecipeData {
    recipeCfgId: string;
    recipeLevel: number;
    recipeItemId: string;
    materials: { [key: string]: number };
    outputItemId: string;
    outputCnt: number;
    outputProsperity: number;
    recipeName: string;
    outputSkillIcon: string;
}

export interface SandboxV3TrapTypeData {
    trapType: SandboxV3TrapType;
    typeName: string;
    typeImg: string;
    sortId: number;
    tagColor: string;
}

export interface SandboxV3BaseTrapTypeData {
    trapType: SandboxV3BaseTrapType;
    typeName: string;
    iconId: string;
    sortId: number;
}

export interface SandboxV3CoinCostData {
    coinType: SandboxShopCoinType;
    coinCount: number;
}

export interface SandboxV3BaseTrapUpgradeData {
    itemId: string;
    upgradeItemId: string;
    costCoinList: SandboxV3CoinCostData[];
    upgradeDesc: string;
    upgradeCondition: string;
    upgradeParamList: string[];
}

export interface SandboxV3BuildAnimalData {
    itemId: string;
    enemyId: string;
    isLegend: boolean;
    isShiny: boolean;
}

export interface SandboxV3BaseTrapDeployData {
    baseLevel: number;
    maxDeployCnt: number;
}

export interface SandboxV3ItemTypeData {
    itemType: SandboxPermItemType;
    itemTypeName: string;
    isShopSell: boolean;
    isBagShow: boolean;
    bagItemType: SandboxV3BagItemType;
}

export interface SandboxV3BagItemTypeData {
    bagItemType: SandboxV3BagItemType;
    bagItemTypeName: string;
    sortId: number;
    bagItemTypePic: string;
}

export interface SandboxV3ToolkitContentData {
    contentItemId: string;
    contentCntMin: number;
    contentCntMax: number;
}

export interface SandboxV3RandomItemData {
    poolId: string;
}

export interface SandboxV3ItemRandomPoolData {
    normalItemList: SandboxV3ItemRandomPoolData_Item[];
    guaranteeItemList: SandboxV3ItemRandomPoolData_Item[];
}

export interface SandboxV3ItemRandomPoolData_Item {
    itemId: string;
    count: number;
    weight: number;
}

export interface SandboxV3ItemExtraData {
    itemId: string;
    itemType: SandboxPermItemType;
    trapCfgId: string;
    recipeCfgId: string;
    relicCfgId: string;
    itemRarity: number;
    itemSortId1: number;
    itemSortId2: number;
    isBagPreview: boolean;
}

export interface SandboxV3EnemyRewardItem {
    itemId: string;
    count: number;
    rewardType: SandboxV3EnemyRewardType;
    weight: number;
}

export interface SandboxV3EnemyRewardData {
    sourceId: string;
    slotDict: { [key: number]: SandboxV3EnemyRewardItem[] };
}

export interface SandboxV3EnemyLevelRewardData {
    enemyLevelType: string;
    slotDict: { [key: number]: SandboxV3EnemyRewardItem[] };
}

export interface SandboxV3TaskSlotData {
    slotId: string;
    stageId: string;
    unlockDay: number;
    isFixed: boolean;
    fixedTasks: string[];
    taskLevel: number;
}

export interface SandboxV3TaskPoolData {
    poolId: string;
    taskWeights: SandboxV3TaskPoolWeightItem[];
}

export interface SandboxV3TaskPoolWeightItem {
    taskId: string;
    weight: number;
}

export interface SandboxV3TaskData {
    taskId: string;
    taskBaseDesc: string;
    taskDesc: string;
    taskLevel: number;
    difficulty: SandboxV3TaskDifficultyType;
    taskType: SandboxV3TaskType;
    taskTypeDesc: string;
    strParams: string[];
    intParams: number[];
    powerValue: number;
    rewards: string[];
    typeMask: number;
    checkRecipes: string[][];
    taskGroup: string;
    preTaskGroupChain: string[];
}

export interface SandboxV3AvgPostTaskData {
    taskId: string;
    avgId: string;
    questId: string;
}

export interface SandboxV3SubStageRoomConstraint {
    top: { [key: string]: number };
    bottom: { [key: string]: number };
    left: { [key: string]: number };
    right: { [key: string]: number };
}

export interface SandboxV3RandomMapPool {
    elements: { [key: string]: SandboxV3SubStageRoomConstraint };
}

export interface SandboxV3GameConst {
    basementGoldItemId: string;
    basementGoldExItemId: string;
    maxDefendCount: number;
    defendProgressVolume: number;
    defaultModeId: string;
    defaultDifficultyId: string;
    hardDifficultyLevel: number;
    basementMapUnlockLevel: number;
    defendUnlockLevel: number;
    highBgmBaseLevel: number;
    buildModeBgmHome: string;
    collectionBaseGoldId: string;
    collectionBaseGoldCount: number;
    collectionMinTime: number;
    collectionMaxTime: number;
    baseCoinMax: number;
    developmentPointsTotal: number;
    recruitBuyTime: number;
    recruitStartPrice: number;
    recruitPriceMultiply: number;
    recruitName: string;
    recruitUsage: string;
    shopDiscountRate: number;
    shopDiscountNumMin: number;
    shopDiscountNumMax: number;
    shopDiscountValueMin: number;
    shopDiscountValueMax: number;
    refreshPrice: number;
    multiplyFactor: number;
    maxRefreshPrice: number;
    refreshCoinType: SandboxShopCoinType;
    recruitCoinType: SandboxShopCoinType;
    characterLimit: number;
    maxLifePoint: number;
    initialCost: number;
    maxCost: number;
    giveUpRewardItemId: string;
    giveUpRewardItemCnt: number;
    recipeOriginRefreshTimes: number;
    recipeRepeatDamp: number;
    taskOptionCnt: number;
    taskRepeatDamp: number;
    taskOriginRefreshTimes: number;
    taskNotAllowRefreshStage: string[];
    taskTimeStampType: SandboxV3TaskType;
    aestheticsRewardItem: string;
    repeatRelicConvertId: string;
    repeatRecipeConvertId: string;
    repeatRecipeConvertCount: number;
    bagPreviewCnt: number;
    bagPreviewFixedItems: string[];
    bagPreviewFixedCnt: number;
    charRarityColorList: string[];
    spicedFoodNameFmt: string;
    essentialFoodMatItemId: string;
    baseCleanerItemId: string;
    baseStartPointLocation: string;
    electricPowerMax: number;
    basementNodeId: string;
    recipeRefreshPriceInit: number;
    recipeRefreshPriceAdd: number;
    recipeRefreshPriceMax: number;
    recipeRefreshItemId: string;
    dayPassRecruitRefreshItemId: string;
    dayPassRecruitRefreshCount: number[];
    dayPassRecruitSubProfessionCount: number;
    dayPassRecruitProfessionCount: number;
    tempRecruitPercentage: number;
    shopNpcRefreshStatus: string;
    imgLoadingNormalName: string;
    techTokenRatio: number;
    luckyRewardMax: number;
    bandAchievementScore: number;
    generalTrademanSkillIndex: number;
    generalTrademanAvgpath: string;
    hideCookEntryNodeIds: string[];
    hideShopEntryNodeIds: string[];
    showProcessorNotWorkingInterval: number;
    neutralBossEnemyId: string[];
    specialBossEnemyId: string[];
    taskPredecessorRampUp: number;
    rainbowShinyAnimalRateMul: number;
    enemyKillBlacklist: string[];
}

export interface SandboxV3Data {
    modeDatas: { [key: string]: SandboxV3ModeData };
    mainMapData: SandboxV3MapData;
    nodeTypeData: { [key: string]: SandboxV3NodeTypeData };
    stageData: { [key: string]: SandboxV3StageData };
    storyStageData: { [key: string]: SandboxV3StoryStageData };
    exploreStageData: { [key: string]: SandboxV3ExploreStageData };
    exploreStageDifficultyData: { [key: string]: SandboxV3ExploreStageDifficultyData };
    subStageData: { [key: string]: SandboxV3SubStageData };
    stageDropData: { [key: string]: SandboxV3StageDropData };
    navigationNodeIds: string[];
    itemTypeData: { [key: string]: SandboxV3ItemTypeData };
    bagItemTypeData: { [key: string]: SandboxV3BagItemTypeData };
    toolkitContentData: { [key: string]: SandboxV3ToolkitContentData };
    itemRandomPoolData: { [key: string]: SandboxV3ItemRandomPoolData };
    randomItemData: { [key: string]: SandboxV3RandomItemData };
    itemExtraData: { [key: string]: SandboxV3ItemExtraData };
    developmentData: { [key: string]: SandboxDevelopmentData };
    developmentLineSegmentDatas: SandboxDevelopmentLineSegmentData[];
    defendScoreData: SandboxV3DefendScoreData[];
    zoneDefendDatas: { [key: string]: SandboxV3ZoneDefendData };
    basementUpdateDatas: SandboxV3BasementUpdateData[];
    basementPreviewDatas: { [key: string]: SandboxV3BasementUpdateFunctionPreviewDetailData };
    wonderDatas: { [key: string]: SandboxV3WonderData };
    buildScoreGroupDatas: { [key: string]: SandboxV3BuildScoreGroupData };
    basementWeatherWeights: { [key: string]: number };
    questData: { [key: string]: SandboxV3QuestData };
    npcData: { [key: string]: SandboxV3NpcData };
    enemyNpcData: { [key: string]: SandboxV3EnemyNpcData };
    dialogData: { [key: string]: SandboxV3DialogData };
    questLineData: { [key: string]: SandboxV3QuestLineData };
    questLineStoryData: { [key: string]: string };
    guideQuestData: { [key: string]: SandboxV3GuideQuestData };
    cookbookData: { [key: string]: SandboxV3CookbookData };
    cookSpiceData: { [key: string]: SandboxV3CookSpiceData };
    baseShopGoodExtraData: { [key: string]: SandboxV3BaseShopGoodExtraData };
    baseShopGoodData: { [key: string]: SandboxPermShopGoodData };
    baseShopSellData: { [key: string]: SandboxPermShopSellData };
    baseShopCoinList: string[];
    baseTrapItemListMap: { [key: string]: string[] };
    stageShopListData: { [key: string]: SandboxV3StageShopData[] };
    shopDetailData: { [key: string]: SandboxV3ShopDetailData };
    shopTypeCoinMap: { [key: string]: string[] };
    shopGoodPoolData: { [key: string]: SandboxV3ShopGoodPoolData };
    shopGoodData: { [key: string]: SandboxPermShopGoodData };
    shopSellData: { [key: string]: SandboxPermShopSellData };
    shopCoinTypeData: { [key: string]: SandboxShopCoinTypeData };
    eventSceneData: { [key: string]: SandboxV3EventSceneData };
    eventChoiceData: { [key: string]: SandboxV3EventChoiceData };
    eventExpeditionData: { [key: string]: SandboxV3EventExpeditionData };
    trapData: { [key: string]: SandboxV3TrapData };
    trapTypeData: { [key: string]: SandboxV3TrapTypeData };
    baseTrapData: { [key: string]: SandboxV3BaseTrapData };
    electricTransferData: { [key: string]: SandboxV3ElectricTransferData };
    electricBuildingList: string[];
    baseTrapTypeData: { [key: string]: SandboxV3BaseTrapTypeData };
    buildRuleData: SandboxV3BuildRuleData[];
    buildScoreData: { [key: string]: SandboxV3BuildScoreData };
    baseTrapUpgradeData: { [key: string]: SandboxV3BaseTrapUpgradeData };
    buildAnimalData: { [key: string]: SandboxV3BuildAnimalData };
    baseTrapDeployMap: { [key: string]: SandboxV3BaseTrapDeployData[] };
    processRecipeData: { [key: string]: SandboxV3ProcessRecipeData };
    buildRecipeData: { [key: string]: SandboxV3BuildRecipeData };
    buildTipData: TipData[];
    enemyRewardData: { [key: string]: SandboxV3EnemyRewardData };
    enemyLevelRewardData: { [key: string]: SandboxV3EnemyLevelRewardData };
    milestoneRewardPools: { [key: string]: string[] };
    recipeWeight: { [key: string]: { [key: string]: number } };
    paramData: { [key: string]: SandboxV3StatParamData };
    weatherData: { [key: string]: SandboxV3WeatherData };
    runeDatas: { [key: string]: RuneTable_PackedRuneData };
    relicData: { [key: string]: SandboxV3RelicData };
    bandDataMap: { [key: string]: SandboxV3BandData };
    modeType2BandIdListMap: { [key: string]: string[] };
    taskSlotData: { [key: string]: SandboxV3TaskSlotData };
    taskPoolData: { [key: string]: SandboxV3TaskPoolData };
    taskData: { [key: string]: SandboxV3TaskData };
    avgPostTaskData: { [key: string]: SandboxV3AvgPostTaskData };
    livestockData: { [key: string]: SandboxV3LivestockData };
    achievementData: { [key: string]: SandboxArchiveAchievementData };
    achievementTypeData: { [key: string]: SandboxArchiveAchievementTypeData };
    archiveQuestData: { [key: string]: SandboxArchiveQuestData };
    archiveQuestTypeData: { [key: string]: SandboxArchiveQuestTypeData };
    archiveMusicUnlockData: { [key: string]: SandboxArchiveMusicUnlockData };
    gameConst: SandboxV3GameConst;
    shopUpdateTimeData: number[];
    extraLoadEnemies: string[];
    randomMapPool: { [key: string]: SandboxV3RandomMapPool };
}

export interface SandboxPermItemData {
    itemId: string;
    itemType: SandboxPermItemType;
    itemName: string;
    itemUsage: string;
    itemDesc: string;
    itemRarity: number;
    sortId: number;
    obtainApproach: string;
}

export interface SandboxPermEnrollPointData {
    enrollPointId: string;
    enrollTime: number;
}

export interface SandboxPermBasicData {
    topicId: string;
    topicTemplate: SandboxPermTemplateType;
    topicName: string;
    topicStartTime: number;
    fullStoredTime: number;
    sortId: number;
    priceItemId: string;
    templateShopId: string;
    homeEntryDisplayData: SandboxPermBasicData_HomeEntryDisplayData[];
    webBusType: string;
    medalGroupId: string;
    showMedalId: string;
    description: string;
    enrollPoints: { [key: string]: SandboxPermEnrollPointData };
}

export interface SandboxPermBasicData_HomeEntryDisplayData {
    displayId: string;
    topicId: string;
    startTs: number;
    endTs: number;
}

export interface SandboxPermDetailData {
    sandboxV2TemplateData: { [key: string]: SandboxV2Data };
    sandboxV3TemplateData: { [key: string]: SandboxV3Data };
    SANDBOX_V2: JsonValue;
    SANDBOX_V3: JsonValue;
}

export interface SandboxPermTable {
    basicInfo: { [key: string]: SandboxPermBasicData };
    detail: SandboxPermDetailData;
    itemData: { [key: string]: SandboxPermItemData };
}

export interface ShopKeeperWord {
    id: string;
    text: string;
}

export interface ShopClientData {
    recommendList: ShopRecommendItem[];
    creditUnlockGroup: { [key: string]: ShopCreditUnlockGroup };
    shopKeeperData: ShopClientData_ShopKeeperData;
    carousels: ShopCarouselData[];
    chooseShopRelations: ChooseShopRelation[];
    chooseOptionToGoodDict: { [key: string]: string };
    shopUnlockDict: { [key: string]: ShopUnlockType };
    extraQCShopRule: string[];
    repQCShopRule: string[];
    shopGPDataDict: { [key: string]: ShopClientGPData };
    tabDisplayData: { [key: string]: ShopGPTabDisplayData };
    shopMonthlySubGoodId: string;
    limitedShopSchedule: LMTGSShopSchedule[];
    overlaySchedule: LMTGSShopOverlaySchedule[];
    ls: JsonValue;
    os: JsonValue;
}

export interface ShopClientData_ShopKeeperData {
    welcomeWords: ShopKeeperWord[];
    clickWords: ShopKeeperWord[];
}

export interface LMTGSShopOverlaySchedule {
    gachaPoolId1: string;
    gachaPoolId2: string;
    picId: string;
}

export interface LMTGSShopSchedule {
    gachaPoolId: string;
    lMTGSId: string;
    iconColor: string;
    iconBackColor: string;
    storeTextColor: string;
    startTime: number;
    endTime: number;
}

export interface ShopRecommendItem {
    tagId: string;
    displayType: string;
    tagName: string;
    itemTag: RecommendItemTagTips;
    orderNum: number;
    startDatetime: number;
    endDatetime: number;
    groupList: ShopRecommendGroup[];
    tagWord: ShopKeeperWord;
    templateType: ShopRecommendTemplateType;
    templateParam: ShopRecommendTemplateParam;
}

export interface ShopRecommendTemplateParam {
    normalGiftParam: ShopRecommendTemplateNormalGiftParam;
    normalSkinParam: ShopRecommendTemplateNormalSkinParam;
    normalFurnParam: ShopRecommendTemplateNormalFurnParam;
    returnSkinParam: ShopRecommendTemplateReturnSkinParam;
}

export interface ShopRecommendTemplateNormalGiftParam {
    showStartTs: number;
    showEndTs: number;
    goodId: string;
    giftPackageName: string;
    price: number;
    logoId: string;
    color: string;
    haveMark: boolean;
    availCount: number;
}

export interface ShopRecommendTemplateNormalSkinParam {
    showStartTs: number;
    showEndTs: number;
    skinIds: string[];
    skinGroupName: string;
    brandIconId: string;
    colorBack: string;
    colorText: string;
    text: string;
}

export interface ShopRecommendTemplateNormalFurnParam {
    showStartTs: number;
    showEndTs: number;
    furnPackId: string;
    isNew: boolean;
    isPackSell: boolean;
    count: number;
    colorBack: string;
    colorText: string;
    actId: string;
}

export interface ShopRecommendTemplateReturnSkinParam {
    showStartTs: number;
    showEndTs: number;
}

export interface ShopClientGPData {
    goodId: string;
    giftPackageId: string;
    displayName: string;
    condTrigPackageType: ShopCondTrigPackageType;
}

export interface ShopRecommendGroup {
    recommendGroup: number[];
    dataList: ShopRecommendData[];
}

export interface ShopRecommendData {
    imgId: string;
    slotIndex: number;
    cmd: ShopRouteTarget;
    param1: string;
    param2: string;
    skinId: string;
    islocked: boolean;
}

export interface ShopCreditUnlockItem {
    sortId: number;
    unlockNum: number;
    charId: string;
}

export interface ShopCreditUnlockGroup {
    id: string;
    index: string;
    startDateTime: number;
    charDict: ShopCreditUnlockItem[];
}

export interface ChooseShopRelation {
    goodId: string;
    optionList: string[];
}

export interface ShopCarouselData {
    items: ShopCarouselData_Item[];
}

export interface ShopCarouselData_Item {
    spriteId: string;
    startTime: number;
    endTime: number;
    cmd: ShopRouteTarget;
    param1: string;
    skinId: string;
    furniId: string;
}

export interface ShopGPTabDisplayData {
    tabId: string;
    tabName: string;
    tabType: ShopGPTabType;
    recomDisplayNum: number;
    tabPicId: string;
    tabPicOnColor: string;
    tabPicOffColor: string;
    sortId: number;
    tabStartTime: number;
    tabEndTime: number;
    markerPicId: string;
}

export interface SpData {
    spType: SpType | number;
    levelUpCost: ItemBundle[];
    maxChargeTime: number;
    spCost: number;
    initSp: number;
    increment: number;
}

export interface SkillDataBundle {
    skillId: string;
    iconId: string;
    hidden: boolean;
    levels: SkillDataBundle_LevelData[];
}

export interface SkillDataBundle_LevelData {
    name: string;
    rangeId: string;
    description: string;
    skillType: SkillType;
    durationType: SkillDurationType;
    spData: SpData;
    prefabId: string;
    duration: number;
    blackboard: Blackboard;
}

export interface CharSkinData {
    EMPTY: CharSkinData;
    skinId: string;
    charId: string;
    tokenSkinMap: CharSkinData_TokenSkinInfo[];
    tmplId: string;
    voiceId: string;
    voiceType: SkinVoiceType;
    displaySkin: CharSkinData_DisplaySkin;
    illustId: string;
    spIllustId: string;
    dynIllustId: string;
    spDynIllustId: string;
    avatarId: string;
    spAvatarId: string;
    portraitId: string;
    spPortraitId: string;
    dynPortraitId: string;
    dynEntranceId: string;
    buildingId: string;
    battleSkin: string;
    isBuySkin: boolean;
}

export interface CharSkinData_DisplaySkin {
    skinName: string;
    colorList: string[];
    titleList: string[];
    modelName: string;
    drawerList: string[];
    designerList: string[];
    skinGroupId: string;
    skinGroupName: string;
    skinGroupSortIndex: number;
    content: string;
    dialog: string;
    usage: string;
    description: string;
    obtainApproach: string;
    sortId: number;
    displayTagId: string;
    getTime: number;
    onYear: number;
    onPeriod: number;
}

export interface CharSkinData_TokenSkinInfo {
    tokenId: string;
    tokenSkinId: string;
}

export interface CharSkinBrandInfo {
    brandId: string;
    groupList: CharSkinGroupInfo[];
    kvImgIdList: CharSkinKvImgInfo[];
    brandName: string;
    brandCapitalName: string;
    description: string;
    publishTime: number;
    sortId: number;
}

export interface CharSkinGroupInfo {
    skinGroupId: string;
    publishTime: number;
}

export interface CharSkinKvImgInfo {
    kvImgId: string;
    linkedSkinGroupId: string;
}

export interface SpecialSkinInfo {
    skinId: string;
    startTime: number;
    endTime: number;
}

export interface SpDynIllustInfo {
    skinId: string;
    spDynIllustId: string;
    spDynIllustSkinTag: string;
    spIllustId: string;
    spPortraitId: string;
    spAvatarId: string;
}

export interface SkinTable {
    charSkins: { [key: string]: CharSkinData };
    buildinEvolveMap: { [key: string]: { [key: number]: string } };
    buildinPatchMap: { [key: string]: { [key: string]: string } };
    brandList: { [key: string]: CharSkinBrandInfo };
    specialSkinInfoList: SpecialSkinInfo[];
    spDynSkins: { [key: string]: SpDynIllustInfo };
    spDynIllustSkinTagsMap: { [key: string]: string };
}

export interface SpecialOperatorBasicData {
    soCharId: string;
    sortId: number;
    targetType: SpecialOperatorTargetType;
    targetId: string;
    targetTopicName: string;
    bgId: string;
    bgEffectId: string;
    charEffectId: string;
    typeIconId: string;
}

export interface SpecialOperatorModeData {
    type: SpecialOperatorTargetType;
    typeName: string;
}

export interface SpecialOperatorConstData {
    weeklyTaskBoardUnlock: string;
    taskPinOnToast: string;
    noFrontNodeToast: string;
    noFrontTaskToast: string;
    skillGotoToast: string;
    evolveTabExpNotice: string;
    pinnedSpecialOperator: string;
}

export interface SpecialOperatorDetailTabData {
    soTabId: string;
    soTabName: string;
    soTabSortId: number;
    nodeType: SpecialOperatorDetailNodeType;
}

export interface SpecialOperatorDetailNodeUnlockData {
    nodeId: string;
    nodeType: SpecialOperatorDetailNodeType;
    isInGameMechanics: boolean;
    unlockEvolvePhase: EvolvePhase;
    unlockLevel: number;
    unlockTaskId: string;
    frontNodeId: string;
    ifAutoUnlock: boolean;
    conditionViewType: SpecialOperatorConditionViewType;
    topoOrder: number;
}

export interface SpecialOperatorDetailEvolveNodeData {
    nodeId: string;
    toEvolvePhase: EvolvePhase;
}

export interface SpecialOperatorDetailSkillNodeData {
    nodeId: string;
    skillKey: string;
    skillLevel: number;
    skillSpLevel: number;
}

export interface SpecialOperatorDetailTalentNodeData {
    nodeId: string;
    talentIndex: number;
    updateCount: number;
}

export interface SpecialOperatorDetailMasterNodeData {
    nodeId: string;
    masterId: string;
    level: number;
}

export interface SpecialOperatorDetailUniEquipNodeData {
    nodeId: string;
    uniEquipId: string;
    equipLevel: number;
}

export interface SpecialOperatorDetailConstData {
    nextRoundBuffToast: string;
}

export interface SpecialOperatorDiagramData {
    width: number;
    height: number;
    pointPosDataMap: { [key: string]: SpecialOperatorPointPosData };
    nodePointDataMap: { [key: string]: SpecialOperatorNodePointData };
    elitePointDataMap: { [key: string]: SpecialOperatorElitePointData };
    levelPointDataMap: { [key: string]: SpecialOperatorLevelPointData };
    linePosDataMap: { [key: string]: SpecialOperatorLinePosData };
    lineRelationDataMap: { [key: string]: SpecialOperatorLineRelationData };
}

export interface SpecialOperatorPointPosData {
    pos: JsonValue;
}

export interface SpecialOperatorElitePointData {
    evolvePhase: EvolvePhase;
}

export interface SpecialOperatorNodePointData {
    nodeId: string;
}

export interface SpecialOperatorLevelPointData {
    evolvePhase: EvolvePhase;
    level: number;
}

export interface SpecialOperatorLinePosData {
    startPos: JsonValue;
    endPos: JsonValue;
}

export interface SpecialOperatorLineRelationData {
    startPointList: string[];
    endPointList: string[];
}

export interface SpecialOperatorDetailData {
    specialOperatorExpMap: number[][];
    detailConstData: SpecialOperatorDetailConstData;
    tabData: { [key: string]: SpecialOperatorDetailTabData };
    nodeUnlockData: { [key: string]: SpecialOperatorDetailNodeUnlockData };
    evolveNodeData: { [key: string]: SpecialOperatorDetailEvolveNodeData };
    skillNodeData: { [key: string]: SpecialOperatorDetailSkillNodeData };
    talentNodeData: { [key: string]: SpecialOperatorDetailTalentNodeData };
    masterNodeData: { [key: string]: SpecialOperatorDetailMasterNodeData };
    uniEquipNodeData: { [key: string]: SpecialOperatorDetailUniEquipNodeData };
    nodeDiagramMap: { [key: string]: SpecialOperatorDiagramData };
}

export interface SpecialOperatorTable {
    operatorBasicData: { [key: string]: SpecialOperatorBasicData };
    operatorDetailData: { [key: string]: SpecialOperatorDetailData };
    modeData: SpecialOperatorModeData[];
    nodeUnlockMissionData: { [key: string]: MissionData };
    nodeUnlockMissionGroup: { [key: string]: MissionGroup };
    constData: SpecialOperatorConstData;
}

export interface StageValidInfo {
    startTs: number;
    endTs: number;
}

export interface StageFogInfo {
    lockId: string;
    fogType: FogType;
    stageButtonInFogRenderType: StageButtonInFogRenderType;
    stageId: string;
    lockName: string;
    lockDesc: string;
    unlockItemId: string;
    unlockItemType: ItemType;
    unlockItemNum: number;
    preposedStageId: string;
    preposedLockId: string;
}

export interface StageData {
    stageType: StageType;
    difficulty: LevelData_Difficulty;
    performanceStageFlag: StageData_PerformanceStageFlag;
    diffGroup: StageDiffGroup;
    unlockCondition: StageData_ConditionDesc[];
    stageId: string;
    levelId: string;
    zoneId: string;
    code: string;
    name: string;
    description: string;
    hardStagedId: string;
    sixStarStageId: string;
    dangerLevel: string;
    dangerPoint: number;
    loadingPicId: string;
    battleFinishLoadingPicId: string;
    canPractice: boolean;
    canBattleReplay: boolean;
    apCost: number;
    apFailReturn: number;
    maxSlot: number;
    etItemId: string;
    etCost: number;
    etFailReturn: number;
    etButtonStyle: string;
    apProtectTimes: number;
    diamondOnceDrop: number;
    practiceTicketCost: number;
    dailyStageDifficulty: number;
    expGain: number;
    goldGain: number;
    loseExpGain: number;
    loseGoldGain: number;
    passFavor: number;
    completeFavor: number;
    slProgress: number;
    displayMainItem: string;
    hilightMark: boolean;
    bossMark: boolean;
    isPredefined: boolean;
    isHardPredefined: boolean;
    isSkillSelectablePredefined: boolean;
    isStoryOnly: boolean;
    appearanceStyle: AppearanceStyle;
    stageDropInfo: StageData_StageDropInfo;
    canUseCharm: boolean;
    canUseTech: boolean;
    canUseTrapTool: boolean;
    canUseBattlePerformance: boolean;
    canUseFirework: boolean;
    canMultipleBattle: boolean;
    startButtonOverrideId: string;
    isStagePatch: boolean;
    mainStageId: string;
    s_extraCondition: StageData_ExtraConditionDesc[];
    s_extraInfo: StageData_SpecialStoryInfo[];
    sixStarBaseDesc: string;
    sixStarDisplayRewardList: ItemBundle[];
    advancedRuneIdList1: string[];
    advancedRuneIdList2: string[];
    useSpecialSizeMapPreview: boolean;
    extraCondition: { index: number; template: string; unlockParam: string[] }[];
    extraInfo: { stageId: string; rewards: ItemBundle[]; progressInfo: JsonValue; imageId: string; keyItemId: string; unlockDesc: string }[];
}

export interface StageData_DisplayRewards {
    type: ItemType;
    id: string;
    dropType: StageDropType;
}

export type StageData_DisplayDetailRewards = { occPercent: OccPer; type: ItemType; id: string; dropType: StageDropType };

export interface StageData_StageDropInfo {
    firstPassRewards: ItemBundle[];
    firstCompleteRewards: ItemBundle[];
    passRewards: WeightItemBundle[][];
    completeRewards: WeightItemBundle[][];
    displayRewards: StageData_DisplayRewards[];
    displayDetailRewards: StageData_DisplayDetailRewards[];
}

export interface StageData_ConditionDesc {
    stageId: string;
    completeState: PlayerBattleRank;
}

export interface StageData_ExtraConditionDesc {
    index: number;
    template: string;
    unlockParam: string[];
}

export interface StageData_SpecialStoryInfo {
    stageId: string;
    rewards: ItemBundle[];
    progressInfo: StageData_SpecialProgressInfo;
    imageId: string;
    keyItemId: string;
    unlockDesc: string;
}

export interface StageData_SpecialProgressInfo {
    progressType: StageData_SpecialStageUnlockProgressType;
    descList: { [key: number]: string };
}

export interface OverrideUnlockInfo {
    groupId: string;
    startTime: number;
    endTime: number;
    unlockDict: { [key: string]: StageData_ConditionDesc[] };
}

export interface OverrideDropInfo {
    itemId: string;
    startTs: number;
    endTs: number;
    zoneRange: string;
    times: number;
    name: string;
    egName: string;
    desc1: string;
    desc2: string;
    desc3: string;
    dropTag: string;
    dropTypeDesc: string;
    dropInfo: { [key: string]: StageData_StageDropInfo };
}

export interface TimelyDropTimeInfo {
    startTs: number;
    endTs: number;
    stagePic: string;
    dropPicId: string;
    stageUnlock: string;
    entranceDownPicId: string;
    entranceUpPicId: string;
    timelyGroupId: string;
    weeklyPicId: string;
    isReplace: boolean;
    apSupplyOutOfDateDict: { [key: string]: number };
}

export interface TimelyDropInfo {
    dropInfo: { [key: string]: StageData_StageDropInfo };
}

export interface RuneStageGroupData {
    groupId: string;
    activeRuneStages: RuneStageGroupData_RuneStageInst[];
    startTs: number;
    endTs: number;
}

export interface RuneStageGroupData_RuneStageInst {
    stageId: string;
    activePackedRuneIds: string[];
}

export interface MapThemeData {
    themeId: string;
    unitColor: string;
    buildableColor: string;
    themeType: string;
    trapTintColor: string;
    emissionColor: string;
    highlandBuildableColor: string;
    highlandEmissionColor: string;
}

export interface TileAppendInfo {
    tileKey: string;
    name: string;
    description: string;
    isFunctional: boolean;
}

export interface WeeklyForceOpenTable {
    id: string;
    startTime: number;
    endTime: number;
    forceOpenList: string[];
}

export interface StageDiffGroupTable {
    normalId: string;
    toughId: string;
    easyId: string;
}

export interface StoryStageShowGroup {
    displayRecordId: string;
    stageId: string;
    accordingStageId: string;
    diffGroup: StageDiffGroup;
}

export interface StageStartCond {
    requireChars: StageStartCond_RequireChar[];
    excludeAssists: string[];
    isNotPass: boolean;
}

export interface StageStartCond_RequireChar {
    charId: string;
    evolvePhase: EvolvePhase;
}

export interface SpecialBattleFinishStageData {
    stageId: string;
    skipAccomplishPerform: boolean;
}

export interface ApProtectZoneInfo {
    zoneId: string;
    timeRanges: ApProtectZoneInfo_TimeRange[];
}

export interface ApProtectZoneInfo_TimeRange {
    startTs: number;
    endTs: number;
}

export interface ActCustomStageData {
    overrideGameMode: OverrideGameMode;
}

export interface SixStarRuneData {
    runeId: string;
    runeDesc: string;
    runeKey: string;
}

export interface SixStarMilestoneGroupData {
    groupId: string;
    stageIdList: string[];
    milestoneDataList: SixStarMilestoneItemData[];
}

export interface SixStarMilestoneItemData {
    id: string;
    sortId: number;
    nodePoint: number;
    rewardType: SixStarMilestoneRewardType;
    unlockStageFog: string;
    unlockStageId: string;
    unlockStageName: string;
    rewardList: ItemBundle[];
}

export interface SixStarLinkedStageCompatibleInfo {
    stageId: string;
    apCost: number;
    apFailReturn: number;
    dropType: SixStarStageCompatibleDropType;
}

export interface ConditionalDropInfo {
    template: string;
    param: string[];
    countLimit: number;
}

export interface StageTable {
    stages: { [key: string]: StageData };
    runeStageGroups: { [key: string]: RuneStageGroupData };
    mapThemes: { [key: string]: MapThemeData };
    tileInfo: { [key: string]: TileAppendInfo };
    forceOpenTable: { [key: string]: WeeklyForceOpenTable };
    timelyStageDropInfo: { [key: string]: TimelyDropTimeInfo };
    overrideDropInfo: { [key: string]: OverrideDropInfo };
    overrideUnlockInfo: { [key: string]: OverrideUnlockInfo };
    timelyTable: { [key: string]: TimelyDropInfo };
    stageValidInfo: { [key: string]: StageValidInfo };
    stageFogInfo: { [key: string]: StageFogInfo };
    stageStartConds: { [key: string]: StageStartCond };
    diffGroupTable: { [key: string]: StageDiffGroupTable };
    storyStageShowGroup: { [key: string]: { [key: string]: StoryStageShowGroup } };
    specialBattleFinishStageData: { [key: string]: SpecialBattleFinishStageData };
    recordRewardData: { [key: string]: RecordRewardServerData };
    apProtectZoneInfo: { [key: string]: ApProtectZoneInfo };
    antiSpoilerDict: { [key: string]: string[] };
    actCustomStageDatas: { [key: string]: ActCustomStageData };
    spNormalStageIdFor4StarList: string[];
    storylines: { [key: string]: StorylineData };
    storylineStorySets: { [key: string]: StorylineStorySetData };
    storylineTags: { [key: string]: StorylineTagData };
    storylineConst: StorylineConstData;
    cgGalleryDisplays: { [key: string]: CGGalleryDisplayData };
    cgGalleryGroups: { [key: string]: CGGalleryGroupData };
    cgGalleryCgs: { [key: string]: CGGalleryCGData };
    sixStarRuneData: { [key: string]: SixStarRuneData };
    sixStarMilestoneInfo: { [key: string]: SixStarMilestoneGroupData };
    sixStarCompatibleInfo: { [key: string]: SixStarLinkedStageCompatibleInfo };
    conditionalDropInfo: { [key: string]: ConditionalDropInfo };
}

export interface StoryData {
    id: string;
    needCommit: boolean;
    repeatable: boolean;
    disabled: boolean;
    videoResource: boolean;
    trigger: StoryData_Trigger;
    condition: StoryData_Condition;
    setProgress: number;
    setFlags: string[];
    completedRewards: ItemBundle[];
    forceOmitCommit: boolean;
}

export interface StoryData_Trigger {
    TRIGGER_TYPE_NUM: number;
    type: StoryData_Trigger_TriggerType;
    key: string;
    useRegex: boolean;
}

export interface StoryData_Condition {
    minProgress: number;
    maxProgress: number;
    minPlayerLevel: number;
    requiredFlags: string[];
    excludedFlags: string[];
    requiredStages: StoryData_Condition_StageCondition[];
}

export interface StoryData_Condition_StageCondition {
    stageId: string;
    minState: PlayerStageState;
    maxState: PlayerStageState;
}

export interface StorylineData {
    storylineId: string;
    storylineType: StorylineType;
    sortId: number;
    storylineName: string;
    storylineIconId: string;
    storylineLogoId: string;
    backgroundId: string;
    hasVideoToPlay: boolean;
    startTs: number;
    locations: { [key: string]: StorylineLocationData };
}

export interface StorylineLocationData {
    locationId: string;
    locationType: StorylineLocationType;
    sortId: number;
    startTime: number;
    presentStageId: string;
    unlockStageId: string;
    relevantStorySetId: string;
    mainlineSplitData: StorylineMainlineSplitData;
}

export interface StorylineMainlineSplitData {
    iconId: string;
    subName: string;
}

export interface StorylineStorySetData {
    storySetId: string;
    storySetType: StorylineStorySetType;
    sortByYear: number;
    sortWithinYear: number;
    kvImageId: string;
    titleImageId: string;
    haveVideoToPlay: boolean;
    backgroundId: string;
    gameMusicId: string;
    coreRewardType: ItemType;
    coreRewardId: string;
    relevantActivityId: string;
    mainlineData: StorylineMainlineData;
    ssData: StorylineSSData;
    collectData: StorylineCollectData;
}

export interface StorylineMainlineData {
    zoneId: string;
    retroId: string;
    decoImageId: string;
    desc: string;
    backgroundId: string;
    tags: string[];
}

export interface StorylineSSData {
    desc: string;
    backgroundId: string;
    tags: string[];
    reopenActivityId: string;
    retroActivityId: string;
    isRecommended: boolean;
    recommendHideStageId: string;
    overrideStageList: string[];
}

export interface StorylineCollectData {
    desc: string;
    backgroundId: string;
}

export interface StorylineTagData {
    tagId: string;
    sortId: number;
    tagDesc: string;
    textColor: string;
    bkgColor: string;
}

export interface StorylineConstData {
    recommendHideGuideGroupId: string;
    tutorialSelectStorylineId: string;
    mainlineStorylineId: string;
}

export interface StoryReadTipsData {
    key: string;
    picId: string;
    mainText: string;
    confirmText: string;
    isAll: boolean;
    stageIdList: string[];
}

export interface StoryReviewInfoClientData {
    storyReviewType: StoryReviewType;
    storyId: string;
    storyGroup: string;
    storySort: number;
    storyDependence: string;
    storyCanShow: number;
    storyCode: string;
    storyName: string;
    storyPic: string;
    storyInfo: string;
    storyCanEnter: number;
    storyTxt: string;
    avgTag: string;
    unLockType: StoryReviewUnlockType;
    costItemType: ItemType;
    costItemId: string;
    costItemCount: number;
    stageCount: number;
    requiredStages: StoryData_Condition_StageCondition[];
}

export type StoryReviewGroupClientData = {
    id: string;
    name: string;
    entryType: StoryReviewEntryType;
    actType: StoryReviewType;
    startTime: number;
    endTime: number;
    startShowTime: number;
    endShowTime: number;
    remakeStartTime: number;
    remakeEndTime: number;
    storyEntryPicId: string;
    storyPicId: string;
    storyMainColor: string;
    customType: number;
    storyCompleteMedalId: string;
    rewards: ItemBundle[];
    infoUnlockDatas: StoryReviewInfoClientData[];
} & { [key: string]: JsonValue };

export interface StoryReviewMetaTable {
    miniActTrialData: MiniActTrialData;
    actArchiveResData: ActArchiveResData;
    actArchiveData: ActArchiveComponentTable;
    trainingCampData: TrainingCampData;
}

export interface TrainingCampConsts {
    unlockStageId: string;
    updateDesc: string;
    rewardItem: ItemBundle;
}

export interface TrainingCampStageData {
    stageId: string;
    stageIconId: string;
    sortId: number;
    levelId: string;
    code: string;
    name: string;
    loadingPicId: string;
    description: string;
    endCharId: string;
    updateTs: number;
}

export interface TrainingCampData {
    stageData: { [key: string]: TrainingCampStageData };
    newTrainingCampStages: NewTrainingCampStageData[];
    consts: TrainingCampConsts;
}

export interface NewTrainingCampStageData {
    updateTs: number;
    stages: string[];
}

export interface MiniActTrialData {
    preShowDays: number;
    ruleDataList: MiniActTrialData_RuleData[];
    miniActTrialDataMap: { [key: string]: MiniActTrialData_MiniActTrialSingleData };
}

export interface MiniActTrialData_RuleData {
    ruleType: MiniActTrialData_RuleType;
    ruleText: string;
}

export interface MiniActTrialData_MiniActTrialSingleData {
    actId: string;
    rewardStartTime: number;
    themeColor: string;
    rewardList: MiniActTrialData_MiniActTrialRewardData[];
}

export interface MiniActTrialData_MiniActTrialRewardData {
    trialRewardId: string;
    orderId: number;
    actId: string;
    targetStoryCount: number;
    item: ItemBundle;
}

export interface ActArchiveResData {
    pics: { [key: string]: ActArchiveResData_PicArchiveResItemData };
    audios: { [key: string]: ActArchiveResData_AudioArchiveResItemData };
    avgs: { [key: string]: ActArchiveResData_AvgArchiveResItemData };
    stories: { [key: string]: ActArchiveResData_StoryArchiveResItemData };
    news: { [key: string]: ActArchiveResData_NewsArchiveResItemData };
    landmarks: { [key: string]: ActArchiveResData_LandmarkArchiveResItemData };
    logs: { [key: string]: ActArchiveResData_LogArchiveResItemData };
    challengeBooks: { [key: string]: ActArchiveResData_ChallengeBookArchiveResItemData };
}

export interface ActArchiveResData_PicArchiveResItemData {
    id: string;
    desc: string;
    assetPath: string;
    type: ActArchivePicType;
    subType: string;
    picDescription: string;
    kvId: string;
}

export interface ActArchiveResData_AudioArchiveResItemData {
    id: string;
    desc: string;
    name: string;
}

export interface ActArchiveResData_AvgArchiveResItemData {
    id: string;
    desc: string;
    breifPath: string;
    contentPath: string;
    imagePath: string;
    rawBrief: string;
    titleIconPath: string;
}

export interface ActArchiveResData_StoryArchiveResItemData {
    id: string;
    desc: string;
    date: string;
    pic: string;
    text: string;
    titlePic: string;
}

export interface ActArchiveResData_NewsArchiveResItemData {
    id: string;
    desc: string;
    newsType: string;
    newsFormat: ActArchiveResData_NewsFormatData;
    newsText: string;
    newsAuthor: string;
    paramP0: number;
    paramK: number;
    paramR: number;
    newsLines: ActArchiveResData_ActivityNewsLine[];
}

export interface ActArchiveResData_NewsFormatData {
    typeId: string;
    typeName: string;
    typeLogo: string;
    typeMainLogo: string;
    typeMainSealing: string;
}

export interface ActArchiveResData_ActivityNewsLine {
    lineType: ActArchiveResData_ArchiveNewsLineType;
    content: string;
}

export interface ActArchiveResData_LandmarkArchiveResItemData {
    landmarkId: string;
    landmarkName: string;
    landmarkPic: string;
    landmarkDesc: string;
    landmarkEngName: string;
}

export interface ActArchiveResData_LogArchiveResItemData {
    logId: string;
    logDesc: string;
}

export interface ActArchiveResData_ChallengeBookArchiveResItemData {
    storyId: string;
    titleName: string;
    storyName: string;
    textId: string;
}

export interface ActArchiveComponentTable {
    components: { [key: string]: ActArchiveComponentData };
}

export interface ActArchiveComponentData {
    timeline: ActArchiveTimelineData;
    music: ActArchiveMusicData;
    pic: ActArchivePicData;
    story: ActArchiveStoryData;
    avg: ActArchiveAvgData;
    news: ActArchiveNewsData;
    landmark: { [key: string]: ActArchiveLandmarkItemData };
    log: { [key: string]: ActArchiveChapterLogData };
    challengeBook: ActArchiveChallengeBookData;
}

export interface TalentData {
    unlockCondition: CharacterData_UnlockCondition;
    requiredPotentialRank: number;
    prefabKey: string;
    name: string;
    description: string;
    rangeId: string;
    blackboard: Blackboard;
    tokenKey: string;
    isHideTalent: boolean;
}

export interface EquipTalentData {
    unlockCondition: CharacterData_UnlockCondition;
    requiredPotentialRank: number;
    prefabKey: string;
    name: string;
    description: string;
    rangeId: string;
    blackboard: Blackboard;
    tokenKey: string;
    isHideTalent: boolean;
    displayRangeId: boolean;
    upgradeDescription: string;
    talentIndex: number;
    validModeIndices: number[];
}

export interface TermDescriptionData {
    termId: string;
    termName: string;
    description: string;
}

export interface TipData {
    tip: string;
    weight: number;
    category: TipData_Category;
}

export interface UniEquipTable {
    equipDict: { [key: string]: UniEquipData };
    missionList: { [key: string]: UniEquipMissionData };
    subProfDict: { [key: string]: SubProfessionData };
    subProfToProfDict: { [key: string]: number };
    charEquip: { [key: string]: string[] };
    equipTypeInfos: UniEquipTypeInfo[];
    equipTrackDict: UniEquipTimeInfo[];
}

export interface SubProfessionData {
    subProfessionId: string;
    subProfessionName: string;
    subProfessionCatagory: number;
}

export interface UniEquipTimeInfo {
    timeStamp: number;
    trackList: UniEquipTrack[];
}

export interface UniEquipTypeInfo {
    uniEquipTypeName: string;
    sortId: number;
    isSpecial: boolean;
    isInitial: boolean;
}

export interface UniEquipTrack {
    charId: string;
    equipId: string;
    type: UniEquipType;
    archiveShowTimeEnd: number;
}

export interface UniEquipData {
    uniEquipId: string;
    uniEquipName: string;
    uniEquipIcon: string;
    uniEquipDesc: string;
    typeIcon: string;
    typeName1: string;
    typeName2: string;
    equipShiningColor: string;
    showEvolvePhase: EvolvePhase;
    unlockEvolvePhase: EvolvePhase;
    charId: string;
    tmplId: string;
    showLevel: number;
    unlockLevel: number;
    missionList: string[];
    unlockFavors: { [key: string]: number };
    itemCost: { [key: number]: ItemBundle[] };
    type: UniEquipType;
    uniEquipGetTime: number;
    uniEquipShowEnd: number;
    charEquipOrder: number;
    hasUnlockMission: boolean;
    isSpecialEquip: boolean;
    specialEquipDesc: string;
    specialEquipColor: string;
    charColor: string;
}

export interface UniEquipMissionData {
    template: string;
    desc: string;
    paramList: string[];
    uniEquipMissionId: string;
    uniEquipMissionSort: number;
    uniEquipId: string;
    jumpStageId: string;
}

export interface VoiceLangData {
    wordkeys: string[];
    charId: string;
    voiceLangInfoDataDict: { [key: string]: VoiceLangInfoData };
    dict: JsonValue;
}

export interface VoiceLangTypeData {
    name: string;
    groupType: VoiceLangGroupType;
}

export interface VoiceLangGroupData {
    name: string;
    members: VoiceLangType[];
}

export interface VoiceLangInfoData {
    wordkey: string;
    voiceLangType: VoiceLangType;
    cvName: string[];
    voicePath: string;
}

export interface NewVoiceTimeData {
    timestamp: number;
    charSet: string[];
}

export interface ExtraVoiceConfigData {
    voiceId: string;
    validVoiceLang: VoiceLangType[];
}

export interface ZoneData {
    zoneID: string;
    zoneIndex: number;
    type: ZoneType;
    zoneNameFirst: string;
    zoneNameSecond: string;
    zoneNameTitleCurrent: string;
    zoneNameTitleUnCurrent: string;
    zoneNameTitleEx: string;
    zoneNameThird: string;
    lockedText: string;
    antiSpoilerId: string;
    canPreview: boolean;
    hasAdditionalPanel: boolean;
    sixStarMilestoneGroupId: string;
    bindMainlineZoneId: string;
    bindMainlineRetroZoneId: string;
    diamondRewardCount: number;
}

export interface WeeklyZoneData {
    daysOfWeek: number[];
    type: WeeklyType;
}

export interface MainlineZoneData {
    zoneID: string;
    chapterId: string;
    preposedZoneId: string;
    zoneIndex: number;
    startStageId: string;
    endStageId: string;
    gameMusicId: string;
    recapId: string;
    recapPreStageId: string;
    buttonName: string;
    buttonStyle: MainlineZoneData_ZoneReplayBtnType;
    spoilAlert: boolean;
    zoneOpenTime: number;
    diffGroup: StageDiffGroup[];
}

export interface ZoneValidInfo {
    startTs: number;
    endTs: number;
}

export interface ZoneTable {
    zones: { [key: string]: ZoneData };
    weeklyAdditionInfo: { [key: string]: WeeklyZoneData };
    zoneValidInfo: { [key: string]: ZoneValidInfo };
    mainlineAdditionInfo: { [key: string]: MainlineZoneData };
    zoneRecordGroupedData: { [key: string]: ZoneRecordGroupData };
    zoneRecordRewardData: { [key: string]: string[] };
    mainlineZoneIdList: string[];
    zoneMetaData: ZoneMetaData;
}

export interface ZoneRecordGroupData {
    zoneID: string;
    records: ZoneRecordData[];
    unlockData: ZoneRecordUnlockData;
}

export interface ZoneRecordData {
    recordId: string;
    zoneID: string;
    recordTitleName: string;
    preRecordId: string;
    nodeTitle1: string;
    nodeTitle2: string;
    rewards: RecordRewardInfo[];
}

export interface RecordRewardInfo {
    bindStageId: string;
    stageDiff1: RecordRewardStageDiff;
    stageDiff: StageDiffGroup;
    picRes: string;
    textPath: string;
    textDesc: string;
    recordReward: ItemBundle[];
}

export interface RecordRewardServerData {
    stageId: string;
    rewards: ItemBundle[];
}

export interface ZoneRecordUnlockData {
    noteId: string;
    zoneID: string;
    initialName: string;
    finalName: string;
    accordingExposeId: string;
    initialDes: string;
    finalDes: string;
    remindDes: string;
}

export interface ZoneMetaData {
    zoneRecordMissionData: { [key: string]: ZoneRecordMissionData };
}

export interface ZoneRecordMissionData {
    missionId: string;
    recordStageId: string;
    templateDesc: string;
    desc: string;
}

export interface ArkventAudioSpatialProfile {
    type: ArkventAudioSpatialType;
    name: string;
}

export interface ArkventAudioSourceData {
    id: string;
    positionX: number;
    positionY: number;
    positionZ: number;
    module: string;
    signal: string;
    subSignal: string;
    meta: ArkventAudioMetaFlag;
    soundPlaybackPolicy: number;
    minDist: number;
    maxDist: number;
    rollOffType: ArkventAudioRollOffType;
    spatialBlend: ArkventAudioSpatialProfile;
    spatialVolume: ArkventAudioSpatialProfile;
    volume: number;
    effectiveRange: ArkventRangeData;
    triggerMode: ArkventAudioTriggerMode;
    periodicFixedInterval: number;
    periodicMinInterval: number;
    periodicMaxInterval: number;
    applyIntervalOnFirstPlay: boolean;
    fadeOutTime: number;
    mutexGroup: string;
    mutexOrder: number;
    bindActors: string[];
    tags: string[];
}

export interface ArkventRangeData {
    type: ArkventRangeType;
    position: JsonValue;
    bounds: JsonValue;
}

