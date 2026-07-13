/**
 * 自动生成的玩家数据类型定义文件
 * 从 com.hypergryph.arknights_2.7.51.cs 反编译文件生成
 * 请勿手动修改此文件
 */

export type SandboxV2BattleAvgChoiceType = "ADD_ITEM" | "ADD_FAVOR" | "ORDER_RIFT" | "GACHA";

export type BuildingToDoCategory = "NONE" | "NORMAL" | "EMERGENCY";

export type AutoChessBattleShopGoodsType = "NORMAL" | "COMB" | "BUFF";

export type AutoChessPlayerGameStateType = "LOADING_NOT_READY" | "LOADING_READY" | "PREPARATION_NOT_READY" | "PREPARATION_READY" | "BATTLE_NOT_COMPLETE" | "BATTLE_COMPLETE";

export type AutoChessPlayerConnectStateType = "ONLINE" | "MISS_CONN" | "QUIT";

export type AutoChessSettleStateType = "FAILED" | "SUCCESS";

export type AutoChessBattleDamageSrcType = "UNKNOWN" | "CHAR" | "TRAP" | "NOSOURCE_CHAR";

export type AutoChessGameStateType = "NONE" | "LOADING" | "SP_PREPARE" | "PREPARE" | "BATTLE" | "HELP_BATTLE" | "BOSS_BATTLE" | "SETTLE" | "END" | "PAUSE" | "BATTLE_WAITING" | "BOSS_PREPARE_WAITING" | "PREPARE_RESTART" | "SP_PREPARE_RESTART" | "BOSS_BATTLE_RESTART";

export type BossPlayerGroup = string;

export type AutoChessBattleStepActionOperate = "ENEMY_KILLED" | "ENEMY_ESCAPED" | "COST_BOSS_HP" | "SUMMONED_ENEMY_ESCAPED" | "ENEMY_APPEAR" | "SUMMONED_ENEMY_APPEAR" | "ENEMY_FINISHED" | "BOSS_STATE_CHANGED" | "BATTLE_STATE_CHANGED" | "PLAYER_STATUS_CHANGED";

export type StageType = "MAIN" | "DAILY" | "TRAINING" | "ACTIVITY" | "GUIDE" | "SUB" | "CAMPAIGN" | "SPECIAL_STORY" | "HANDBOOK_BATTLE" | "CLIMB_TOWER" | "ENUM";

export type BuildingGetFurnitureGoodListResponse_FurnShopDisplayPlace = "BUILDING" | "ALL";

export type BuildingBuyFurnitureGoodRequest_CostType = "COIN_FURN" | "DIAMOND";

export type CharRotationUpdatePresetRequest_UpdateFlag = "PRESET_NAME" | "HOME_BACKGROUND" | "HOME_THEME" | "PRESET_SECRETARY" | "PRESET_SLOTS";

export type CrisisShopTitleType = "SEASON" | "REMASTERED" | "NONE";

export type EditNameCardFlag = "NONE" | "COMPONENT_ORDER" | "SKIN_ID" | "MISC" | "SKIN_TMPL";

export type GachaType = string;

export type PlayerSyncModuleMask = "NONE" | "UNREAD_MAILS" | "FRIEND_REQ" | "ANNOUNCE_VER" | "REFRESH_USER_CARD" | "GOOD_PURCHASE_STATE" | "CASH_PURCHASE_STATE" | "CLUE_STATE" | "SYNC_BUILDING" | "SYNC_CRISIS" | "SYNC_ACTIVITY" | "SYNC_MEDAL" | "CHECK_FORBIDDEN" | "SYNC_ACTIVITY_FIXED_INTERVAL";

export type GachaVoucherType = string;

export type RoguelikeDiceChoiceRequest_Choice = "REROLL" | "LEAVE";

export type ShopQCGoodType = "NORMAL" | "PROGRESS";

export type ExtraShopGroupType = "TEMP" | "PERM" | "MONTH";

export type PlayerAvatarType = "NONE" | "ASSISTANT" | "ICON" | "DEFAULT";

export type PlayerSpecialOperatorNode_State = "LOCK" | "CONFIRMED";

export type PlayerActivity_PlayerMultiplayV2Activity_DailyMissionState = "NOT_CLAIM" | "CLAIMED";

export type PlayerActivity_PlayerMultiplayV2Activity_StageState = "LOCK" | "UNLOCKED";

export type PlayerActivity_PlayerEnemyDuelActivity_DailyMissionState = "NOT_CLAIM" | "CLAIMED";

export type PlayerActivity_PlayerArcadeActivity_BadgeStatus = string;

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

export type PlayerSixStarTagFinishState = "NONE";

export type PlayerSixStarMilestoneState = "UNLOCK" | "FINISH" | "CONFIRMED";

export type PlayerCampaign_MissionState = "UNCOMPLETE" | "COMPLETE" | "FINISHED";

export type PlayerRecruit_NormalModel_SlotModel_State = "LOCK" | "IDLE" | "BUSY" | "FAST_FINISH";

export type PlayerGacha_PlayerDoubleGacha_HitCharState = "NONE" | "FIRST" | "SECOND";

export type NameCardMedalType = "EMPTY" | "CUSTOM" | "TEMPLATE";

export type PlayerTroop_CharMissionState = "UNCOMPLETE" | "FULLFILLED" | "COMPLETE";

export type PlayerInviteType = "ACTIVITY";

export type PlayerBuildingHiringState = "EMPTY" | "HIRING";

export type PlayerBuildingTrainerState = "EMPTY" | "TRAINING" | "FINISH" | "WAITING";

export type PlayerBuildingTraineeState = "EMPTY" | "TRAINING" | "OUTOFDATE" | "WAITING";

export type MissionHoldingState = "NOT_OPEN" | "IN_EFFECT" | "CONFIRMED" | "FINISHED";

export type MissionPlayerData_MissionGroupState = string;

export type PlayerCrisisV2Season_RuneState = "UNKNOWN" | "LOCKED" | "UNLOCK" | "FINISH";

export type PlayerCrisisV2Season_NodeState = "INACTIVE" | "ACTIVED" | "CLAIMED";

export type PlayerCrisisV2Season_BagState = "INCOMPLETE" | "COMPLETED" | "CLAIMED";

export type PlayerRecalRuneStage_State = "NO_PASS" | "PASSED";

export type PlayerRecalRuneReward_State = "UNCLAIMED" | "CLAIMED";

export type PlayerRoguelikeState = "NONE" | "GAME_REWARD_RELIC" | "GAME_REWARD_SCENE" | "GAME_REWARD_RECRUIT" | "MOVE_WAIT" | "BUY_WAIT" | "CHOICE_WAIT" | "REWARD_WAIT" | "BATTLE_WAIT_START" | "BATTLE_WAIT_END" | "GAME_END";

export type PlayerNodeForesightType = "NORMAL" | "HIDE_INVISIBLE" | "HIDE_BATTLE" | "PRESAGE";

export type RoguelikeArchiveItemUnlockStatus = "LOCKED" | "UNATTAINED" | "ATTAINED";

export type PlayerRoguelikeV2_CurrentData_PlayerStatus_Properties_RewardHpShowStatus = "NONE" | "NORMAL" | "HIDDEN";

export type PlayerRoguelikeV2_CurrentData_PlayerStatus_NodeMission_NodeMissionState = "NOT_COMPLETED" | "COMPLETED" | "ALL_FINISHED";

export type PlayerRoguelikeV2_CurrentData_Troop_ExpedType = "EXPED" | "TRAVEL" | "CANDLE" | "NO_UPGRADE" | "GUIDED" | "NON_GUIDED" | "ENDING_RELIC";

export type PlayerRoguelikeV2_CurrentData_Recruit_State = "CREATE" | "ACTIVE" | "DONE";

export type PlayerRoguelikeV2_CurrentData_Module_SkyZoneNodeState = "LOCK" | "UNLOCK" | "FINISH" | "CLOSE";

export type PlayerRoguelikeV2_CurrentData_Module_GridMapZoneNodeStatus = "NOT_REACHED" | "RECURSIVE" | "FINISHED";

export type PlayerRoguelikeV2_OuterData_PlayerRogueActivity_PlayerRogueActivityUnlockInfo_PlayerRogueActivityUnlockState = "LOCKED" | "UNLOCKED_UNPLAYED" | "UNLOCKED_PLAYED";

export type PlayerReturnData_Version = "OLD" | "NEW";

export type PlayerRoguelikePlayerState = "NONE" | "INIT" | "PENDING" | "WAIT_MOVE";

export type PlayerRoguelikeZoneType = "NORMAL" | "SP";

export type RoguelikeBattleFailDisplay = "NORMAL";

export type PlayerRoguelikePlayerEventType = "NONE" | "GAME_INIT_MODE_RELIC" | "GAME_INIT_TEAM" | "GAME_INIT_RELIC" | "GAME_INIT_GIFT" | "GAME_INIT_SUPPORT" | "GAME_INIT_SUPPORT_MULTI" | "GAME_INIT_RECRUIT_SET" | "GAME_INIT_RECRUIT" | "GAME_INIT_EXPLORE_TOOL" | "GAME_INIT_END" | "RECRUIT" | "BATTLE" | "BATTLE_REWARD" | "SCENE" | "SHOP" | "GAME_SETTLE" | "DICE" | "SACRIFICE" | "EXPEDITION" | "BATTLE_SHOP" | "PREDICT" | "ALCHEMY" | "ALCHEMY_REWARD" | "CHANGE_COPPER" | "DRAW_COPPER" | "USE_STASHED_TICKET" | "GILD_COPPER";

export type PlayerRoguelikePendingEvent_PlayerRoguelikeChoiceRewardType = "NONE" | "ITEM" | "MISSION";

export type PlayerRoguelikePendingEvent_DrawCopperHitReason = "NORMAL" | "BUFF_EXTRA" | "FREEZE";

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

export type PlayerMainlineClue_ClueState = "LOCK" | "UNLOCK";

export type PlayerMissionArchiveNodeState = "LOCKED" | "UNLOCKED" | "CLAIMED";

export type PlayerSandboxV2_GameState = "INACTIVE" | "ACTIVE" | "SETTLE_DATE" | "READING_ARCHIVE";

export type PlayerSandboxV2_NodeState = "LOCKED" | "UNLOCKED" | "COMPLETED";

export type PlayerSandboxV2_StageState = "UNEXPLORED" | "EXPLORED" | "COMPLETED";

export type PlayerSandboxV2_Dungeon_FloatSourceType = "NONE" | "SRC_QUEST" | "SRC_MARKET" | "SRC_RIFT_MAIN";

export type PlayerSandboxV2_RiftInfo_RiftGameStatus = "ACTIVE" | "SETTLE" | "INVALID";

export type PlayerSandboxV2_Challenge_ChallengeStatus = "NOT_IN_CHALLENGE" | "IN_CHALLENGE" | "CHALLENGE_SETTLE" | "UNDEFINED";

export type PlayerSandboxV3StageState = "NOT_PLAYED" | "NOT_COMPLETE" | "COMPLETED";

export type PlayerSandboxV3GameState = "NONE" | "BAND_SELECT" | "INIT_GAP" | "IN_BATTLE" | "GAP_REPORT" | "EXPEDITION" | "NORM_GAP" | "GAME_FINISH";

export type PlayerSandboxV3Node_State = "UNLOCK" | "PLAYED" | "PASSED";

export type PlayerSandboxV3Npc_DialogType = "NONE" | "BEFORE_BATTLE" | "IN_BATTLE" | "AFTER_BATTLE";

export type PlayerSandboxV3QuestGroup_Quest_State = "UNCOMPLETE" | "COMPLETED" | "CLOSED";

export type PlayerSandboxV3Difficulty_State = "LOCK" | "UNLOCK" | "PASSED";

export type SandboxV3SquadCharType = "PLAYER_REPO" | "TRYOUT_CHAR" | "TEMP_RECRUIT" | "ROOKIE" | "ASSIST" | "PRE_DEFINED" | "DEFEND";

export type PlayerData_FakeInstType = "VAULT" | "ASSIST" | "PREDEFINED";

export type PlayerDataDelta_TypeCategory = "NONE" | "CLS" | "MAP" | "JOBJ" | "MISC";

export type RoguelikeCopperType = "NONE" | "BLANK" | "FIGHT" | "RESOURCE" | "UNSOUND" | "TREASURE" | "SPECIAL";

export type Act12SideData_ActZoneClass = "NONE" | "NORMAL" | "HIGHLEVEL" | "SUB";

export type Act13SideData_ActZoneClass = "NONE" | "NORMAL" | "HIGHLEVEL" | "SUB";

export type Act17sideData_ArchiveItemStageUnlockParam = "NONE" | "PLAYED" | "PASS" | "COMPLETE";

export type Act1VHalfIdleGachaPoolType = "NONE" | "GACHA_NORMAL" | "GACHA_NEWPLAYER" | "GACHA_PAC" | "GACHA_DIRECT";

export type Act1VHalfIdleEquipType = "WEAPON" | "ARMOR" | "ACCESSORY" | "NUM";

export type CartComponents_CartAccessoryType = "NONE" | "ROOF" | "HEADSTOCK" | "TRUNK" | "CAR_OS";

export type CartComponents_CartAccessoryPos = "NONE" | "ROOF" | "HEADSTOCK";

export type CartCompetitionRank = "NONE" | "B" | "A" | "S" | "SS";

export type SiracusaData_ZoneUnlockType = "NONE" | "STAGE_UNLOCK" | "TASK_UNLOCK";

export type SiracusaData_CardGainType = "NONE" | "STAGE_GAIN" | "TASK_GAIN";

export type SiracusaData_TaskRingLogicType = "NONE" | "LINEAR" | "AND" | "OR";

export type SiracusaData_TaskType = "NONE" | "BATTLE" | "AVG";

export type SiracusaData_NavigationType = "NONE" | "AVG" | "LEVEL" | "CHAR_CARD";

export type Act24SideData_MeldingGoodGachaType = "NONE" | "LIMITED" | "UNLIMITED";

export type Act24SideData_MissionType = "NONE" | "HUNTING_TASK" | "COLLECTION_TASK" | "EXPLORATION_TASK" | "MONSTER_TASK" | "INVATION_TASK";

export type Act3D0Data_GachaBoxType = "LIMITED" | "UNLIMITED";

export type Act9D0Data_ActivityNewsLineType = string;

export type AutoChessEffectType = "NONE" | "BAND_INITIAL" | "ENEMY" | "ENEMY_TEMPORARY" | "ALLY" | "EQUIP" | "MAGIC" | "CHAR_MAP" | "BOND" | "ENEMY_GAIN" | "BUFF_GAIN" | "GARRISON";

export type AutoChessPrepareStepType = "NONE" | "INFO_CHECK" | "BAND_CHECK" | "BATTLE_CHECK";

export type AutoChessBondType = "NONE" | "REGULAR" | "SEASON";

export type AutoChessShopTokenDisplayType = "DEFAULT" | "HIDDEN";

export type AutoChessSkillTriggerType = "DEFAULT" | "ALWAYS" | "SEARCH" | "MLYSS_WTRMAN" | "TRY_SEARCH_ENEMY_SKILL" | "TRY_SEARCH_ALLY_SKILL" | "CUSTOM_RANGE_SEARCH_ENEMY" | "CUSTOM_RANGE_SEARCH_ALLY" | "ACT_DEFAULT" | "AUTO_STOP" | "TAKE_DAMAGE";

export type AutoChessCountType = "NONE" | "BATTLE_LAYER" | "COUNTING" | "PROFESSIONS" | "GROUPS" | "LEVEL" | "PURCHASE";

export type AutoChessEffectCounterType = "NONE" | "TURN_COUNT" | "TRIGGER_COUNT" | "CHAR_COUNT" | "STACK_COUNT" | "COIN_JAR";

export type AutoChessSpecialEnemyType = "NONE" | "FLY" | "TIMES" | "ELEMENT" | "DOT" | "INVISIBLE" | "REFLECTION" | "SPECIAL";

export type AutoChessTrophyGetType = "ROUND" | "BOSS";

export type ActAutoChessModeType = "NONE" | "LOCAL" | "SINGLE" | "MULTI";

export type ActAutoChessMultiModeSubType = "NONE" | "SOLO" | "TEAM";

export type ActAutoChessModeDifficultyType = "NONE" | "TRAINING" | "FUNNY" | "NORMAL" | "HARD" | "ABYSS";

export type AutoChessEffectChoiceType = "EQUIP_FREE" | "EQUIP_PAID" | "BOUNTY_HUNT" | "BUFF_SELECT" | "PERSONAL_CHOOSE";

export type AutoChessItemType = "CHAR" | "EQUIP" | "MAGIC" | "TOKEN";

export type ActAutoChessBondActiveType = "BATTLE" | "ALL" | "MANI";

export type ActAutoChessBondActiveConditionType = "BOARD" | "BOARD_AND_DECK" | "DECK" | "BOARD_ALL_CHESS";

export type AutoChessBroadcastType = "NONE" | "GOLDEN_CHAR" | "SHOP_LEVEL" | "BOSS_HIT" | "CHAR_DAMAGE" | "CHAR_GIFT" | "BOND_EFFECT";

export type AutoChessChessType = "NORMAL" | "DIY" | "PRESET";

export type ActivityBossRushData_BossRushStageType = "NONE" | "NORMAL" | "TEAM" | "EX" | "SP";

export type ActivityBossRushData_BossRushPrincipleDialogType = "NONE";

export type ActivityCollectionData_JumpType = "NONE" | "ROGUE" | "CHAR_REPO";

export type ActivityInterlockData_InterlockStageType = "NONE" | "NORMAL" | "INTERLOCK" | "FINAL";

export type ActMultiV3MatchPosType = "NORMAL" | "COACH" | "STUDENT";

export type ActVecBreakV2StageOrderType = "NONE" | "A" | "B" | "C" | "D";

export type FireworkData_FireworkDirectionType = "TWO_DIR" | "FOUR_DIR";

export type FireworkData_FireworkType = "RED" | "BLUE" | "YELLOW" | "GREEN";

export type ActivityType = "DEFAULT" | "MISSION_ONLY" | "CHECKIN_ONLY" | "CHECKIN_ALL_PLAYER" | "COLLECTION" | "AVG_ONLY" | "LOGIN_ONLY" | "MINISTORY" | "ROGUELIKE" | "PRAY_ONLY" | "MULTIPLAY" | "GRID_GACHA" | "INTERLOCK" | "APRIL_FOOL" | "BOSS_RUSH" | "FLOAT_PARADE" | "MAIN_BUFF" | "FLIP_ONLY" | "CHECKIN_VS" | "SWITCH_ONLY" | "UNIQUE_ONLY" | "MAINLINE_BP" | "BLESS_ONLY" | "CHECKIN_ACCESS" | "VEC_BREAK" | "CHECKIN_VIDEO" | "ARCADE" | "TYPE_MAINSS" | "ENEMY_DUEL" | "TEAM_QUEST" | "RECRUIT_ONLY" | "AUTOCHESS_SEASON" | "ACT_FOOTBALL" | "ENUM";

export type ActivityDisplayType = "NONE" | "SIDESTORY" | "BRANCHLINE" | "MINISTORY";

export type ActivityCompleteType = "SPECIAL" | "CAN_COMPLETE" | "CANNOT_COMPLETE";

export type ActivityThemeType = "NONE" | "ACTIVITY" | "CRISIS" | "MAINLINE" | "ROGUELIKE" | "SANDBOX_PERM" | "ACTIVITY_COMP";

export type Act4funStageAttributeType = "POS" | "NEG";

export type BuildingData_RoomCategory = "NONE" | "FUNCTION" | "OUTPUT" | "CUSTOM" | "ELEVATOR" | "CORRIDOR" | "SPECIAL" | "CUSTOM_P" | "ELEVATOR_P" | "CORRIDOR_P" | "ALL";

export type BuildingData_RoomType = "NONE" | "CONTROL" | "POWER" | "MANUFACTURE" | "SHOP" | "DORMITORY" | "MEETING" | "HIRE" | "ELEVATOR" | "CORRIDOR" | "TRADING" | "WORKSHOP" | "TRAINING" | "PRIVATE" | "FUNCTIONAL" | "ALL";

export type BuildingData_OrderType = "O_COMPOUND" | "O_GOLD" | "O_DIAMOND";

export type BuildingData_FurnitureCategory = "FURNITURE" | "WALL" | "FLOOR";

export type BuildingData_BuildingToDoType = "NONE" | "MANUF_STOP" | "TRADE_STOP" | "HIRE_EMPTY" | "MEETING_EMPTY" | "NEW_PRODUCTS" | "HAS_ORDERS" | "CHAR_TIRED" | "TRAIN_FINISH" | "HIRE_REFRESHED" | "NEW_CLUES" | "NEW_FAVOR" | "NEW_FAVOR_MAX" | "BATCH_WORK" | "BATCH_REST" | "MESSAGE_BOARD";

export type BuildingData_FurnitureType = "FLOOR" | "CARPET" | "SEATING" | "BEDDING" | "TABLE" | "CABINET" | "DECORATION" | "WALLPAPER" | "WALLDECO" | "WALLLAMP" | "CEILING" | "CEILINGLAMP" | "FUNCTION" | "INTERACT";

export type BuildingData_FurnitureSubType = "NONE" | "CHAIR" | "SOFA" | "BARSTOOL" | "STOOL" | "BENCH" | "ORTHER_S" | "POSTER" | "CURTAIN" | "BOARD_WD" | "SHELF" | "INSTRUMENT_WD" | "ART_WD" | "PLAQUE" | "CONTRACT" | "ANNIHILATION" | "ORTHER_WD" | "FLOORLAMP" | "PLANT" | "PARTITION" | "COOKING" | "CATERING" | "DEVICE" | "INSTRUMENT_D" | "ART_D" | "BOARD_D" | "ENTERTAINMENT" | "STORAGE" | "DRESSING" | "WARM" | "WASH" | "ORTHER_D" | "COLUMN" | "DECORATION_C" | "CURTAIN_C" | "DEVICE_C" | "LIGHT" | "ORTHER_C" | "VISITOR" | "MUSIC";

export type BuildingData_FurnitureLocation = "NONE" | "WALL" | "FLOOR" | "CARPET" | "CEILING" | "POSTER" | "CEILINGDECAL";

export type BuildingData_FurnitureInteract = "NONE" | "ANIMATOR" | "MUSIC" | "FUNCTION";

export type BuildingData_LODLEVEL = "HIGHEST" | "HIGH" | "LOW" | "LOWEST" | "COUNT";

export type BuildingData_FormulaItemType = "NONE" | "F_EVOLVE" | "F_BUILDING" | "F_GOLD" | "F_DIAMOND" | "F_FURNITURE" | "F_EXP" | "F_ASC" | "F_SKILL";

export type BuildingData_DiySortType = "NONE" | "THEME" | "FURNITURE" | "FURNITURE_IN_THEME" | "RECENT_THEME" | "RECENT_FURNITURE" | "MEETING_THEME" | "MEETING_FURNITURE" | "MEETING_FURNITURE_IN_THEME" | "MEETING_RECENT_THEME" | "MEETING_RECENT_FURNITURE";

export type BuildingData_DiyUIType = "MENU" | "THEME" | "FURNITURE" | "FURNITURE_IN_THEME" | "RECENT_THEME" | "RECENT_FURNITURE" | "PRESET";

export type BuildingData_DiyUISortOrder = "DESC" | "ASC";

export type BuildingData_LayoutData_StoreyData_Type = "UPGROUND" | "DOWNGROUND";

export type BuildingData_BuffCategory = "NONE" | "FUNCTION" | "OUTPUT" | "RECOVERY";

export type BuildingData_CharStationFilterType = string;

export type CampaignStageType = "NONE" | "PERMANENT" | "ROTATE" | "TRAINING";

export type CGGalleryCGSource = "IMAGE" | "BACKGROUND" | "ITEM";

export type CGGalleryCGCompositeType = "NONE" | "HORIZONTAL" | "VERTICAL" | "GRID";

export type CharmRarity = "NONE" | "LOW" | "MEDIUM" | "HIGH";

export type SpCharMissionCondType = "NONE" | "EVOLVE_PHASE";

export type CharWordVoiceType = "ONLY_TEXT" | "HAVE_CV" | "ENUM";

export type BattleVoiceOption_BattleVoiceType = "BATTLE_START" | "ENCOUNTER_ENEMY" | "PLACE_CHAR" | "FOCUS_CHAR" | "SKILL_ACTIVE" | "SKILL_PASSIVE_IMP" | "SKILL_PASSIVE_NOR" | "NORMAL_ATTACK" | "E_NUM";

export type FestivalVoiceTimeType = "NONE" | "FESTIVAL" | "BIRTHDAY";

export type ClimbTowerLevelType = "NORMAL" | "HIGHLEVEL" | "BOSS";

export type ClimbTowerTaticalBuffType = "A" | "B";

export type ClimbTowerTowerType = "TRAINING" | "NORMAL";

export type ClimbTowerCardType = "SEASON" | "TOWER";

export type CrisisStageType = "TEMPORARY" | "PERMANENT" | "TRAINING";

export type CrisisV2StageType = "NONE" | "PERMANENT" | "TEMPORARY";

export type CrisisV2AppraiseType = "RANK_D" | "RANK_C" | "RANK_B" | "RANK_A" | "RANK_S" | "RANK_SS" | "RANK_SSS";

export type CrisisV2NodeSlotType = "NONE" | "START" | "NORMAL" | "KEYPOINT" | "TREASURE";

export type CrisisV2MapRoadPointType = "NONE" | "NODE" | "BAG";

export type CrisisV2RunePackType = "NONE" | "HIGHEST_TOTAL_SCORE";

export type CrisisV2GoodType = "NONE" | "NORMAL" | "PROGRESS";

export type CrisisV2MissionType = "RUNEPACK" | "CHALLENGE" | "TREASURE";

export type HomeMultiFormChangeRule = "NONE" | "TIME";

export type PlayerAvatarGroupType = "NONE" | "ASSISTANT" | "DEFAULT" | "SPECIAL" | "ACTIVITY" | "DYNAMIC";

export type NameCardV2ModuleType = "NONE" | "BACKGROUND" | "ILLUST" | "COLLECT" | "AVATAR" | "REMOVABLE" | "AVATAR_SIMPLE";

export type NameCardV2ModuleSubType = "NONE" | "SIGN" | "ASSIST" | "MEDAL" | "MAINLINE" | "EQUIPMENT";

export type NameCardV2SkinType = "NONE" | "BASE" | "SPECIAL" | "DYNAMIC";

export type UniEquipTarget = "NONE" | "TRAIT" | "TRAIT_DATA_ONLY" | "TALENT" | "TALENT_DATA_ONLY" | "DISPLAY" | "OVERWRITE_BATTLE_DATA";

export type GachaDetailData_GachaType = "TEXT" | "UP_CHAR" | "AVAIL_CHAR" | "UP_CHAR_WITH_LIMIT" | "ATTAIN_CHAR" | "IMAGE" | "FES_CLASSIC_CHAR" | "FES_CLASSIC_UP_CHAR" | "SPECIAL_PICKUP_CHAR" | "SPECIAL_PICKUP_SELECT_CHAR" | "SPECIAL_PICKUP_AVAIL_CHAR";

export type GachaDetailData_GachaTextType = "NORMAL_HIGHLIGHT" | "NORMAL_GRAY" | "NORMAL_GRAY_UP" | "NEWBEE_HIGHLIGHT" | "NEWBEE_NORMAL_TEXT" | "NORMAL_TEXT" | "ORANGE_HIGHLIGHT" | "RED_HIGHLIGHT";

export type GachaDetailData_GachaImageType = "CLASSIC_SHD_RULE";

export type GachaDetailData_GachaObjGroupType = "ALL" | "BEFORE_FES_CLASSIC_CHOSEN" | "AFTER_FES_CLASSIC_CHOSEN" | "BEFORE_SPECIAL_PICKUP_CHOSEN" | "AFTER_SPECIAL_PICKUP_CHOSEN";

export type GachaRuleType = "NORMAL" | "LIMITED" | "LINKAGE" | "ATTAIN" | "CLASSIC" | "SINGLE" | "FESCLASSIC" | "CLASSIC_ATTAIN" | "SPECIAL" | "DOUBLE" | "CLASSIC_DOUBLE" | "BACKFLOW";

export type ItemType = "NONE" | "CHAR" | "CARD_EXP" | "MATERIAL" | "GOLD" | "EXP_PLAYER" | "TKT_TRY" | "TKT_RECRUIT" | "TKT_INST_FIN" | "TKT_GACHA" | "ACTIVITY_COIN" | "DIAMOND" | "DIAMOND_SHD" | "HGG_SHD" | "LGG_SHD" | "FURN" | "AP_GAMEPLAY" | "AP_BASE" | "SOCIAL_PT" | "CHAR_SKIN" | "TKT_GACHA_PRSV" | "AP_ITEM" | "AP_SUPPLY" | "RENAMING_CARD" | "ET_STAGE" | "ACTIVITY_ITEM" | "VOUCHER_PICK" | "VOUCHER_CGACHA" | "VOUCHER_MGACHA" | "CRS_SHOP_COIN" | "CRS_RUNE_COIN" | "LMTGS_COIN" | "EPGS_COIN" | "LIMITED_FREE_GACHA" | "REP_COIN" | "ROGUELIKE" | "VOUCHER_SKIN" | "RETRO_COIN" | "PLAYER_AVATAR" | "UNI_COLLECTION" | "VOUCHER_FULL_POTENTIAL" | "RL_COIN" | "RETURN_CREDIT" | "MEDAL" | "CHARM" | "HOME_BACKGROUND" | "EXTERMINATION_AGENT" | "OPTIONAL_VOUCHER_PICK" | "ACT_CART_COMPONENT" | "ACTIVITY_POTENTIAL" | "ITEM_PACK" | "SANDBOX" | "FAVOR_ADD_ITEM" | "CLASSIC_SHD" | "CLASSIC_TKT_GACHA" | "LIMITED_BUFF" | "RETURN_PROGRESS" | "NEW_PROGRESS" | "MCARD_VOUCHER" | "MATERIAL_ISSUE_VOUCHER" | "HOME_THEME" | "SANDBOX_PERM" | "SANDBOX_TOKEN" | "TEMPLATE_TRAP" | "NAME_CARD_SKIN" | "EMOTICON_SET" | "EXCLUSIVE_TKT_GACHA" | "SO_CHAR_EXP" | "GIFTPACKAGE_TKT" | "RANDOM_VOUCHER_SKIN" | "PLOT_ITEM" | "MAGAZINE_LEAF" | "STICKER";

export type ItemDropShopType = "HGGSHD_SHOP" | "LGGSHD_SHOP" | "XSHD_SHOP" | "EPGS_SHOP" | "REP_SHOP" | "CLASSIC_SHOP";

export type MedalRarity = string;

export type MedalExpireType = "NONE" | "INIT" | "TEMP" | "PERM";

export type MissionType = "UNKNOWN" | "MAIN" | "DAILY" | "WEEKLY" | "GUIDE" | "SUB" | "ACTIVITY" | "OPENSERVER" | "TOWERSEASON" | "RETRO" | "SPECIAL_OPERATOR" | "SPECIAL_OPERATOR_WEEKLY";

export type MissionItemBgType = "COMMON";

export type CrossAppShareMissionType = "NORMAL" | "ACTIVITY";

export type TemplateMissionBigRewardType = "NONE" | "ILLUST_CHAR_REWARD" | "CUSTOM" | "PIC_REWARD" | "SKIN_REWARD";

export type TemplateMissionTitleType = "COMMON" | "CUSTOM";

export type TemplateMissionCoinInfoType = "COMMON" | "CUSTOM";

export type ReturnMissionGroupType = "DAILY" | "NORMAL" | "DIFF";

export type RoguelikeActivityType = "NONE" | "SEED_MODE";

export type RoguelikeNodeLine_HiddenType = "SHOW" | "HIDE" | "APPEAR";

export type RoguelikeDungeonLine_VertType = "NONE" | "DOWN_AVAIL" | "UP_AVAIL" | "DISCARD" | "FUTURE_NORMAL" | "ALREADY_GO_UP" | "ALREADY_GO_DOWN";

export type RoguelikeSpZoneNodeType = "NORMAL" | "SKY";

export type RoguelikeItemType = "NONE" | "HP" | "GOLD" | "POPULATION" | "SQUAD_CAPACITY" | "RECRUIT_TICKET" | "UPGRADE_TICKET" | "RELIC" | "TOTEM_EFFECT";

export type RoguelikeItemRarity = "NONE" | "BORN" | "NORMAL" | "RARE" | "SUPER_RARE";

export type RoguelikeTotemColorType = "NONE" | "RED" | "GREEN" | "BLUE" | "ALL";

export type RoguelikeTotemPosType = "LOCATION" | "EFFECT";

export type RoguelikeTotemBlurNodeType = "NONE" | "BATTLE" | "NO_BATTLE";

export type RoguelikeVisionModuleData_VisionChoiceCheckType = "LOWER" | "UPPER";

export type RoguelikeFragmentType = "NONE" | "INSPIRATION" | "WISH" | "IDEA";

export type RoguelikeCopperLuckyLevel = "NONE" | "HIGH" | "MID" | "LOW";

export type RoguelikeCopperBuffType = "NONE" | "REFRESH" | "MOVE";

export type RoguelikeCopperDivineType = "NONE" | "DIVINE" | "EVENT";

export type RoguelikeCopperDivineResultType = "NONE" | "GOOD" | "NORMAL" | "BAD";

export type RoguelikeSkyZoneNodeType = "NONE" | "ORIGIN" | "BATTLE" | "TRIAL_GATE" | "INCIDENT" | "TREASURE" | "SHOP" | "SACRIFICE" | "ENTERTAINMENT" | "MARKET" | "BATTLE_HARD" | "INCIDENT_BOSS" | "INCIDENT_BOSS_ONLY" | "CHOICES" | "BATTLES";

export type RoguelikeScrapType = "ERROR" | "NONE" | "MOVE" | "GOODS" | "PASSIVE";

export type RoguelikeMoveScrapRangeType = "RANGE" | "FULL_MAP";

export type RoguelikeEventType = "NONE" | "BATTLE_NORMAL" | "BATTLE_ELITE" | "BATTLE_BOSS" | "SHOP" | "REST" | "INCIDENT" | "TREASURE" | "ENTERTAINMENT" | "UNKNOWN" | "WISH" | "SACRIFICE" | "EXPEDITION" | "BATTLE_SHOP" | "PORTAL" | "MISSION" | "STORY" | "STORY_HIDDEN" | "ALCHEMY" | "DUEL" | "STASHED_RECRUIT" | "SPECIAL_ZONE" | "SCRAP_SHOP" | "DOOR" | "FINAL" | "EVACUATE" | "EMPLOY" | "LIGHT" | "BATTLE_SAVAGE" | "EMPTY" | "BATTLES" | "CHOICES" | "EVENTS" | "ALL";

export type RoguelikeSacrificeType = "RELIC" | "TOTEM" | "COPPER" | "SCRAP";

export type RoguelikeExpeditionType = "NORMAL" | "CANDLE" | "GUIDED" | "ENDING_RELIC";

export type RoguelikeModuleType = "NONE" | "SANCHECK" | "DICE" | "CHAOS" | "TOTEMBUFF" | "VISION" | "FRAGMENT" | "DISASTER" | "NODE_UPGRADE" | "COPPER" | "WRATH" | "CANDLE" | "SKY" | "GRID_ZONE" | "WEATHER" | "SCRAP";

export type RoguelikeRewardExDropTagSrcType = "NONE" | "TREASURE" | "TOTEM" | "EXPLORE_TOOL" | "COPPER" | "EVIL_TEMPLE" | "TREASURE_MAP" | "LOOP_CHIP" | "STEP" | "GREED" | "GOLDEN_AGE";

export type RoguelikeBankRewardCountType = "HIGHEST_RECORD" | "TOTAL_SUM";

export type RoguelikeEnrollType = "DLC" | "REVIEW";

export type RoguelikePredefinedConstStyle = "EXP_STYLE";

export type RoguelikePredefinedStyleMask = "NONE" | "STYLE_SPECIAL_EXP";

export type RoguelikeExpStyleConfigParam = "BATTLE_END_HP_LOSE_TEXT";

export type RoguelikeMonthChatTrigType = "NONE" | "TRANSITING" | "DUNGEON";

export type RoguelikeCharState = "NORMAL" | "UPGRADE" | "UPGRADE_BUFF" | "UPGRADE_BONUS" | "FREE" | "ASSIST" | "THIRD" | "MONTHLY" | "THIRD_LOW" | "MERCENARY";

export type RoguelikeTopicDevNodeType = "BRANCH" | "KEY" | "NONE";

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

export type RoguelikeGameShopDialogType = "NONE" | "BUY_SELECT" | "RECYCLE_SELECT" | "BUY_CHANGE" | "RECYCLE_CHANGE" | "BUY_CONFIRM" | "RECYCLE_CONFIRM" | "BANK_ENTRY" | "BANK_INVEST" | "BANK_WITHDRAWAL" | "BANK_FAULTY" | "BANK_REWARD_UNLOCK" | "OUTER_NORMAL" | "OUTER_REWARD" | "FIGHT_BOSS" | "BATCH_RECYCLE" | "SEED_ENTRY" | "SEED_CONFIRM" | "QUIT_SELECT" | "CANNOT_AFFORD" | "BUY_SELECT_SCRAP_MOVE" | "BUY_SELECT_SCRAP_GOODS" | "BUY_SELECT_SCRAP_PASSIVE";

export type RoguelikeGameChoiceType = "NONE" | "LEAVE" | "NEXT" | "NEXT_PROB" | "TRADE" | "TRADE_PROB" | "SACRIFICE" | "TELEPORT" | "EXPEDITION" | "WISH" | "TRADE_PROB_SHOW" | "SACRIFICE_TOTEM" | "WISH_ALL" | "KILL" | "USE_STASHED_TICKET" | "EXPEDITION_ALL" | "EXPEDITION_RETURN_ALL" | "PACIFY_WRATH" | "GILD_COPPER" | "ITEM_REROLL" | "ITEM_TOP_UP" | "GILD_COPPER_ALL" | "JUMP_PROB" | "JUMP" | "ZONE_END" | "MOVE" | "VISION" | "SCRAP_PAY_SHOW";

export type RoguelikeChoiceLeftDecoType = "NONE" | "TASK" | "TASK_REWARD" | "DICE" | "VISION";

export type RoguelikeGameVariationType = "NONE" | "MAP" | "RES" | "BAT";

export type RoguelikeGameRelicCheckType = "NONE" | "PROFESSION" | "SUB_PROFESSION" | "UPGRADE";

export type RoguelikeTaskRarity = "NORMAL" | "RARE" | "SUPER_RARE";

export type RoguelikeStageDuelResultType = "LOSE" | "DRAW" | "WIN";

export type RoguelikeEndingDetailText_Type = "SHOW_CHOICE" | "SHOW_RELIC" | "SHOW_CAPSULE" | "SHOW_ACTIVE_TOOL" | "SHOW_ACCELERATE_CHAR" | "SHOW_NORMAL_RECRUIT" | "SHOW_DIRECT_RECRUIT" | "SHOW_FRIEND_RECRUIT" | "SHOW_FREE_RECRUIT" | "BUY" | "INVEST" | "SHOW_STAGE" | "SHOW_CONST" | "SUM" | "SHOW_BOSS_END" | "SHOW_BATTLE";

export type RoguelikeCommonDevelopmentNodeType = "NONE" | "NORMAL" | "KEY" | "DIFFICULTY";

export type RoguelikeCommonDevelopmentEffectType = "BUFF" | "RAW_TEXT_EFFECT" | "RAW_TEXT_BAND";

export type CrisisData_StageType = "TEMPORARY" | "PERMANENT";

export type SandboxFoodAttribute = "NONE" | "SURVIVE" | "COST" | "ATTACK" | "COOLDOWN" | "SKILL_POINT" | "SPECIAL" | "ENHANCED" | "FUNCTION";

export type SandboxFoodMatType = "MAIN" | "SUB";

export type SandboxFoodVariantType = "NONE" | "ALPHA" | "BETA" | "GAMMA";

export type SandboxShopCoinType = "DIMENSION_COIN" | "GOLD" | "BASE_GOLD" | "BASE_GOLDEX";

export type SandboxDevelopmentType = "NONE" | "SURVIVE" | "COLLECT" | "SHOP" | "BATTLE" | "DUNGEON" | "EXPLORE" | "RESOURCE" | "INITIAL";

export type SandboxDevelopmentLineStyle = "EMPTY" | "LEVEL_PASS" | "LEVEL_BLOCK";

export type SandboxArchiveQuestType = "NONE" | "MAIN" | "SIDE";

export type SandboxV2NodeTopologicalType = "NONE" | "TRAFFIC_NODE" | "ENDING_NODE";

export type SandboxV2NodeType = "NONE" | "HOME" | "HOME_OUTPOST" | "BATTLE" | "NEST" | "COLLECT" | "HUNT" | "CAVE" | "MINE" | "ENCOUNTER" | "EXPEDITION" | "SHOP" | "GATE" | "MARKET" | "HOME_PORTABLE" | "HOME_PORTABLE_RIFT" | "SELECTION" | "RACING";

export type SandboxV2TrapItemType = "NONE" | "BATTLE" | "TACTICAL" | "FUNCTION" | "ANIMAL";

export type SandboxV2ItemTrapTag = "OUTPUT" | "COLLECTION" | "IMPAIR" | "ENHANCE" | "EXPLORE" | "SPECTACLE" | "DECORATE" | "DEFEND" | "SCOUT";

export type SandboxV2WeatherType = "NORMAL" | "RAINFOREST" | "VOLCANO" | "DESERT";

export type SandboxV2SeasonType = "NONE" | "DRY" | "RAINY" | "CHALLENGE";

export type SandboxV2EnemyRushType = "NORMAL" | "ELITE" | "BOSS" | "BANDIT" | "RALLY" | "THIEF" | "MESSENGER" | "INSECT";

export type SandboxV2RareAnimalType = "RARE_DEAR" | "RARE_TURTLE" | "MESSENGER" | "PREY";

export type SandboxV2BuffType = "NORMAL" | "CHARACTER_RUNE" | "LEVEL_RUNE" | "COMPOUND";

export type SandboxV2CoinType = "DIMENSION_COIN" | "GOLD";

export type SandboxV2RacerTalentType = "BORN" | "LEARNED";

export type SandboxV2RacerNameType = "PREFIX" | "SUFFIX";

export type SandboxV2CraftItemUnlockType = "INITIAL" | "UPGRADE_BASE" | "GAIN" | "GAIN_ITEM";

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

export type SandboxV3ElectricTransferType = "NONE" | "FUNCTION" | "SUPPLY" | "ADDITION" | "AMPLIFY";

export type SandboxV3BuildScoreType = "NONE" | "NPC" | "TRAP" | "LEVEL" | "ENPC";

export type SandboxV3ElectricSupplyType = "NONE" | "WOOD" | "STONE" | "IRON";

export type SandboxV3BagItemType = "NONE" | "MATERIALBAG" | "RELICBAG";

export type SandboxV3EnemyRewardType = "NONE" | "ITEM" | "POWER" | "LUCKYDROP";

export type SandboxV3TaskDifficultyType = "NONE" | "EASY" | "NORMAL" | "HARD";

export type SandboxV3TaskType = "DEPLOY_TRAP_BY_GROUP" | "CONSTRUCT_TRAP_BY_GROUP" | "OWN_TRAP_BY_GROUP" | "OWN_TRAP_AND_DELIVER" | "OWN_TRAP_BY_TYPE" | "ITEM_DELIVERY" | "GATHER" | "KILL_ENEMY" | "KILL_ENEMY_FILTER_BY_TAG" | "KILL_ENEMY_FILTER_BY_LEVELTYPE" | "UNLOCK_ROOM_BY_MASK" | "UNLOCK_ROOM_CULMULATIVE" | "CATCH_ANIMAL" | "PROSPERITY_KEEP" | "AESTHETICS_REACH" | "PROSPERITY_REACH" | "AESTHETICS_INCREASE" | "PROSPERITY_INCREASE" | "TRADE_IN_SALE" | "CHARACTER_CHECK" | "RAILWAY_CHECK";

export type SandboxV3LevelRoomTypeMask = "NONE" | "START" | "BOSS" | "WOOD" | "STONE" | "IRON" | "WATER" | "ENEMY" | "EVENT" | "ANIMAL" | "NORMAL" | "DIAMOND" | "DANGER";

export type SandboxPermTemplateType = "NONE";

export type SandboxPermItemType = "NONE" | "TACTICAL" | "BUILDING" | "BUILDINGMAT" | "FOOD" | "FOODMAT" | "SPECIALMAT" | "COIN" | "CRAFT" | "PLACEHOLDER" | "STAMINAPOT" | "ANIMAL" | "INSECT" | "SLUGITEM" | "RELIC" | "RECIPE" | "PRODUCT" | "TOOLKIT" | "RANDRELIC" | "RANDRECIPE" | "CURRENCY" | "COOKBOOK" | "BASEBUILDING" | "BASECOIN" | "BASEANIMAL" | "BASETACTICAL" | "TECHPOINT";

export type ShopCurrencyUnit = "CASH" | "DIAMOND" | "TICKET" | "DIAMOND_SHD";

export type ShopUnlockType = "ALWAYS_UNLOCK" | "SKIN_UNLOCK" | "FURN_UNLOCK" | "BOTH_SKIN_FURN";

export type ShopType = "RECOMMENDSHOP" | "CASHSHOP" | "GIFTPACKAGE" | "SKINSHOP" | "QCSHOP" | "SOCAILSHOP" | "FURNSHOP" | "NONE";

export type ShopRouteTarget = "RECOMMENDSHOP" | "CASHSHOP" | "GIFTPACKAGE" | "SKINSHOP" | "HQCSHOP" | "LQCSHOP" | "EXQCSHOP" | "SOCAILSHOP" | "FURNSHOP" | "REPSHOP" | "LMGTSSHOP" | "EPGSSHOP" | "CLASSICSHOP" | "NONE";

export type ShopCondTrigPackageType = "NONE" | "RETURN_PROGRESS" | "RETURN_ONCE" | "NEW_PROGRESS" | "CHOOSE_REGISTER_TIME" | "CHOOSE_NEWBIE";

export type ShopRecommendTemplateType = "DEFAULT" | "NORSKIN" | "RETURNSKIN" | "NORFURN" | "NORGIFT";

export type ShopGPTabType = "DEFAULT_ALL" | "MONTH_CARD" | "PERM" | "NEWBIE" | "RETURN" | "RECOMMOND" | "TIMELY";

export type ShopGPPanelType = "DEFAULT_COMMON" | "RECOMMEND" | "MONTH_CARD";

export type SkinObtainApproachType = "SHOP" | "ACTIVITY";

export type SkinVoiceType = "NONE" | "ILLUST" | "ALL";

export type CharSkinUnlockType = "BUYSKIN" | "INITSKIN" | "ONEEVOLVESKIN" | "TWOEVOLVESKIN";

export type StageDropType = "NONE" | "ONCE" | "NORMAL" | "SPECIAL" | "ADDITIONAL" | "APRETURN" | "DIAMOND_MATERIAL" | "FUNITURE_DROP" | "COMPLETE" | "CHARM_DROP" | "OVERRIDE_DROP" | "ITEM_RETURN" | "CONDITION_DROP";

export type StageButtonInFogRenderType = "HIDE" | "SHOW_WITH_FOG_SIX_STAR";

export type StageDiffGroup = "NONE" | "EASY" | "NORMAL" | "TOUGH" | "ALL";

export type StageData_PerformanceStageFlag = "NORMAL_STAGE" | "PERFORMANCE_STAGE";

export type StageData_SpecialStageUnlockProgressType = "ONCE" | "PROGRESS";

export type SixStarStageCompatibleDropType = "COMPLETE_ONLY";

export type UniEquipType = "INITIAL" | "ADVANCED";

export type VoiceLangType = "NONE" | "JP" | "CN_MANDARIN" | "EN" | "KR" | "CN_TOPOLECT" | "LINKAGE" | "ITA" | "GER" | "RUS" | "FRE" | "SPA";

export type VoiceLangGroupType = "NONE" | "CN_MANDARIN" | "JP" | "EN" | "KR" | "CUSTOM" | "LINKAGE";

export type ZoneType = "NONE" | "MAINLINE" | "WEEKLY" | "ACTIVITY" | "GUIDE" | "TRAINING" | "CAMPAIGN" | "SIDESTORY" | "BRANCHLINE" | "ROGUELIKE" | "CLIMB_TOWER" | "MAINLINE_ACTIVITY" | "MAINLINE_RETRO";

export type MainlineZoneData_ZoneReplayBtnType = "NONE" | "RECAP" | "REPLAY";

export type RecordRewardStageDiff = "NONE" | "EASY" | "NORMAL" | "TOUGH" | "PREDEFINED" | "HARD";

export type ShopDetailType = "CHAR" | "PROGRESS" | "COMMON" | "GIFTPACKAGE" | "FURNITURE" | "MONTHLYSUB" | "CASH" | "SKIN" | "BLINDBOX";

export type ShopDetailPriceType = "CASH" | "HIGHQC" | "LOWQC" | "EXTRAQC" | "FURNITURE" | "DIAMOND" | "SOCIAL" | "LMTGS_COIN" | "EPGS_COIN" | "REP_COIN" | "CLASSIC_QC" | "DIAMOND_SHD";

export type ShopItemType = "NORMAL" | "PROGRESS";

export type StageDataUtil_StageDataSource = "NONE" | "STAGE_DB" | "RETRO_DB";

export type Mission_MissionPageType = "STARTMISSION" | "DAILYMISSION" | "MAINMISSION" | "ACTIVITYMISSION" | "WEEKLYMISSION" | "SOCHAR";

export type Multiplayer_MultiStageTargetPos = "POS_RANDOM" | "POS_ENUM";

export type Multiplayer_PlayerOperator = string;

export type Multiplayer_PlayerOnlineParam = string;

export type Multiplayer_BattlePlayerStatus = string;

export type Multiplayer_PlayerMarkType = string;

export type Multiplayer_Servers_TeamProtocol_StageRandomType = "NOT_RANDOM" | "RANDOM" | "HARD_RANDOM" | "EXTREMLY_HARD_RANDOM";

export type Grading_PerformanceTest_PerformanceTestState = "IDLE" | "START" | "END";

export type Grading_PerformanceTest_DeviceLevel = "NODEFINE" | "LOW" | "HIGH";

export type Gacha_GachaController_PlayMode = "FULL_GACHA" | "SIMPLE_GACHA" | "DISPLAY_ONLY" | "DISPLAY_SKIN";

export type Gacha_GachaController_StateEnum = "NONE" | "INIT" | "HOLD";

export type Gacha_GachaPhase0_States_State = "DEFAULT" | "DROP" | "UNPACK" | "FOLDER" | "TERMINAL";

export type CharWord_VoiceLangManager_HotUpdatePref = "NONE" | "CN" | "JP" | "EN" | "KR" | "DONT_CHANGE";

export type Building_ScaleType = "FIT_CENTER" | "CROP_CENTER" | "FIT_HEIGHT";

export type Building_BuildingEvent = "BUILDING_DATA_LOADED" | "BUILDING_MODE_CHANGED" | "VAULT_LAYOUT_UPDATE" | "VAULT_ROOM_OBJ_CREATED" | "VAULT_ROOM_OBJ_CHANGED" | "VAULT_ROOM_OBJ_DESTROYED" | "VAULT_ROOM_FURN_CREATED" | "VAULT_FUNC_FURN_UPDATED" | "OPERATION_MODE_CHANGED" | "ROOM_SELECTED" | "ROOM_UNSELECTED" | "ROOM_ROUTE_FAIL" | "ROOM_REQUEST_CLEAN" | "ROOM_REQUEST_BUILD" | "ROOM_REQUEST_LEVELUP" | "ROOM_REQUEST_TEARDOWN" | "ROOM_REQUEST_DIY" | "ROOM_REQUEST_DIY_CANCEL" | "ROOM_REQUEST_DIY_LEVELUP" | "ROOM_REQUEST_DIY_LEVELUP_OK" | "ROOM_REQUEST_DIY_LEVELUP_CANCEL" | "ROOM_SHOW_DETAIL" | "ROOM_BUILD_CHOICE_SELECTED" | "BP_ROOM_SETTLE_REQUESTED" | "BP_HILIGHT_MASK_CLICKED" | "DIY_PAGE_SAVED_CHANGES" | "TODO_NOTIFY_STATE_CHANGED" | "LOCAL_TRACK_REFRESH" | "ROUTE_TO_CHAR_CTRL" | "FLOAT_STATE_UPDATE" | "ON_MEETING_ROOM_FOCUSED_BY_SCENE_PARAM" | "OBJECT_SELECTED";

export type Building_RoomSlotState = "UNCLEANED" | "EMPTY" | "UPGRADING" | "BUILT";

export type Building_OperationMode = "NONE" | "NORMAL" | "ARCHITECTURE" | "VISIT";

export type Building_RaycastBlockKey = "NONE" | "VAULT_MODE" | "BP_MODE" | "COMMON_PAGE_TRANSITION" | "FLOAT_PAGE_POPUP" | "NETWORK" | "VAULT_STATION_FLOAT" | "VAULT_DETAIL_FLOAT" | "EMPTY_PAGE" | "AVG" | "GUIDEBOOK" | "MUSIC_PAGE" | "TWEEN_ENTER";

export type Building_BuildingStateMachine_TransitionParam_TransitionType = "NONE" | "ZOOM_IN_TO_VAULT" | "ZOOM_OUT_TO_BP";

export type Building_GridMap_GridNode_State = "EMPTY" | "OCCUPIED" | "ABANDONED";

export type Building_FurnitureLodObjType = "MESH" | "EFFECT";

export type Building_BuildingAssistantType = "NONE" | "MAIN" | "LAYER";

export type Building_TradingOrderReward = "NONE" | "GOLD" | "DIAMOND";

export type Building_DynamicAssetPriority = "HIGH" | "DEFAULT";

export type Building_DIY_DIYRoomPart = "FLOOR" | "WALL";

export type Building_DIY_FurnitureSorter_FurnitureSortingOption = "COMFORT" | "RARITY" | "COUNT" | "PRICE" | "SHOP_DEFAULT" | "ENUM_COUNT";

export type Building_DIY_FurnitureSorter_SortingMethod = "ASCENT" | "DESCENT" | "ENUM_COUNT";

export type Building_DIY_FurnitureLocationType = "GROUND" | "WALL" | "CARPET" | "CEILING" | "POSTER" | "CEILING_DECAL";

export type Building_DIY_FurnitureInteractType = "NONE" | "ANIMATOR" | "MUSIC" | "FUNCTION";

export type Building_DIY_DIYRoomIndicatorButton_ButtonType = "NONE" | "RESET" | "UNEQUIP" | "COMFIRM" | "ROTATE" | "DRAG";

export type Building_DIY_UI_DIYSortButton_State = "INACTIVE" | "ASCENT" | "DESCENT";

export type Building_DIY_UI_DIYSortPanel_FilterType = "RARITY" | "HAS_FURNITURE" | "DISCOUNT";

export type Building_DIY_UI_DIYCameraSwitchToggle_CameraSwitchState = "GENERAL" | "CEILING" | "WALL" | "FLOOR";

export type Building_DIY_UI_DIYItemViewData_CountStatus = "AVAILABLE" | "ADDED" | "OCCUPIED" | "NO_STORAGE";

export type Building_DIY_UI_DIYRecycleElementView_ElementType = "DEFAULT" | "FUNC" | "EMPTY" | "ROW_EMPTY";

export type Building_DIY_UI_DIYBottomMenuState_MenuState = "OVERVIEW" | "RECENT" | "NONE";

export type Building_DIY_UI_DIYFilterType = "FLOOR" | "CARPET" | "SEATING" | "BEDDING" | "TABLE" | "CABINET" | "DECORATION" | "WALLPAPER" | "WALLDECO" | "WALLLAMP" | "CEILING" | "CEILINGLAMP" | "FUNCTION" | "INTERACT" | "ALL";

export type Building_DIY_UI_DIYViewListModel_DIYViewListThemeState = "MENU" | "FURNITURE_VIEW" | "THEME_VIEW" | "THEME_FURNITURE_VIEW";

export type Building_DIY_UI_DIYViewListModel_UIExpandListState = "NONE" | "EXPAND" | "FOLD";

export type Building_Vault_VCharacter_States_State = "DEFAULT" | "IDLE" | "MOVE" | "INTERACT" | "SLEEP" | "FURNITURE" | "SPECIAL" | "C_MOVE" | "C_IDLE" | "C_FURNITURE" | "C_SPECIAL" | "TERMINAL";

export type Building_Vault_VCharacter_States_CFurnitureState_SubState = "DEFAULT" | "MOVE" | "INTERACT" | "TERMINAL";

export type Building_Vault_VCharacter_States_FurnitureState_SubState = "DEFAULT" | "MOVE" | "INTERACT" | "TERMINAL";

export type Building_Vault_VCameraController_FocusMatchType = "WIDTH" | "HEIGHT";

export type Building_Vault_VCharacterController_DoorPosState = "NORMAL" | "BESIDE_LDOOR" | "BESIDE_RDOOR";

export type Building_Vault_VWallGenerator_BoundaryItem_BoundaryType = "BEGIN" | "END";

export type Building_Vault_AnimatorStateEvent = string;

export type Building_UI_DIYPage_CameraStateType = "NONE" | "GENERAL" | "FLOOR" | "FLOOR_DIR" | "WALL" | "CEILING" | "CEILING_DIR" | "WALL_DIR";

export type Building_UI_StationedCharState = "NONE" | "WORK" | "REST" | "IDLE" | "TIRED" | "TRAINING";

export type Building_UI_CharManpowerState = "NONE" | "FULL" | "HALF" | "EMPTY";

export type Building_UI_BuildingCharAvatar_OverrideStatus = "NONE" | "EMPTY" | "LOCKED";

export type Building_UI_StationBPSlotStyle = "NONE" | "LIGTH" | "DARK";

export type Building_UI_BuildingStaticIconHub_IconType = "NONE" | "WORKSHOP" | "MANUFACT" | "GOLD";

export type Building_UI_UIArchitectureCleanView_Argument_ConditionPanelShown = "NONE" | "CONTROL_LEVEL" | "CONNECT";

export type Building_UI_LevelInfoType = "NONE" | "POWER_PROVIDE" | "POWER_COST" | "PRODUCT_SPEED" | "PRODUCT_CAPACITY" | "SHOP_COUNT" | "SHOP_SPEED" | "SHOP_CAPACITY" | "HIRE_ECONOMIZE_RATE" | "HIRE_SLOT_PROVIDE" | "DORM_MAN_POWER_RECOVERY" | "DORM_WEIGHT_LIMIT" | "MEETING_FRIEND_SLOT" | "MEETING_VISIORS_NUM" | "LEVELUP_TIME" | "ROOM_MAX_LEVEL" | "DIY_LEVEL" | "COMFORT" | "FURNITURE_COUNT" | "CHAR_STATION" | "ROOM_COUNT_POWER" | "ROOM_COUNT_MANUF" | "ROOM_COUNT_TRADING" | "ROOM_COUNT_DORM" | "TRADING_ORDER_NUM" | "TRADING_ORDER_QUALITY" | "WORKSHOP_MANPOWER_COST_RATE" | "TRAINING_SPEC_LVL" | "HIRE_SPEED" | "NEW_FORMULA_COUNT" | "COMFORT_LIMIT" | "ROOM_COUNT_PRIVATE";

export type Building_UI_BuildingFavorNotifyView_FavorType = "NORMAL" | "ASSIST" | "PRIVATE";

export type Building_UI_CleanConditionCheckingResult_Reason = "NONE" | "NOT_CONNECT_TO_CONTROL" | "LOW_CONTROL_LEVEL";

export type Building_UI_Workshop_BuildingWorkshopFilterIndex = "INDEX_BUILDING" | "INDEX_ELITE" | "INDEX_SKILL" | "INDEX_ASC" | "INDEX_FURNITURE";

export type Building_UI_Workshop_BuildingWorkshopModel_FormulaItem_SubType = "NORMAL" | "DIYITEM";

export type Building_UI_Workshop_WorkshopFormulaSorter_WorkshopSortingOption = "RARITY" | "PRICE" | "ID_ORDER" | "ENUM_COUNT";

export type Building_UI_Workshop_WorkshopFormulaSorter_SortingMethod = "ASCENT" | "DESCENT" | "ENUM_COUNT";

export type Building_UI_Workshop_WorkshopSortButton_State = "INACTIVE" | "ASCENT" | "DESCENT";

export type Building_UI_Workshop_WorkshopCheckResult = "OK" | "INGREDIENT_NOT_ENOUGH";

export type Building_UI_Workshop_MaxCountLimitReason = "UNKNOWN" | "GOLD" | "INGREDIENT" | "MOOD";

export type Building_UI_Trading_OrderStatus = "NONE" | "GAINING" | "GAINED";

export type Building_UI_Trading_OrderViewAction = "NONE" | "UPDATE" | "REMOVE" | "RELOAD" | "REMOVE_IMMEDIATE";

export type Building_UI_Trading_TradingOrderViewType = "COMPOUND" | "GOLD" | "DIAMOND";

export type Building_UI_StationSelect_ChangedRoomViewModel_StationedCharChangeStatus = string;

export type Building_UI_StationSelect_ChangedRoomGroupViewModel_ChangedRoomGroupType = string;

export type Building_UI_StationSelect_CharSortType = "NONE" | "ROOM" | "AP" | "WORK" | "LEVEL" | "EVOLVE_PHASE" | "RARITY" | "NAME" | "BUFF" | "BUFF_SORTID" | "FAVOR" | "EFFICIENCY";

export type Building_UI_StationSelect_CharFilterType = "ALL" | "ROOM_NONE" | "ROOM_CATEGORY_OUTPUT" | "ROOM_CATEGORY_FUNC" | "ROOM_CATEGORY_CUSTOM" | "ROOM_TYPE_CONTROL" | "ROOM_BUFF_OUTPUT" | "ROOM_BUFF_FUNC" | "ROOM_BUFF_RECOVER" | "ROOM_CATEGORY_CUSTOM_P";

export type Building_UI_StationSelect_StationSelectStateBean_StationSelectStateBeanInputType = string;

export type Building_UI_SM_PreQueueStatus = string;

export type Building_UI_SM_ManageMode = "WORK" | "DORM";

export type Building_UI_Shop_FormulaFilterType = "ALL";

export type Building_UI_Shop_FormulaSortType = "NONE" | "RARITY" | "RESERVE" | "PRICE" | "TIME" | "FORMULA_ID";

export type Building_UI_Meeting_BuildingMessageLeavePage_MessageBoardType = string;

export type Building_UI_Manufact_FormulaFilterType = "ALL";

export type Building_UI_Manufact_FormulaSortType = "NONE" | "UNLOCK" | "RARITY" | "TIME" | "FORMULA_ID";

export type Building_UI_Float_FloatState = "NONE" | "VAULT_CONTROL" | "VAULT_DORMITIORY" | "VAULT_NONE" | "BP_NONE" | "BP_ARCHITECTURE" | "VAULT_MANUFACT" | "VAULT_SHOP" | "VISIT" | "VAULT_POWER" | "VAULT_HIRE" | "VAULT_MEETING" | "VAULT_UPGRADING" | "VAULT_TRAINING" | "VAULT_WORKSHOP" | "VAULT_TRADING" | "BP_TODO_NOTIFY" | "VAULT_PRIVATE" | "BLUEPRINT" | "VAULT" | "ALL";

export type Building_UI_Float_BuildingFloatSlideMode = "NONE" | "STATION" | "DETAIL";

export type Scripts_UI_ConstructLand_SandboxV2ConstructDetailModel_HideUIReasonMask = "NONE" | "IN_HIDE_STATE" | "PRESSED_HIDE_UI" | "GAME_NOT_READY";

export type EventTrack_EventLogTrace_ArtGalleryClickRank = "ENTRY" | "SUB_ENTRY" | "LIST_TAB" | "DETAIL_VIEW";

export type EventTrack_EventLogTrace_EventLogShopContext_ShopClickRank = string;

export type Battle_BattleStageMeta_BusinessType = "DEFAULT" | "CRISIS" | "HANDBOOK" | "DEEPSEA" | "CLIMBTOWER" | "BOSSRUSH" | "ACTCART" | "SIRACUSAMAP" | "SANDBOX" | "TRAINING_CAMP" | "VEC_BREAK_OFFENSE" | "VEC_BREAK_DEFENSE" | "AUTOCHESS" | "ACTARCADE" | "SIX_STAR" | "ENEMY_DUEL" | "RECAL_RUNE" | "ACTFOOTBALL";

export type Battle_SkinType = "CHARACTER" | "TRAP";

export type Battle_PlayerOperationType = "SPAWN" | "WITHDRAW" | "SKILL" | "CHEAT";

export type Battle_Act44SideBattleManager_GameStage = "NORMAL" | "RUSHTIME";

export type Battle_Mainline15PrtsManager_PrtsActionType = "MOVE_AND_SPAWNENEMY" | "MOVE_AND_CREATEBUFF" | "MOVE_AND_DRAG_SOURCE";

export type Battle_Mainline15PrtsManager_PrtsSubActionType = "MOVE_TO_ORIGIN" | "MOVE_TO_DRAG" | "DRAG" | "SPAWN" | "MOVE_TO_CREATE_BUFF" | "CREATE_BUFF" | "FOLLOW_BOSS";

export type Battle_BuildingElectricManager_WorkType = "WOOD" | "STONE" | "IRON" | "ELECTRIC" | "AMPLIFY";

export type Battle_BuildingGeneratorManager_GeneratorType = string;

export type Battle_BuildingRenderManager_RuleType = string;

export type Battle_BuildingScoreManager_BuildingType = string;

export type Battle_AutoChessShopTrapHudPlugin_CoinDisplayType = "NONE" | "REFRESH_PRICE" | "UPGRADE_PRICE";

export type Battle_AdvancedSelectorForSandboxV3Gather_SandboxV3GatherFilterType = "SEARCH_RES" | "TRACE_TARGET_ONLY";

export type Battle_AdvancedSelectorInSandbox_SandboxFilterType = "SANDBOX_TRANSFER_RES" | "REMOVE_CANNOT_BE_TRACED" | "RANDOM_NEAREST" | "TRACE_TARGET_ONLY";

export type Battle_Cooperate_CoopStageType = "BASIC" | "KILL" | "SURVIVE" | "TOWER" | "PROTECT" | "CAR" | "TARGET" | "BOSS" | "ENUM";

export type Battle_AutoChess_AutoChessGameStatus_SubState = "NONE" | "PRELOAD" | "BEGIN" | "MAIN" | "END" | "START" | "FINISH";

export type Battle_AutoChess_AutoChessGameStatus_AutoChessHUDTipDisplay = "NONE" | "PLAYER_INFO_TIP" | "BOND_DETAIL_TIP";

export type Battle_AutoChess_AutoChessGameStatus_AutoChessBattleMapLayer = "START" | "LEFT" | "MID" | "RIGHT" | "END";

export type Battle_AutoChess_AutoChessOperationType = "MOVE_ONLY" | "EQUIP_ITEM" | "USE_MAGIC" | "WITHDRAW" | "REPLACE_EQUIP";

export type Battle_AutoChess_AutoChessDragOperationFlag = "NONE" | "IS_START_BATTLE" | "IS_END_BATTLE" | "IS_START_VALID_HAND" | "IS_END_VALID_HAND" | "IS_START_HAND" | "IS_END_HAND" | "END_CONTAINS_TARGET" | "START_CONTAINS_TOKEN_POS" | "END_CONTAINS_TOKEN_POS" | "ALL";

export type Battle_AutoChess_AutoChessLevelEnemyManager_RandomEnemyGenerater_AutoChessRandomEnemyType = string;

export type Battle_AutoChess_AutoChessMapAreaManager_TileIndexer_TileCacheType = "BATTLE_FIELD" | "HAND" | "VALID_HAND";

export type Battle_AutoChess_AutoChessEffectChooseDataModel_AutoChessBattleEffectChooseMode = "SP_PREPARE" | "MAGIC_SELECT";

export type Battle_AutoChess_AutoChessSettleDataModel_EndingStatus = "NONE" | "NORM_BOSS_WIN" | "HIDE_BOSS_FAIL" | "HIDE_BOSS_WIN" | "GAME_OVER";

export type Battle_AutoChess_ChessBackupCharDiff = "NONE" | "DIFF_YELLOW" | "DIFF_GREEN" | "DIFF_BLUE";

export type Battle_AutoChess_AutoChessCameraPlugin_PositionType = "NONE" | "LEFT_PREPARE" | "LEFT_SHOP" | "LEFT_BATTLE" | "RIGHT_BATTLE" | "MID_BATTLE" | "LEFT_BOSS_PREPARE" | "RIGHT_BOSS_PREPARE" | "LEFT_BOSS_SHOP" | "RIGHT_BOSS_SHOP" | "LEFT_BOSS_BATTLE" | "RIGHT_BOSS_BATTLE" | "MID_BOSS_BATTLE" | "ENEMY_PREVIEW" | "CUSTOM_CHARACTER";

export type Battle_GameMode_GameModeFactory_RoguelikeDeifyGameMode_DeifyBattleResult = string;

export type Battle_GameMode_GameModeFactory_RoguelikeDeifyGameMode_GameStage = "STAGE_CHOSEN" | "STAGE_BATTLE";

export type Battle_GameMode_GameModeFactory_RoguelikeDeifyGameMode_BattleResult = string;

export type Battle_GameMode_GameModeFactory_RoguelikeDuelGameMode_DuelBattleResult = string;

export type Battle_GameMode_GameModeFactory_RoguelikeDuelGameMode_DuelMode = string;

export type Battle_GameMode_GameModeFactory_RoguelikeDuelGameMode_GameStage = "STAGE_CHOSEN" | "STAGE_READY" | "STAGE_BATTLE";

export type Battle_Skills_SandboxV3RecipeHolder_RecipeType = "PROCESS" | "SERVICE";

export type Battle_Roguelike_BasicRelic_RelicType = "NONE" | "LEVEL_OPTIONS" | "CHARACTER" | "GLOBAL_BUFF" | "ENEMY" | "CARD" | "LEVEL_PREDEFINE" | "MISC" | "ENV_SYSTEM";

export type Battle_Projectiles_HoveringInPlaceMovement_HoveringStage = "SEMICIRCLE" | "CIRCLE";

export type Battle_SandboxV3_ListenerType = "TRANSFER" | "PRODUCER" | "ENEMY" | "BASE" | "NORMAL_UPPER_MASK" | "ALL";

export type Battle_SandboxV3_ProducerDropType = "DEFAULT" | "DIRECTLY_CONVERT_ITEM";

export type Battle_SandboxV3_GatherSpatialMode = string;

export type Battle_SandboxV3_ShowType = "NONE" | "POWER" | "BEAUTY";

export type Battle_SandboxV3_UpgradeCondition = string;

export type Battle_SandboxV3_BuildOperationType = "NONE" | "PLACE" | "UPGRADE" | "WITHDRAW" | "CLEAN";

export type Battle_SandboxV3_RefreshPriceDiscountProcessorHolder_DiscountType = "SHOP_REFRESH" | "MILESTONE_REFRESH";

export type Battle_SandboxV3_RecipeStatus = "OK" | "LOCKED" | "LACK_MATERIAL";

export type Battle_SandboxV3_ItemChangeReason = "NONE" | "SHOP_PURCHASE" | "CONSTRUCT_OUTPUT" | "PROCESS_OUTPUT" | "PRODUCE_OUTPUT" | "SHOP_SALE" | "GATHER" | "ENEMY_DROP" | "ENEMY_SPECIFIC" | "QUEST_REWARD" | "WITHDRAW_RETURN" | "SPECIAL_TRIGGER" | "ANIMAL_PRODUCE" | "DEPLOY" | "CONSTRUCT_MATERIAL" | "DELIVERY" | "PROCESS_MATERIAL" | "SHOP_PURCHASE_COST" | "SHOP_SALE_COST" | "MAINTAIN_SERVICE" | "SHOP_REFRESH_COST" | "ANIMAL_PRODUCE_COST" | "GATHER_DROP";

export type Battle_SandboxV3_SandboxV3GameState = "WAIT_BASE" | "WAIT_START" | "CONSTRUCT" | "IN_GAME";

export type Battle_SandboxV3_BasicProcessType = "MILESTONE_OPTION_COUNT" | "QUEST_OPTION_COUNT" | "GATHER_RES_MAX_DEATH_TIME" | "SHOP_DISCOUNT_RATE" | "MILESTONE_REFRESH_PRICE" | "SHOP_REFRESH_PRICE";

export type Battle_SandboxV3_SandboxV3GameFinishReason = "NONE" | "TIME_UP" | "BASE_BREAK" | "SKIP" | "QUIT";

export type Battle_SandboxV3_ResDropSourceType = "TRAP" | "ENEMY";

export type Battle_SandboxV3_SandboxV3StatType = "PROSPERITY" | "AESTHETICS" | "POWER_PER_SEC" | "E_NUM";

export type Battle_SandboxV3_PowerValueChangeReason = "NONE" | "ENEMY_DROP" | "PER_SEC_PRODUCE" | "QUEST_REWARD" | "FROM_RELIC";

export type Battle_SandboxV3_SandboxV3BattleTaskManager_TaskState = string;

export type Battle_Sandbox_SandboxOutput_EnemyDeathDetailType = "CATCHED" | "CATCHED_SHINING" | "STOLEN" | "ENUM";

export type Battle_Sandbox_SandboxOutput_UniEnemyDeathDetailType = "CATCHED" | "CATCHED_SHINING" | "ENUM";

export type Battle_Sandbox_ResDropSourceType = "TRAP" | "ENEMY";

export type Battle_Sandbox_ResPackType = "WOOD" | "STONE" | "IRON" | "DIAMOND" | "COUNT" | "INVALID";

export type Battle_Action_Nodes_AutoChessLogExtraBattleInfo_LogType = "DEFAULT" | "WITHOUT_INST_ID";

export type Battle_Action_Nodes_RoguelikeLogExp_ExpType = "ENEMY_KILLED" | "TRAP_GAINED";

export type Battle_UI_AutoChessCharacterMenuButton_DisplayType = "SELL" | "DESTROY";

export type Battle_UI_AutoChessUnderFramePanelButton_DisplayType = "SELL" | "DESTROY";

export type Battle_UI_UIRoguelikePluginRL05_ToastTypeRL05 = "GOLD_STEAL";

export type Battle_UI_UIRoguelikePluginRL06_ToastTypeRL06 = "GOLD_STEAL" | "MODEL_STEAL" | "STEP_STEAL";

export type Battle_UI_UIRoguelikePluginRL04_ToastTypeRL04 = "GOLD_STEAL" | "DISASTER_CONTINUE" | "SKZDD_PREACH";

export type Battle_UI_SandboxV3_UIBuildSandboxV3MenuItemList_ShowType = "NONE" | "UPGRADE" | "WITHDRAW";

export type Battle_UI_SandboxV3_UIBuildSandboxV3MenuItemList_BuildType = "NONE" | "BEAUTY" | "ELECTRIC";

export type Battle_UI_Sandbox_UIBattleSandboxConstructMenuItemList_ShowType = "NONE" | "REPAIR" | "UPGRADE" | "WITHDRAW";

export type Battle_UI_Sandbox_SandboxBattleStyle = "DEFAULT" | "TIME" | "CORE_BATTLE" | "BUILD" | "MARKET" | "READ_ONLY_BUILD";

export type UI_DynIllustStartMgr_CharVoiceManager_State = "STATE_NOT_INITED" | "STATE_INITED" | "STATE_TRIGGERD";

export type UI_UICharIllustInfoCache_CharRotationUpdateStrategy = "FIRST_TIME_IN_DAY" | "EVERY_TIME";

export type UI_CharacterHandbookStageStatus = "NONE" | "UNLOCKED" | "LOCKED" | "PASS";

export type UI_CommonCharCardView_CommonCharCardEquipAssets_EquipIconType = "COLOR_DIRECTION" | "WHITE";

export type UI_PlayerSyncStatusEvent = "NONE" | "STAGE" | "BUILDING" | "ACTIVITY" | "BIRTHDAY";

export type UI_CustomPageActivityStateEntryComp_EntryAnim_AnimType = "LOOP" | "ENTRY";

export type UI_CustomPageActivityStateEntryComp_EntryCompStatus = string;

export type UI_RecruitDataConverter_SingleGachaCost = "DIAMOND" | "LIMIT_FREE" | "COMMON_TKT" | "CLASSIC_TKT" | "LIMIT_TICKET";

export type UI_RecruitDataConverter_TenGachaCost = "DIAMOND" | "LIMIT_TKT" | "COMMON_TKT" | "CLASSIC_TKT";

export type UI_SandboxV2TrackType = "NONE" | "RIFT_UNLOCK_NEW_DIFFICULTY" | "SHOP_UNLOCK" | "SHOP_HAS_DISCOUNT_GOOD" | "SUPPLY_UNLOCK" | "SUPPLY_UNLOCK_NEW_BLOCK" | "WORKBENCH_UNLOCK_NEW_ITEM" | "WORKBENCH_UNLOCK_NEW_RECIPE" | "COOK_UNLOCK_NEW_RECIPE" | "BASE_UPGRADE" | "ACT_ARCHIVE_QUEST_UNLOCK" | "ACT_ARCHIVE_MUSIC_UNLOCK";

export type UI_SandboxV3TrackType = "NONE" | "ACT_ARCHIVE_QUEST_UNLOCK" | "ACT_ARCHIVE_MUSIC_UNLOCK" | "QUEST_START" | "UNLOCK_DIFFICULTY";

export type UI_VoucherSkin_VoucherSkinPage_VoucherSkinType = "NOTVOUCHER" | "EXCHANGE" | "PREVIEW";

export type UI_VoicelangSetting_ConfirmViewState = string;

export type UI_UniEquipArchive_UniEquipArchiveFilterEquipState = "ALL" | "UNLOCKED" | "LOCKED";

export type UI_UniEquipArchive_UniEquipArchiveCollectionInfoType = "NONE" | "TOTAL_COLLECTION_MODULES" | "OWN_MODULE_CHARS";

export type UI_UniEquipArchive_EntryCollectionEquipItemShowState = "NOT_OWN_CHAR";

export type UI_UniEquipArchive_EntryCollectionEquipItemUnlockState = "NOT_OWN_CHAR_CANT_UNLOCK" | "UNLOCKED";

export type UI_UniEquipArchive_EntryCollectionEquipItemClickType = "NONE" | "JUMP_TO_MODULE_SELECT" | "JUMP_TO_CHAR_DETAIL" | "JUMP_TO_CHAR_DISPLAY";

export type UI_UniEquipArchive_EntryCollectionEquipItemCharPartClickType = "NONE" | "JUMP_TO_CHAR_DETAIL";

export type UI_UniEquipArchive_ModuleCollectionItemUnlockState = string;

export type UI_UniEquipArchive_UniEquipSortType = "BY_LEVEL_UP" | "BY_LEVEL_DOWN" | "BY_UPDATE_TIME_UP" | "BY_UPDATE_TIME_DOWN";

export type UI_UniEquip_UniEquipSelectViewModel_EquipAvgSortType = "NONE" | "INITIAL" | "LEVEL_MAX" | "LEVELUP_VALID" | "LOCKED";

export type UI_Tuning_TuningHomeMajorInvestViewModel_Status = "NOT_UNLOCKABLE" | "UNLOCKABLE" | "UNLOCKED" | "COMPLETE";

export type UI_Tuning_TuningHomeMajorInvestItemViewModel_Status = "UNKNOWN" | "UNLOCKED" | "COMPLETE";

export type UI_TemplateShop_TemplateShopSource = "ACT" | "SANDBOX" | "ENUM";

export type UI_TemplateShop_TemplateShopData_TShopType = "NORMAL" | "SHOP_RARITY_GROUP" | "SHOP_PERIOD_UNLOCK";

export type UI_TemplateShop_TemplateShopData_GoodType = "NORMAL" | "PROGRESS";

export type UI_TemplateMission_TemplateMissionListItemViewType = "NORMAL_ITEM" | "CLAIM_ALL_ITEM";

export type UI_TemplateMission_TemplateMissionDisplaySource = "ACT" | "RETRO" | "ENUM";

export type UI_TemplateMission_TemplateMissionDataSource = "ACT" | "RETRO" | "ENUM";

export type UI_TemplateMission_TemplateMissionLayoutType = "COMMON";

export type UI_SpecialOperator_SpecialOperatorBoardEvolveNodeViewModel_MissionState = "LOCK" | "CAN_SUBMIT" | "UNLOCK";

export type UI_SocialCardAlbum_CardType = "NAME_CARD" | "ART_MAGAZINE_LEAF";

export type UI_Skin_SkinPage_PageReferrer = "NONE" | "SHOP_SKIN" | "SHOP_GP" | "ACTIVITY_MILESTONE" | "VOUCHER" | "CHARACTER_INFO" | "ROGUELIKE_BATTLE_PASS" | "TEMPLATE_SHOP" | "CRISIS_MAP" | "WARDROBE" | "ART_GALLERY";

export type UI_Skin_SkinGroupCommonView_IllustObjectType = "DEFAULT" | "SP_DYN_ILLUST";

export type UI_Skin_SkinPreviewPanel_IllustType = "SHOW_DYN" | "FORCE_STATIC" | "PLAYER_CONFIG";

export type UI_Skin_SkinState = "EQUIPED" | "CAN_EQUIP" | "NOT_GET" | "NOT_UNLOCK" | "DONT_HAVE_CHAR" | "JUST_FOR_SHOW" | "TMPL_ID_NOT_MACTH" | "BUY_WITH_VOUCHER" | "HAS_GOT" | "NOT_REDEEM";

export type UI_SiracusaMap_SIRACUSA_MAP_AVG_TYPE = "NONE" | "MID" | "BEFORE" | "AFTER";

export type UI_SiracusaMap_SiracusaCharCardModel_DisplayEnum = "NONE" | "EMPTY" | "EQUIP" | "COMPLETED";

export type UI_SiracusaMap_SiracusaMapNodeViewBase_ViewType = "NORMAL" | "TASK" | "SELECTED";

export type UI_SiracusaMap_SiracusaMapMapNodeViewModel_NodeType = "NONE" | "NORMAL" | "TASK";

export type UI_SiracusaMap_SiracusaMapPanelMapViewModel_MapState = "NONE" | "BIG" | "SMALL";

export type UI_SandboxPerm_SandboxPermCommonConfirmDialog_BtnColorType = "GREEN" | "RED";

export type UI_SandboxPerm_SandboxPermCommonConfirmDialog_IconType = "INFO" | "TASK" | "REFRESH" | "FINISH_RED" | "FINISH_GREEN" | "RECRUIT";

export type UI_SandboxPerm_SandboxPermCommonItemCard_CountShowType = "NONE" | "HIDE" | "SINGLE_SHOW" | "MULTI_SHOW" | "PLUS_PREFIX" | "SHOW";

export type UI_SandboxPerm_SandboxPermCommonItemCard_SelectShowType = "NONE" | "SHOW_COUNT" | "SHOW_REDUCE_BTN" | "DEFAULT";

export type UI_SandboxPerm_SandboxPermCommonItemCard_MaxCountUsage = "NONE" | "NEED" | "MAX_PRODUCE";

export type UI_SandboxPerm_SandboxPermScienceNodeState = "CANT_LIGHT_UP" | "NEED_FRONT" | "DOT_NOT_ENOUGH" | "BASE_LEVEL_NOT_ENOUGH" | "CAN_LIGHT_UP" | "LIGHTED";

export type UI_SandboxPerm_SandboxPermShopTradeType = "NONE" | "SELL" | "BUY";

export type UI_SandboxPerm_SandboxPermShopTradeGoodType = "NONE" | "COMMON" | "RECRUIT";

export type UI_SandboxPerm_SandboxPermShopGoodSellType = "NONE" | "AVAIL" | "SOLDOUT" | "OWNED";

export type UI_SandboxPerm_SandboxV3_SandboxV3BagDataSourceType = "PLAYER_DATA" | "BATTLE";

export type UI_SandboxPerm_SandboxV3_SandboxV3BaseShopFilterType = "NONE" | "ALL" | "COOKBOOK" | "BUILDING";

export type UI_SandboxPerm_SandboxV3_SandboxV3BattleTaskStatus = "NONE" | "RECEIVABLE" | "RECEIVED" | "COMPLETING" | "ALL_DONE";

export type UI_SandboxPerm_SandboxV3_SandboxV3BuildInfoModel_ShowType = "NONE" | "POWER" | "BEAUTY";

export type UI_SandboxPerm_SandboxV3_SandboxV3BuildUIState = "DEFAULT" | "HIDE_UI" | "HIDE_ALL" | "CAMERA_ZOOM" | "CARD_DETAIL";

export type UI_SandboxPerm_SandboxV3_SandboxV3CharSelectCardViewModel_CardStatus = "NONE" | "NORMAL" | "PREDEFINED" | "DEFEND";

export type UI_SandboxPerm_SandboxV3_SandboxV3CharSelectCustomInput_ContextType = "NONE" | "EXPEDITION" | "INIT_RECRUIT" | "DEFEND_LEADER" | "DEFEND_SUB" | "CHAR_REPO";

export type UI_SandboxPerm_SandboxV3_SandboxV3MapOverviewUnitModel_Status = "EMPTY" | "UNLOCK" | "LOCK";

export type UI_SandboxPerm_SandboxV3_SandboxV3NotificationBgType = "NONE" | "ACHV" | "WARN" | "GAINITEM" | "TASK" | "TRADE" | "COOK";

export type UI_SandboxPerm_SandboxV3_SandboxV3NotificationIconType = "NONE" | "ACHV" | "WARN" | "TASK" | "RECRUIT" | "COOK" | "BATTLE" | "TREASURE";

export type UI_SandboxPerm_SandboxV3_SandboxV3CookModel_CookStatus = "NONE" | "SELECT_FOOD" | "COOK_FOOD";

export type UI_SandboxPerm_SandboxV3_SandboxV3DungeonCameraController_LockSource = "SELF" | "PAGE" | "STATE" | "ENTER_ANIM";

export type UI_SandboxPerm_SandboxV3_SandboxV3DungeonLodRank = "LOD_NEAR" | "LOD_FAR";

export type UI_SandboxPerm_SandboxV3_SandboxV3DungeonViewModel_SandboxV3DungeonFocusPosType = "CENTER" | "SELECT_NODE_LEFT" | "NAVIGATE_RIGHT_TOP";

export type UI_SandboxPerm_SandboxV3_SandboxV3DungeonViewModel_MapUIType = "NORMAL" | "WATCH";

export type UI_SandboxPerm_SandboxV3_SandboxV3DungeonDialogType = "QUEST_LINE_FINISH" | "QUEST_LINE_START" | "ZONE";

export type UI_SandboxPerm_SandboxV3_SandboxV3DungeonPage_CameraActiveSrc = "PAGE" | "STATE_TRANSITION" | "CUSTOM";

export type UI_SandboxPerm_SandboxV3_SandboxV3CharRepoCharCard_CharCardStatus = "NONE" | "AVAIL";

export type UI_SandboxPerm_SandboxV3_IRecruitCharBlockStatus_RecruitCharStatus = "ERROR" | "AVAIL" | "ALREADY_RECRUIT" | "PRE_DEFINED" | "DEFEND_IN_OTHER_ZONE";

export type UI_SandboxPerm_SandboxV3_SandboxV3GapHomeRecruitViewModel_RecruitStatus = "INIT_AVAIL" | "INIT_RECRUIT_FULL" | "REPO_FULL" | "DAY_PASS_AVAIL";

export type UI_SandboxPerm_SandboxV3_SandboxV3SettleViewModel_State = "RESULT" | "SCORE";

export type UI_SandboxPerm_SandboxV2_SandboxV2CharSelectCharCardType = "CHAR_SELECT" | "SUPPLY" | "ENUM";

export type UI_SandboxPerm_SandboxV2_SandboxV2AdminCharSelectStateMode = "SINGLE_SQUAD" | "MULTIPLE_SQUAD" | "MULTIPLE_EXPEDITION" | "CHARACTER_SHOW" | "LOGISTICS" | "ENUM";

export type UI_SandboxPerm_SandboxV2_SandboxV2CharSelectTabEnum = "FOOD" | "SKILL" | "BRANCH" | "NONE";

export type UI_SandboxPerm_SandboxV2_SandboxV2AdminMainTabPanelUpdateCase = "NONE" | "ON_VISIBLE" | "ON_RESUME";

export type UI_SandboxPerm_SandboxV2_SandboxV2AdminMainMaterialModel_ColorType = "NORMAL" | "WATER" | "GOLD";

export type UI_SandboxPerm_SandboxV2_SandboxV2CookDrinkModel_SelectMode = "FOODMAT" | "FOOD";

export type UI_SandboxPerm_SandboxV2_SandboxV2AdminMainCookType = "NONE" | "ENERGY_DRINK" | "COOK" | "FREE_COOK";

export type UI_SandboxPerm_SandboxV2_SandboxV2AdminMainInventoryItemShowType = "NONE" | "RES" | "FOOD" | "BUILDING" | "TACTICAL" | "CRAFT" | "ANIMAL";

export type UI_SandboxPerm_SandboxV2_SandboxV2AdminMainPanelType = "NONE" | "CHAR_REPO" | "INVENTORY" | "COOK" | "WORKBENCH" | "SHOP" | "SCIENCE";

export type UI_SandboxPerm_SandboxV2_SandboxV2AdminMainWorkbenchType = "NONE" | "BASE_BUILDING" | "TACTICAL" | "COMBAT_BUILDING" | "ALCHEMY";

export type UI_SandboxPerm_SandboxV2_SandboxV2FoodVariantShowType = "NONE" | "ONE_STAR" | "TWO_STAR";

export type UI_SandboxPerm_SandboxV2_SandboxV2ConfirmDialogThemeType = "LIGHT" | "DARK";

export type UI_SandboxPerm_SandboxV2_SandboxV2ConfirmDialogConfirmVisualType = "GREEN" | "RED" | "GRAY" | "BLUE";

export type UI_SandboxPerm_SandboxV2_SandboxV2ConfirmDialogConfirmAudioType = "CONFIRM" | "QUIT";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonLodRank = "NONE";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonCameraController_ZoomType = "NONE" | "NEAR" | "MID" | "FAR";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonCameraController_LockSource = "SELF" | "PAGE" | "STATE";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonCrossDayViewStatus = "NONE" | "SHOW_CALC" | "HIDE_CALC" | "SHOW_DAY_INFO";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonCrossDayEnemyRushType = "NORMAL" | "ELITE" | "BOSS" | "OTHER";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonReadArchiveType = "NONE" | "PASSIVE" | "INITIATIVE";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonMonthModel_UpdateStatus = "NORMAL" | "LAST" | "COMPLETE";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonMonthBrief_Status = "OFFLINE" | "BEFORE_STARTING" | "UPDATING" | "UPDATING_IDLE" | "FULL_STORE";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonPage_CameraActiveSrc = "SRC_PAGE_SHOW" | "SRC_STATE_TRANSITION" | "SRC_CUSTOM_SET_ACTIVE";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonDialogShowType = "ZONE" | "QUEST" | "RIFT_QUEST" | "GUIDE_START";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonDialogQuestProcessType = "NONE" | "FAIL" | "FINISH" | "START";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonPushMessageObservableType = "ZONE_UNLOCK" | "QUEST_STATUS" | "UNKNOWN";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonLayerType = "LAYER_BACKGROUND" | "LAYER_SHADOW" | "LAYER_LINE" | "LAYER_ENEMY_RUSH_LINE" | "LAYER_CONTENT" | "LAYER_CLOUD" | "LAYER_TOP" | "LAYER_FLOAT";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonMiscRiftMainMissionState = "FAIL" | "UNFINISHED" | "FINISHED";

export type UI_SandboxPerm_SandboxV2_SandboxV2NodeAppearanceType = "NONE" | "LOCKED" | "UNLOCKED" | "OCCUPIED" | "ENEMY_RUSH" | "LOCKED_ENEMY_RUSH";

export type UI_SandboxPerm_SandboxV2_SandboxV2NodeSelectionShowType = "NONE" | "NODE_DETAIL" | "NODE_CONSTRUCTION" | "ENCOUNTER";

export type UI_SandboxPerm_SandboxV2_SandboxV2EnemyDetailShowType = "NONE" | "NORMAL" | "ENEMY_RUSH";

export type UI_SandboxPerm_SandboxV2_SandboxV2NodeStartBattleFuncType = "NONE" | "NORMAL" | "MARKET" | "CONSTRUCT_LOCKED" | "CONSTRUCT_UNLOCKED" | "ENEMY_RUSH" | "RACING" | "SELECTION";

export type UI_SandboxPerm_SandboxV2_SandboxV2ConstructHpType = "NONE" | "NORMAL" | "DAMAGED";

export type UI_SandboxPerm_SandboxV2_SandboxV2ConstructTipType = "TRAP_DAMAGED" | "CAN_UPGRADE" | "BASEMENT_BUILDING_DAMAGED" | "BATTLE_BUILDING_DAMAGED" | "BASEMENT_BUILDING_CAN_UPGRADE" | "BATTLE_BUILDING_CAN_UPGRADE" | "E_NUM";

export type UI_SandboxPerm_SandboxV2_SandboxV2NodeState = "NONE" | "LOCKED" | "UNLOCKED";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonNodeFocusType = "CENTER" | "SELECTION" | "TRACKER";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonNodeFocusPosType = "MIDDLE_LEFT" | "MIDDLE_CENTER" | "MIDDLE_RIGHT";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonFocusType = "FOCUS_NODE" | "FOCUS_ZONE" | "PURE_ZOOM";

export type UI_SandboxPerm_SandboxV2_SandboxV2ProgressAppearanceType = "NONE" | "NEST" | "CAVE" | "MINE" | "GATE" | "ENEMY_RUSH";

export type UI_SandboxPerm_SandboxV2_SandboxV2FloatAppearanceType = "NONE" | "ENEMY_RUSH_BOSS" | "ENEMY_RUSH_ELITE" | "ENEMY_RUSH" | "MESSENGER" | "RIFT_BOSS" | "RIFT_PREY" | "RIFT" | "NPC" | "ENCOUNTER" | "RARE_ANIMAL";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonPathLineViewModel_PathType = "NONE" | "ENEMY_RUSH" | "MESSENGER";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonViewModel_SequenceNumFlag = "NONE" | "DUNGEON_CONSTRUCT" | "DUNGEON_CHANGE" | "NODE_SELECTION" | "PATH_SELECTION" | "FLOAT_GROUP_SELECTION" | "DUNGEON_FOCUS" | "ENTER_ANIM" | "TUTORIAL_ONLY_NODE_REGISTER";

export type UI_SandboxPerm_SandboxV2_SandboxV2DungeonViewModel_ChallengeState = "NONE" | "INACTIVE" | "FIRST_CROSS_DAY" | "ACTIVE";

export type UI_SandboxPerm_SandboxV2_SandboxV2ChallengeRewardDialog_SandboxV2ChallengeRewardViewModel_State = "STATE_CAN_RECEIVE" | "STATE_INCOMPLETE" | "STATE_COMPLETED";

export type UI_SandboxPerm_SandboxV2_SandboxV2LogisticsVisitMode = "MODE_SIMPLE" | "MODE_COMPLEX";

export type UI_SandboxPerm_SandboxV2_SandboxV2LogisticsBuffInvalidStatus = "NONE" | "NO_CHAR" | "NO_DRINK" | "IN_RIFT";

export type UI_SandboxPerm_SandboxV2_SandboxV2RacerInfoPage_Type = "NONE" | "INVENTORY" | "START_BATTLE";

export type UI_SandboxPerm_SandboxV2_SandboxV2ConstructOperationType = "INVALID" | "PLACE" | "UPGRADE" | "WITHDRAW" | "REPAIR" | "REPAIR_ALL" | "PLACE_ANIMAL";

export type UI_SandboxPerm_SandboxV2_SandboxV2Const_SandboxV2ToastType = "NONE" | "COMMON" | "COOK" | "BUILD" | "ARCHIEVEMENT";

export type UI_SandboxPerm_SandboxV2_SandboxV2Const_SandboxV2BattleBgmType = "NONE" | "ENEMY_RUSH" | "BOSS_RUSH" | "COLLECT" | "HUNT";

export type UI_SandboxPerm_SandboxV2_SandboxV2SquadGroupModel_ViewType = "NONE" | "REPO" | "SQUAD";

export type UI_SandboxPerm_SandboxV2_SandboxV2SquadPanelShowMode = "NORMAL" | "MONTH";

export type UI_SandboxPerm_SandboxV2_SandboxV2CharFilter = "NONE" | "AVAIL" | "UNAVAIL";

export type UI_SandboxPerm_SandboxV2_SandboxV2CharStatus = "NONE" | "USED" | "SUPPLY" | "EXPED";

export type UI_SandboxPerm_SandboxV2_SandboxV2SlotStatus = "EMPTY" | "USED" | "NORMAL";

export type UI_RoguelikeTopic_ROGUELIKE_TOPIC_TOGGLE_DOT_STATE = "LOCK" | "UNCOMPLETE" | "COMPLETE";

export type UI_RoguelikeTopic_RoguelikeTopicDifficultyItemStatus = "INCLUDE" | "SELECTED" | "EXCLUSIVE";

export type UI_RoguelikeTopic_RoguelikeTopicMonthTaskItemView_CompleteType = "DEFAULT" | "FLAG";

export type UI_RoguelikeTopic_RoguelikeCommonOuterBuffLine_Direction = "FORWARD" | "BACKWARD";

export type UI_RoguelikeTopic_RoguelikeCommonOuterBuffViewType = "NORMAL" | "DIFFICULTY";

export type UI_RoguelikeTopic_RoguelikeTopicSetSeedResponse_ResultCode = "SUCCESS" | "INVALID_LENGTH" | "INVALID_CHARSET" | "SENSITIVE_WORD" | "FUNCTION_CLOSE" | "USER_BANNED" | "FAIL";

export type UI_RoguelikeTopic_RoguelikeTopicBattlePassPurchaseViewModel_IndexUpdateStrategy = "LIST_SPECIFICATION" | "WHEEL_PICKER_MOVEMENT";

export type UI_RoguelikeTopic_RoguelikeTopicBPPrizeViewModel_RoguelikeTopicBPPrizeState = "CAN_NOT_RECEIVE" | "CAN_RECEIVE" | "RECEIVED";

export type UI_RoguelikeTopic_RoguelikeTopicModeViewType = "NONE" | "NORMAL" | "MONTH_TEAM" | "CHALLENGE";

export type UI_RoguelikeTopic_RoguelikeTopicDifficultyViewSub = "NONE" | "BASE" | "ADD_DETAIL" | "RULES" | "MAX";

export type UI_RoguelikeTopic_MonthSquadCardSwitchDirection = "NONE" | "PREV" | "NEXT";

export type UI_RoguelikeTopic_RL03_Rl03OuterBuffLine_Direction = "FORWARD" | "BACKWARD";

export type UI_RoguelikeTopic_RL03_Rl03OuterBuffViewType = "NORMAL" | "DIFFICULTY";

export type UI_RoguelikeTopic_RL02_RL02OuterBuffController_LODController_LOD = "BEFORE_INIT" | "SHOW_NODE_NAME" | "HIDE_NODE_NAME";

export type UI_RoguelikeTopic_RL02_RL02OuterBuffItemModel_UnlockStatus = "LOCKED" | "UNLOCK" | "ACTIVATED";

export type UI_RoguelikeTopic_RL01_Rl01OuterBuffSkillTreeLineType = "HORIZONTAL" | "VERTICAL" | "POINT";

export type UI_RoguelikeTopic_Mode_ModeTabIDs_SerializeTabID = "NONE" | "NORMAL" | "MONTH" | "CHALLENGE";

export type UI_RoguelikeTopic_Ending_RoguelikeTopicEndingSPOperatorGrowInfoItemViewModel_GrowInfoType = "NODE_ACTIVE" | "EVOLVE_UNLOCK" | "EVOLVE_ACTIVE";

export type UI_RoguelikeTopic_Activity_SeedMode_SeedItemType = "NONE" | "HISTORY" | "PREDEFINE";

export type UI_Recruit_BuildTagType = "SATISFIED" | "UNSATISFIED" | "DELETED";

export type UI_Recruit_RecruitSpecialGachaViewModel_Status = "INIT_VIEW" | "GACHA_VIEW";

export type UI_RecalRune_RecalRuneSeasonStageMedalState = "SENIOR" | "JUNIOR" | "NONE";

export type UI_RecalRune_RecalRuneStageRunePackType = "RUNE" | "HEAD_ESSENTIAL" | "HEAD_REWARDING";

export type UI_Monopoly_MonopolyEntryStageModel_StageTaskStatus = "FAIL" | "NORMAL" | "EXCELLENT";

export type UI_MissionArchive_MissionArchiveNodeState = "LOCKED" | "UNLOCKED" | "CLAIMED";

export type UI_MissionArchive_MissionArchiveVoicePlayState = "NONE" | "PLAY_NODE" | "PLAY_HIDDEN";

export type UI_Mission_DailyMissionSimpleView_DailyOrWeekly = "DAILY" | "WEEKLY";

export type UI_Medal_MedalSize = "NONE";

export type UI_Medal_MedalGetState = "NOTGET" | "ABLETOGET" | "ALREADYGET";

export type UI_Medal_MedalBarListShowType = "ALL" | "ALREADY_HAVE" | "NOT_HAVE";

export type UI_Medal_MedalBarListItemModel_ViewType = "TITLE" | "VIEWMODEL";

export type UI_Informant_InformantHomeViewModel_State = "WAIT_START" | "CONTINUE" | "ITEM_LOCKED" | "CLOSE";

export type UI_Home_HomePage_InitOpts = "NONE" | "EDIT_ILLUST" | "CHANGE_BKG" | "HOME_ACT" | "CHANGE_SECRETARY" | "CHANGE_SECRETARY_SKIN" | "CHANGE_THEME";

export type UI_Home_AutoPopupType = "NONE" | "ANNOUNCE" | "CHECKIN" | "OPEN_SERVER" | "HOME_ACT" | "HOME_ACT_AVG" | "UNFINISHED_ORDERS" | "HOME_BEFORE_ACT_AVG" | "HOME_ACT_WITH_AVG" | "HOME_GUIDE_AFTER_ALL" | "RETURN" | "BIRTHDAY_SETTING";

export type UI_Home_HomeDisplayController_PreviewElemFlag = "LEFT_PANEL" | "RIGHT_PANEL" | "FRONT_PANEL" | "ALL_PANELS" | "CHAR_WORD" | "BACKGROUND_BTN";

export type UI_Home_HomeDisplayCompType = "BACKGROUND" | "THEME";

export type UI_Home_HomeCharRotationViewModel_SelectSkinStrategy = "DO_NOT_MODIFY" | "USE_NOW_PREVIEWING" | "USE_FIRST";

export type UI_Home_HomeSecretarySkinChangeViewModel_FilterType = "NONE" | "EVOLVE_TWO_SKIN" | "SHOP_SKIN" | "DYN_SKIN" | "SHOW_SELECTED" | "SP_DYN_SKIN";

export type UI_Home_HomeMailArchiveItemViewModel_ViewType = "TITLE" | "ITEM";

export type UI_Home_ActShowType = "NONE" | "HIDDEN" | "SHOW_FINISHED" | "SHOW_NOT_FINISHED";

export type UI_Home_HomeActTabOnBattle_EntryType = "NONE" | "ACTIVITY" | "CRISIS" | "ROGUELIKE" | "MAINLINE" | "SANDBOX_PERM";

export type UI_Home_ActivityEntryType = "NONE" | "TRAINING" | "MAIN_STAGE" | "GACHA" | "SHOP";

export type UI_Home_Activity_OpenServerFuncType = "CHAIN_LOGIN" | "MISSION" | "TOTAL_CHECKIN";

export type UI_Home_Activity_OpenServerCheckinItemState = "LOCKED" | "RECEIVABLE" | "ALREADY_GOT";

export type UI_Grocery_GroceryHomeViewModel_State = "BEFORE_SALE" | "PURCHASE" | "SELL" | "BEFORE_SETTLE" | "AFTER_SETTLE" | "REWARD_ONLY";

export type UI_Grocery_GroceryHomeLaunchPanelGoodGroupModel_Status = "STAGE_LOCKED" | "TIME_LOCKED" | "UNLOCKED" | "OUTDATED";

export type UI_Grocery_GroceryOrderOtherShopStatus = "NONE" | "NOT_INQUIRE" | "INQUIRED";

export type UI_Grocery_GroceryOrderMyShopStatus = "NONE" | "SECTION" | "EXACT";

export type UI_Friend_NameCardV2ViewModel_ShowType = "DISPLAY_ONLY" | "IN_NAME_CARD_STATE" | "IN_SELF_EDIT_STATE" | "IN_SOCIAL_CARD_ALBUM_PAGE";

export type UI_Friend_NameCardV2ViewModel_ShowDetailOption = "READ_FROM_MISC" | "FORCE_SHOW_DETAIL" | "FORCE_HIDE_DETAIL";

export type UI_Friend_NameCardV2ViewModel_MiscFlag = "NONE" | "MISC_SHOW_DETAIL" | "MISC_SET_BIRTH" | "MISC_SHOW_BIRTH" | "MISC_ENABLE_BIRTH" | "MISC_DYN_INTRO_ENABLE" | "MISC_DYN_LOOP_ENABLE" | "ALL";

export type UI_Friend_NameCardV2CollectModuleModel_OperatorProgressStyle = "NUMBER" | "PERCENT";

export type UI_Friend_NameCardV2AssistModuleModel_Style = "HEAD_ICON" | "PORTRAIT";

export type UI_Firework_FireworkPlateSlotType = "NONE" | "NORMAL" | "DISABLED" | "FILLED" | "FILLED_CONFLICT" | "CENTER";

export type UI_Firework_FireworkUtil_AnimalIconType = "OUTLINE" | "NON_OUTLINE_SELECTED" | "NON_OUTLINE_UNSELECT";

export type UI_Firework_FireworkCraft_FireworkCraftAnimalSelectViewModel_AnimalStatus = "NONE" | "LOCKED" | "NORMAL" | "EQUIPED" | "SELECTED";

export type UI_Firework_FireworkCraft_FireworkCraftModel_EditStatus = "FIREWORK_WITH_NO_STAGE_BG" | "FIREWORK_WITH_STAGE_BG" | "STAGE_CHOOSE";

export type UI_Firework_FireworkCraft_FireworkCraftModel_OpenSource = "ZONE" | "STAGE";

export type UI_FifthAnnivMainline_FifthAnnivExploreDecisionModel_DecisionStatus = "NONE" | "EVT_INFO" | "PLAN" | "LOG";

export type UI_FifthAnnivMainline_FifthAnnivExploreUIEvent = "ON_STATE_ENTER" | "ON_STATE_RESUME" | "ON_STATE_PAUSE" | "ON_BEFORE_TRANSITION";

export type UI_FifthAnnivMainline_FifthAnnivExploreMapViewConfig_FifthAnnivExploreMapNodeShowType = "NONE" | "START" | "CHECKPOINT" | "EVENT" | "CURRENT" | "END";

export type UI_FifthAnnivMainline_FifthAnnivRouteType = "NONE" | "NORMAL" | "FAIL" | "SUCCESS";

export type UI_FifthAnnivMainline_FifthAnnivNodeType = "NONE" | "START" | "CHECKPOINT" | "EVENT" | "END";

export type UI_FifthAnnivMainline_FifthAnnivExploreTopMenuViewModel_DynViewType = "HERITAGE" | "PROGRESS";

export type UI_EnemyDuel_EnemyDuelPrepareRoomPlayerCardViewModel_State = "EMPTY" | "READY" | "BATTLE_FINISHING" | "OFFLINE";

export type UI_EnemyDuel_EnemyDuelPrepareRoomPlayerCardViewModel_FriendState = "NOT_FRIEND" | "SENT_REQUEST" | "FRIEND";

export type UI_EnemyDuel_Service_STDuelPlayerStatus_State = "UNREADY" | "READY" | "IN_BATTE";

export type UI_Emoticon_PlayerIndex = "NONE" | "SELF";

export type UI_DeepSeaRP_DeepSeaRPZoneMapModel_ZoneStatus = "TIMELOCKED" | "STAGELOCKED" | "OPEN" | "TIMEOUT";

export type UI_DeepSeaRP_DeepSeaRPNodeDetailView_IntroStep = "IDLE" | "TYPING" | "WAIT_ACTION" | "UI_TWEEN";

export type UI_DeepSeaRP_DeepSeaRPTechTreeViewModel_SETTING_STATE = "NONE" | "CHANGE_HAPPENED" | "SAVED";

export type UI_Roguelike_RoguelikeCommonJudgeDialog_ResultType = "NEGATIVE" | "POSITIVE";

export type UI_Roguelike_RoguelikeMenuRelicItemType = "RELIC" | "TRAP" | "EXPLORE_TOOL";

export type UI_Roguelike_RoguelikeCustomNotifyType = "NONE" | "DIASTER";

export type UI_Roguelike_DialogType = "RELIC" | "FRAGMENT" | "EXPED" | "TRADER" | "MONTH_ARC" | "CHG_BOSS" | "FIN_MISSION" | "GAIN_RECRUIT_TICKET" | "GAIN_UPGRADE_TICKET" | "STEP_ZERO";

export type UI_Roguelike_RoguelikeTransitionView_SubTransType = "NONE" | "AVG_CHAT" | "DICE" | "PREDICT" | "EXPEDITION_RETURN" | "DRAW_COPPER";

export type UI_Roguelike_ViewType = "NONE" | "STATS_VIEW" | "NORMAL_SCORE_VIEW" | "MONTH_SCORE_VIEW" | "CHALLENGE_SCORE_VIEW";

export type UI_Roguelike_RoguelikeEndingScoreViewModel_EndingStatsType = "STATS_CROSSED" | "STATS_ARRIVED" | "STATS_BATTLE_NORMAL" | "STATS_BATTLE_ELITE" | "STATS_BATTLE_BOSS" | "STATS_ITEM" | "STATS_RECRUIT";

export type UI_Roguelike_RoguelikeEndingScoreViewModel_EndingStatsNumType = "TYPE_COUNT" | "TYPE_SCORE";

export type UI_Roguelike_RoguelikeMenuCharObjectStatus = "HIDE" | "NORMAL" | "SELECTED" | "FORBIDDEN";

export type UI_Roguelike_RoguelikeMenuSquadObjectStatus = "NORMAL" | "FORBIDDEN";

export type UI_Roguelike_RoguelikeMenuTotemObjectStatus = "NORMAL" | "SELECTED" | "FORBIDDEN";

export type UI_Roguelike_RoguelikeMenuEffect_RoguelikeMenuEffectControlSource = "SOURCE_MENU_BAR" | "SOURCE_COUNT";

export type UI_Roguelike_RoguelikeMenuType = "INIT_SQUAD" | "RELIC" | "RELIC_ADAPTER" | "TRAP" | "CHAR_INVENTORY" | "SQUAD" | "HP" | "LEVEL" | "ZONE" | "BTN_PLUGIN" | "CHALLENGE_TASK" | "GOLD" | "POPULATION" | "KEY" | "TASK" | "SP_LEVEL" | "NONE";

export type UI_Roguelike_RoguelikeMenuBinary = "NONE" | "INIT_SQUAD" | "RELIC" | "CHAR_INVENTORY" | "SQUAD" | "ALL" | "CHAR_RELATED" | "SQUAD_CHAR_SELECT";

export type UI_Roguelike_ReportItemType = "NONE" | "SQUAD" | "SUMMARY" | "INIT" | "ZONE" | "NODE" | "END" | "ENDFAIL" | "ZONE_OVERVIEW" | "SUMMARY_WITH_DIFFICULTY";

export type UI_Roguelike_RoguelikeScrollReportEndingFrameViewModel_CandleSrc = "NONE" | "DIRECT" | "RECRUIT" | "UPGRADE" | "BATTLE" | "EXPEDITION" | "COPPER";

export type UI_Roguelike_ROGUELIKE_REWARDS_LEVEL_UP_POP_TYPE = "NONE" | "MAX_HP_ADD" | "HOPE_ADD" | "SQUAD_ADD";

export type UI_Roguelike_ROGUELIKE_REWARDS_LOCKED_TREASURE_SUB_TYPE = "USE_KEY" | "USE_DICE" | "LEAVE";

export type UI_Roguelike_RoguelikeRewardShowType = "NONE" | "GOLD" | "RECRUIT_TICKET" | "RELIC" | "RELIC_SELECT" | "RELIC_CURSE" | "RELIC_INIT" | "TRAP" | "CAPSULE" | "RELIC_RANDOM" | "LEAVE" | "HP" | "LOCKED_TREASURE" | "LOCKED_TREASURE_KEY" | "LOCKED_TREASURE_DICE" | "LOCKED_TREASURE_LEAVE" | "KEY" | "DICE" | "TOTEM_UPPER" | "TOTEM_LOWER" | "TOTEM_SELECT" | "VISION" | "SHIELD" | "POPULATION" | "EXPLORE_TOOL" | "FRAGMENT" | "FRAGMENT_SELECT" | "PILL" | "RED_CAPSULE" | "COPPER" | "COPPER_SELECT" | "DIVINATION_KIT" | "SCRAP" | "SCRAP_SELECT" | "LEGACY";

export type UI_Roguelike_RogueLikeRewardItemExDropSrc = "TOTEM_EXTRA" | "LEVEL_UP_EXTRA" | "COPPER_EXTRA" | "EVIL_TEMPLE_EXTRA" | "TREASURE_MAP_EXTRA" | "LOOP_CHIP_EXTRA" | "STEP_EXTRA" | "GREED_EXTRA" | "GOLDEN_AGE_EXTRA";

export type UI_Roguelike_RoguelikeCameraController_LockSource = "DUNGEON_PAGE" | "DUNGEON_STATE" | "DIALOG_POPUP" | "ZONE_CONFIG";

export type UI_Roguelike_RoguelikeUIEvent = "ON_DATA_UPDATED" | "ON_STATE_ENTER" | "ON_STATE_RESUME" | "ON_STATE_PAUSE" | "ON_DUNGEON_ZONE_CREATED" | "ON_DUNGEON_NODE_FOCUS" | "ON_DUNGEON_NODE_SELECT" | "ON_BEFORE_TRANSITION" | "ON_DUNGEON_SHOW_EFFECT_AND_ANIM" | "ON_CHAOS_CHANGED_TOAST" | "ON_DISASTER_TOAST" | "ON_FRAGMENT_GAIN" | "ON_FRAGMENT_BAG_WEIGHT_WORSE" | "ON_COPPER_GAIN" | "ON_SELECT_CHAR_CHANGE" | "ON_DUNGEON_SP_ZONE_BACK_CLICKED" | "ON_LEAVE_SKY_ZONE_TOAST" | "ON_NEW_WRATH_GAIN" | "ON_PENDING_COMMON_STATE" | "ON_CAMERA_ZOOM_POSITION_CHANGE" | "ON_CAMERA_ZOOM_POSITION_CHANGE_REQUEST" | "ON_HIGHLIGHT_CURSOR" | "ON_SCRAP_GAIN" | "ON_CHECK_ONLY_ENDING_CHANGE";

export type UI_Roguelike_RoguelikeCharCardDecoPanelPluginBase_DecoLayer = "NONE" | "BOTTOM" | "UPTYPE" | "TOP" | "SELECT";

export type UI_Roguelike_RoguelikeCharCardViewPluginPriority = "HIGHEST" | "NORMAL" | "LOWEST";

export type UI_Roguelike_PanelType = "SP_CHAR" | "EXPEDITION" | "TRAVEL" | "CANDLE" | "NO_UPGRADE" | "GUIDED" | "NON_GUIDED";

export type UI_Roguelike_RoguelikeGameBankViewModel_BankInvestStatus = "INVEST_FAULTY" | "INVEST_SUC_WITH_NEW_REWARD" | "INVEST_SUC";

export type UI_Roguelike_RoguelikeGameBankWithdrawlViewType = "NONE" | "SIMPLE" | "CONSUME";

export type UI_Roguelike_RoguelikeGoodsViewModel_GoodsItemType = string;

export type UI_Roguelike_RoguelikeGoodsViewModel_SlotBannedStatus = "NOT_BANNED" | "MISSING_IN_BATTLE";

export type UI_Roguelike_RoguelikeGameShopStatusEnum = "NONE" | "BUY" | "RECYCLE" | "GOODS_DETAIL" | "BANK_ENTRY" | "BANK_INVESTMENT" | "BANK_WITHDRAWAL" | "BANK_FAULTY" | "BATCH_RECYCLE" | "SEED_ENTRY" | "NORMAL";

export type UI_Roguelike_RoguelikeShopGoodPluginType = "NONE" | "PRICE" | "ICON" | "CUSTOM_GOODS_VIEW";

export type UI_Roguelike_RoguelikeShopDetailExtraInfoType = "NONE" | "RECRUIT_ITEM_TIPS" | "TOOL_ITEM_TRAP_TIPS" | "RELIC_ITEM_EFFECTIVE_TIPS" | "VISION_ITEM_MAX_TIPS" | "TOTEM_ITEM_COUNT_TIPS" | "COPPER_ITEM_TIPS";

export type UI_Roguelike_RoguelikeShopLineupView_LineupLayer = "BUY" | "RECYCLE";

export type UI_Roguelike_RoguelikeCharCardViewModel_ShowType = "CHAR_SKILL" | "RECRUIT" | "RECRUIT_TEMP" | "UPGRADE" | "ONLY_FOR_SHOW" | "SQUAD";

export type UI_Roguelike_TalentUnlockType = "NONE" | "NEW" | "UPDATE" | "LVLNEW" | "LVLUPDATE";

export type UI_Roguelike_RL06_RL06GridNodeViewData_NodeThemeType = "GRAY" | "CYAN" | "GREEN" | "HIDE_EVENT_CYAN" | "FINAL_GREEN" | "EVACUATE_YELLOW" | "PURPLE" | "RED" | "YELLOW" | "HIDE_BATTLE_PURPLE";

export type UI_Roguelike_RL06_RL06GridZoneNodeContainer_ZoneNodeShowType = "NONE" | "EMPTY" | "NORMAL" | "ULTRA";

export type UI_Roguelike_RL06_RL06ScrapDetailDialog_ScrapBtnTransState = "NONE" | "EXPEND" | "REDUCE";

export type UI_Roguelike_RL06_RL06WarehouseScrapMainViewType = "NORMAL" | "OVERFLOW";

export type UI_Roguelike_RL06_RL06WarehouseScrapSortType = "SCRAPTYPE" | "SCRAPVALUE";

export type UI_Roguelike_RL06_RL06WarehouseViewTypeChangeTag = "NONE" | "TO_NORMAL" | "TO_OVERFLOW";

export type UI_Roguelike_RL06_RL06CommonToastView_RenderType = "NORMAL" | "SCRAP" | "OVERWEIGHT";

export type UI_Roguelike_RL06_RL06ToastNormalView_NormalSubType = "VEHICLE_CHANGE" | "EMPLOY_LEAVE" | "SAVAGE_CLEAR" | "CHAR_TIRED";

export type UI_Roguelike_RL06_RL06ToastScrapView_ScrapSubType = "SCRAP_ITEM_LOST";

export type UI_Roguelike_RL06_RL06MainTransitionView_WeatherType = "UTOPIA" | "PRACTOPIA_NEGATIVE" | "PRACTOPIA_POSITIVE";

export type UI_Roguelike_RL06_WeatherPositiveType = "NOT_INIT" | "NONE" | "GOOD" | "BAD";

export type UI_Roguelike_RL06_RL06DungeonGridZoneNodePlugin_NodeReachStatusType = "CAN_NOT_REACH" | "CAN_REACH" | "CAN_ENTER";

export type UI_Roguelike_RL06_RL06DungeonZoneLineState = "HIDDEN" | "PASSABLE" | "BLOCKED";

export type UI_Roguelike_RL06_RL06DungeonZoneLineConnectDir = "UP" | "DOWN" | "LEFT" | "RIGHT";

export type UI_Roguelike_RL05_RL05CopperPackageListPatternView_PatternType = "ONLY" | "FIRST" | "MID" | "LAST";

export type UI_Roguelike_RL05_RL05CopperPackageType = "INIT" | "VIEW_ONLY" | "NORMAL";

export type UI_Roguelike_RL05_Rl05FocusSkyShopPreviewItemView_NameBgColorType = "NORMAL" | "CURSE";

export type UI_Roguelike_RL05_RL05MenuCopperObject_RL05CopperObjectStatus = "NORMAL" | "SELECTED";

export type UI_Roguelike_RL05_RL05RoguelikeMenuButtonTheme_MenuButtonType = "RECRUIT_COMMON" | "GET_CANDLE_ONLY" | "RECRUIT_AND_CANDLE" | "UPGRADE_AND_CANDLE";

export type UI_Roguelike_RL05_RL05SpecialZoneNodeState = "NOMRAL" | "LOCKED" | "CLOSED";

export type UI_Roguelike_RL05_RL05SpecialZoneNodeConnector = "NONE" | "UP" | "DOWN" | "LEFT" | "RIGHT";

export type UI_Roguelike_RL05_RL05CommonToastView_ToastType = "NONE" | "SKY" | "GOLD" | "WRATH" | "EVIL_TEMPLE" | "COPPER_CONVERT";

export type UI_Roguelike_RL04_RL04AlchemySlotItemViewModel_SlotItemStatus = "EMPTY" | "FILLED";

export type UI_Roguelike_RL04_RL04AlchemySlotListViewModel_SlotListStatus = "NONE" | "FULL" | "EMPTY" | "NEITHER_FULL_NOR_EMPTY";

export type UI_Roguelike_RL04_RL04AlchemyForecastRandomViewModel_RandomRewardRarityItemStatus = "GRAY" | "BRIGHT";

export type UI_Roguelike_RL04_RL04AlchemyForecastViewModel_ForecastStatus = "NOT_READY" | "READY";

export type UI_Roguelike_RL04_RL04AlchemyForecastViewModel_ForecastType = "NONE" | "RANDOM" | "DEFINITENESS";

export type UI_Roguelike_RL04_RL04AlchemyFragmentListItemViewType = "ROW_ITEM" | "TITLE";

export type UI_Roguelike_RL04_RL04AlchemyFragmentListViewModel_FragmentStorageStatus = "EMPTY" | "HAS_FRAGMENTS";

export type UI_Roguelike_RL04_RL04AlchemyResultViewModel_ResultState = "NORMAL" | "FAIL" | "SSR";

export type UI_Roguelike_RL04_RL04AlchemyImplViewModel_ViewAlchemyStatus = "NOT_MELD" | "MELDING" | "MELDED";

export type UI_Roguelike_RL04_RL04AlchemyImplViewModel_LeaveBtnStatus = "CLOSE_STATE" | "OPEN_STATE";

export type UI_Roguelike_RL04_RL04FragmentItemGroupViewModel_Type = "TITLE" | "ITEM";

export type UI_Roguelike_RL04_RL04MenuFragmentObject_RL04FragmentObjectStatus = "NORMAL" | "SELECTED" | "FORBIDDEN";

export type UI_Roguelike_RL02_RL02ReportController_ReportViewType = "NONE" | "TYPE_ENTER" | "TYPE_ZONE" | "TYPE_BUFF" | "TYPE_DICE" | "TYPE_NEWS" | "TYPE_FIN";

export type UI_Roguelike_RL02_RL02EndingFrameDiceReportViewModel_DiceResultType = "GOOD" | "NORMAL" | "BAD";

export type UI_Roguelike_RL02_RL02EndingFrameNewsReportViewModel_NewsType = "NONE" | "COMMU" | "HIDDEN" | "KNIGHT" | "PRACTICE" | "GOLD";

export type UI_Roguelike_Scrap_RoguelikeScrapUtil_ScrapWareHouseStatus = "ERROR" | "ALL_FEATURE_ACCEPT" | "CHECK_ONLY";

export type UI_Roguelike_Init_RoguelikeInitRelic_NameBgColorType = "NORMAL" | "CURSE";

export type UI_Roguelike_Fragment_RoguelikeFragmentDialogMode = "NONE" | "CHECK_ONLY" | "CAN_USE";

export type UI_Roguelike_Fragment_RoguelikeFragmentDialogListType = "NONE" | "DETAIL" | "SUMMARY";

export type UI_Roguelike_RL03_TotemMapNodeSelectType = "NONE" | "MANUAL_SELECT" | "AUTO_SELECT";

export type UI_Roguelike_RL03_TotemViewShowType = "VIEW_ONLY" | "OPERABLE";

export type UI_Roguelike_RL03_TotemItemDisplayType = "NONE" | "NORMAL" | "DIVINATION" | "CANT_USE";

export type UI_Roguelike_RL03_RL03TotemListViewType = "NORMAL_ITEM" | "TITLE";

export type UI_Roguelike_Dice_RoguelikeDiceModelType = string;

export type UI_CrisisV2_CrisisV2DiagramInput_DisplayScoreType = "NONE" | "CURRENT" | "HIGHEST_TOTAL" | "HIGHEST_SINGLE";

export type UI_CrisisV2_CrisisV2DiagramInput_DescAndScoreStyle = "NONE" | "ACHIEVE" | "BATTLE_SETTLE";

export type UI_CrisisV2_CrisisV2DiagramInput_BackgroundStyle = "ACHIEVE" | "MAP" | "ENTRY" | "BATTLE_SETTLE_BIG" | "BATTLE_SETTLE_SMALL";

export type UI_CrisisV2_CrisisV2SettleViewType = "BATTLE_FINISH" | "ACHIEVEMENT_SIMPLE" | "ACHIEVEMENT_DETAIL";

export type UI_CrisisV2_CrisisV2EntryViewModel_TempState = "NOTOPEN" | "OPEN" | "REWARD_AVAIL" | "REWARD_ALL_GET" | "REWARD_OUT_OF_TIME";

export type UI_CrisisV2_CrisisV2MapNodeModel_Connectivity = "CLOSE" | "BLOCK" | "CONNECT";

export type UI_CrisisV2_CrisisV2MapRoadStatus = "DISABLE" | "UNSELECT" | "SELECTED";

export type UI_CrisisV2_CrisisV2MapNodeStatus = "DISABLE" | "UNREACH" | "REACHABLE" | "SELECTED";

export type UI_CrisisV2_CrisisV2MapBagStatus = "DISABLE" | "UNREACH" | "REACHABLE" | "SELECTED";

export type UI_CrisisV2_CrisisV2RoadPointStyle = "NONE" | "SQUARE" | "CIRCLE";

export type UI_CrisisV2_CrisisV2MapModel_ViewType = "NONE" | "SLOT" | "BAG";

export type UI_CrisisV2_CrisisV2MapModel_ActionType = "NONE" | "ADD" | "REMOVE" | "UNAVAIL" | "HIGHLIGHT";

export type UI_CrisisV2_CrisisV2MapModel_TargetType = "NONE" | "NODE" | "BAG";

export type UI_CrisisV2_CrisisV2MissionItemModel_SortState = "COMPLETE" | "UNLOCK" | "CLAIMED";

export type UI_CrisisV2_CrisisV2MissionItemModel_MissionSortType = "SORT_TREASURE" | "SORT_CHALLENGE" | "SORT_RUNEPACK";

export type UI_CrisisV2_CrisisV2RuneBaseViewModel_ViewType = "NONE" | "SINGLE" | "GROUP";

export type UI_CrisisV2_CrisisV2RuneBaseViewModel_SingleViewInfoBgType = "NONE" | "DARK" | "GRAY";

export type UI_CrisisV2_CrisisV2RuneSingleViewModel_SingleViewInfoType = "NONE" | "TITLE" | "ITEM";

export type UI_CrisisV2_CrisisV2RuneSingleItmePointLvType = "NONE" | "LOW" | "MIDDLE" | "HIGH";

export type UI_CrisisV2_CrisisV2MapAVGAdapter_MapType = "NONE" | "BAG_VIEW" | "NODE_VIEW";

export type UI_CrisisV2_CrisisV2MapAVGAdapter_FocusSlotType = "NONE" | "BAG_VIEW_BAG" | "SLOT_VIEW_BAG" | "RUNE" | "TREASURE" | "KEYPOINT";

export type UI_Crisis_CrisisShopWrapped_SeasonFlag = string;

export type UI_Crisis_CrisisShopVer = "CRISIS";

export type UI_Shop_ShopDetailFurnGroupView_SelectClass = "COIN" | "DIAMOND";

export type UI_Shop_ShopDetailFurnView_SelectClass = "COIN" | "DIAMOND";

export type UI_Shop_GPType = "PERIOD" | "ONCE" | "MONTHLYSUB" | "LEVEL" | "CHOOSE" | "CONDTION_TRIGGER";

export type UI_Shop_GPPeriodDetailType = "WEEKLY" | "MONTLY" | "CUSTOM";

export type UI_Shop_QCShopExtraObj_SortingOrderGroup = "PERM_AVAIL" | "MONTH" | "TEMP_AVAIL" | "PERM_SOLDOUT" | "TEMP_SOLDOUT" | "ENUM";

export type UI_Shop_ShopKeeperGraphic_States_State = "DEFAULT" | "BORN" | "IDLE" | "INTERACT" | "TERMINAL";

export type UI_Shop_ShopPage_Referrer = "NONE" | "DIRECT" | "BANNER" | "CLOSURE" | "BACKFLOW";

export type UI_Shop_SkinShopItemType = "SKIN" | "BLINDBOX";

export type UI_Shop_SkinShopViewModel_GiftShowType = "NONE" | "FLOAT" | "SIDE";

export type UI_Shop_QCShopDetailShopEnum = "LOW" | "HIGH" | "EXTRA" | "EPGS" | "LMTGS" | "REP" | "CLASSIC" | "NONE";

export type UI_CommonInviteDialog_CommonInviteDialog_ResultToastType = "TOO_FAST" | "INVITE_FULL" | "INVITE_INVALID";

export type UI_CommonInviteDialog_CommonInviteShowType = "INVITE" | "INVITED";

export type UI_Test_UICharSkinOffsetEditView_EditType = string;

export type UI_ClimbTower_ClimbTowerController_ClimbTowerUIEvent = "ON_STATE_ENTER" | "ON_STATE_PAUSE" | "ON_BEFORE_TRANSITION" | "ON_PLAYER_DATA_CHANGED";

export type UI_ClimbTower_ClimbTowerMenu_TweenType = "NONE" | "FADE" | "TRANSLATE";

export type UI_ClimbTower_ClimbTowerSquadMenuObject_ButtonState = "NORMAL" | "SELECTED" | "FORCE_SELECTED";

export type UI_ClimbTower_ClimbTowerTrapMenuObject_ButtonState = "NORMAL" | "SELECTED" | "DISABLED";

export type UI_ClimbTower_ClimbTowerTrapGroupViewModel_TrapGroupType = "NONE" | "GOD_CARD" | "CURSE_CARD" | "TRAP_CARD";

export type UI_ClimbTower_ClimbTowerTrapType = "NONE" | "MAIN_CARD" | "SUB_CARD" | "CURSE_CARD" | "TRAP_CARD";

export type UI_ClimbTower_ClimbTowerEndTrapViewModel_Type = "NONE" | "NORMAL" | "CURSECARD";

export type UI_ClimbTower_ClimbTowerEndingViewModel_Status = "FAILED" | "ACCOMPLISHED";

export type UI_ClimbTower_ClimbTowerSquadMultiEditModel_EditType = "SKILL" | "UNIEQUIP";

export type UI_ClimbTower_ClimbTowerRewardModel_State = "STATE_CAN_RECEIVE" | "STATE_INCOMPLETED" | "STATE_COMPLETED";

export type UI_CGGallery_CGGalleryFilterMode = "NONE" | "STORYLINE" | "FAVOURITE";

export type UI_CGGallery_CGGalleryInspectImageViewScaleHandler_ScaleApplyType = "USE_HORIZONTAL" | "USE_VERTICAL" | "USE_MIN";

export type UI_Carving_CarvingHomeEntryChallengeTabView_AnimType = "ENTER" | "PREV_OUT" | "PREV_IN" | "NEXT_OUT" | "NEXT_IN";

export type UI_Campaign_CampaignWorldCameraController_LockSource = "SELF" | "PAGE" | "HOME_STATE";

export type UI_Campaign_CampaignWorldHomeState_InternalState = "IDLE" | "CHECK_GUIDDE_BOOK" | "WAIT_GUIDE_BOOK" | "CHECK_BRIEF" | "WAIT_BRIEF" | "CHECK_FOCUS" | "BEGIN_FOCUS" | "WAIT_FOCUS" | "FOG_DISAPPEAR" | "MARK_READY" | "UPDATE_VIEW";

export type UI_Campaign_CampaignWorldLayer = "DEFAULT" | "STAGE_FLOAT" | "ZONE_FLOAT";

export type UI_Campaign_CampaignWorldZoneHolder_PanelInfoAlignment = "LEFT" | "CENTER" | "RIGHT";

export type UI_Campaign_CampaignBreakDetailItemViewModel_State = "UNREACHED" | "REACHED_BUT_NOT_CONFIRMED" | "CONFIRMED";

export type UI_Campaign_AutoCampConfigModel_Status = "NONE" | "AUTO_BATTLE_ONLY" | "ENABLE_FAST_BATTLE";

export type UI_Campaign_AutoCampConfigModel_FastBattleLockAlert = "NONE" | "NO_RECORD" | "NO_TICKET" | "IS_TRAIN";

export type UI_Campaign_AutoCampConfigModel_EnableFastBattle_Selection = "NONE" | "AUTO_BATTLE" | "FAST_BATTLE";

export type UI_AutoChess_AutoChessOuterTopMenu_ShowType = "NONE" | "IN_ROOM" | "IN_TEAM" | "IN_TEAM_WITHOUT_DELAY";

export type UI_AutoChess_AutoChessPrepareController_SimpleDialogType = "NONE" | "MATCH_CANCELED" | "ENTER_ROOM";

export type UI_AutoChess_AutoChessPrepareController_BusinessEvent = "MATCH_RESULT" | "RECEIVE_LIKE";

export type UI_AutoChess_AutoChessPrepareStateViewType = "NONE" | "MATCH_STATE" | "MULTI_ROOM_CHOOSE_STATE" | "MULTI_ROOM_STATE" | "STAGE_INFO_STATE" | "BAND_CHOOSE_STATE" | "SETTLE_STATE" | "BATTLE_READY" | "RECONNECT";

export type UI_AutoChess_FriendState = "NOT_FRIEND" | "SENT_REQUEST" | "IS_FRIEND" | "DIFFERENT_SERVER";

export type UI_AutoChess_FromBattleSource = "NOT_FROM_BATTLE" | "FROM_NORMAL_BATTLE" | "FROM_TRAINING_BATTLE";

export type UI_AutoChess_AutoChessServiceCommonResultType = "OK" | "TOO_FAST" | "BAN" | "SERVER_OVERLOAD" | "TEAM_NOT_EXIST" | "TEAM_IS_FULL";

export type UI_AutoChess_AutoChessSettleGamePlayerStatus = "NONE" | "INTERRUPT" | "DEAD" | "PASS" | "BATTLING";

export type UI_AutoChess_AutoChessQueryMatchResponse_QueryMatchResultType = "OK" | "CANCEL" | "TIME_OUT";

export type UI_AutoChess_AutoChessBandChoosePlayerStatus = "WAIT_CHOOSE" | "CHOOSING" | "CHOSEN";

export type UI_AutoChess_AutoChessConfirmDialogBtnType = "ONLY_CONFIRM" | "CONFIRM_AND_CANCEL";

export type UI_AutoChess_AutoChessConfirmDialogConfirmBtnColType = "GREEN" | "RED";

export type UI_AutoChess_AutoChessModeChoiceConfirmBtnType = "NONE" | "TRAINING" | "SINGLE_MATCH" | "MULTI_MATCH" | "MULTI_TEAM";

export type UI_AutoChess_AutoChessMultiMatchStatus = "NONE" | "MATCHING" | "RESULT";

export type UI_AutoChess_AutoChessMultiMatchResult = "NONE" | "CANCEL" | "SUCCESS" | "TIMEOUT";

export type UI_AutoChess_AutoChessRoomViewModel_ReadyButtonState = "READY" | "CANCEL_READY" | "UNAVAIL_START_MATCH" | "START_MATCH" | "UNAVAIL_START_GAME" | "START_GAME";

export type UI_AutoChess_AutoChessSettleGameInterruptType = "NONE" | "WARN" | "SAFE";

export type UI_AutoChess_AutoChessSettleGameTeamStateType = "NONE" | "BATTLING" | "FAIL" | "SUCCESS";

export type UI_AutoChess_AutoChessSettleGameTeamRoundType = "NONE" | "FAIL" | "PASS_NORMAL_BOSS" | "PASS_HIDDEN_BOSS";

export type UI_AutoChess_AutoChessSettleGameTeamPlayerTitleType = "NONE" | "WAITING" | "EVALUATED";

export type UI_AutoChess_AutoChessSettleGameTeamPlayerRoundType = "NONE" | "BATTLING" | "INTERRUPT" | "FAIL" | "SUCCESS";

export type UI_AutoChess_AutoChessShopQuickAssistListItemViewType = "TITLE_WITH_ITEM" | "ONLY_ITEM";

export type UI_AutoChess_AutoChessShopQuickEditType = "NONE" | "SKILL" | "MODULE";

export type UI_AutoChess_AutoChessShopStatus = "NONE" | "CHAR_LIST" | "ITEM_LIST" | "CHAR_DETAIL" | "CHAR_SKILL_AND_MODULE_QUICK_EDIT" | "QUICK_ASSIST_LIST";

export type UI_AutoChess_AutoChessShopLevelCharItemType = "NONE" | "CHAR" | "DIY";

export type UI_AutoChess_CharSelect_AutoChessCharSelectDetailPanel_ButtonType = "CHESS_FEATURE" | "SKILL" | "BRANCH";

export type UI_AutoChess_CharSelect_FloatType = "NONE" | "SMALL" | "LARGE";

export type UI_AutoChess_Server_AutoChessServiceEvent = "TEAM_CHANGED" | "TEAM_LEAVE" | "TEAM_LOST" | "TEAM_CHAT" | "TEAM_MATCH_RESULT" | "SCENE_START" | "SCENE_START_SUC" | "SCENE_CHANGED" | "SCENE_CHAT" | "SCENE_BROADCAST" | "SCENE_LOST" | "SCENE_SETTLE_LIKE";

export type UI_AutoChess_Server_AutoChessBattleProtocol_AutoChessScenePreparationStatusResp_RetCode = "SUC" | "FAIL";

export type UI_AutoChess_Server_AutoChessBattleSceneEndReasonType = "SCENE_END_OK" | "SCENE_END_QUITE" | "SCENE_END_NEGATIVE_GAME";

export type UI_AutoChess_Server_AutoChessBattlePreparationReadyType = "CANCEL_READY" | "READY";

export type UI_AutoChess_Server_AutoChessServiceRequestTarget = "TEAM" | "BATTLE";

export type UI_AutoChess_Server_AutoChessTeamProtocol_KickDn_ReasonType = "DISBAND" | "DISLIKE" | "TIMEOUT" | "MATE_FAIL" | "SCENE_START_FAIL";

export type UI_AutoChess_Server_AutoChessTeamState = "NONE" | "TEAM_BUILDING" | "TEAM_MATCHING" | "TEAM_MATCH_SUC" | "ENTER" | "INFO_SHOW" | "STRATEGY_CHOOSE" | "ENTER_BATTLE_COUNT_DOWN" | "IN_BATTLE" | "END";

export type UI_AutoChess_Server_AutoChessMatchModeRange = "WIDE" | "PRECISE";

export type UI_AutoChess_Server_AutoChessPlayerState = "TEAM_BUILDING_NOT_READY" | "TEAM_BUILDING_READY" | "MATCHING" | "MATCH_FAILED" | "ENTER" | "INFO_NOT_CONFIRM" | "INFO_CONFIRM" | "STRATEGY_NOT_CHOOSE" | "STRATEGY_CHOSEN" | "IN_BATTLE" | "IN_SETTLE_RESULT";

export type UI_AutoChess_Server_AutoChessPlayerConnectState = "ONLINE" | "MISS" | "OFFLINE";

export type UI_AutoChess_Server_AutoChessTeamLostReason = "NONE" | "NET_EXCEPTION" | "KICK_DISBAND" | "KICK_DISLIKE" | "KICK_TIMEOUT" | "KICK_MATE_FAIL" | "KICK_SCENE_START_FAIL" | "KICK_UNKNOWN" | "PLAYER_LEAVE";

export type UI_AutoChess_Server_AutoChessServiceMatchResult_RetCode = "SUC" | "CANCEL" | "TIMEOUT";

export type UI_AutoChess_Server_AutoChessBattleServer_AutoChessBattleException = "NONE" | "JOIN_FAILED" | "NET_FAILED" | "SERVER_KICK";

export type UI_AutoChess_Battle_AutoChessBattleUIViewModel_AutoChessGiveUpTipType = "GIVE_UP_VIOLATION" | "GIVE_UP_WITH_PUNISH" | "GIVE_UP_WITHOUT_PUNISH" | "TEMP_LEAVE";

export type UI_AutoChess_Battle_AutoChessBattleBossRoundModel_AnimStatus = "NONE" | "ENTER" | "EXPAND" | "EXIT";

export type UI_AutoChess_Battle_AutoChessBattleUIBottomTipsShowType = "NONE" | "HAND_FULL" | "HAND_OVERFLOW" | "WAIT_FINISH" | "PREP_READY";

export type UI_AutoChess_Battle_AutoChessBattleSpPrepareStepModel_Step = "NONE" | "SELECT_OTHER" | "SELECT_SELF";

export type UI_AutoChess_Battle_AutoChessHUDStatus = "REST" | "NORMAL_BATTLE" | "HELP_BATTLE" | "BOSS_BATTLE";

export type UI_AutoChess_Battle_AutoChessBattlePlayerStatusGroupModel_ActionState = "IDLE" | "MOVING" | "COMPLETE";

export type UI_AutoChess_Battle_AutoChessBattlePlayerStatusGroupModel_BossGrpStatus = "NONE" | "MAJOR" | "MINOR";

export type UI_ArtGallery_ArtGalleryUtils_CollectSetMissionRewardsState = "NONE" | "CANT_CLAIM" | "CAN_CLAIM" | "CLAIMED";

export type UI_ArtGallery_ArtGalleryCollectDetailMissionItemViewModel_ClaimState = "NOT_AVAILABLE" | "AVAILABLE" | "CLAIMED";

export type UI_ArtGallery_ArtGalleryDisplayType = "LIST";

export type UI_ArtGallery_ArtGalleryTabType = "HOME_THEME" | "HOME_BACKGROUND" | "NAME_CARD" | "AVATAR";

export type UI_ArtGallery_ArtGalleryFilterType = "ALL" | "SHOW_HAVE" | "SHOW_NOT_HAVE";

export type UI_ArtGallery_ArtGalleryDisplayGridVirtualParam_ViewType = "NONE" | "TITLE" | "ITEM";

export type UI_Anniv7thMainline_Anniv7thClueBoardViewModel_ClueState = "NONE" | "LOCK" | "UNLOCK";

export type UI_Anniv7thMainline_Anniv7thClueRewardItemViewModel_State = "COMPLETED" | "UNCOMPLETED" | "GAINED";

export type UI_DevTester_UIDebugRoguelikePanel_RoguelikeTheme = "ALL";

export type UI_ActivityPage_ActivityEntryPage_PageInOutType = "NONE" | "BLACK_IN_OUT" | "MASK_IN_OUT";

export type UI_Stage_ActivityCustomZoneMapPage_InitState = "CUSTOM_ZONE_STATE" | "CUSTOM_STAGE_PREVIEW_STATE";

export type UI_Stage_HomeEntryFuncType = "NONE" | "MAINLINE" | "STAGE_ACT" | "ROGUELIKE" | "SANDBOX_PERM";

export type UI_Stage_HomeEntryLayoutLevel = "NONE";

export type UI_Stage_HomeToDoFuncType = "NONE" | "CAMPAIGN_WEEKLY" | "ROGUELIKE" | "CLIMB_TOWER" | "SANDBOX_PERM";

export type UI_Stage_HomeRecentStageType = "NONE" | "MAINLINE" | "ACTIVITY" | "CAMPAIGN" | "WEEKLY";

export type UI_Stage_HomeEntrySortIndex = "NONE" | "BREAKING_NEWS" | "NEW_ACT_NEW_MEDAL" | "CRISIS_NEW_MEDAL" | "MINI_ACT_NEW_MEDAL" | "REPLICATE_NEW_MEDAL" | "NEW_ACT_ALL_DONE" | "CRISIS_ALL_DONE" | "MINI_ACT_ALL_DONE" | "REPLICATE_ALL_DONE" | "NEW_ACT_STAGE_CLOSE" | "MINI_ACT_STAGE_CLOSE" | "REPLICATE_STAGE_CLOSE" | "MAINLINE" | "MAINLINE_FINISH";

export type UI_Stage_HomeToDoSortIndex = "NONE" | "CAMPAIGN" | "ROGUELIKE" | "SANDBOX_PERM";

export type UI_Stage_SixStarStagePreviewView_StageSixStarRuneStatus = string;

export type UI_Stage_SixStarRuneSelectGroupStatus = "LOCKED" | "UNSELECTED" | "SELECTED";

export type UI_Stage_CampaignViewModel_BreakLadderViewModel_State = "UNREACHED" | "REACHED_BUT_NOT_CONFIRMED" | "CONFIRMED";

export type UI_Stage_ZoneViewType = "NONE" | "HOME" | "MAINLINE" | "WEEKLY" | "SIDESTORY" | "BRANCHLINE" | "CAMPAIGN" | "SEASON" | "ACTIVITY" | "PERM_MODE" | "MIX_STORY";

export type UI_Stage_CrisisV2ZoneEntryTempState = "INREWARD" | "OUTREWARD" | "NOTOPEN";

export type UI_Stage_SeasonEntryType = "RECAL_RUNE" | "VEC_BREAK";

export type UI_Stage_VecBreakV2SchedulePartModel_Status = "INCOMING" | "ACTIVE" | "EXPIRE";

export type UI_Stage_StageActivityLoader_State = "NONE" | "LOADING" | "TRANSITING" | "LOADED";

export type UI_Stage_MultipleBattleSelectTimesItemView_ApStatus = string;

export type UI_Stage_StageButtonOnMap_RankViewType = "COMMON" | "SIX_STAR";

export type UI_Stage_StageZoneSelectBlackLoadingManager_BlackLoadingType = "DEFAULT" | "BLACK_MASK_FADE";

export type UI_Stage_StageZoneMilestoneButtonBase_StageZoneMilestoneButtonType = "NONE" | "SIX_STAR";

export type UI_Stage_ZoneRecordViewModel_ZoneRecordDiffStatus = "NONE" | "COMMON_LOCK" | "EASY_UNLOCK" | "NORMAL_UNLOCK" | "TOUGH_UNLOCK" | "PREDEFINED_LOCK" | "PREDEFINED_UNLOCK" | "HARD_LOCK" | "HARD_UNLOCK";

export type UI_Stage_ZoneRecordViewModel_RecordDiffIconType = "NONE" | "EASY" | "NORMAL" | "TOUGH" | "PREDEFINED";

export type UI_Stage_ZoneOpenState = "FORCE_OPEN" | "OPEN" | "CLOSE" | "CLOSE_TWEEN_TO_OPEN";

export type UI_Stage_SpecialStageType = "NORMAL" | "HARD" | "SIX_STAR";

export type UI_Stage_Campaign_LadderItem_Type = "KILL_CNT" | "AP_RETURN" | "DIAMOND_GAIN";

export type UI_Stage_MixStory_MixStoryUtil_MixStoryArtSpriteType = "NONE" | "ABBR" | "BACKGROUND" | "DECO" | "KV" | "BRIEF_BKG" | "SPLIT" | "TITLE" | "LOGO";

export type UI_Stage_MixStory_StageStorylineStorySetViewModel_ProgressType = "NONE" | "STAGE" | "STORY";

export type UI_Stage_MixStory_StageStorylineStorySetViewModel_CGGalleryEntryState = "NONE" | "LOCKED" | "OPEN";

export type UI_Stage_MixStory_StageMixStoryOverallView_OverallSortMode = "STORYLINE" | "RELEASE_YEAR";

export type UI_Stage_MixStory_StageMixStoryOverallView_OverallDisplayFeature = "NONE" | "DEFAULT" | "CORE_REWARD" | "PROGRESS" | "ALL";

export type UI_ActivityStage_TemplateActivityEntry_EntryAnim_AnimType = "LOOP" | "ENTRY";

export type UI_ActivityStage_TemplateEffectView_DisableSource = "SELF" | "STATE" | "PAGE";

export type UI_ActivityStage_TemplateActivityLifeCycleViewModel_ActState = "NOT_OPEN" | "ON_ACT" | "ON_REWARD" | "ONCLOSE";

export type UI_ActivityStage_TemplateActivityMileStoneItemModel_Status = "NONE" | "AVAIL" | "NOTAVAIL" | "FINISH" | "LOCKED";

export type UI_ActivityStage_TemplateActivityMilestoneGroupViewModel_ActivityStatus = "NONE" | "BEFORE_TIME" | "OPEN" | "STAGE_TIME_OUT" | "SHOP_TIME_OUT";

export type UI_ActivityStage_ActivityStageController_ActivityControllerTransitionType = "NONE" | "TRANSITION_IN" | "TRANSITION_OUT";

export type UI_ActivityStage_ActivityStageController_ActivityControllerTransitionReason = "NONE" | "DYN_ENTRY_REPLACE";

export type Activity_Act29signSpecialCheckinItemViewModel_ItemType = "NORMAL" | "E_NUM";

export type Activity_Act29signSpecialCheckinItemViewModel_ItemStatus = "ALREADY_GET" | "CAN_RECEIVE" | "CAN_RECEIVE_LAST_TARGET" | "LOCKED" | "E_NUM";

export type Activity_MileStoneViewModel_State = "FINISH" | "AVAIL" | "NOTAVAIL";

export type Activity_MileStoneViewModel_PartType = "GAP";

export type Activity_TimelyDropAssetType = "ZONE_SELECT_EX" | "DROP_PIC_EX" | "DROP_PIC_AP_PROTECT_EX" | "STAGE_PIC_EX" | "STYLE_EX";

export type Activity_ActivityCheckinEntryView_CheckinViewType = "NONE" | "LIST_VIEW" | "DETAIL_VIEW";

export type Activity_VecBreakV2_ActVecBreakV2AchvDefenseBuffModel_BuffState = "NONE" | "CLOSED" | "OPEN" | "COMPLETE";

export type Activity_VecBreakV2_StageViewType = "OFFENSE" | "OFFENSE_RAID" | "DEFENSE";

export type Activity_VecBreakV2_VecBreakV2OffenseBattleFinishAnimationType = "NORMAL" | "FINAL";

export type Activity_VecBreakV2_ActVecBreakV2ZoneType = "NONE" | "OFFENSE" | "DEFENSE" | "HARD";

export type Activity_VecBreakV2_ActVecBreakV2ZoneViewModel_ZoneStatus = "NONE" | "TIME_LOCK" | "STAGE_EMPTY" | "STAGE_LOCK" | "ACTIVE" | "TIME_OUT";

export type Activity_VecBreakV2_ActVecBreakV2DefenseStageBaseItem_BackgroundType = "SINGLE" | "GROUP_LEFT" | "GROUP_MIDDLE" | "GROUP_RIGHT";

export type Activity_VecBreakV2_ActVecBreakV2DefenseCharSlotModel_SlotType = "UNLOCK" | "LOCK";

export type Activity_VecBreakV2_OffenseStateType = "NORMAL" | "RAID";

export type Activity_VecBreakV2_VecBreakV2OffenseStageModelBase_StageStatus = "NONE" | "LOCK" | "TODO" | "FINISH";

export type Activity_VecBreakV2_VecBreakStageType = "NONE" | "OFFENSE" | "DEFENSE";

export type Activity_VecBreakV2_VecBreakStageDefendStatus = "NONE" | "OTHER" | "SAME_GROUP" | "CURR_STAGE";

export type Activity_ActMultiV3_ActMultiV3CreateTeamResponse_CreateResultType = "OK" | "TOO_FAST" | "BAN" | "SERVER_OVERLOAD";

export type Activity_ActMultiV3_ActMultiV3JoinTeamResponse_JoinResultType = "OK" | "TOO_FAST" | "BAN" | "ROOM_NOT_EXIST" | "ROOM_IS_FULL";

export type Activity_ActMultiV3_ActMultiV3StartMatchResponse_StartMatchResultType = "OK" | "TOO_FAST" | "BAN" | "SERVER_OVERLOAD";

export type Activity_ActMultiV3_ActMultiV3QueryMatchResponse_QueryMatchResultType = "OK" | "CANCEL" | "TIME_OUT";

export type Activity_ActMultiV3_ActMultiV3RouteTarget = "NONE" | "ENTRY" | "MATCH" | "TRAINING" | "PREPARE";

export type Activity_ActMultiV3_ActMultiV3EmoticonController_LeftChatPosType = "NONE" | "SMALL" | "BIG";

export type Activity_ActMultiV3_ActMultiV3EntryPage_CameraActiveSrc = "SRC_PAGE_SHOW" | "SRC_STATE_TRANSITION";

export type Activity_ActMultiV3_ActMultiV3EntryState_ShowStatus = "ENTRY" | "MAIN" | "ROOM" | "MATCH";

export type Activity_ActMultiV3_ActMultiV3EntryView_PnlMask_ShowType = "NONE" | "TYPE_FORBIDDEN" | "TYPE_UNAVAILABLE";

export type Activity_ActMultiV3_ActMultiV3LifeCycleViewModel_ActState = "NOT_OPEN" | "ON_ACT" | "ON_REWARD" | "ON_CLOSE";

export type Activity_ActMultiV3_ActMultiV3EntryViewModel_MatchButtonStatus = "NONE" | "ACT_ENDED" | "TUTORIAL_INCOMPLETED" | "SQUAD_COUNT_INVALID" | "NORMAL";

export type Activity_ActMultiV3_ManualTabType = "TITLE_TASK" | "PHOTO_COLLECTION_BOARD";

export type Activity_ActMultiV3_ActMultiV3PrepareMapInfoViewModel_MapType = "EMPTY" | "RANDOM" | "SELECTED";

export type Activity_ActMultiV3_ActMultiV3MatchStatus = "NONE" | "MATCHING" | "RESULT";

export type Activity_ActMultiV3_ActMultiV3MatchResult = "NONE" | "CANCEL" | "SUCESS" | "TIMEOUT";

export type Activity_ActMultiV3_ActMultiV3SquadEffectItemView_OverlayType = "NONE" | "EQUIP" | "SELF_LABEL" | "PARTNER_LABEL";

export type Activity_ActMultiV3_ActMultiV3StageListViewModel_ViewMode = "NONE" | "MODE_STATE" | "MODE_DIALOG";

export type Activity_ActMultiV3_Prepare_ActMultiV3PrepareMainPlayerInfoViewModel_BusinessType = "STAGE_CHOOSE" | "CHAR_PICK";

export type Activity_ActMultiV3_Prepare_ActMultiV3StepUpdateCase = "BEFORE_IN" | "NORMAL" | "BEFORE_OUT";

export type Activity_ActMultiV3_Prepare_ActMultiV3PrepareMainBannerType = "CHAR_PICK_FIRST" | "CHAR_PICK_SECOND" | "CHAR_PICK_NONE" | "SQUAD_CHECK";

export type Activity_ActMultiV3_Prepare_ActMultiV3PrepareMainEntranceShowView_TransState = "HIDE" | "MAP_CONFIRM" | "PLAYER_SHOW_AND_EXIT";

export type Activity_ActMultiV3_Prepare_ActMultiV3PrepareMainSquadProc = "NONE" | "SELECT" | "SKILL" | "CHECK";

export type Activity_ActMultiV3_BattleFinish_ActMultiV3BattleFinishCompleteInfoType = "NONE" | "NORMAL" | "SOCCER" | "DEFENCE" | "SELF_QUIT" | "MATE_QUIT";

export type Activity_ActMainSS_ActMainSSEntryZoneViewModel_Status = "LOCKED" | "UNLOCK" | "RETRO";

export type Activity_Act1BossRush_Act1BossRushMileStoneItemViewModel_State = "NOTAVAIL" | "AVAIL" | "FINISH";

export type Activity_AutoChess_ActAutoChessEntryViewModel_Status = "TRAIN" | "NORMAL" | "TIME_OUT";

export type Activity_AutoChess_ActAutoChessHandbookTabType = "BOND" | "BAND" | "ENEMY";

export type Activity_AutoChess_ActAutoChessHandbookEnemyType = "NONE" | "BOSS" | "ENEMY_GROUP";

export type Activity_Act9D0_Act9D0StageController_Act9D0Event = "NONE" | "NEWS_UPDATED" | "MISSION_UPDATED" | "BEFORE_HIDE_EFFECT" | "TIMEOUT_UPDATE";

export type Activity_Act9D0_Act9D0HiddenStageMissionNotifyViewModel_HiddenStageMissionNotifyState = "NONE" | "HIDDEN_STAGE_UNLOCK" | "HIDDEN_STAGE_UPDATE" | "HIDDEN_MISSION_UPDATE" | "HIDDEN_MISSION_COMPLETE";

export type Activity_Act6fun_Act6FunAchieveRewardItemState = "LOCKED" | "UNLOCKED" | "CLAIMED";

export type Activity_Act5D0_Act5D0MissionViewModel_State = "FINISH" | "NOTAVAIL";

export type Activity_Act5D0_Act5D0MissionViewModel_DifficultyLevel = "C" | "B" | "A" | "S";

export type Activity_Act5D1_RuneClassify = "ALL" | "NEWHAND" | "DANGER";

export type Activity_Act4D0_Act4D0MileStoneViewModel_State = "FINISH" | "AVAIL" | "NOTAVAIL";

export type Activity_Act4D0_Act4D0MileStoneViewModel_Type = "STORY" | "ITEM";

export type Activity_Act4D0_StoryItemState = "LOCK" | "NEW" | "READ";

export type Activity_Act46Side_Act46SideEntryMonopolyViewModel_Status = "LOCK" | "UNLOCK" | "TIMEOUT";

export type Activity_Act45Side_Act45SideEntryLivePageViewModel_Status = "LOCKED" | "UNLOCK" | "CLOSED";

export type Activity_Act45Side_Act45SideLiveViewModel_AnimStep = "CHAR_UNLOCK" | "MAIL" | "CLOCK_ANIM" | "WAIT" | "OPEN";

export type Activity_Act45Side_Act45SideLiveViewModel_StageState = "NONE" | "SLEEP" | "REHEARSE" | "LIVE";

export type Activity_Act45Side_Act45SideMailDialog_EntryType = "NEW" | "REVIEW";

export type Activity_Act45Side_Act45SideMailViewModel_AnimType = "ENTER" | "LEFT" | "RIGHT";

export type Activity_Act44side_Act44SideEntryInformantViewModel_Status = "LOCKED" | "UNLOCK" | "ITEM_LOCKED" | "PLAYING" | "TIME_OUT";

export type Activity_Act42side_Act42sideRewardState = "NOT_REACHED" | "CURRENT" | "REACHED";

export type Activity_Act42side_Act42SideEntryGunTaskViewModel_Status = "LOCKED" | "UNLOCK" | "CLOSED";

export type Activity_Act42side_Act42sideGunTaskEntryTrustorState = "NOT_TAKE" | "IN_PROGRESS" | "CAN_SUBMIT" | "COMPLETE";

export type Activity_Act42D0_Act42D0FinishInfoModel_ViewType = "NONE" | "NORMAL" | "CHALLENGE";

export type Activity_Act3D0_Act3D0Event = "CAMP_SELECTED";

export type Activity_Act3D0_UIGachaBoxDrawEffectFloatPage_Style = "WHITE" | "YELLOW" | "RED" | "GREEN";

export type Activity_Act3D0_Act3D0ClueInfo_State = "GET" | "NOTGET";

export type Activity_Act3D0_Act3D0GachaBoxInfo_UnlockState = "OUT_OF_STACK" | "UNLOCKED" | "LOCKED";

export type Activity_Act3D0_Act3D0MileStoneViewModel_State = "FINISH" | "AVAIL" | "NOTAVAIL";

export type Activity_Act36side_Act36sideEntryFoodHandbookViewModel_Status = "TIME_OUT" | "OPEN" | "HAS_REWARD";

export type Activity_Act36side_Act36sideFoodHandbookTabType = "POT" | "ENEMY" | "TOKEN";

export type Activity_Act35side_Act35sideEntryCarvingViewModel_Status = "LOCKED" | "TIME_OUT" | "UNLOCK_NORMAL" | "UNLOCK_WITH_NEW_CONTENT";

export type Activity_Act33Sign_Act33SignRedpackStatus = "GOT" | "AVAILABLE" | "LOCKED";

export type Activity_Act29sign_View_DynViewState = "INIT_DAY" | "CHOICE_DETAIL" | "CHECK_PROGRESS";

export type Activity_Act29sign_View_Act29signExpandViewItem_State = "FOLD_NOT_DONE" | "EXPAND_NOT_DONE" | "FOLD_DONE" | "EXPAND_DONE";

export type Activity_Act29side_Act29sideEntryTuningViewModel_Status = "LOCKED" | "UNLOCK" | "TIME_OUT";

export type Activity_Act27side_Act27sideEntryGroceryViewModel_Status = "LOCKED" | "UNLOCK" | "TIME_OUT";

export type Activity_Act25side_RhineArcPage_EnterType = "ENUM" | "FROM_ENTRY" | "FROM_RESEARCH";

export type Activity_Act25side_Act25sideResearchFloatInfoStateBean_InfoType = "NONE" | "RESERACH_TOKEN" | "HARVEST_RULE";

export type Activity_Act24side_Act24SideEatResponse_EndingAction = "SUCCESS" | "LACK_COST" | "AP_FULL";

export type Activity_Act24side_Act24sideBattleFinishMeldingDropViewModel_Act24sideBattleFinishMeldingDropType = "ONCE" | "EAT" | "NORMAL";

export type Activity_Act24side_Act24sideBattleTrapItemViewModel_UnlockState = "NONE" | "LOCK" | "NEW_UNLOCK" | "UNLOCKED";

export type Activity_Act24side_Act24sideMeldingProgressChangeInfo_PRICE_CHANGE_TYPE = "NONE" | "ADD" | "MINUS";

export type Activity_Act24side_Act24sideMeldingProgressChangeInfo_SLOT_LIGHT_CHANGE_TYPE = "NONE" | "LIGHT_ON" | "LIGHT_OFF";

export type Activity_Act24side_ACT24SIDE_MELDING_SMALL_ITEM_BG_TYPE = "NONE" | "GRAY" | "WHITE";

export type Activity_Act24side_Act24sideMissionObjViewModel_MissionState = "CAN_RECEIVE" | "DOING" | "COMPLETE";

export type Activity_Act1VHalfIdle_Act1VHalfIdleCommonTopMenu_TopMenuIconType = "NONE" | "SQUAD" | "DEPOT" | "DEPOT_BUFF";

export type Activity_Act1VHalfIdle_PlotTypeIconType = "TYPE_ICON" | "TYPE_BKG" | "TYPE_GROUP_TITLE";

export type Activity_Act1VHalfIdle_Act1VHalfIdleUtil_ActHalfIdleToastType = "TEXT" | "ITEM" | "LEVEL_UPGRADE" | "ELITE_UPGRADE";

export type Activity_Act1VHalfIdle_Act1VHalfIdleCharViewModel_Act1VHalfIdleCharType = "COMMON" | "ASSIST" | "NPC";

export type Activity_Act1VHalfIdle_Act1VHalfIdleCharSelectCustomInput_ConfirmButtonType = "SQUAD" | "DEPOT";

export type Activity_Act1VHalfIdle_Act1VHalfIdleCharLevelUpgradeNotFullView_ShowStatus = "NONE" | "LEVEL" | "ELITE";

export type Activity_Act1VHalfIdle_Act1VHalfIdlePlotFilterType = "NONE" | "LANDSCAPE" | "ROAD" | "ROADSIDE" | "SPECIAL" | "ALL";

export type Activity_Act1VHalfIdle_Act1VHalfIdleDepotBuffDetailType = "NONE" | "BUFF" | "CHAR";

export type Activity_Act1VHalfIdle_Act1VHalfIdleHarvestViewModel_ProduceState = "EMPTY" | "PRODUCING" | "FULL";

export type Activity_Act1VHalfIdle_Act1VHalfIdleIncomeGraphViewModel_GraphStyle = "INCOME_ONLY" | "COMPARE";

export type Activity_Act1Lock_UI_Act1LockMilestoneItem_Status = "NONE" | "UNCOMPLETED" | "COMPLETED" | "GOT";

export type Activity_Act1Lock_UI_Act1LockMissionItem_Status = "NONE" | "DOING" | "DONE" | "COMPLETE";

export type Activity_Act38side_Act38sideEntryFireworkPuzzleViewModel_Status = "LOCKED" | "UNLOCK" | "CLOSED";

export type Activity_Act1Football_Act1FootballBattleFinishCharCardView_CharCardType = "NORMAL" | "NPC" | "ASSIST" | "EMPTY";

export type Activity_Act1Arcade_Act1ArcadeBadgeBookDetailContentAnimator_Direction = "NONE" | "FORWARD" | "BACKWARD";

export type Activity_Act1Arcade_BadgeBookLayoutMode = "SHOW_TAIL" | "HIDE_TAIL";

export type Activity_Act1Arcade_Act1ArcadeEntryGameEntryItemViewModel_LockState = "LOCK" | "OPEN" | "ACT_CLOSE";

export type Activity_Act1Arcade_Act1ArcadeSettlementModel_SettlementViewStatus = string;

export type Activity_Act1Arcade_Act1ArcadeSingleStageModel_StageStatus = "NONE" | "NOT_OPEN" | "LOCK" | "TODO" | "FINISH";

export type Activity_Act1Arcade_Act1ArcadeSingleZoneModel_ZoneStatus = string;

export type Activity_Act1Arcade_Act1ArcadeGameObjectSwitchComp_OutOfRangeLogicType = string;

export type Activity_Act13Side_Act13SideArchiveStageUnlockCond_UnlockType = "PLAYED" | "PASSED";

export type Activity_Act13Side_Act13sideMissionViewModelPlugin_MissionType = "MISSION" | "EMPTY" | "ALLFINISH";

export type Activity_Act13D5_Act13D5LineFiller_FillType = "VERTICAL" | "HORIZONTAL";

export type Activity_Act12side_Act12sideMilestoneItemModel_MilestoneItemType = "ITEM" | "TITLE";

export type Activity_Act12side_Act12sideMilestoneItemModel_RewardState = "NORMAL" | "ACTIVE" | "COMPLETED";

export type Activity_Act12side_UI_CharmCardMode = "DEFAULT" | "SHOW_RECYCLE" | "SHOW_PRICE" | "FORCE_OWN";

export type Activity_Act12D6_Act12D6MileStoneViewModel_State = "FINISH" | "AVAIL" | "NOTAVAIL";

export type Activity_Act12D6_eRelicSortType = "ALL" | "HAVE" | "LOCKED";

export type Activity_Act1_ActivityFirstMissionShopEnum = "MISSION" | "SHOP";

export type CharStarMarkState = "NONE" | "STARED";

export type PlayerSide = "INVALID" | "DEFAULT" | "SIDE_A" | "SIDE_B" | "E_NUM";

export type PlayerSideMask = "ALL" | "SIDE_A" | "SIDE_B" | "NONE";

export type PlayerStageState = "UNLOCKED" | "PLAYED" | "PASS" | "COMPLETE";

export type PlayerBattleRank = "FAIL" | "PASS" | "COMPLETE";

export type RecruitBuildSlotState = "EMPTY" | "BUILDING" | "FINISH" | "LOCKED" | "TOBUY";

export type PlayerRoomSlotState = "EMPTY" | "UPGRADING" | "BUILT";

export type PlayerRoomState = "STOP" | "RUN";

export type EvolvePhase = "E_NUM";

export type SharedConsts_Direction = "UP" | "RIGHT" | "DOWN" | "LEFT" | "E_NUM" | "INVALID";

export type Video_AbstractMediaPlayerHolder_Status = "UNKNOWN" | "STOP" | "PREPARE" | "READY" | "PLAYING" | "PLAYEND" | "ERROR";

export type UI_UISwitchTween_ResetStage = "NONE" | "BEFORE_SHOW_EFFECT" | "AFTER_SHOW_EFFECT" | "BEFORE_HIDE_EFFECT" | "AFTER_HIDE_EFFECT" | "RESET_TO_STATE";

export type Audio_UiBuildingSoundType = string;

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
    isOpen: boolean;
    groupId: string;
    checkInHistory: number[];
    checkinFinTs: number;
    stopSaleTs: number;
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
    tmpl: { [key: string]: PlayerCharPatch[] };
}

export interface PlayerCharPatch {
    skinId: string;
    defaultSkillIndex: number;
    currentEquip: string;
    equip: { [key: string]: PlayerCharEquipInfo[] };
}

export interface PlayerNpcWithAudio {
    voiceLan: VoiceLangType;
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
    rate: { [key: string]: number[] };
    product: { [key: string]: number[] };
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

export interface PlayerActivity {
    defaultActivityList: { [key: string]: PlayerActivity_PlayerDefaultActivity[] };
    missionOnlyActivityList: { [key: string]: PlayerActivity_PlayerMissionOnlyTypeActivity[] };
    checkinOnlyActivityList: { [key: string]: PlayerActivity_PlayerCheckinOnlyTypeActivity };
    checkinAllActivityList: { [key: string]: PlayerActivity_PlayerCheckinAllTypeActivity };
    checkinVsActivityList: { [key: string]: PlayerActivity_PlayerCheckinVsTypeActivity };
    collectionActivityList: { [key: string]: PlayerActivity_PlayerCollectionTypeActivity };
    avgOnlyActivityList: { [key: string]: PlayerActivity_PlayerAVGOnlyTypeActivity[] };
    loginOnlyActivityList: { [key: string]: PlayerActivity_PlayerLoginOnlyTypeActivity[] };
    miniStoryActivityList: { [key: string]: PlayerActivity_PlayerMiniStoryActivity };
    roguelikeActivityList: { [key: string]: PlayerActivity_PlayerRoguelikeActivity[] };
    prayOnlyActivityList: { [key: string]: PlayerActivity_PlayerPrayOnlyActivity[] };
    flipOnlyActivityList: { [key: string]: PlayerActivity_PlayerFlipOnlyActivity[] };
    multiplayActivityList: { [key: string]: PlayerActivity_PlayerMultiplayActivity[] };
    multiplayV2ActivityList: { [key: string]: PlayerActivity_PlayerMultiplayV2Activity[] };
    multiV3ActivityList: { [key: string]: PlayerActivity_PlayerMultiV3Activity };
    interlockActivityList: { [key: string]: PlayerActivity_PlayerInterlockActivity[] };
    act3D0ActivityList: { [key: string]: PlayerActivity_PlayerAct3D0Activity[] };
    act4D0ActivityList: { [key: string]: PlayerActivity_PlayerAct4D0Activity[] };
    act5D0ActivityList: { [key: string]: PlayerActivity_PlayerAct5D0Activity[] };
    act5D1ActivityList: { [key: string]: PlayerActivity_PlayerAct5D1Activity[] };
    act9D0ActivityList: { [key: string]: PlayerActivity_PlayerAct9D0Activity };
    act17D7ActivityList: { [key: string]: PlayerActivity_PlayerAct17D7Activity[] };
    act12sideActivityList: { [key: string]: PlayerActivity_PlayerAct12sideActivity[] };
    act13sideActivityList: { [key: string]: PlayerActivity_PlayerAct13sideActivity[] };
    gridGachaActivityList: { [key: string]: PlayerActivity_PlayerGridGachaActivity[] };
    gridGachaV2ActivityList: { [key: string]: object[] };
    actFunActivityList: { [key: string]: PlayerActivity_PlayerAprilFoolActivity[] };
    act17sideActivityList: { [key: string]: PlayerActivity_PlayerAct17SideActivity[] };
    bossRushActivityList: { [key: string]: PlayerActivity_PlayerBossRushActivity[] };
    enemyDuelActivityList: { [key: string]: PlayerActivity_PlayerEnemyDuelActivity[] };
    vecBreakV2ActivityList: { [key: string]: PlayerActivity_PlayerVecBreakV2[] };
    arcadeActivityList: { [key: string]: PlayerActivity_PlayerArcadeActivity[] };
    act20sideActivityList: { [key: string]: PlayerActivity_PlayerAct20SideActivity[] };
    floatParadeActivityList: { [key: string]: PlayerActivity_PlayerActFloatParadeActivity[] };
    act21sideActivityList: { [key: string]: PlayerActivity_PlayerAct21SideActivity[] };
    mainlineBuffActivityList: { [key: string]: PlayerActivity_PlayerActMainlineBuff[] };
    act24sideActivityList: { [key: string]: PlayerActivity_PlayerAct24SideActivity[] };
    act25sideActivityList: { [key: string]: PlayerActivity_PlayerAct25SideActivity[] };
    switchOnlyList: { [key: string]: PlayerActivity_PlayerSwitchOnlyActivity[] };
    act27sideActivityList: { [key: string]: PlayerActivity_PlayerAct27SideActivity[] };
    uniqueOnlyList: { [key: string]: PlayerActivity_PlayerUniqueOnlyActivity[] };
    mainlineBpActivityList: { [key: string]: object[] };
    act42D0ActivityList: { [key: string]: PlayerActivity_PlayerAct42D0Activity[] };
    act29sideActivityList: { [key: string]: PlayerActivity_PlayerAct29SideActivity[] };
    blessOnlyList: { [key: string]: PlayerActivity_PlayerBlessOnlyActivity[] };
    checkinAccessList: { [key: string]: object[] };
    year5GeneralList: { [key: string]: PlayerActivity_PlayerYear5GeneralActivity[] };
    act35sideActivityList: { [key: string]: PlayerActivity_PlayerAct35SideActivity[] };
    act36sideActivityList: { [key: string]: PlayerActivity_PlayerAct36SideActivity[] };
    act38sideActivityList: { [key: string]: PlayerActivity_PlayerAct38SideActivity[] };
    autoChessList: { [key: string]: PlayerActivity_PlayerAutoChessV1Activity[] };
    checkinVideoActivityList: { [key: string]: object[] };
    actMainSSActivityList: { [key: string]: PlayerActivity_PlayerActMainSSActivity[] };
    act42sideActivityList: { [key: string]: PlayerActivity_PlayerAct42SideActivity[] };
    act44sideActivityList: { [key: string]: PlayerActivity_PlayerAct44SideActivity[] };
    act1vHalfIdleActivityList: { [key: string]: PlayerActivity_PlayerAct1VHalfIdleActivity[] };
    act45sideActivityList: { [key: string]: PlayerActivity_PlayerAct45SideActivity[] };
    teamQuestActivityList: { [key: string]: object };
    recruitOnlyList: { [key: string]: PlayerActivity_PlayerRecruitOnlyAct[] };
    act46sideActivityList: { [key: string]: PlayerActivity_PlayerAct46SideActivity[] };
    actAutoChessActivityList: { [key: string]: PlayerActivity_PlayerActAutoChessActivity[] };
    actFootballActivityList: { [key: string]: PlayerActivity_PlayerActFootballActivity[] };
}

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
    zones: { [key: string]: PlayerZone[] };
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
}

export interface PlayerAutoChessPerm {
    band: { [key: string]: number };
    trainingModeFin: { [key: string]: number };
}

export interface PlayerCampaign_StageOpenInfo {
    permanent: string[];
    training: string[];
    rotate: string;
    rotateGroup: string;
    trainingGroup: string;
    trainingAllOpenGroup: string;
}

export interface PlayerCampaign_Stage {
    maxKills: number;
}

export interface PlayerCampaign {
    campaignCurrentFee: number;
    campaignTotalFee: number;
    activeGroupId: string;
    open: PlayerCampaign_StageOpenInfo;
    missions: { [key: string]: PlayerCampaign_MissionState };
    instances: { [key: string]: PlayerCampaign_Stage };
    sweepMaxKills: { [key: string]: number };
}

export interface PlayerRecruit_NormalModel_SlotModel {
    state: PlayerRecruit_NormalModel_SlotModel_State;
    startTs: string;
    maxFinishTs: string;
    realFinishTs: string;
    durationInSec: number;
}

export interface PlayerRecruit_NormalModel {
    slots: { [key: string]: PlayerRecruit_NormalModel_SlotModel[] };
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
    linkage: { [key: string]: { [key: string]: object[] } };
    attain: { [key: string]: PlayerGacha_PlayerAttainGacha };
    single: { [key: string]: PlayerGacha_PlayerSingleGacha };
    doubleGacha: { [key: string]: PlayerGacha_PlayerDoubleGacha };
    fesClassic: { [key: string]: PlayerGacha_PlayerFesClassicGacha };
    special: { [key: string]: PlayerGacha_PlayerSpecialGacha };
    backflow: { [key: string]: PlayerGacha_PlayerReturnGacha };
}

export interface PlayerMedalBoard {
    type: NameCardMedalType;
    customIndex: string;
    templateGroupId: string;
}

export interface PlayerSocialReward {
    canReceive: boolean;
    first: number;
    assistAmount: number;
    comfortAmount: number;
}

export interface PlayerSocial {
    yesterdayCrisisSeasonId: string;
    yesterdayCrisisV2SeasonId: string;
    assistCharList: PlayerFriendAssist[];
    yesterdayReward: PlayerSocialReward;
    medalBoard: PlayerMedalBoard;
    starFriendFlag: number;
}

export interface PlayerTroop {
    troopCapacity: number;
    curSquadCount: number;
    curCharInstCount: number;
    squads: { [key: string]: PlayerSquad };
    chars: { [key: string]: PlayerCharacter };
    addon: { [key: string]: PlayerHandBookAddon };
    charMission: { [key: string]: { [key: string]: PlayerTroop_CharMissionState } };
    spOperator: { [key: string]: { [key: string]: { [key: string]: PlayerSpecialOperatorNode } } };
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

export interface PlayerShop {
    lowQCShop: PlayerLowQCShopProgressData;
    highQCShop: PlayerHighQCShopProgressData;
    classicQCShop: PlayerClassicQCShopProgressData;
    extraQCShop: PlayerCommonShopProgressData;
    lmtgsQCShop: PlayerLMTGSProgressData;
    epgsQCShop: PlayerEPGSProgressData;
    repQCShop: PlayerEPGSProgressData;
    cashShop: PlayerCashProgressData;
    giftShop: PlayerGiftProgressData;
    socialShop: PlayerSocialShopData;
    furnitureShop: PlayerFurnitureShopData;
    skinShop: PlayerSkinShopData;
}

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
}

export interface PlayerBuildingStatus {
    labor: PlayerBuildingLabor;
    workshop: PlayerBuildingWorkshopStatus;
}

export interface PlayerBuildingCharBubble {
    add: number;
}

export interface PlayerBuildingChar_BubbleContainer {
    normal: PlayerBuildingCharBubble;
    assist: PlayerBuildingCharBubble;
    privateBubble: PlayerBuildingCharBubble;
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
}

export interface PlayerBuildingRoomSlot {
    level: number;
    state: PlayerRoomSlotState;
    roomId: BuildingData_RoomType;
    completeConstructTime: string;
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
}

export interface PlayerDexNav {
    enemy: PlayerEnemyHandBook;
    formula: PlayerFormulaUnlockRecord;
}

export interface PlayerSkins {
    characterSkins: { [key: string]: number[] };
    skinTs: { [key: string]: number[] };
    skinSp: { [key: string]: boolean[] };
}

export interface PlayerPerMedal {
    id: string;
    fts: number;
    rts: number;
    reward: string;
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
}

export interface PlayerRetroBlock {
    locked: boolean;
    open: boolean;
}

export interface PlayerAvatar {
    playerAvatarIcons: { [key: string]: PlayerAvatarBlock[] };
}

export interface PlayerAvatarBlock {
    ts: number;
    src: string;
}

export interface PlayerCollection {
    team: { [key: string]: number };
}

export interface PlayerEquipment {
    missions: { [key: string]: PlayerEquipMission[] };
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
}

export interface PlayerBuildingPower {
    buff: PlayerBuildingPowerBuff;
    presetQueue: number[][];
}

export interface PlayerBuildingControlBuff_Global {
    apCost: number;
}

export interface PlayerBuildingControlBuff {
    global: PlayerBuildingControlBuff_Global;
}

export interface PlayerBuildingControl {
    buff: PlayerBuildingControlBuff;
    apCost: number;
    presetQueue: number[][];
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
    rate: { [key: string]: number[] };
    apRate: { [key: string]: number };
    frate: PlayerBuildingWorkshopBuff_Frate[];
    goldFree: { [key: string]: number[] };
    cost: PlayerBuildingWorkshopBuff_Cost;
    costRe: PlayerBuildingWorkshopBuff_CostRe;
    costFormula: PlayerBuildingWorkshopBuff_CostFormula;
    costForce: PlayerBuildingWorkshopBuff_CostForce;
    costDevide: PlayerBuildingWorkshopBuff_CostDevide;
}

export interface PlayerBuildingWorkshop {
    buff: PlayerBuildingWorkshopBuff;
}

export interface PlayerBuildingMeetingClueChar {
    charId: string;
    level: number;
    evolvePhase: number;
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
}

export interface PlayerBuildingHireBuff {
    speed: number;
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
}

export interface PlayerBuildingTradingBuff {
    speed: number;
    limit: number;
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
}

export interface PlayerBuildingTrainingBuff {
    speed: number;
    reduceTimeBd: PlayerBuildingTrainingReduceTimeBd;
}

export interface PlayerBuildingTraining {
    buff: PlayerBuildingTrainingBuff;
    lastUpdateTime: string;
    trainer: PlayerBuildingTrainer;
    trainee: PlayerBuildingTrainee;
    completeWorkTime: string;
}

export interface PlayerBuildingRoom {
    manufact: { [key: string]: PlayerBuildingManufacture[] };
    shop: { [key: string]: PlayerBuildingShop[] };
    power: { [key: string]: PlayerBuildingPower[] };
    control: { [key: string]: PlayerBuildingControl[] };
    meeting: { [key: string]: PlayerBuildingMeeting[] };
    hire: { [key: string]: PlayerBuildingHire[] };
    dorm: { [key: string]: PlayerBuildingDormitory[] };
    privateDorm: { [key: string]: PlayerBuildingPrivate[] };
    training: { [key: string]: PlayerBuildingTraining[] };
    workshop: { [key: string]: PlayerBuildingWorkshop[] };
    trading: { [key: string]: PlayerBuildingTrading[] };
}

export interface BuildingMusic {
    inUse: boolean;
    selected: string;
    state: { [key: string]: BuildingMusicState };
}

export interface BuildingMusicState {
    unlock: boolean;
}

export interface PlayerBuilding_PlayerBuildingSolution {
    furnitureTs: { [key: string]: number };
}

export interface PlayerBuilding {
    status: PlayerBuildingStatus;
    chars: { [key: string]: PlayerBuildingChar };
    assist: number[];
    roomSlots: { [key: string]: PlayerBuildingRoomSlot };
    rooms: PlayerBuildingRoom;
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
    currentSeason: string;
    shop: PlayerCrisisShop;
    season: { [key: string]: PlayerCrisisSeason };
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
    endbook: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
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
}

export interface PlayerRoguelikeV2_OuterData_MonthTeam {
    reward: { [key: string]: number };
    mission: { [key: string]: number[] };
}

export interface PlayerRoguelikeV2_OuterData_ChallengeCollection {
    exploreTool: { [key: string]: PlayerRoguelikeV2_OuterData_Collection_ItemUnlockInfo };
}

export interface PlayerRoguelikeV2_OuterData_Challenge {
    reward: { [key: string]: number };
    grade: { [key: string]: PlayerRoguelikeChallengeStatus };
    collect: PlayerRoguelikeV2_OuterData_ChallengeCollection;
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
    roguelikeActivitySeedModeDatas: { [key: string]: PlayerRoguelikeV2_OuterData_PlayerRogueActivity_PlayerRoguelikeActivitySeedModeData[] };
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

export interface PlayerCartInfo_Cart {}

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
    pioneer: string;
    warrior: string;
    tank: string;
    sniper: string;
    caster: string;
    support: string;
    medic: string;
    special: string;
}

export interface TowerCurrent_Status {
    state: TowerCurrent_TowerGameState;
    towerId: string;
    coord: number;
    tactical: TowerTactical;
    start: number;
    isHard: boolean;
}

export interface TowerCurrent_TowerGodCard {
    godCardId: string;
    subGodCardId: string;
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
}

export interface TowerOuter {
    training: { [key: string]: number };
    towers: { [key: string]: TowerOuter_TowerData };
    hasTowerPass: number;
    tactical: TowerTactical;
    strategy: TowerGameStrategy;
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
}

export interface TowerSeason {
    id: string;
    finishTs: number;
    missions: { [key: string]: TowerSeason_TowerSeasonMission };
    period: TowerSeason_TowerSeasonPeriod;
}

export interface PlayerHomeUnlockStatus {
    unlockTime: number;
    conditions: { [key: string]: PlayerHomeConditionProgress };
}

export interface PlayerHomeConditionProgress {
    curProgress: number;
    total: number;
    DEFAULT: PlayerHomeConditionProgress;
}

export interface PlayerHomeBackground {
    selectedId: string;
    bgs: { [key: string]: PlayerHomeUnlockStatus };
}

export interface PlayerHomeTheme {
    selectedId: string;
    themes: { [key: string]: PlayerHomeUnlockStatus };
}

export interface PlayerSetting {
    settingPerf: PlayerSettingPerf;
}

export interface PlayerSettingPerf {
    lowPower: boolean;
}

export interface PlayerAprilFool {
    actFun3: PlayerActFun3;
    actFun4: PlayerActFun4;
    actFun5: PlayerActFun5;
    actFun6: PlayerActFun6;
    actFun7: PlayerActFun7;
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
    speedRunning: number;
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
    sandboxV2TemplateData: { [key: string]: PlayerSandboxV2[] };
    sandboxV3TemplateData: { [key: string]: PlayerSandboxV3[] };
}

export interface PlayerSandboxPerm_PlayerSandboxSummaryData {
    sandboxV2SummaryData: { [key: string]: PlayerSandboxV2Summary[] };
    sandboxV3SummaryData: { [key: string]: PlayerSandboxV3Summary[] };
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
}

export interface PlayerCharRotation {
    currentPresetId: string;
    presets: { [key: string]: PlayerCharRotationPreset };
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
}

export interface PlayerDataModel {
    ACTIVITY_FIELD: string;
    SANDBOX_PERM_FIELD: string;
    SANDBOX_PERM_TEMPLATE_FIELD: string;
    events: PlayerEvents;
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
    PlayerAvatar: PlayerAvatar;
    collectionReward: PlayerCollection;
    equipment: PlayerEquipment;
    inventory: { [key: string]: number };
    consumable: { [key: string]: { [key: number]: PlayerConsumableItem[] } };
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
    campaign: PlayerCampaign;
    autoChessPerm: PlayerAutoChessPerm;
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
    playerHomeBackground: PlayerHomeBackground;
    playerHomeTheme: PlayerHomeTheme;
    playerNameCardStyle: PlayerNameCardStyle;
    playerSetting: PlayerSetting;
    playerAprilFool: PlayerAprilFool;
    npcAudio: { [key: string]: PlayerNpcWithAudio };
    charRotation: PlayerCharRotation;
    gallery: PlayerGallery;
    playerMainlineRecord: PlayerMainlineRecord;
    limitedBuff: PlayerLimitedDropBuff;
    performanceStory: PlayerPerformanceStory;
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
    equips: { [key: string]: SharedCharData_CharEquipInfo[] };
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
    tmpl: { [key: string]: SharedCharData_TmplData[] };
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

