import { ItemBundle } from "./character_table";

export type StoryTable = {[key: string]:StoryData}
export interface StoryData {
    id:               string;
    needCommit:       boolean;
    repeatable:       boolean;
    disabled:         boolean;
    videoResource:    boolean;
    trigger:          Trigger;
    condition:        Condition | null;
    setProgress:      number;
    setFlags:         string[] | null;
    completedRewards: ItemBundle[] | null;
    forceOmitCommit?:boolean
}

export interface Condition {
    minProgress:    number;
    maxProgress:    number;
    minPlayerLevel: number;
    requiredFlags:  string[];
    excludedFlags:  string[];
    requiredStages: StageCondition[];
}

export interface StageCondition {
    stageId:  string;
    minState: string//PlayerStageState;
    maxState: string//PlayerStageState;
}



export interface Trigger {
    type:     TriggerType;
    key:      null | string;
    useRegex: boolean;
}

export enum TriggerType {
    ActivityAnnounce = "ACTIVITY_ANNOUNCE",
    ActivityLoaded = "ACTIVITY_LOADED",
    AfterBattle = "AFTER_BATTLE",
    BeforeBattle = "BEFORE_BATTLE",
    CrisisSeasonLoaded = "CRISIS_SEASON_LOADED",
    CustomOperation = "CUSTOM_OPERATION",
    GameStart = "GAME_START",
    PageLoaded = "PAGE_LOADED",
    StoryFinishOrCustomOperation = "STORY_FINISH_OR_CUSTOM_OPERATION",
    StoryFinishOrPageLoaded = "STORY_FINISH_OR_PAGE_LOADED",
}
