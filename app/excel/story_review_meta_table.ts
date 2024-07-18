import { ItemBundle } from "./character_table";

export interface StoryReviewMetaTable {
    miniActTrialData:  MiniActTrialData;
    actArchiveResData: ActArchiveResData;
    actArchiveData:    ActArchiveComponentTable;
}

export interface ActArchiveComponentTable {
    components: {[key:string]:ActArchiveComponentData};
}


export interface ActArchiveComponentData {
    timeline:      ActArchiveTimelineData | null;
    music:         ActArchiveMusicData | null;
    pic:           ActArchivePicData | null;
    story:         ActArchiveStoryData | null;
    avg:           ActArchiveAvgData | null;
    news:          ActArchiveNewsData | null;
    landmark:      {[key:string]:ActArchiveLandmarkItemData}|null;
    log:           {[key:string]:ActArchiveChapterLogData}|null;
    challengeBook: ActArchiveChallengeBookData | null;
}

export interface ActArchiveAvgData {
    avgs: {[key:string]: ActArchiveAvgItemData};
}

export interface ActArchiveAvgItemData {
    avgId:     string;
    avgSortId: number;
}

export interface ActArchiveChallengeBookData {
    stories: {[key:string]: ActArchiveChallengeBookItemData};
}

export interface ActArchiveChallengeBookItemData {
    storyId: string;
    sortId:  number;
}

export interface ActArchiveMusicData {
    musics: {[key:string]: ActArchiveMusicItemData};
}


export interface ActArchiveMusicItemData {
    musicId:     string;
    musicSortId: number;
}

export interface ActArchiveNewsData {
    news: { [key: string]: ActArchiveNewsItemData };
}

export interface ActArchiveNewsItemData {
    newsId:     string;
    newsSortId: number;
}

export interface ActArchivePicData {
    pics: { [key: string]: ActArchivePicItemData };
}

export interface ActArchivePicItemData {
    picId:     string;
    picSortId: number;
}

export interface ActArchiveStoryData {
    stories: { [key: string]: ActArchiveStoryItemData };
}

export interface ActArchiveStoryItemData {
    storyId:     string;
    storySortId: number;
}

export interface ActArchiveTimelineData {
    timelineList: ActArchiveTimelineItemData[];
}

export interface ActArchiveTimelineItemData {
    timelineId:     string;
    timelineSortId: number;
    timelineTitle:  string;
    timelineDes:    string;
    picIdList:      string[] | null;
    audioIdList:    string[] | null;
    avgIdList:      string[] | null;
    storyIdList:    string[] | null;
    newsIdList:     string[] | null;
}





export interface ActArchiveLandmarkItemData {
    landmarkId:     string;
    landmarkSortId: number;
}

export interface ActArchiveChapterLogData {
    chapterName: string;
    displayId:   string;
    unlockDes:   string;
    logs:        string[];
    chapterIcon: ChapterIconType;
}

export enum ChapterIconType {
    Ex = "EX",
    Hard = "HARD",
    Normal = "NORMAL",
}


export interface ActArchiveResData {
    pics:           { [key: string]: PicArchiveResItemData };
    audios:         { [key: string]: AudioArchiveResItemData };
    avgs:           { [key: string]: AvgArchiveResItemData };
    stories:        { [key: string]: StoryArchiveResItemData };
    news:           { [key: string]: NewsArchiveResItemData };
    landmarks:      { [key: string]: LandmarkArchiveResItemData };
    logs:           { [key: string]: LogArchiveResItemData };
    challengeBooks: { [key: string]: ChallengeBookArchiveResItemData };
}

export interface AudioArchiveResItemData {
    id:   string;
    desc: string;
    name: string;
}

export interface AvgArchiveResItemData {
    id:            string;
    desc:          string;
    breifPath:     null | string;
    contentPath:   string;
    imagePath:     string;
    rawBrief:      null | string;
    titleIconPath: null | string;
}

export interface ChallengeBookArchiveResItemData {
    storyId:   string;
    titleName: string;
    storyName: string;
    textId:    string;
}

export interface LandmarkArchiveResItemData {
    landmarkId:      string;
    landmarkName:    string;
    landmarkPic:     string;
    landmarkDesc:    string;
    landmarkEngName: string;
}

export interface LogArchiveResItemData {
    logId:   string;
    logDesc: string;
}

export interface NewsArchiveResItemData {
    id:         string;
    desc:       string;
    newsType:   string;
    newsFormat: NewsFormatData;
    newsText:   string;
    newsAuthor: string;
    paramP0:    number;
    paramK:     number;
    paramR:     number;
    newsLines:  ActivityNewsLine[];
}


export interface NewsFormatData {
    typeId:          string;
    typeName:        string;
    typeLogo:        string;
    typeMainLogo:    string;
    typeMainSealing: string;
}




export interface ActivityNewsLine {
    lineType: string;
    content:  string;
}



export interface PicArchiveResItemData {
    id:             string;
    desc:           string;
    assetPath:      string;
    type:           ActArchivePicType;
    subType:        null | string;
    picDescription: string;
    kvId:           null | string;
}

export enum ActArchivePicType {
    EndingImage = "ENDING_IMAGE",
    Image = "IMAGE",
    RogueImage = "ROGUE_IMAGE",
}

export interface StoryArchiveResItemData {
    id:       string;
    desc:     string;
    date:     null | string;
    pic:      string;
    text:     string;
    titlePic: null | string;
}

export interface MiniActTrialData {
    preShowDays:         number;
    ruleDataList:        RuleData[];
    miniActTrialDataMap: { [key: string]: MiniActTrialSingleData };
}

export interface MiniActTrialSingleData {
    actId:           string;
    rewardStartTime: number;
    themeColor:      string;
    rewardList:      MiniActTrialRewardData[];
}

export interface MiniActTrialRewardData {
    trialRewardId:    string;
    orderId:          number;
    actId:            string;
    targetStoryCount: number;
    item:             ItemBundle;
}


export interface RuleData {
    ruleType: string;//RuleType
    ruleText: string;
}
