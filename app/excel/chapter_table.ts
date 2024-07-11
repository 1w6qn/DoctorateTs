export type ChapterTable = {[key:string]:ChapterData}

export interface ChapterData {
    chapterId:         string;
    chapterName:       string;
    chapterName2:      string;
    chapterIndex:      number;
    preposedChapterId: null | string;
    startZoneId:       string;
    endZoneId:         string;
    chapterEndStageId: string;
}
