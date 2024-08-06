export interface FavorTable {
    maxFavor:    number;
    favorFrames: FavorDataFrames[];
}

export interface FavorDataFrames {
    level: number;
    data:  FavorData;
}

export interface FavorData {
    favorPoint:  number;
    percent:     number;
    battlePhase: number;
}
