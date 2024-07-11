import { Blackboard, BuildableType } from "./character_table";
//不读了
export interface CharmTable {
    charmList: CharmList[];
}

export interface CharmList {
    id:                    string;
    sort:                  number;
    name:                  string;
    icon:                  string;
    itemUsage:             string;
    itemDesc:              string;
    itemObtainApproach:    string;
    rarity:                string;
    desc:                  string;
    price:                 number;
    specialObtainApproach: null | string;
    charmType:             string;
    obtainInRandom:        boolean;
    dropStages:            string[];
    runeData:              RuneData;
}

export interface RuneData {
    id:            string;
    points:        number;
    mutexGroupKey: null;
    description:   string;
    runes:         Rune[];
}

export interface Rune {
    key:        string;
    selector:   Selector;
    blackboard: Blackboard;
}

export interface Selector {
    professionMask:             number | string;
    buildableMask:              BuildableType;
    playerSideMask:             string;
    charIdFilter:               null;
    enemyIdFilter:              null;
    enemyIdExcludeFilter:       null;
    enemyLevelTypeFilter:       null;
    skillIdFilter:              null;
    tileKeyFilter:              null;
    groupTagFilter:             null;
    filterTagFilter:            null;
    filterTagExcludeFilter:     null;
    subProfessionExcludeFilter: null;
    mapTagFilter:               null;
}

