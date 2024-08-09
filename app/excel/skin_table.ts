export interface SkinTable {
    charSkins:           { [key: string]: CharSkinData };
    buildinEvolveMap:    { [key: string]: { [key: string]: string } };
    buildinPatchMap:     { [key: string]: { [key: string]: string } };
    brandList:           { [key: string]: CharSkinBrandInfo };
    specialSkinInfoList: SpecialSkinInfo[];
}

export interface CharSkinBrandInfo {
    brandId:          string;
    groupList:        CharSkinGroupInfo[];
    kvImgIdList:      CharSkinKvImgInfo[];
    brandName:        string;
    brandCapitalName: string;
    description:      string;
    publishTime:      number;
    sortId:           number;
}

export interface CharSkinGroupInfo {
    skinGroupId: string;
    publishTime: number;
}

export interface CharSkinKvImgInfo {
    kvImgId:           string;
    linkedSkinGroupId: string;
}




export interface CharSkinData {
    skinId:        string;
    charId:        string;
    tokenSkinMap:  TokenSkinInfo[] | null;
    illustId:      null | string;
    dynIllustId:   null | string;
    avatarId:      string;
    portraitId:    null | string;
    dynPortraitId: null | string;
    dynEntranceId: null | string;
    buildingId:    null | string;
    battleSkin:    BattleSkin;
    isBuySkin:     boolean;
    tmplId:        null | string;
    voiceId:       null | string;
    voiceType:     string;
    displaySkin:   DisplaySkin;
}

export interface BattleSkin {
    overwritePrefab: boolean;
    skinOrPrefabId:  null | string;
}

export interface DisplaySkin {
    skinName:           null | string;
    colorList:          string[] | null;
    titleList:          string[] | null;
    modelName:          null | string;
    drawerList:         string[] | null;
    designerList:       string[] | null;
    skinGroupId:        null | string;
    skinGroupName:      null | string;
    skinGroupSortIndex: number;
    content:            null | string;
    dialog:             null | string;
    usage:              null | string;
    description:        null | string;
    obtainApproach:     string | null;
    sortId:             number;
    displayTagId:       string | null;
    getTime:            number;
    onYear:             number;
    onPeriod:           number;
}


export interface TokenSkinInfo {
    tokenId:     string;
    tokenSkinId: string;
}
export interface SpecialSkinInfo {
    skinId:    string;
    startTime: number;
    endTime:   number;
}
