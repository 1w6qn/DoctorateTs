export interface PlayerActivity {
    LOGIN_ONLY: {};
    CHECKIN_ONLY: { [key: string]:PlayerActivity.PlayerCheckinOnlyTypeActivity };
    TYPE_ACT9D0: {};
    AVG_ONLY: {};
    TYPE_ACT4D0: {};
    COLLECTION: {};
    TYPE_ACT5D1: {};
    TYPE_ACT5D0: {};
    TYPE_ACT3D0: {};
    DEFAULT: {};
    MISSION_ONLY: {};
    MINISTORY: {};
    ROGUELIKE: {};
    PRAY_ONLY: {};
    MULTIPLAY: {};
    TYPE_ACT17D7: {};
    GRID_GACHA: {};
    INTERLOCK: {};
    TYPE_ACT12SIDE: {};
    GRID_GACHA_V2: any;
    TYPE_ACT13SIDE: {};
    APRIL_FOOL: {};
    TYPE_ACT17SIDE: {};
    TYPE_ACT20SIDE: {};
    BOSS_RUSH: {};
    TYPE_ACT21SIDE: {};
    FLOAT_PARADE: {};
    SANDBOX: {};
    TYPE_ACT24SIDE: {};
    FLIP_ONLY: {};
    MAIN_BUFF: {};
    TYPE_ACT25SIDE: {};
    CHECKIN_ALL_PLAYER: {};
    TYPE_ACT38D1: {};
    CHECKIN_VS: {};
    SWITCH_ONLY: {};
    TYPE_ACT27SIDE: {};
    MAINLINE_BP: {};
    UNIQUE_ONLY: {};
    TYPE_ACT42D0: {};
    TYPE_ACT29SIDE: {};
    BLESS_ONLY: {};
    CHECKIN_ACCESS: { [key: string]:PlayerActivity.PlayerAccessActivity };
    YEAR_5_GENERAL: { [key: string]:PlayerActivity.PlayerYear5GeneralActivity };
}

export namespace PlayerActivity {
    export interface PlayerAccessActivity {
        rewardsCount: number;
        currentStatus: number;
        lastTs: number;
    }
    export interface PlayerYear5GeneralActivity {
        unconfirmedPoints: number;
        nextRewardIndex: number;
        coin: number;
        favorList: string[];
    }
    export interface PlayerCheckinOnlyTypeActivity {
        lastTs: number;
        history: number[];
    }
    

}