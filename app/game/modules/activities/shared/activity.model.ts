export interface PlayerActivity {
  LOGIN_ONLY: object;
  CHECKIN_ONLY: { [key: string]: PlayerActivity.PlayerCheckinOnlyTypeActivity };
  TYPE_ACT9D0: object;
  AVG_ONLY: object;
  TYPE_ACT4D0: object;
  COLLECTION: object;
  TYPE_ACT5D1: object;
  TYPE_ACT5D0: object;
  TYPE_ACT3D0: object;
  DEFAULT: object;
  MISSION_ONLY: object;
  MINISTORY: object;
  ROGUELIKE: object;
  PRAY_ONLY: object;
  MULTIPLAY: object;
  TYPE_ACT17D7: object;
  GRID_GACHA: object;
  INTERLOCK: object;
  TYPE_ACT12SIDE: object;
  GRID_GACHA_V2: object;
  TYPE_ACT13SIDE: object;
  APRIL_FOOL: object;
  TYPE_ACT17SIDE: object;
  TYPE_ACT20SIDE: object;
  BOSS_RUSH: object;
  TYPE_ACT21SIDE: object;
  FLOAT_PARADE: object;
  SANDBOX: object;
  TYPE_ACT24SIDE: object;
  FLIP_ONLY: object;
  MAIN_BUFF: object;
  TYPE_ACT25SIDE: object;
  CHECKIN_ALL_PLAYER: object;
  TYPE_ACT38D1: object;
  CHECKIN_VS: object;
  SWITCH_ONLY: object;
  TYPE_ACT27SIDE: object;
  MAINLINE_BP: object;
  UNIQUE_ONLY: object;
  TYPE_ACT42D0: object;
  TYPE_ACT29SIDE: object;
  BLESS_ONLY: object;
  CHECKIN_ACCESS: { [key: string]: PlayerActivity.PlayerAccessActivity };
  YEAR_5_GENERAL: { [key: string]: PlayerActivity.PlayerYear5GeneralActivity };
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
