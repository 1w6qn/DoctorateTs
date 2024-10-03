import { ItemBundle } from "@excel/character_table";
import { readJson } from "@utils/file";

export class ShopData {
  lowGoodList!: LowGoodList;
  skinGoodList!: SkinGoodList;
  cashGoodList!: CashGoodList;
  highGoodList!: HighGoodList;
  REPGoodList!: REPGoodList;
  LMTGSGoodList!: LMTGSGoodList;
  EPGSGoodList!: EPGSGoodList;
  classicGoodList!: ClassicGoodList;
  extraGoodList!: ExtraGoodList;
  GPGoodList!: GPGoodList;

  constructor() {}

  async init(): Promise<void> {
    this.lowGoodList = await readJson<LowGoodList>(
      "./data/shop/LowGoodList.json",
    );
    this.skinGoodList = await readJson<SkinGoodList>(
      "./data/shop/SkinGoodList.json",
    );
    this.cashGoodList = await readJson<CashGoodList>(
      "./data/shop/CashGoodList.json",
    );
    this.highGoodList = await readJson<HighGoodList>(
      "./data/shop/HighGoodList.json",
    );
    this.REPGoodList = await readJson<REPGoodList>(
      "./data/shop/REPGoodList.json",
    );
    this.LMTGSGoodList = await readJson<LMTGSGoodList>(
      "./data/shop/LMTGSGoodList.json",
    );
    this.EPGSGoodList = await readJson<EPGSGoodList>(
      "./data/shop/EPGSGoodList.json",
    );
    this.classicGoodList = await readJson<ClassicGoodList>(
      "./data/shop/ClassicGoodList.json",
    );
    this.extraGoodList = await readJson<ExtraGoodList>(
      "./data/shop/ExtraGoodList.json",
    );
    this.GPGoodList = await readJson<GPGoodList>("./data/shop/GPGoodList.json");
  }
}

export interface QCObject {
  goodId: string;
  item: ItemBundle;
  progressGoodId: string;
  displayName: string;
  slotId: number;
  originPrice: number;
  price: number;
  availCount: number;
  discount: number;
  priority: number;
  number: number;
  groupId: string;
  goodStartTime: number;
  goodEndTime: number;
  goodType: string;
}

export interface LowGoodList {
  goodList: QCObject[];
  groups: string[];
  shopEndTime: number;
  newFlag: string[];
}

export interface SkinGoodList {
  goodList: ShopSkinItemViewModel[];
}

export interface ShopSkinItemViewModel {
  goodId: string;
  skinId: string;
  skinName: string;
  charId: string;
  currencyUnit: string;
  originPrice: number;
  price: number;
  discount: number;
  desc1: null | string;
  desc2: null | string;
  startDateTime: number;
  endDateTime: number;
  slotId: number;
  isRedeem: boolean;
}

export interface CashGoodList {
  goodList: CashShopObject[];
}

export interface CashShopObject {
  goodId: string;
  slotId: number;
  price: number;
  diamondNum: number;
  doubleCount: number;
  plusNum: number;
  desc: string;
}

export interface HighGoodList {
  goodList: QCObject[];
  progressGoodList: { [key: string]: QCProgressGoodItem[] };
  newFlag: string[];
}

export interface QCProgressGoodItem {
  order: number;
  price: number;
  displayName: string;
  item: ItemBundle;
}

export interface ClassicGoodList {
  goodList: QCObject[];
  progressGoodList: { [key: string]: QCProgressGoodItem[] };
  newFlag: string[];
}

export interface ExtraGoodList {
  goodList: ExtraQCObject[];
  lastClick: number;
  newFlag: string[];
}

export interface ExtraQCObject {
  goodId: string;
  item: ItemBundle;
  displayName: string;
  slotId: number;
  originPrice: number;
  price: number;
  availCount: number;
  discount: number;
  goodEndTime: number;
  shopType: string;
  newFlag: number;
}

export interface LMTGSGood {
  goodId: string;
  startTime: number;
  endTime: number;
  availCount: number;
  item: ItemBundle;
  price: ItemBundle;
  sortId: number;
}

export interface LMTGSGoodList {
  goodList: LMTGSGood[];
  newFlag: string[];
}

export interface EPGSGood {
  goodId: string;
  startTime: number;
  endTime: number;
  availCount: number;
  item: ItemBundle;
  price: number;
  sortId: number;
}

export interface EPGSGoodList {
  goodList: EPGSGood[];
  newFlag: string[];
}

export interface REPGood {
  goodId: string;
  startTime: number;
  endTime: number;
  availCount: number;
  item: ItemBundle;
  price: number;
  sortId: number;
}

export interface REPGoodList {
  goodList: REPGood[];
  newFlag: string[];
}

export interface SocialShopData {
  goodId: string;
  displayName: string;
  item: ItemBundle;
  price: number;
  availCount: number;
  slotItem: ShopSLot;
  discount: number;
  originPrice: number;
}

export interface ShopSLot {
  price: number;
  displayName: string;
  item: ItemBundle;
}

export interface SocialGoodList {
  goodList: SocialShopData[];
  charPurchase: { [key: string]: string };
}

export interface MonthlySubItem extends NormalGPItem {
  cardId: string;
  dailyBonus: ItemBundle[];
  imgId: string;
  backId: string;
}

export interface LevelGPItem extends NormalGPItem {
  playerLevel: number;
}

export interface ChooseGPItem extends NormalGPItem {
  options: Array<ChooseGiftPackageShopOption>;
  desc: string;
  itemDisplayDesc: string;
  itemDisplayNum: number;
}

export interface ChooseGiftPackageShopOption {
  goodId: string;
  OptionId: string;
  orderNum: number;
  item: ItemBundle;
}

export interface NormalGPItem {
  goodId: string;
  giftPackageId: string;
  priority: number;
  displayName: string;
  currencyUnit: string;
  availCount: number;
  buyCount: number;
  price: number;
  originPrice: number;
  discount: number;
  items: ItemBundle[];
  specialItemInfos: Record<string, SpecialItemInfo>;
  startDateTime: number;
  endDateTime: number;
}

export interface SpecialItemInfo {
  showPreview: boolean;
  specialDesc: string;
  specialBtnText: string;
}

export interface PeriodicityGPItem extends NormalGPItem {
  groupId: string;
}

export interface PeriodicityGroup {
  groupId: string;
  startDateTime: number;
  endDateTime: number;
  packages: Record<string, PeriodicityGPItem>;
}

export interface CondTrigGPItem extends NormalGPItem {
  type: string;
}

export interface GPGoodList {
  weeklyGroup: PeriodicityGroup;
  monthlyGroup: PeriodicityGroup;
  monthlySub: Array<MonthlySubItem>;
  levelGP: Array<LevelGPItem>;
  oneTimeGP: Array<NormalGPItem>;
  chooseGroup: Array<ChooseGPItem>;
  condtionTriggerGroup?: Array<CondTrigGPItem>;
}
