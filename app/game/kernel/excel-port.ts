/**
 * excel 数据端口（Excel Data Port）
 *
 * 模块层读取游戏配置表的**唯一契约**：模块不再直接 import `@excel/excel` 全局单例
 * （该单例在导入期即存在，且 init/懒加载表读写盘，测试只能靠 vi.mock 模块打桩），
 * 而是经 `player.excel`（PlayerDataManager 组合根注入）访问。
 *
 * 设计口径：
 * - **消费方驱动（consumer-driven）**：成员表由 app 内实际使用面度量得出（2026-09 实测
 *   37 个成员 / 484 处访问）；模块需要新表时**显式**加入本表——这是编译期棘轮，
 *   而不是运行时兜底。
 * - **只读数据，不含生命周期**：`init` / `resetLazyTables` / `warmupLazyTables` 属组合根职责，
 *   刻意不在端口内，避免模块层触发数据重载。
 * - **单例仍是默认实现**：`PlayerDataManager` 缺省绑定 `@excel/excel` 单例，行为零变化；
 *   端口只是把「谁提供数据」变成可覆写的构造参数（与 `deps.modules` 同款）。
 *
 * 迁移方式（渐进）：`import excel from "@excel/excel"` → `this._player.excel`；
 * 守卫 tests/unit/architecture/excel-singleton-ratchet.test.ts 以基线棘轮防止新增直连。
 */
import type { Excel } from "@excel/excel";

/**
 * 端口内的数据表成员（按 app 内实际使用面度量，新增需显式加入）
 */
export type ExcelTableMember =
  | "ActivityTable"
  | "ArkhubCreatureTable"
  | "BuildingData"
  | "CampaignTable"
  | "CharMetaTable"
  | "CharWordTable"
  | "CharacterTable"
  | "CharmTable"
  | "CheckinTable"
  | "ClimbTowerTable"
  | "DisplayMetaTable"
  | "FavorTable"
  | "GameDataConst"
  | "GachaDetailTable"
  | "GachaTable"
  | "HandbookInfoTable"
  | "ItemTable"
  | "MedalTable"
  | "MissionTable"
  | "OpenServerTable"
  | "RetroTable"
  | "RoguelikeConsts"
  | "RoguelikeTopicTable"
  | "ShopClientTable"
  | "ShopTable"
  | "SkinTable"
  | "SpecialOperatorTable"
  | "StageTable"
  | "StoryReviewMetaTable"
  | "StoryReviewTable"
  | "UniequipTable";

/**
 * 端口内的门面方法成员（取数/构造的收敛入口，避免长链访问）
 */
export type ExcelFacadeMember =
  | "charData"
  | "getItem"
  | "itemName"
  | "makeItem"
  | "stageData";

/**
 * excel 数据端口
 *
 * 模块层可见的全部 excel 能力面：表 + 门面方法。结构上兼容 `Excel` 单例实例，
 * 因此「注入真实单例」与「注入测试替身」是同一份契约。
 */
export type ExcelData = Pick<Excel, ExcelTableMember | ExcelFacadeMember>;
