/**
 * DI 注入替身适配器（测试专用）
 *
 * `PlayerDataManager` 的构造 deps 有两处「替身 → 契约」的硬边界：子模块注入（`deps.modules`）
 * 与 excel 数据端口注入（`deps.excel`）。两者的真实类型都**不是**鸭子类型能结构兼容的：
 * - 子模块是含**私有实现**的类实例（TS 私有成员只允许同类实例赋值）；
 * - `ExcelData` 是 32 个成员**全必填**的 `Pick<Excel, …>`（见 `kernel/excel-port.ts`）。
 *
 * 与 {@link asPlayerManager} 同款口径：适配集中在本文件，调用点写
 * `asChildModules({ … })` / `asExcelPort(mockExcelWith({ … }))`，运行期传的是**同一对象引用**，
 * 行为零变化。**禁止**用它掩盖其它类型不匹配（字段名/字段类型不符一律就地修夹具）。
 */
import type { ExcelData } from "@game/kernel/excel-port";
import type { PlayerChildModules } from "@game/kernel/player-composition";
import type { MockExcel } from "./mockExcel";
import type { MockSeed } from "./mockPlayerData";

/**
 * `deps.modules` 注入替身视图
 *
 * 深可选（{@link MockSeed}）：用例只需覆盖被测分支读到的成员面
 * （如 `{ mission: { init, initPromise } }`）。
 */
export type MockChildModules = Partial<{
  [K in keyof PlayerChildModules]: MockSeed<PlayerChildModules[K]>;
}>;

/**
 * 子模块注入替身 → `deps.modules` 契约
 *
 * 断言方向合法：完整的 `PlayerChildModules`（真实类实例）可赋值给深可选替身视图，
 * 故反向收窄不需要 suppression；真实子模块类含私有实现，鸭子替身本身不可结构兼容。
 * @param deps - 用例提供的部分子模块替身
 * @returns 同一对象，类型视作 `Partial<PlayerChildModules>`（仅供构造 DI）
 */
export function asChildModules(deps: MockChildModules): Partial<PlayerChildModules> {
  return deps as Partial<PlayerChildModules>;
}

/**
 * 窄 excel 端口替身 → 全必填 `ExcelData`
 *
 * `ExcelData` 是 32 个成员全必填的 `Pick<Excel, …>`，而替身只提供被测分支读到的表与门面
 * 方法：**两个方向都不足以重叠**（`ExcelData → MockExcel` 也因门面方法返回类型不同而不成立），
 * 故此处是本文件唯一 suppression。它与 `asPlayerManager` 同属「替身 → 完整契约」边界：
 * 运行期传入同一对象引用，未覆盖的表与旧「最小端口替身」一样读不到数据。
 * **禁止**用它掩盖字段名/字段类型不符——那属于夹具缺陷，必须就地修夹具。
 * @param port - `mockExcel()` / `mockExcelWith({ … })` 产出的窄端口
 * @returns 同一对象，类型视作 `ExcelData`（仅供构造 DI）
 */
export function asExcelPort(port: MockExcel): ExcelData {
  // @ts-expect-error 见上：窄替身与 32 成员全必填的 ExcelData 双向都不可结构兼容
  return port;
}
