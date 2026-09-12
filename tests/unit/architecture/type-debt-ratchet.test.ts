/**
 * 类型债守卫（棘轮 / Ratchet）
 *
 * 背景：仓库曾以 `any` / `unknown` / `object` 作为「快速通过编译」的逃生口，
 * 使类型系统在关键路径上失效（审计与策略见 docs/type-system-audit.md）。本守卫把
 * 「模糊类型」量化成可测指标并固化现状，保证只减不增：
 *
 *  1. 不允许**新增**含模糊类型的文件；
 *  2. 既有文件的模糊类型计数只允许下降（棘轮），上升即红灯；
 *  3. 已清零的文件必须从基线移除（收紧棘轮）；
 *  4. 基线总量必须与逐文件明细自洽，且不得残留已删除路径。
 *
 * 术语与豁免（与 docs/type-system-audit.md §2 策略一致）：
 *  - 受控关键字为 TS 的 `any` / `unknown` / `object`（大小写敏感、词边界匹配）。
 *  - 注释、字符串、模板字面量与正则字面量在统计前一律剥离，避免把
 *    `typeof x === "object"` 或文档说明词误计为类型债。
 *  - 生成的类型文件（app/game/excel/types*）同样纳入统计：其模糊类型源自生成器
 *    而非手写，修复方向是改生成器，因此同样只能减少。
 *
 * 扫描范围是**全仓代码**：`app/`、`scripts/`、`tests/`、`hook/` 与根 `index.ts`
 * （见 scripts/lib/type-debt-scan.ts#SCAN_DIRS）——测试与脚本同样是仓库资产，
 * `any` 不因所在目录而合法。
 *
 * 扫描器为纯函数（scripts/lib/type-debt-scan.ts），与 CLI `pnpm run type:debt` 共用，
 * 保证「守卫判定」与「基线刷新」口径完全一致。刷新基线：`pnpm run type:debt -- --write`
 * （该命令拒绝让总量上升）；**扫描范围扩容**时用
 * `pnpm run type:debt -- --write --expand-scope`（只放行新增文件，既有文件仍禁止上升）。
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import {
  countVagueTypes,
  scanTypeDebt,
  totalOf,
  type TypeDebtBaseline,
} from "../../../scripts/lib/type-debt-scan";

const REPO_ROOT = path.resolve(__dirname, "../../..");
const BASELINE_FILE = path.join(__dirname, "type-debt-baseline.json");

/** 读取棘轮基线 */
function readBaseline(): TypeDebtBaseline {
  return JSON.parse(fs.readFileSync(BASELINE_FILE, "utf-8")) as TypeDebtBaseline;
}

/**
 * 当前扫描结果（惰性缓存）
 *
 * 扫描范围已扩到全仓（`app`/`scripts`/`tests`/`hook` + `index.ts`，约 470 个文件），
 * 单次扫描在本机需数十秒；四个校验用例若各扫一遍会让整个用例组在并发跑测时超时。
 * 一次扫描结果在所有用例间共享（文件在单次测试运行内不会被改写）。
 */
let cachedScan: ReturnType<typeof scanTypeDebt> | null = null;

/** 当前扫描结果（首次调用时扫描，后续复用） */
function currentScan(): ReturnType<typeof scanTypeDebt> {
  return (cachedScan ??= scanTypeDebt(REPO_ROOT));
}

// 全仓扫描耗时随范围增长（秒级），显式放宽单用例上限，避免在慢机器/并发负载下假失败
describe("类型债守卫（any/unknown/object 棘轮）", { timeout: 180000 }, () => {
  it("负样本自证：注释、字符串、正则中的关键字不计为类型债", () => {
    expect(countVagueTypes("// any unknown object")).toEqual({ any: 0, unknown: 0, object: 0 });
    expect(countVagueTypes("/* any unknown object */")).toEqual({ any: 0, unknown: 0, object: 0 });
    expect(countVagueTypes('typeof x === "object" ? "any" : "unknown"')).toEqual({
      any: 0,
      unknown: 0,
      object: 0,
    });
    expect(countVagueTypes("const re = /^(string|number|object|any|Date)$/;")).toEqual({
      any: 0,
      unknown: 0,
      object: 0,
    });
    expect(countVagueTypes("const s = `any ${x} object`;")).toEqual({
      any: 0,
      unknown: 0,
      object: 0,
    });
    // 标识符内的子串与大小写变体不是关键字
    expect(countVagueTypes("const anyValue = 1; class Anys {} const objectId = 2;")).toEqual({
      any: 0,
      unknown: 0,
      object: 0,
    });
    // 成员访问不是类型关键字：zod 的 z.object({...}) 是精确 schema，不计类型债
    expect(countVagueTypes("const s = z.object({ a: z.string() });")).toEqual({
      any: 0,
      unknown: 0,
      object: 0,
    });
    expect(countVagueTypes("const t = foo.object;")).toEqual({ any: 0, unknown: 0, object: 0 });
  });

  it("负样本自证：真实类型位置的关键字被计入", () => {
    expect(countVagueTypes("function f(a: any): void {}")).toEqual({
      any: 1,
      unknown: 0,
      object: 0,
    });
    expect(countVagueTypes("const x = y as any;")).toEqual({ any: 1, unknown: 0, object: 0 });
    expect(countVagueTypes("function f(a: unknown): object { return a as object; }")).toEqual({
      any: 0,
      unknown: 1,
      object: 2,
    });
    expect(countVagueTypes("const m: { [k: string]: any } = {};")).toEqual({
      any: 1,
      unknown: 0,
      object: 0,
    });
    // 除法不是正则，其后的关键字仍应统计
    expect(countVagueTypes("const r = a / b; const t: any = r;")).toEqual({
      any: 1,
      unknown: 0,
      object: 0,
    });
    // zod 逃生口与类型关键字同属模糊表述，必须计入
    expect(countVagueTypes("const s = z.any(); const u = z.unknown();")).toEqual({
      any: 1,
      unknown: 1,
      object: 0,
    });
    // 内联结构化类型中的 object 字段
    expect(countVagueTypes("const m: Record<string, object> = {};")).toEqual({
      any: 0,
      unknown: 0,
      object: 1,
    });
  });

  it("基线自洽：总量等于逐文件明细之和，且不含零计数条目", () => {
    const baseline = readBaseline();
    expect(baseline.totals).toEqual(totalOf(baseline.counts));
    const zeroed = Object.entries(baseline.counts)
      .filter(([, c]) => c.any + c.unknown + c.object === 0)
      .map(([f]) => f);
    expect(zeroed, `基线含零计数条目（应从基线移除）：\n  ${zeroed.join("\n  ")}`).toEqual([]);
  });

  it("不得新增含模糊类型的文件（棘轮：只减不增）", () => {
    const baseline = readBaseline();
    const added = Object.keys(currentScan()).filter((f) => !(f in baseline.counts));
    expect(
      added,
      `新增模糊类型（请改用具体类型，勿以 any/unknown/object 通过编译）：\n  ${added.join(
        "\n  ",
      )}`,
    ).toEqual([]);
  });

  it("既有文件的模糊类型计数不得上升", () => {
    const baseline = readBaseline();
    const current = currentScan();
    const grown: string[] = [];
    for (const [file, counts] of Object.entries(current)) {
      const base = baseline.counts[file];
      if (!base) continue;
      for (const key of ["any", "unknown", "object"] as const) {
        if (counts[key] > base[key]) grown.push(`${file}: ${key} ${base[key]} → ${counts[key]}`);
      }
    }
    expect(grown, `模糊类型计数上升：\n  ${grown.join("\n  ")}`).toEqual([]);
  });

  it("已清零的文件必须从基线移除（收紧棘轮）", () => {
    const baseline = readBaseline();
    const current = currentScan();
    const migrated = Object.keys(baseline.counts)
      .filter((f) => !(f in current))
      .sort();
    expect(
      migrated,
      `以下文件已无模糊类型，请从 type-debt-baseline.json 移除：\n  ${migrated.join("\n  ")}`,
    ).toEqual([]);
  });

  it("基线不含已不存在的文件（防止基线失去约束力）", () => {
    const baseline = readBaseline();
    const ghosts = Object.keys(baseline.counts).filter(
      (f) => !fs.existsSync(path.join(REPO_ROOT, f)),
    );
    expect(ghosts, `基线含已不存在的文件：\n  ${ghosts.join("\n  ")}`).toEqual([]);
  });
});
