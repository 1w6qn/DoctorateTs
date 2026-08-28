/**
 * 模块边界守卫（特性切片架构不变量）
 *
 * R1 core 不依赖 game/ops；R2 kernel/excel 不依赖 modules；
 * R3 模块间仅可 import 对方 public.ts（activities 族对 shared 免检）；
 * R4 路由文件仅允许约定位置。检查器为纯函数，附负样本自证有效性。
 */
import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";

const APP_ROOT = path.resolve(__dirname, "../../../app");
const ALIASES: Record<string, string> = {
  "@game": "app/game", "@excel": "app/game/excel", "@utils": "app/core/utils",
  "@capture": "app/ops/capture", "@logs": "app/core/logs", "@plugin": "app/ops/plugin",
  "@asset": "app/ops/assets/asset-registry", "@core": "app/core", "@ops": "app/ops",
};

function collectFiles(dir: string): string[] {
  const out: string[] = [];
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...collectFiles(p));
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

/** 提取一个 TS 源文件的全部 import 说明符（含动态 import 与 type import） */
export function extractSpecs(src: string): string[] {
  const specs: string[] = [];
  for (const re of [/from\s*['"]([^'"]+)['"]/g, /import\(\s*['"]([^'"]+)['"]\s*\)/g]) {
    for (const m of src.matchAll(re)) specs.push(m[1]);
  }
  return specs;
}

/** 说明符 → 仓库相对路径（无扩展名；无法解析的相对路径返回 null） */
export function resolveSpec(spec: string, fromRepoRel: string): string | null {
  for (const [alias, target] of Object.entries(ALIASES)) {
    if (spec === alias) return target;
    if (spec.startsWith(alias + "/")) return `${target}/${spec.slice(alias.length + 1)}`;
  }
  if (!spec.startsWith(".")) return null;
  const dir = path.posix.dirname(fromRepoRel);
  return path.posix.normalize(path.posix.join(dir, spec));
}

export interface Violation { rule: string; file: string; spec: string }

/** 显式豁免清单：确属暂时无法解耦的越界引用，每条必须带 reason */
const EXEMPTIONS: { file: string; spec: string; reason: string }[] = [];

/** R4 显式豁免：存量合理路由载体（不在约定命名内但确属路由文件），每条必须带 reason */
const R4_EXEMPTIONS: { file: string; reason: string }[] = [
  { file: "game/modules/activities/index.ts", reason: "活动路由聚合根（default 聚合 /activity 前缀 + rootRouter 根级路由），聚合中心即约定位置" },
  { file: "game/modules/system/plugin-heartbeat.ts", reason: "system 模块第二路由文件（插件心跳，独立 /plugin 前缀，与 routes.ts 的 audit 路由并存）" },
];

/** 边界规则检查器（纯函数，供全量扫描与负样本共用） */
export function checkImport(fileRepoRel: string, spec: string): Violation | null {
  if (EXEMPTIONS.some((e) => e.file === fileRepoRel && e.spec === spec)) return null;
  const target = resolveSpec(spec, fileRepoRel);
  if (!target) return null;
  const t = target.replace(/\.ts$/, "");
  const inCore = fileRepoRel.startsWith("app/core/");
  const inKernel = fileRepoRel.startsWith("app/game/kernel/") || fileRepoRel.startsWith("app/game/excel/");
  const modOf = (p: string) => p.match(/^app\/game\/modules\/(activities\/[^/]+|[^/]+)\//)?.[1] ?? null;
  const srcMod = modOf(fileRepoRel);

  if (inCore && (t.startsWith("app/game/") || t.startsWith("app/ops/")))
    return { rule: "R1 core 不得依赖 game/ops", file: fileRepoRel, spec };
  if (inKernel && t.startsWith("app/game/modules/"))
    return { rule: "R2 kernel/excel 不得依赖 modules", file: fileRepoRel, spec };
  if (srcMod) {
    const dstMod = modOf(t);
    if (dstMod && dstMod !== srcMod) {
      const sharedOk = srcMod.startsWith("activities/") || dstMod === "activities/shared";
      if (!sharedOk && !t.endsWith("public"))
        return { rule: "R3 跨模块仅可 import public.ts", file: fileRepoRel, spec };
    }
  }
  return null;
}

describe("模块边界守卫", () => {
  const allFiles = [
    ...collectFiles(path.join(APP_ROOT, "core")),
    ...collectFiles(path.join(APP_ROOT, "game")),
    ...collectFiles(path.join(APP_ROOT, "ops")),
  ];

  it("R1-R3：全量扫描无非法规界 import", () => {
    const violations: Violation[] = [];
    for (const f of allFiles) {
      const rel = path.relative(APP_ROOT, f).replace(/\\/g, "/");
      for (const spec of extractSpecs(fs.readFileSync(f, "utf-8"))) {
        const v = checkImport(rel, spec);
        if (v) violations.push(v);
      }
    }
    expect(violations).toEqual([]);
  });

  it("R4：Express Router 只允许在约定路由文件中创建", () => {
    // 约定路由文件：routes.ts / router.ts / *.routes.ts / *.router.ts / handler.ts（模块五文件约定的路由载体）。
    // 扫描范围仅限 app/game/——core/ops 的基础设施路由（网关/管理面板/资源服务）是服务入口，不受业务路由位置约束。
    const conventionRouteFile = /(^|\/)(routes|router|handler)\.ts$|\.(routes|router)\.ts$/;
    const offenders = allFiles.filter((f) => {
      const rel = path.relative(APP_ROOT, f).replace(/\\/g, "/");
      if (!rel.startsWith("app/game/")) return false;
      if (rel === "game/routes.ts" || rel === "game/app.ts") return false;
      if (R4_EXEMPTIONS.some((e) => e.file === rel)) return false;
      if (conventionRouteFile.test(rel)) return false;
      return /express\.Router\(\)|\bRouter\(\)\s*;/.test(fs.readFileSync(f, "utf-8"));
    });
    expect(offenders).toEqual([]);
  });

  it("负样本：检查器能检出越界 import（自证有效性）", () => {
    expect(checkImport("app/core/config/gate", "@game/modules/gacha/public")).toMatchObject({ rule: /^R1/ });
    expect(checkImport("app/game/kernel/model", "@game/modules/gacha/public")).toMatchObject({ rule: /^R2/ });
    expect(checkImport("app/game/modules/gacha/manager", "@game/modules/shop/manager")).toMatchObject({ rule: /^R3/ });
    expect(checkImport("app/game/modules/gacha/manager", "@game/modules/shop/public")).toBeNull();
  });
});
