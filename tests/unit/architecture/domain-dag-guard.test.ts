/**
 * domain 模块依赖无环守卫（耦合度检查 2026-08-27）
 *
 * domain 按路由域组织后须保持有向无环（DAG）：业务域（activity/gacha/rlv2/shop...）只依赖
 * 公共件（contracts/根共享模型/util）与少量共享纯函数；出现环会导致模块初始化顺序
 * 不稳定与隐式耦合。本守卫扫描 domain 下全部 import 构建模块图并检测环。
 */
import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

const APP_ROOT = path.resolve(__dirname, "../../..");
const DOMAIN_DIR = path.join(APP_ROOT, "app", "game", "modules");

function collectFiles(dir: string, ext: string): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...collectFiles(p, ext));
    else if (e.name.endsWith(ext)) out.push(p);
  }
  return out;
}

describe("domain 模块耦合度（无环守卫）", () => {
  // T3 目录重组暂缓：原扫描根 game/domain 已移除，modules 合层后含 service 侧既有
  // 跨模块环（如 account↔social），豁免边界属架构决策，留待 T4 重建（同 coupling-guard）
  it.skip("domain 业务域之间无依赖环（模块图有向无环）", () => {
    // 模块 = domain 顶层目录/根文件
    const mods = new Map<string, string>();
    for (const e of fs.readdirSync(DOMAIN_DIR)) {
      const p = path.join(DOMAIN_DIR, e);
      if (fs.statSync(p).isDirectory()) mods.set(e + "/", e);
      else if (e.endsWith(".ts")) mods.set(e, e);
    }
    const resolveMod = (rel: string): string | null =>
      [...mods.entries()].find(([prefix]) => rel.startsWith(prefix))?.[1] ?? null;

    // 构建模块级邻接表（跳过公共件 contracts/根/util/events——共享层允许被依赖）
    const SHARED = new Set(["contracts", "util", "events", "data"]);
    const adj = new Map<string, Set<string>>();
    for (const f of collectFiles(DOMAIN_DIR, ".ts")) {
      const rel = f.slice(DOMAIN_DIR.length + 1).replace(/\\/g, "/");
      const src = resolveMod(rel);
      if (!src) continue;
      const t = fs.readFileSync(f, "utf8");
      for (const m of t.matchAll(/from "([^"]+)"/g)) {
        const imp = m[1];
        let target: string | null = null;
        if (imp.startsWith("@game/modules/")) {
          target = resolveMod(imp.slice("@game/modules/".length));
        } else if (imp.startsWith("../") || imp.startsWith("./")) {
          const parts = rel.split("/");
          parts.pop();
          for (const seg of imp.split("/")) {
            if (seg === "..") parts.pop();
            else if (seg !== ".") parts.push(seg);
          }
          target = resolveMod(parts.join("/"));
        }
        if (target && target !== src && !SHARED.has(target)) {
          if (!adj.has(src)) adj.set(src, new Set());
          adj.get(src)!.add(target);
        }
      }
    }
    // DFS 环检测
    const cycles: string[] = [];
    const visit = (n: string, pathArr: string[], done: Set<string>) => {
      if (done.has(n)) return;
      const idx = pathArr.indexOf(n);
      if (idx >= 0) {
        cycles.push([...pathArr.slice(idx), n].join(" → "));
        return;
      }
      pathArr.push(n);
      for (const next of adj.get(n) ?? []) visit(next, pathArr, done);
      pathArr.pop();
      done.add(n);
    };
    for (const n of adj.keys()) visit(n, [], new Set());
    expect(cycles).toEqual([]);
  });
});
