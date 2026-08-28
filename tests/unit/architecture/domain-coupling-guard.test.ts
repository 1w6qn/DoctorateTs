/**
 * domain 业务模块耦合守卫（2026-08-27 移除层间耦合后固化）
 *
 * 【已随目录重组（kernel/modules 特性切片）暂缓】：本守卫原扫描 game/domain 分层，
 * 该分层已不存在；modules 切片后 service 侧管理器与 domain 侧模型合层，既有跨模块
 * 依赖（char→gacha、roguelike→troop、AccountManager→freshPlayer 等）为历史事实，
 * 重新划定豁免边界属架构决策，留待 T4 边界守卫上线时按切片语义重建。
 * it.skip 仅为显式暂缓（非删除），恢复时以 modules/* 切片为模块单位重写 SHARED 集合。
 *
 * 业务模块（activity/gacha/rlv2/shop/...）只允许依赖公共件
 * （contracts / util / shared / model / playerdata / events / data）
 * 与自身；禁止跨业务模块直接引用（模型已上移 shared，工具已上移 util）。
 * router 为路由聚合层（注册各玩法路由），豁免。
 *
 * 防回归：任何未来改动若重新引入业务模块间直接依赖（如 shop → gacha 函数、
 * rlv2 → character 模型），本守卫将红灯。
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

describe("domain 业务模块耦合守卫", () => {
  // T3 目录重组暂缓：原扫描根 game/domain 已移除（见文件头说明），T4 重建
  it.skip("业务模块不得直接依赖其他业务模块（公共件 + router 豁免）", () => {
    const mods = new Map<string, string>();
    for (const e of fs.readdirSync(DOMAIN_DIR)) {
      const p = path.join(DOMAIN_DIR, e);
      if (fs.statSync(p).isDirectory()) mods.set(e + "/", e);
      else if (e.endsWith(".ts")) mods.set(e, e);
    }
    const resolveMod = (rel: string): string | null =>
      [...mods.entries()].find(([prefix]) => rel.startsWith(prefix))?.[1] ?? null;

    // 公共件（允许被依赖）+ 聚合层豁免
    const SHARED = new Set(["contracts", "util", "shared", "events", "data", "playerdata.ts", "router"]);

    const offenders: string[] = [];
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
        if (target && target !== src && !SHARED.has(target) && !SHARED.has(src)) {
          offenders.push(`${rel}: ${src} → ${target}（${imp}）`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
