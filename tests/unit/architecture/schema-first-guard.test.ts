/**
 * 契约先行守卫（schema-first）
 *
 * 强制「新路由先落 contract」：modules 各模块 routes 与 activities 各族 router 下所有 POST 路由
 * 必须经 validateBody 校验（契约层 modules/<模块>/*.schema.ts 定义请求形状）。
 * GET 路由（无 body）豁免；plugin-heartbeat 为内部 GET 端点豁免。
 */
import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";

const APP_ROOT = path.join(__dirname, "../../../app");

function collectFiles(dir: string): string[] {
  const out: string[] = [];
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...collectFiles(p));
    else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) out.push(p);
  }
  return out;
}

describe("契约先行守卫", () => {
  it("router 层 POST 路由必须经 validateBody 校验（契约先行）", () => {
    const offenders: string[] = [];
    // 路由面 = 各模块 routes.ts / 次路由 *.routes.ts / plugin-heartbeat.ts（原 domain/router 的对应物）。
    // 注意：building/gacha 等 handler.ts 在旧守卫（仅扫 domain/router + domain/activity）中不在册，
    // 维持 HEAD 等价范围不纳入；是否扩展到 handler 面留待 T4 边界守卫裁决。
    const ROUTER_FACE = /(?:^|[\\/])routes\.ts$|(?:^|[\\/])[\w-]+\.routes\.ts$|(?:^|[\\/])plugin-heartbeat\.ts$/;
    const files = [
      ...collectFiles(path.join(APP_ROOT, "game/modules")).filter((f) => ROUTER_FACE.test(f)),
      ...collectFiles(path.join(APP_ROOT, "game/modules/activities")),
    ];
    for (const file of files) {
      const lines = fs.readFileSync(file, "utf-8").split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const m = lines[i].match(/\.(post|put|patch)\(/);
        if (!m) continue;
        // 路由注册行须在同一行或后续 6 行内出现 validateBody（多行签名/中间件场景）
        const window = lines.slice(i, i + 6).join(" ");
        // multipart 上传端点（像素画/杂志编队）无 JSON body，豁免
        if (/parseMultipartForm|multipart\/form-data|pixelData|saveDiyMagazine/.test(window)) continue;
        if (!/validateBody/.test(window)) {
          offenders.push(`${path.relative(APP_ROOT, file)}:${i + 1} 缺少 validateBody`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
