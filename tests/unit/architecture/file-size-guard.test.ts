/**
 * 文件规模守卫
 *
 * 防巨型文件回潮：service 层 logic 文件与 router 文件单文件不超过 1500 行。
 * 拆分基准（2026-08-26）：mission 983 / building 900 / rlv2 1231 行。
 */
import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";

const APP_ROOT = path.join(__dirname, "../../../app");
const MAX_LINES = 1500;

function collectFiles(dir: string, ext: string): string[] {
  const out: string[] = [];
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...collectFiles(p, ext));
    else if (entry.name.endsWith(ext)) out.push(p);
  }
  return out;
}

describe("文件规模守卫", () => {
  it("service 层 logic.ts 单文件不超过 1500 行", () => {
    const offenders: string[] = [];
    for (const file of collectFiles(path.join(APP_ROOT, "game/service"), ".ts")) {
      if (!file.endsWith("logic.ts")) continue;
      const count = fs.readFileSync(file, "utf-8").split("\n").length;
      if (count > MAX_LINES) {
        offenders.push(`${path.relative(APP_ROOT, file)}: ${count} 行（> ${MAX_LINES}）`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("router 层单文件不超过 1500 行（活动已按族拆分）", () => {
    const offenders: string[] = [];
    const scan = (dir: string) => {
      for (const file of collectFiles(dir, ".ts")) {
        if (!file.endsWith("router.ts") && !file.endsWith("handler.ts")) continue;
        const count = fs.readFileSync(file, "utf-8").split("\n").length;
        if (count > MAX_LINES) {
          offenders.push(`${path.relative(APP_ROOT, file)}: ${count} 行（> ${MAX_LINES}）`);
        }
      }
    };
    scan(path.join(APP_ROOT, "game/domain/router"));
    scan(path.join(APP_ROOT, "game/domain/activity"));
    expect(offenders).toEqual([]);
  });
});
