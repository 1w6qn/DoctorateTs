# DoctorateTs 目录重组实施计划（特性切片 · 一次性大迁移）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 按 spec `docs/superpowers/specs/2026-08-28-project-restructure-design.md` 将 `app/` 重组为 core/game(kernel+modules+activities+excel)/ops 三层特性切片结构，清理仓库根目录，并以架构守卫测试锁定边界。

**Architecture:** 纯结构迁移（git mv + 映射表驱动的 import 批量重写），不改业务逻辑。分 4 个 commit 落地：commit 1（core+ops）→ commit 2（game）→ commit 3a（守卫）→ commit 3b（文档），每步 `tsc --noEmit` + `vitest run` 全绿后推进。

**Tech Stack:** Node 24 + TSX + Express 5 + Vitest；环境为 Windows + Git Bash；包管理 pnpm。临时工具脚本放 `tmp/restructure/`（gitignored，最后删除）。

**执行前置（硬门禁）：** `app/asset.ts` 当前有未提交修改。开始 Task 1 前必须由用户提交或暂存该修改，工作树必须干净（`git status --short` 仅允许出现本计划自己产生的变更）。

---

## Task 1: 基线建立与前置门禁

**Files:** 无文件修改（只读验证）

- [ ] **Step 1: 确认工作树干净**

Run: `git status --short`
Expected: 空输出。若出现 `app/asset.ts` 等用户修改，**停止并向用户确认处置方式**，不得自行丢弃。

- [ ] **Step 2: 记录基线——类型检查**

Run: `pnpm exec tsc --noEmit`
Expected: 退出码 0，无输出。若基线就不干净，停止并报告用户（不得在脏基线上做迁移，否则无法归因错误）。

- [ ] **Step 3: 记录基线——测试套件**

Run: `pnpm exec vitest run 2>&1 | tail -15`
Expected: 全部通过。记录通过用例数（例：`Tests  N passed (N)`），后续每步必须不低于此数。已知潜伏项：`tests/unit/model/battle.test.ts` 引用不存在的 `@game/domain/battle`（type-only import，运行时被剥离，不影响通过）。

---

## Task 2: commit 1 —— core + ops 迁移

**Files:**
- Modify: `tsconfig.json:11-19`（paths 块）
- Modify: `vitest.config.mts:30-40`（alias 块）、`vitest.config.mts:20`（coverage.exclude）
- Create: `tmp/restructure/moves-1.json`、`tmp/restructure/rewrite.mjs`
- Move: `app/{config,db,logs,utils,auth}` → `app/core/*`；`app/{admin,capture,proxy,updater,plugin}` → `app/ops/*`；`app/{asset-registry,asset.ts,asset-backfill.ts}` → `app/ops/assets/*`
- Modify: `app/ops/assets/asset.ts`（8 处 `__dirname`）、`app/ops/assets/asset-backfill.ts`（1 处）

- [ ] **Step 1: 新增 @core/@ops 别名（tsconfig.json paths 块，在 `"@asset/*"` 行后追加两行）**

```json
      "@core/*": ["./app/core/*"],
      "@ops/*": ["./app/ops/*"]
```

注意给原有最后一行补逗号。改完后 paths 块共 9 个别名。

- [ ] **Step 2: vitest.config.mts alias 块同步追加**

```ts
      '@core': path.resolve(__dirname, 'app/core'),
      '@ops': path.resolve(__dirname, 'app/ops'),
```

- [ ] **Step 3: 目录迁移（git mv，目录需先建父级）**

```bash
mkdir -p app/core app/ops/assets
git mv app/config app/core/config
git mv app/config.ts app/core/config/index.ts
git mv app/db app/core/db
git mv app/logs app/core/logs
git mv app/utils app/core/utils
git mv app/auth app/core/auth
git mv app/admin app/ops/admin
git mv app/capture app/ops/capture
git mv app/proxy app/ops/proxy
git mv app/updater app/ops/updater
git mv app/plugin app/ops/plugin
git mv app/asset-registry app/ops/assets/asset-registry
git mv app/asset.ts app/ops/assets/asset.ts
git mv app/asset-backfill.ts app/ops/assets/asset-backfill.ts
```

Expected: 全部成功无报错。`app/config.ts`（模块入口，含 `detectLocalIp`）并入目录成为 `index.ts`。

- [ ] **Step 4: 修正 __dirname 相对深度（asset 系文件从 app/ 移到 app/ops/assets/，深了一层）**

```bash
grep -c 'join(__dirname, "\.\."' app/ops/assets/asset.ts app/ops/assets/asset-backfill.ts
sed -i 's/join(__dirname, "\.\."/join(__dirname, "..", ".."/g' app/ops/assets/asset.ts app/ops/assets/asset-backfill.ts
grep -c 'join(__dirname, "\.\.", "\.\."' app/ops/assets/asset.ts app/ops/assets/asset-backfill.ts
```

Expected: 第一次 grep 输出 `app/ops/assets/asset.ts:8` 与 `app/ops/assets/asset-backfill.ts:1`；第二次 grep 输出相同计数（8 与 1），说明全部替换到位。原理：原来 `join(__dirname, "..", "assets")` 从 `app/` 上跳到仓库根；现在文件在 `app/ops/assets/`，需上跳两层。

- [ ] **Step 5: 写入迁移映射文件 `tmp/restructure/moves-1.json`**

```json
{
  "moves": [
    { "from": "app/config", "to": "app/core/config" },
    { "from": "app/config.ts", "to": "app/core/config/index.ts" },
    { "from": "app/db", "to": "app/core/db" },
    { "from": "app/logs", "to": "app/core/logs" },
    { "from": "app/utils", "to": "app/core/utils" },
    { "from": "app/auth", "to": "app/core/auth" },
    { "from": "app/admin", "to": "app/ops/admin" },
    { "from": "app/capture", "to": "app/ops/capture" },
    { "from": "app/proxy", "to": "app/ops/proxy" },
    { "from": "app/updater", "to": "app/ops/updater" },
    { "from": "app/plugin", "to": "app/ops/plugin" },
    { "from": "app/asset-registry", "to": "app/ops/assets/asset-registry" },
    { "from": "app/asset.ts", "to": "app/ops/assets/asset.ts" },
    { "from": "app/asset-backfill.ts", "to": "app/ops/assets/asset-backfill.ts" }
  ],
  "aliases": {
    "@game": "app/game",
    "@excel": "app/game/service/excel",
    "@utils": "app/core/utils",
    "@capture": "app/ops/capture",
    "@logs": "app/core/logs",
    "@plugin": "app/ops/plugin",
    "@asset": "app/ops/assets/asset-registry",
    "@core": "app/core",
    "@ops": "app/ops"
  },
  "movedRoots": ["app/config", "app/config.ts", "app/db", "app/logs", "app/utils", "app/auth", "app/admin", "app/capture", "app/proxy", "app/updater", "app/plugin", "app/asset-registry", "app/asset.ts", "app/asset-backfill.ts"]
}
```

`aliases` 是**迁移后**的目标态（脚本自查，不依赖 tsconfig 当前值）。

- [ ] **Step 6: 写入 import 重写工具 `tmp/restructure/rewrite.mjs`（commit 2 复用同一脚本）**

```js
// 用法: node tmp/restructure/rewrite.mjs <moves.json> [更多moves.json...]
// 读取映射表，重写 app/**、tests/**、index.ts 中所有 import/export/动态 import 的路径说明符。
// 无法解析且指向已迁移子树的说明符 → 列出并 exit 1（禁止盲改）。
import fs from "node:fs";
import path from "node:path";

const repo = process.cwd();
const files = [];
const walk = (dir) => {
  if (!fs.existsSync(dir)) return;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else if (p.endsWith(".ts") || p.endsWith(".mts")) files.push(p);
  }
};
walk(path.join(repo, "app"));
walk(path.join(repo, "tests"));
if (fs.existsSync(path.join(repo, "index.ts"))) files.push(path.join(repo, "index.ts"));

// 载入全部映射
const fileMap = new Map();  // 旧文件仓库相对路径(无扩展名) -> 新仓库相对路径(无扩展名)
const dirMoves = [];        // [{from, to}] 目录级，长前缀优先
const movedRoots = [];
const aliases = {};
for (const arg of process.argv.slice(2)) {
  const cfg = JSON.parse(fs.readFileSync(arg, "utf-8"));
  Object.assign(aliases, cfg.aliases);
  movedRoots.push(...cfg.movedRoots);
  for (const m of cfg.moves) {
    if (m.from.endsWith(".ts")) {
      fileMap.set(m.from.slice(0, -3), m.to.slice(0, -3));
    } else {
      dirMoves.push({ from: m.from.replace(/\/$/, ""), to: m.to.replace(/\/$/, "") });
    }
  }
}
dirMoves.sort((a, b) => b.from.length - a.from.length);
const movedRootSet = new Set(movedRoots.map((r) => r.replace(/\.ts$/, "").replace(/\/$/, "")));

function stripExt(p) {
  return p.endsWith(".ts") ? p.slice(0, -3) : p;
}
// 说明符 → 仓库相对路径候选
function resolveSpec(spec, fileAbs) {
  let abs;
  for (const [alias, target] of Object.entries(aliases)) {
    if (spec === alias) return path.join(repo, target);
    if (spec.startsWith(alias + "/")) return path.join(repo, target, spec.slice(alias.length + 1));
  }
  abs = path.resolve(path.dirname(fileAbs), spec);
  return abs;
}
function lookup(abs) {
  const rel = stripExt(path.relative(repo, abs)).replace(/\\/g, "/");
  if (fileMap.has(rel)) return fileMap.get(rel);
  for (const d of dirMoves) {
    if (rel === d.from) return d.to;
    if (rel.startsWith(d.from + "/")) return d.to + rel.slice(d.from.length);
  }
  return null;
}
// 新说明符：优先别名（导入方不在别名目标子树内时），否则相对路径
function makeSpec(newRelNoExt, fileAbs) {
  for (const [alias, target] of Object.entries(aliases)) {
    const norm = newRelNoExt.replace(/\\/g, "/");
    if (norm === target || norm.startsWith(target + "/")) {
      const fileInSubtree = path.resolve(path.dirname(fileAbs)).replace(/\\/g, "/").startsWith(path.join(repo, target).replace(/\\/g, "/"));
      if (!fileInSubtree) {
        const rest = norm === target ? "" : norm.slice(target.length + 1);
        return rest ? `${alias}/${rest}` : alias;
      }
    }
  }
  let rel = path.relative(path.dirname(fileAbs), path.join(repo, newRelNoExt)).replace(/\\/g, "/");
  if (!rel.startsWith(".")) rel = "./" + rel;
  return rel;
}

const RE_FROM = /from\s*['"]([^'"]+)['"]/g;
const RE_DYN = /import\(\s*['"]([^'"]+)['"]\s*\)/g;
const RE_SIDE = /(?<=\bimport\s*)['"](\.[^'"]*|@[^'"]+)['"]/g;

let totalRewritten = 0;
const unresolved = [];
for (const file of files) {
  const src = fs.readFileSync(file, "utf-8");
  let changed = false;
  const rewrite = (match, spec, whole) => {
    if (!spec.startsWith(".") && !spec.startsWith("@")) return whole;
    const abs = resolveSpec(spec, file);
    const mapped = lookup(abs);
    if (!mapped) {
      const rel = stripExt(path.relative(repo, abs)).replace(/\\/g, "/");
      for (const root of movedRootSet) {
        if (rel === root || rel.startsWith(root + "/")) {
          unresolved.push(`${path.relative(repo, file)}: '${spec}'`);
          return whole;
        }
      }
      return whole; // 不指向迁移区域，放行
    }
    totalRewritten++;
    changed = true;
    return makeSpec(mapped, file) !== spec ? whole.split(spec).join(makeSpec(mapped, file)) : whole;
  };
  let out = src.replace(RE_FROM, (m, s) => rewrite(m, s, m));
  out = out.replace(RE_DYN, (m, s) => rewrite(m, s, m));
  out = out.replace(RE_SIDE, (m, s) => rewrite(m, s, m));
  if (changed) fs.writeFileSync(file, out);
}
console.log(`rewritten specifiers: ${totalRewritten}`);
if (unresolved.length) {
  console.error(`UNRESOLVED (${unresolved.length}) — 指向已迁移区域但映射表未覆盖:`);
  for (const u of unresolved) console.error("  " + u);
  process.exit(1);
}
```

- [ ] **Step 7: 运行重写脚本**

Run: `node tmp/restructure/rewrite.mjs tmp/restructure/moves-1.json`
Expected: 输出 `rewritten specifiers: N`（N > 0）且退出码 0。若 exit 1 列出 UNRESOLVED，逐条检查：属于映射遗漏则补入 moves-1.json 重跑；属于拼写/动态拼接路径则手改。

- [ ] **Step 8: 别名 retarget（tsconfig.json + vitest.config.mts 五处旧别名指向新路径）**

tsconfig.json paths 改为：

```json
      "@excel/*": ["./app/game/service/excel/*"],
      "@utils/*": ["./app/core/utils/*"],
      "@game/*": ["./app/game/*"],
      "@capture/*": ["./app/ops/capture/*"],
      "@logs/*": ["./app/core/logs/*"],
      "@plugin/*": ["./app/ops/plugin/*"],
      "@asset/*": ["./app/ops/assets/asset-registry/*"],
      "@core/*": ["./app/core/*"],
      "@ops/*": ["./app/ops/*"]
```

vitest.config.mts alias 对应改为：

```ts
      '@game': path.resolve(__dirname, 'app/game'),
      '@excel': path.resolve(__dirname, 'app/game/service/excel'),
      '@utils': path.resolve(__dirname, 'app/core/utils'),
      '@capture': path.resolve(__dirname, 'app/ops/capture'),
      '@logs': path.resolve(__dirname, 'app/core/logs'),
      '@plugin': path.resolve(__dirname, 'app/ops/plugin'),
      '@asset': path.resolve(__dirname, 'app/ops/assets/asset-registry'),
      '@core': path.resolve(__dirname, 'app/core'),
      '@ops': path.resolve(__dirname, 'app/ops'),
```

（`@excel` 本 commit 不动，commit 2 再 retarget。）

- [ ] **Step 9: 更新 vitest coverage.exclude 中的失效路径（`vitest.config.mts:20`）**

```ts
      exclude: ['app/game/service/excel/**', 'app/core/config/**', 'app/ops/assets/**'],
```

（原 `'app/assets.ts'` 是已失效路径，借机修正为 `app/ops/assets/**`；excel 行 commit 2 再改。）

- [ ] **Step 10: 残留扫描**

Run: `grep -rn "from ['\"]\./app/\(config\|db\|logs\|utils\|auth\|admin\|capture\|proxy\|updater\|plugin\|asset\)" app index.ts --include='*.ts' | grep -v "app/core\|app/ops\|app/game" | head`
Expected: 空输出（root index.ts 的 `./app/config` 等已被脚本改写为 `./app/core/config` 等，会被 grep -v 放行；若出现其他命中则手工修正）。

- [ ] **Step 11: 验证**

Run: `pnpm exec tsc --noEmit`
Expected: 退出码 0。
Run: `pnpm exec vitest run 2>&1 | tail -8`
Expected: 与 Task 1 基线相同的通过数，0 failed。

- [ ] **Step 12: Commit**

```bash
git add -A
git status --short | head -20
git commit -m "refactor(core-ops): app 顶层重组为 core/ops（config/assets 三合一 + __dirname 深度修正 + 别名 retarget）"
```

提交前 `git status --short` 抽查：应全部为 R（rename）或 M，不得出现 D+?? 成对（那是复制丢失元数据的征兆）。

---

## Task 3: commit 2 —— game 侧特性切片迁移

**Files:**
- Create: `tmp/restructure/moves-2.json`（由 `map-game.mjs` 生成）
- Create: `tmp/restructure/map-game.mjs`
- Modify: `app/game/kernel/events/index.ts`（+1 行 runtime 导出）
- Modify: `scripts/generate-types.ts:41-42`（输出常量）
- Modify: `tests/unit/model/battle.test.ts:3-8`（stale import 重定向）
- Modify: `tests/unit/architecture/file-size-guard.test.ts:28,49-50`、`tests/unit/architecture/schema-first-guard.test.ts:29-30`、`tests/unit/architecture/decoupling.test.ts`（扫描根 retarget）
- Create: `app/server.ts`；Modify: `index.ts`（拆分）

- [ ] **Step 1: 写入映射生成器 `tmp/restructure/map-game.mjs`（内嵌完整映射数据，生成 moves-2.json 并执行 git mv）**

```js
// 生成 tmp/restructure/moves-2.json 并逐条执行 git mv（先目录后散件，kernel/http/events 目标目录自动创建）
import fs from "node:fs";
import { execSync } from "node:child_process";
import path from "node:path";

const G = "app/game";
const K = `${G}/kernel`, M = `${G}/modules`, A = `${M}/activities`;
const moves = [];
const mv = (from, to) => moves.push({ from: `${G}/${from}`, to: to.startsWith("app/") ? to : `${G}/${to}` });

// --- kernel（组合根 + 横切） ---
mv("service/PlayerDataManager.ts", `${K}/PlayerDataManager.ts`);
mv("service/PlayerStatus.ts", `${K}/PlayerStatus.ts`);
mv("service/player-composition.ts", `${K}/player-composition.ts`);
mv("service/events.ts", `${K}/events/runtime.ts`);
mv("domain/events", `${K}/events`);
mv("domain/contracts", `${K}/http`);
mv("resp-schema.ts", `${K}/http/resp-schema.ts`);
mv("request-context.ts", `${K}/http/request-context.ts`);
mv("auth-strategy.ts", `${K}/http/auth-strategy.ts`);
mv("service/player/inventory-pipeline.ts", `${K}/inventory-pipeline.ts`);
mv("service/player/inventory.ts", `${K}/inventory.ts`);
mv("domain/playerdata.ts", `${K}/playerdata.ts`);
mv("domain/shared/model.ts", `${K}/model.ts`);
mv("service/util/save-health.ts", `${K}/save-health.ts`);
for (const f of ["random", "multipart", "stage-unlock", "maxout"]) mv(`domain/util/${f}.ts`, `${K}/util/${f}.ts`);

// --- excel 上移 ---
mv("service/excel", `${G}/excel`);

// --- 业务模块（domain 目录 1:1，rlv2→roguelike）---
const domainDirs = {
  account: "account", aprilFool: "aprilFool", arkodc: "arkodc", autochess: "autochess",
  building: "building", businessCard: "businessCard", campaignV2: "campaignV2",
  character: "character", charm: "charm", crisis: "crisis", deepsea: "deepsea",
  depot: "depot", explore: "explore", gacha: "gacha", home: "home", interlock: "interlock",
  mail: "mail", "misc-alignment": "misc-alignment", mission: "mission", multiplayer: "multiplayer",
  pay: "pay", quest: "quest", retro: "retro", rune: "rune", sandbox: "sandbox", shop: "shop",
  siracusaMap: "siracusaMap", social: "social", storyreview: "storyreview",
  templateShop: "templateShop", tower: "tower", vecbreak: "vecbreak", rlv2: "roguelike",
};
for (const [d, mod] of Object.entries(domainDirs)) mv(`domain/${d}`, `${M}/${mod}`);

// --- 集中路由 → 模块 routes.ts ---
const routerToMod = {
  account: "account", aprilFool: "aprilFool", arkodc: "arkodc", audit: "system",
  autochess: "autochess", businessCard: "businessCard", campaignV2: "campaignV2",
  charBuild: "character", charRotation: "character", charm: "charm", crisis: "crisis",
  deepsea: "deepsea", depot: "depot", explore: "explore", home: "home", interlock: "interlock",
  mail: "mail", mailCollection: "mail", "misc-alignment": "misc-alignment",
  multiplayer: "multiplayer", pay: "pay", "plugin-heartbeat": "system", quest: "quest",
  retro: "retro", roguelike: "roguelike", rune: "rune", sandbox: "sandbox",
  siracusaMap: "siracusaMap", social: "social", storyreview: "storyreview",
  templateShop: "templateShop", tower: "tower", user: "user", vecbreak: "vecbreak",
};
for (const [r, mod] of Object.entries(routerToMod)) mv(`domain/router/${r}.ts`, `${M}/${mod}/routes.ts`);

// --- service/player managers → 模块 ---
const sp = {
  AccountManager: "account", BattleInfoStore: "battle", BattleStore: "battle",
  SocialService: "social", aprilFool: "aprilFool", battle: "battle", char: "character",
  charRotation: "character", checkin: "checkin", dexnav: "dexnav", dungeon: "dungeon",
  equipmentMission: "equipmentMission", freshPlayer: "user", home: "home", mail: "mail",
  medal: "medal", recruit: "gacha", retro: "retro", social: "social", status: "user",
  storyreview: "storyreview", troop: "character",
};
for (const [f, mod] of Object.entries(sp)) mv(`service/player/${f}.ts`, `${M}/${mod}/${f}.ts`);

// --- domain/shared 与 domain/util 散件 ---
mv("domain/shared/battle-model.ts", `${M}/battle/battle-model.ts`);
mv("domain/shared/rlv2-model.ts", `${M}/roguelike/rlv2-model.ts`);
mv("domain/shared/social-model.ts", `${M}/social/social-model.ts`);
mv("domain/util/char-skills.ts", `${M}/character/char-skills.ts`);
mv("domain/util/gacha-up-list.ts", `${M}/gacha/gacha-up-list.ts`);
mv("domain/util/purchase-record.ts", `${M}/pay/purchase-record.ts`);

// --- activities（24 族 + 共享层）---
const families = fs.readdirSync(path.join(G, "domain/activity"), { withFileTypes: true })
  .filter((e) => e.isDirectory()).map((e) => e.name);
if (families.length !== 24) throw new Error(`活动族数量异常: ${families.length}（预期 24）`);
for (const f of families) mv(`domain/activity/${f}`, `${A}/${f}`);
mv("domain/activity/activity.ts", `${A}/shared/activity.ts`);
mv("service/player/unlockActivity.ts", `${A}/shared/unlockActivity.ts`);
mv("domain/data/vhalfidle.ts", `${A}/act1vhalfidle/vhalfidle.ts`);

// --- 执行 git mv（目录级先建父目录）---
const repo = process.cwd();
const uniq = [...new Set(moves.map((m) => `${m.from}\t${m.to}`))].map((s) => { const [from, to] = s.split("\t"); return { from, to }; });
for (const m of uniq) {
  const targetDir = path.dirname(path.join(repo, m.to));
  fs.mkdirSync(targetDir, { recursive: true });
  execSync(`git mv "${m.from}" "${m.to}"`, { cwd: repo, stdio: "inherit" });
}
// 残留检查：domain/service 下除 excel 外应为空
const leftovers = [];
for (const dir of [`${G}/domain`, `${G}/service`]) {
  for (const e of fs.readdirSync(path.join(repo, dir), { withFileTypes: true })) {
    if (e.name !== "excel") leftovers.push(`${dir}/${e.name}`);
  }
}
if (leftovers.length) {
  console.error("domain/service 下存在未映射残留（须人工裁决后重跑）:\n" + leftovers.join("\n"));
  process.exit(1);
}
// 落盘映射（供 rewrite.mjs 使用；aliases 为 commit 2 后目标态）
fs.writeFileSync(path.join(repo, "tmp/restructure/moves-2.json"), JSON.stringify({
  moves: uniq,
  aliases: {
    "@game": "app/game", "@excel": "app/game/excel", "@utils": "app/core/utils",
    "@capture": "app/ops/capture", "@logs": "app/core/logs", "@plugin": "app/ops/plugin",
    "@asset": "app/ops/assets/asset-registry", "@core": "app/core", "@ops": "app/ops",
  },
  movedRoots: ["app/game/domain", "app/game/service"],
}, null, 2));
console.log(`OK: ${uniq.length} moves executed`);
```

- [ ] **Step 2: 运行映射生成器**

Run: `node tmp/restructure/map-game.mjs`
Expected: 输出 `OK: N moves executed`（N≈130）。若报 `活动族数量异常` 或 `未映射残留`，停止并人工裁决——不得跳过残留检查继续。

- [ ] **Step 3: 事件契约与总线合一（`app/game/kernel/events/index.ts` 末尾追加一行）**

```ts
export * from "./runtime";
```

若 tsc 报 `Priority` 重复导出冲突（runtime.ts 可能已 re-export Priority）：删除 index.ts 中原有的 `export { Priority } from "./priority";` 行（契约侧让位），保 `export * from "./runtime"`。

- [ ] **Step 4: 更新类型生成器输出常量（`scripts/generate-types.ts:41-42`）**

```ts
const PLAYERDATA_OUT = path.join(__dirname, "../app/game/excel/types-playerdata.ts");
const EXCEL_OUT = path.join(__dirname, "../app/game/excel/types_excel_gen.ts");
```

- [ ] **Step 5: 修正 stale 测试导入（`tests/unit/model/battle.test.ts:3-8`）**

```ts
import type {
  BattleData,
  BattleLogger,
  BattleStats,
  CommonStartBattleRequest,
} from '@game/modules/battle/battle-model';
```

（四个类型实测定义于原 `domain/shared/battle-model.ts`，已迁至 `modules/battle/battle-model.ts`。）

- [ ] **Step 6: 运行 import 重写**

Run: `node tmp/restructure/rewrite.mjs tmp/restructure/moves-1.json tmp/restructure/moves-2.json`
Expected: `rewritten specifiers: N`（N 数百），退出码 0。UNRESOLVED 时逐条人工裁决（预期来源：动态拼路径、index 省略导入）。

- [ ] **Step 7: 架构守卫扫描根 retarget**

`tests/unit/architecture/file-size-guard.test.ts:28`：
```ts
    for (const file of collectFiles(path.join(APP_ROOT, "game/modules"), ".ts")) {
```
`tests/unit/architecture/file-size-guard.test.ts:49-50`：
```ts
    scan(path.join(APP_ROOT, "game/modules"));
    scan(path.join(APP_ROOT, "game/modules/activities"));
```
`tests/unit/architecture/schema-first-guard.test.ts:29-30`（在 `...collectFiles(...)` 数组内）：
```ts
      ...collectFiles(path.join(APP_ROOT, "game/modules")),
      ...collectFiles(path.join(APP_ROOT, "game/modules/activities")),
```
`tests/unit/architecture/decoupling.test.ts`：先 `grep -n "game/service\|game/domain" tests/unit/architecture/decoupling.test.ts` 定位 excel 扫描根，将 `app/game/service/excel`（或等价写法）改为 `app/game/excel`；其余规则若按 import 模式扫描则无需改。

- [ ] **Step 8: excel 别名 retarget（tsconfig.json + vitest.config.mts）**

tsconfig: `"@excel/*": ["./app/game/excel/*"]`；vitest: `'@excel': path.resolve(__dirname, 'app/game/excel')`。同时 vitest coverage.exclude 的 `'app/game/service/excel/**'` 改为 `'app/game/excel/**'`。

- [ ] **Step 9: index.ts 拆分 → app/server.ts**

将 `index.ts` 全文移入新文件 `app/server.ts`，做以下机械调整（其余逐字保留）：

1. 删除文件头注释中的"应用入口文件"表述，改为 `DoctorateTs 服务器启动编排（由根 index.ts 调用）`。
2. 原 `(async () => { ... })();` IIFE（约 108-661 行）改为：
   ```ts
   export async function main(): Promise<void> {
     // …IIFE 原函数体逐字保留…
   }
   ```
3. 保留在 **index.ts**（不迁入 server.ts）的内容：`process.on("unhandledRejection"/"uncaughtException"/信号/exit)` 四段进程级兜底、`process.report.*` 三行、`const now`/`const pad` 两行（仅被 report 文件名使用）。
4. server.ts 内的动态导入路径修正：
   - `await import("./scripts/update-data")` → `await import("../scripts/update-data")`（3 处）
   - `await import("./scripts/generate-max-account")` → `await import("../scripts/generate-max-account")`
   - `await import("./app/admin/admin-router")` → `await import("./ops/admin/admin-router")`
   - `import("./app/admin/server-repl")` → `import("./ops/admin/server-repl")`
   - `import("./app/updater/auto-update-watch")` → `import("./ops/updater/auto-update-watch")`
5. server.ts 静态导入修正：`"./app/config"` → `"./core/config"`、`"./app/utils/logger"` → `"./core/utils/logger"`、`"./app/utils/traffic-recorder"` → `"./core/utils/traffic-recorder"`、`"./app/capture/capture-manager"` → `"./ops/capture/capture-manager"`、`"./app/config/prod"` → `"./core/config/prod"`、`"./app/config/remote-config"` → `"./core/config/remote-config"`、`"./app/config/host-router"` → `"./core/config/host-router"`、`"./app/auth/auth"` → `"./core/auth/auth"`、`"./app/asset"` → `"./ops/assets/asset"`、`"./app/game/app"` → `"./game/app"`、`"./app/game/service/player/AccountManager"` → `"./game/modules/account/AccountManager"`、`"./app/game/domain/activity/arkhub/*"` → `"./game/modules/activities/arkhub/*"`（2 个 import 块）。（若 Task 3 Step 6 的重写脚本已覆盖 index.ts 这些行，此处仅需核对。）

新 `index.ts` 全文：

```ts
/**
 * DoctorateTs 应用入口
 *
 * 仅保留进程级兜底与 CLI 调用；服务器启动编排在 app/server.ts。
 */
import * as path from "path";
import { logger, flush as flushLogs } from "./app/core/utils/logger";
import { main } from "./app/server";

// 全局错误兜底（修复：未处理 Promise 拒绝/异常会导致 Node 24 进程直接终止——
// 记录错误栈便于定位，并保持服务器存活）
process.on("unhandledRejection", (reason) => {
  logger.error(
    "process",
    `unhandledRejection: ${
      reason instanceof Error ? reason.stack ?? reason.message : String(reason)
    }`,
  );
});
process.on("uncaughtException", (err) => {
  logger.error("process", `uncaughtException: ${err.stack ?? err.message}`);
});

// 进程级诊断（防"静默退出无提示"）：
// 1) V8 致命错误（OOM/原生崩溃）落盘 report 文件——stderr 可能随终端/重定向丢失。
//    文件名启动时计算（<date>/<pid> 占位符在当前 Node 构建不可用，errno 22）
const now = new Date();
const pad = (n: number) => String(n).padStart(2, "0");
process.report.reportOnFatalError = true;
process.report.directory = path.resolve(__dirname, "logs");
process.report.filename = `report-${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}.json`;

// 2) 信号退出留痕（Ctrl+C 行为不变，仅先记录再按约定码退出）
// SIGHUP = 终端关闭（POSIX）；Windows 控制台关闭由看门狗显式终止子进程兜底
for (const sig of ["SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP"] as const) {
  process.on(sig, () => {
    logger.warn("process", `收到 ${sig}，进程退出`);
    process.exit(sig === "SIGTERM" ? 143 : 130);
  });
}

// 3) 任何退出都记录退出码（看门狗依据 code≠0/130 判断是否自动重启）
process.on("exit", (code) => {
  // 退出日志入缓冲后显式 flush（logger 批量落盘——确保退出码与最后日志都写入文件）
  logger.info("process", `进程退出: code=${code}`);
  flushLogs();
});

void main();
```

- [ ] **Step 10: 根目录 player_data.json 归档（未跟踪文件，本地移动）**

Run: `mv player_data.json data/player_data.json.root-backup && git status --short | head -3`
Expected: git status 不受影响（该文件从未被跟踪）。

- [ ] **Step 11: 验证**

Run: `pnpm exec tsc --noEmit`
Expected: 退出码 0。常见残余错误类型：遗漏的动态路径、`@game/model/events` 类历史别名（grep 修正）。
Run: `pnpm exec vitest run 2>&1 | tail -8`
Expected: 通过数不低于基线，0 failed。
Run: `grep -n "app/game/excel" scripts/generate-types.ts`
Expected: 恰好 2 行（Step 4 的常量）。若本机存在反编译参考文件（`reference/com.hypergryph.*.cs`），另跑 `pnpm run generate:excel` 并确认新文件落点 `app/game/excel/types_excel_gen.ts`；参考文件缺失属既有环境限制，跳过并注明。
Run: `grep -rn "game/service\|game/domain" app tests index.ts --include='*.ts' | grep -v "tests/unit/architecture" | head`
Expected: 空输出。

- [ ] **Step 12: Commit**

```bash
git add -A
git status --short | awk '{print $1}' | sort | uniq -c
git commit -m "refactor(game): game 侧特性切片迁移（kernel/modules/activities + excel 上移 + 入口拆分 server.ts）"
```

---

## Task 4: commit 3a —— 模块边界守卫上线

**Files:**
- Create: `tests/unit/architecture/module-boundary.test.ts`
- Delete: `tests/unit/architecture/domain-coupling-guard.test.ts`、`tests/unit/architecture/domain-dag-guard.test.ts`
- Modify: `app/game/modules/**`（守卫暴露的越界 import 修复）

- [ ] **Step 1: 写入守卫测试（完整文件）**

```ts
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
    const conventionRouteFile = /(^|\/)(routes|router)\.ts$/;
    const offenders = allFiles.filter((f) => {
      const rel = path.relative(APP_ROOT, f).replace(/\\/g, "/");
      if (rel === "game/routes.ts" || rel === "game/app.ts") return false;
      if (conventionRouteFile.test(f.replace(/\\/g, "/"))) return false;
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
```

- [ ] **Step 2: 运行守卫（预期先红）**

Run: `pnpm exec vitest run tests/unit/architecture/module-boundary.test.ts`
Expected: `R1-R3 全量扫描` **FAIL** 并列出违规清单（迁移自三种旧模式，预期存在少量跨模块深引用）。负样本用例必须 PASS（证明检查器本身有效）。

- [ ] **Step 3: 修复违规**

对清单逐条处理，按优先级：(a) 改为 import 对方 `public.ts` 并在对方模块创建 `public.ts` 导出所需符号（re-export 原文件符号，不改实现）；(b) 属事件通知语义的改走 `globalEventBus`（须在 `kernel/events` 契约中已有对应事件，禁止新增事件类型）；(c) 确属暂时无法解耦的，加入测试内 `EXEMPTIONS: { file, spec, reason }[]` 数组并在检查器开头跳过——每条必须带 reason。
禁止：为过测试而复制代码、删除功能调用。

- [ ] **Step 4: 退役 domain 层内守卫**

```bash
git rm tests/unit/architecture/domain-coupling-guard.test.ts tests/unit/architecture/domain-dag-guard.test.ts
```

理由：二者守护的是 `domain/` 层内部 DAG 不变量；该层在本重组中按设计废除，其职责由 module-boundary R1-R3 接管。decoupling.test.ts（excel 反向依赖/请求上下文/抓包端口三条规则）与 file-size-guard、schema-first-guard、composition-order、errors-guard 保留。

- [ ] **Step 5: 全量验证**

Run: `pnpm exec tsc --noEmit && pnpm exec vitest run 2>&1 | tail -8`
Expected: tsc 0 错误；vitest 全绿（用例数 ≥ 基线 − 退役守卫的用例数，且 module-boundary 4 条全过）。

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "test(architecture): module-boundary 边界守卫上线，退役 domain 层内守卫"
```

---

## Task 5: commit 3b —— 文档收口

**Files:**
- Modify: `AGENTS.md`（Architecture 与 Conventions 节）
- Modify: `design-spec.md`（目录结构相关章节）

- [ ] **Step 1: 重写 AGENTS.md Architecture 节（整体替换为下文）**

```markdown
## Architecture

- **目录三层**：`app/core/`（基础设施内核：config/db/logs/utils/auth，被依赖方，禁止 import game/ops）、`app/game/`（业务）、`app/ops/`（运营设施：admin/capture/proxy/updater/plugin/assets，可依赖 core 与 game 模块的 public.ts）。
- **game 侧特性切片**：`game/kernel/`（PlayerDataManager 组合根、PlayerStatus、player-composition、events 事件契约+总线、http 路由契约基建、inventory-pipeline、共享 util）、`game/excel/`（游戏数据 + 生成类型）、`game/modules/<mod>/`（一业务模块一目录，自含 routes.ts 薄路由 + manager/业务 + rules/types + public.ts 对外出口）、`game/modules/activities/<family>/`（活动族自含 router.ts+logic.ts，共享逻辑在 `activities/shared/`）。
- **落位规则（唯一）**：新功能 = 找到业务模块包，没有就在 `modules/` 建包。不设 domain/service/manager 目录。模块间只允许 import 对方 `public.ts` 或走事件总线；守卫见 `tests/unit/architecture/module-boundary.test.ts`。
- **Flow**: `game/routes.ts` 聚合注册（懒加载）→ `modules/<mod>/routes.ts`（薄壳 + validateBody）→ 模块内 manager（经 `kernel/PlayerDataManager` 组合，`httpContext` key `playerData`）。事件驱动：managers 在构造器 `this._trigger.on(...)` 订阅，事件契约在 `game/kernel/events/`。
- **State changes**: all through `player.update(recipe)` (mutative two-phase in `kernel/PlayerStatus`) which records patches. mutative `enableAutoFreeze` is off — managers mutate arrays directly; do not re-enable freezing.
- **Response contract**: `res.send(player.delta)`. The `delta` getter returns `{ playerDataDelta }`, **clears `_changes` and triggers `save`** (persists to `data/user/databases/{uid}.json`). Never read `player.delta` twice in one request.
- **Single-account private server**: `game/app.ts` middleware forces any `secret` header to `"1"` → every request is uid=1.
- **统一抓包存储** (`app/ops/capture/capture-manager.ts` 单例 `captureManager` + `capture-db.ts`)、**统一日志服务** (`app/core/logs/log-service.ts` 单例 `logService` + `app/utils/sse.ts`)：职责不变，路径更新如上。
- **入口**：根 `index.ts` 仅含进程级兜底与 CLI 解析，服务器编排在 `app/server.ts` 的 `main()`。
```

（其余小节——Event-driven/State changes 等若原文有独立段落，按上述要点合并去重；`2221.js`、generated files 等条目中 `service/excel` 路径字样全部替换为 `game/excel`。）

- [ ] **Step 2: 同步 AGENTS.md 其余路径字样**

Run: `grep -n "service/player\|domain/\|app/config\|app/admin\|app/capture\|app/asset\|app/utils\|app/logs\|app/auth\|app/plugin\|app/proxy\|app/updater" AGENTS.md`
对每处命中按映射表更新（例：`app/game/service/excel/types_excel_gen.ts` → `app/game/excel/types_excel_gen.ts`；`service/activity/<family>` 表述删除——现实与文档首次一致）。aliases 说明段落更新为 9 个别名。

- [ ] **Step 3: design-spec.md 同步**

Run: `grep -n "app/game/domain\|app/game/service\|domain/router\|service/player" design-spec.md | head -40`
按映射表逐处更新路径引用；目录结构总览章节（若有）替换为 Task 5 Step 1 的三层结构描述。§17.7/§35 等行为性章节不改（仅路径字样变化）。逐处修改量大时以映射表为准机械替换，禁止改动行为描述文字。

- [ ] **Step 4: 验证文档一致性**

Run: `grep -c "game/service/\|game/domain/" AGENTS.md`
Expected: 0。

- [ ] **Step 5: Commit**

```bash
git add AGENTS.md design-spec.md
git commit -m "docs: AGENTS.md/design-spec 对齐特性切片目录结构"
```

---

## Task 6: 端到端冒烟验证

**Files:** 无修改

- [ ] **Step 1: 起服冒烟**

Run: `pnpm run start:quick`（后台或另开终端）
Expected 日志依次出现：`本地数据校验通过`（或 `跳过游戏数据更新`）、`--------------DoctorateTs--------------`、`running at http://localhost:8443`、`懒加载大表后台预热完成`、`命令行已就绪`。

- [ ] **Step 2: admin dashboard 与 CLI**

Run: `curl -s -o /dev/null -w "%{http_code}" http://localhost:8443/admin`
Expected: `200`。
Run: `pnpm run admin -- users list`
Expected: 退出码 0，列出 uid=1 账号。
Run: `pnpm run admin -- logs server --last 20 --json`
Expected: 退出码 0，输出 JSON 行。
Run: `pnpm run admin -- capture stats --json`
Expected: 退出码 0（统一抓包存储索引可读，验证 capture 路径未受迁移影响）。

- [ ] **Step 3: 资源/mod 路径冒烟（__dirname 修正专项）**

Run: `curl -s -o /dev/null -w "%{http_code}" "http://localhost:8443/assets/热更清单路径"` 不可行时改为：起服日志中确认无 `ENOENT`/`assets` 目录相关 error；并检查 `logs/` 下当次日志无 `asset` 标签错误。
Expected: 无路径类报错。

- [ ] **Step 4: capture 模式起服**

Run: `pnpm run start:quick -- --capture`（先停掉上一实例）
Expected: 日志出现 capture 模式禁用 mod 提示与正常 `running at` 行，无异常栈。

- [ ] **Step 5: 收尾清理**

```bash
rm -rf tmp/restructure
pnpm exec tsc --noEmit && pnpm exec vitest run 2>&1 | tail -5
```

Expected: 全绿。对照 spec §10 成功标准逐条勾验（5 条全部满足后任务完成）。

---

## 自审记录（写计划时已核）

1. **Spec 覆盖**：spec §5.4→Task 2；§5.1-5.3→Task 3；§7→Task 4；§8 步骤 1-3→Task 2/3，4→Task 4，5→Task 5，6→Task 6；§9 各风险的缓解动作分别落在 Task 2 Step 4/10、Task 3 Step 4/5/11、Task 4 Step 3；§10→Task 6 Step 5。无缺口。
2. **占位符扫描**：无 TBD/TODO；所有代码步骤含完整代码或精确命令。
3. **类型一致性**：rewrite.mjs 在 Task 2/3 复用同一份（参数化 moves 文件）；moves-2.json 的 aliases 与 Task 3 Step 8 的 tsconfig/vitest retarget 一致；battle-model 路径在 Step 5 与 map-game.mjs 中一致。
