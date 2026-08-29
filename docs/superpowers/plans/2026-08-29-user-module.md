# User 模块完整实现 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** 完整实现并修正 `app/game/modules/user/` 全部端点，对齐官服反编译/抓包/excel 契约（线索奖励、语音档案、长期签到、CG 持久化、特勤板、演出/分享、管道规范化）。

**Architecture:** 全部业务状态走 `player.update(draft)`（mutative）；物品发放经 `player.gainItem` 管道且在 update recipe 之外执行；协议类型集中在 `modules/account/user.ts`，schema 在 `account/user.schema.ts`；CG 收藏持久化新增 `modules/user/cg-store.ts`；`checkIn.showCount` 由 `modules/checkin/checkin.ts` 维护。

**Tech Stack:** Express 5 + TypeScript + mutative（Immer 语义）+ vitest + zod。

**Spec:** `docs/superpowers/specs/2026-08-29-user-module-design.md`

## Global Constraints

- Node 24；别名 `@game/*`/`@excel/*`/`@utils/*`（tsconfig + vitest.config 已配）。
- 物品增减一律 `player.gainItem.setTarget(...).use()/handle()`（AGENTS.md §35.3），禁直发 `items:get/items:use`。
- 新增 POST 路由必须 `validateBody(zodSchema)`（schema-first 守卫）；multipart 豁免。
- 模块间只 import `public.ts`（守卫 `tests/unit/architecture/module-boundary.test.ts`）；本计划不跨模块 import。
- 状态写入在 `player.update` 内；物品发放必须移到 recipe 之外（避免嵌套 update）。
- 响应契约：`res.send(player.delta)` 只能读一次 delta。
- 本仓库按 AGENTS.md 约定**不自动 git commit**（用户未要求）；每任务以「跑通测试」为完成门槛。
- 验证顺序：`pnpm exec tsc --noEmit` → `pnpm exec vitest run`。

---

### Task 1: 协议类型、schema 与测试 helper 基础设施

**Files:**
- Modify: `app/game/modules/account/user.ts`
- Modify: `app/game/modules/account/user.schema.ts`
- Modify: `tests/helpers/mockPlayerData.ts`
- Test: `tests/unit/helpers/mocks.test.ts`（验证 mock 兼容，无需新用例）

**Interfaces:**
- Consumes: 现有 `PlayerDeltaResponse`、`ItemBundle`、`AvatarInfo`、`PlayerMedalCustomLayout`。
- Produces:
  - `ItemGet { type: string; id: string; charGet?: unknown; count: number }`
  - `RewardItemModel { type: string; id: string; charGet?: unknown; count: number }`
  - `RecvLongTermCheckInRewardRequest { groupId: string }` / `RecvLongTermCheckInRewardResponse extends PlayerDeltaResponse { rewards: RewardItemModel[] }`
  - `EnterCharVoiceRecordRequest { topicId: string }` / `EnterCharVoiceRecordResponse extends PlayerDeltaResponse { reward: ItemGet[] }`
  - `ConfirmCharVoiceRecordRewardRequest { topicId: string; nodeId: string }` / `ConfirmCharVoiceRecordRewardResponse extends PlayerDeltaResponse { reward: ItemGet[] }`
  - `GetClueRewardsRequest { ids: string[] }` / `GetClueRewardsResponse extends PlayerDeltaResponse { items: RewardItemModel[] }`
  - `StartStoryRequest { storyId: string }`、`ConfirmShareMissionRequest { shareMissionId: string }`、`SpecialOperatorUnlockNodeRequest { instId: string; nodeId: string }`
  - schemas：`recvLongTermCheckInRewardSchema`（groupId 必填）、`getRewardsSchema`（ids 可选数组 + id 兼容）、`startStorySchema`/`confirmShareMissionSchema`/`specialOperatorUnlockNodeSchema`（字段必填）
  - `mockPlayerData()` 增加 `gainItem` fluent mock（`setTarget`/`add`/`clear` 返回 this，`use`/`handle` resolved）

- [x] **Step 1: 在 `account/user.ts` 追加请求/响应类型**

```ts
/** 道具获得项（CS: ItemGet 结构；charGet 无干员时省略） */
export interface ItemGet {
  type: string;
  id: string;
  charGet?: unknown;
  count: number;
}

/** 奖励物品模型（CS: RewardItemModel struct { type, id, charGet?, count }） */
export interface RewardItemModel {
  type: string;
  id: string;
  charGet?: unknown;
  count: number;
}

/** 领取长期签到奖励请求（CS: UI.LongTermCheckIn.ReceiveLongTermCheckInRewardRequest { groupId }） */
export interface RecvLongTermCheckInRewardRequest {
  groupId: string;
}
/** 领取长期签到奖励响应（CS: ReceiveLongTermCheckInRewardResponse : PlayerDeltaResponse { rewards }） */
export interface RecvLongTermCheckInRewardResponse extends PlayerDeltaResponse {
  rewards: RewardItemModel[];
}

/** 领取主线线索奖励请求（CS: Anniv7thService.Anniv7thGetRewardsRequest { ids }） */
export interface GetClueRewardsRequest {
  ids: string[];
}
/** 领取主线线索奖励响应（CS: Anniv7thGetRewardsResponse { items }） */
export interface GetClueRewardsResponse extends PlayerDeltaResponse {
  items: RewardItemModel[];
}

/** 进入角色语音档案请求（CS: FifthAnnivService.MissionArchiveClaimEntryRewardRequest { topicId }） */
export interface EnterCharVoiceRecordRequest {
  topicId: string;
}
/** 进入角色语音档案响应（CS: MissionArchiveClaimEntryRewardResponse { reward }） */
export interface EnterCharVoiceRecordResponse extends PlayerDeltaResponse {
  reward: ItemGet[];
}

/** 领取语音档案节点奖励请求（CS: MissionArchiveClaimNodeRewardRequest { topicId, nodeId }） */
export interface ConfirmCharVoiceRecordRewardRequest {
  topicId: string;
  nodeId: string;
}
/** 领取语音档案节点奖励响应（CS: MissionArchiveClaimNodeRewardResponse { reward }） */
export interface ConfirmCharVoiceRecordRewardResponse extends PlayerDeltaResponse {
  reward: ItemGet[];
}

/** 演出剧情开始请求（CS: PerformanceStoryRequest { storyId }） */
export interface StartStoryRequest {
  storyId: string;
}

/** 确认分享任务请求（服务端自定义 { shareMissionId }） */
export interface ConfirmShareMissionRequest {
  shareMissionId: string;
}

/** 特勤干员解锁节点请求（服务端自定义 { instId, nodeId }） */
export interface SpecialOperatorUnlockNodeRequest {
  instId: string;
  nodeId: string;
}
```

- [x] **Step 2: 更新 `account/user.schema.ts`**

```ts
/** 领取长期签到奖励请求（CS: ReceiveLongTermCheckInRewardRequest { groupId }） */
export const recvLongTermCheckInRewardSchema = z.object({
  groupId: z.string(),
});

/** 领取线索奖励请求（CS: Anniv7thGetRewardsRequest { ids }；兼容旧单 id 写法） */
export const getRewardsSchema = z.object({
  ids: z.array(z.string()).optional(),
  id: z.string().optional(),
});

/** 演出剧情开始请求（CS: PerformanceStoryRequest { storyId }） */
export const startStorySchema = z.object({
  storyId: z.string(),
});

/** 确认分享任务请求（服务端自定义 { shareMissionId }） */
export const confirmShareMissionSchema = z.object({
  shareMissionId: z.string(),
});

/** 特勤干员解锁节点请求（服务端自定义 { instId, nodeId }） */
export const specialOperatorUnlockNodeSchema = z.object({
  instId: z.string(),
  nodeId: z.string(),
});
```

- [x] **Step 3: `tests/helpers/mockPlayerData.ts` 增加 gainItem mock**

在 `MockPlayerDataManager` 接口与 `mockPlayerData` 返回对象中增加：

```ts
gainItem: {
  setTarget: vi.fn(function () { return this; }),
  add: vi.fn(function () { return this; }),
  use: vi.fn().mockResolvedValue(undefined),
  handle: vi.fn().mockResolvedValue(undefined),
  clear: vi.fn(function () { return this; }),
  get size() { return 0; },
  get targets() { return []; },
} as any,
```

- [x] **Step 4: 跑测试确认无回归**

Run: `pnpm exec vitest run tests/unit/helpers/mocks.test.ts tests/unit/router/user-gallery.test.ts`
Expected: PASS（既有 helper/路由测试不受影响）。

---

### Task 2: 主线线索 getRewards 完整实现（多 id + 条件 + 奖励发放）

**Files:**
- Modify: `app/game/modules/user/routes.ts`（`/mainlineClue/getRewards` 处理器；`unlockClue`/`readClue` 保持）
- Test: `tests/unit/router/user-mainline-clue.test.ts`

**Interfaces:**
- Consumes: `GetClueRewardsRequest/Response`（Task 1）、`getRewardsSchema`、`player.gainItem`、`excel.ActivityTable.anniv7thData`。
- Produces: `mainline.clue.reward[clueRecordId]=1` + 响应 `{ items: RewardItemModel[], ...player.delta }`。

- [x] **Step 1: 写失败测试**

```ts
// tests/unit/router/user-mainline-clue.test.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
vi.mock("@excel/excel", () => ({
  default: {
    ActivityTable: {
      anniv7thData: {
        clueRewardData: [
          { clueRecordId: "clueActivity_1", clueRecord: 1, rewards: [{ id: "31024", count: 1, type: "MATERIAL" }] },
          { clueRecordId: "clueActivity_2", clueRecord: 3, rewards: [{ id: "31054", count: 1, type: "MATERIAL" }] },
        ],
      },
    },
  },
}));
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), type: vi.fn().mockReturnThis(), json: vi.fn() };
}
async function call(player: any, body: any) {
  const res = mockRes();
  (httpContext.get as any).mockReturnValue(player);
  rootRouter({ method: "POST", url: "/mainlineClue/getRewards", body } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("mainlineClue getRewards", () => {
  let player: any;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1" } as any,
      mainline: { clue: { unlock: false, state: { clue_1_1: 2, clue_1_2: 2 }, reward: {} } } as any,
    });
  });

  it("ids 全部达标时发放奖励并标记已领取", async () => {
    const res = await call(player, { ids: ["clueActivity_1"] });
    const response = res.send.mock.calls[0][0];
    expect(response.items).toEqual([{ type: "MATERIAL", id: "31024", count: 1 }]);
    expect(player._playerdata.mainline.clue.reward["clueActivity_1"]).toBe(1);
    expect(player.gainItem.handle).toHaveBeenCalled();
  });

  it("已领取的线索奖励不重复发放", async () => {
    player._playerdata.mainline.clue.reward["clueActivity_1"] = 1;
    const res = await call(player, { ids: ["clueActivity_1"] });
    expect(res.send.mock.calls[0][0].items).toEqual([]);
  });

  it("已解锁线索数不足时（gainedRecord < clueRecord）不发放", async () => {
    const res = await call(player, { ids: ["clueActivity_2"] });
    expect(res.send.mock.calls[0][0].items).toEqual([]);
    expect(player._playerdata.mainline.clue.reward["clueActivity_2"]).toBeUndefined();
  });

  it("兼容旧单 id 请求写法", async () => {
    const res = await call(player, { id: "clueActivity_1" });
    expect(res.send.mock.calls[0][0].items).toEqual([{ type: "MATERIAL", id: "31024", count: 1 }]);
  });

  it("unlockClue 仍写 state[id]=2", async () => {
    const res = mockRes();
    (httpContext.get as any).mockReturnValue(player);
    rootRouter({ method: "POST", url: "/mainlineClue/unlockClue", body: { id: "clue_1_3" } } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
    expect(player._playerdata.mainline.clue.state["clue_1_3"]).toBe(2);
  });
});
```

- [x] **Step 2: 跑测试确认 RED**

Run: `pnpm exec vitest run tests/unit/router/user-mainline-clue.test.ts`
Expected: FAIL —— getRewards 当前忽略奖励、仅写 `reward[id]=1`，`items` 不存在。

- [x] **Step 3: 实现 getRewards**

替换 `routes.ts` 中 `/mainlineClue/getRewards` 处理器为：

```ts
/**
 * 领取线索奖励
 * CS: Anniv7thService.GET_REWARDS "/mainlineClue/getRewards"（请求 { ids: string[] }）
 * 条件：已解锁线索数（state >= 2）达到 clueRewardData[recordId].clueRecord；
 * 发放后写 mainline.clue.reward[recordId]（幂等）。奖励经 gainItem 管道发放（recipe 外）。
 */
rootRouter.post("/mainlineClue/getRewards", validateBody(getRewardsSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as GetClueRewardsRequest & { id?: string };
  const ids = Array.isArray(body?.ids) && body.ids.length > 0 ? body.ids : body?.id ? [body.id] : [];
  if (ids.length === 0) {
    return res.send({ ...player.delta, items: [] } satisfies GetClueRewardsResponse);
  }
  const anniv = excel.ActivityTable?.anniv7thData as
    | { clueRewardData?: Array<{ clueRecordId: string; clueRecord: number; rewards: ItemBundle[] }> }
    | undefined;
  const rewardConfig = anniv?.clueRewardData ?? [];
  const pending: ItemBundle[] = [];
  await player.update(async (draft) => {
    const mainline = draft.mainline as any;
    if (!mainline.clue) mainline.clue = { unlock: false, state: {}, reward: {} };
    const gainedRecord = Object.values(mainline.clue.state ?? {}).filter((v: number) => v >= 2).length;
    for (const recordId of ids) {
      const cfg = rewardConfig.find((c) => c.clueRecordId === recordId);
      if (!cfg || mainline.clue.reward[recordId]) continue;
      if (gainedRecord < cfg.clueRecord) continue;
      mainline.clue.reward[recordId] = 1;
      pending.push(...(cfg.rewards ?? []));
    }
  });
  const items: RewardItemModel[] = [];
  if (pending.length > 0) {
    for (const item of pending) player.gainItem.add(item);
    await player.gainItem.handle();
    for (const item of pending) items.push({ type: item.type, id: item.id, count: item.count });
  }
  res.send({ items, ...player.delta } satisfies GetClueRewardsResponse);
});
```

- [x] **Step 4: 跑测试确认 GREEN**

Run: `pnpm exec vitest run tests/unit/router/user-mainline-clue.test.ts`
Expected: PASS。

---

### Task 3: 语音档案 charVoiceRecord（字段修正 + 入口/节点奖励）

**Files:**
- Modify: `app/game/modules/user/routes.ts`（`/mainline/enterCharVoiceRecord`、`/mainline/confirmCharVoiceRecordReward`）
- Test: `tests/unit/router/user-char-voice-record.test.ts`

**Interfaces:**
- Consumes: `EnterCharVoiceRecordRequest/Response`、`ConfirmCharVoiceRecordRewardRequest/Response`、`excel.ActivityTable.missionArchives`。
- Produces: 写 `mainline.charVoiceRecord[topicId]`（`isOpen`/`confirmEnterReward`/`nodes`），响应 `{ reward, ...delta }`。

- [x] **Step 1: 写失败测试**

```ts
// tests/unit/router/user-char-voice-record.test.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
vi.mock("@excel/excel", () => ({
  default: {
    ActivityTable: {
      missionArchives: {
        mission_archive_main_14: {
          topicId: "mission_archive_main_14",
          nodes: [
            { nodeId: "main_node_1", clips: [{ charId: "char_4134_cetsyr", voiceId: "EX_CN_101", index: 1 }] },
            { nodeId: "main_node_2", clips: [{ charId: "char_4134_cetsyr", voiceId: "EX_CN_201", index: 1 }] },
          ],
          hiddenClips: [{ charId: "char_4134_cetsyr", voiceId: "EX_CN_601", index: 1 }],
        },
      },
    },
  },
}));
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() { return { send: vi.fn(), status: vi.fn().mockReturnThis(), type: vi.fn().mockReturnThis(), json: vi.fn() }; }
async function call(player: any, url: string, body: any) {
  const res = mockRes();
  (httpContext.get as any).mockReturnValue(player);
  rootRouter({ method: "POST", url, body } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("语音档案 charVoiceRecord", () => {
  let player: any;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({ status: { uid: "1" } as any });
  });

  it("enterCharVoiceRecord：写入 charVoiceRecord.isOpen/confirmEnterReward 并发干员本体", async () => {
    const res = await call(player, "/mainline/enterCharVoiceRecord", { topicId: "mission_archive_main_14" });
    const response = res.send.mock.calls[0][0];
    expect(response.reward).toEqual([{ type: "CHAR", id: "char_4134_cetsyr", count: 1 }]);
    const archive = player._playerdata.mainline.charVoiceRecord["mission_archive_main_14"];
    expect(archive.isOpen).toBe(true);
    expect(archive.confirmEnterReward).toBe(true);
    expect(player.gainItem.handle).toHaveBeenCalled();
  });

  it("enterCharVoiceRecord：已领取入口奖励时幂等不发奖励", async () => {
    player._playerdata.mainline = {
      charVoiceRecord: { mission_archive_main_14: { isOpen: true, confirmEnterReward: true, nodes: {} } },
    };
    const res = await call(player, "/mainline/enterCharVoiceRecord", { topicId: "mission_archive_main_14" });
    expect(res.send.mock.calls[0][0].reward).toEqual([]);
  });

  it("confirmCharVoiceRecordReward：写 nodes[nodeId]=2 并发 p_char_{charId} 信物", async () => {
    const res = await call(player, "/mainline/confirmCharVoiceRecordReward", {
      topicId: "mission_archive_main_14",
      nodeId: "main_node_2",
    });
    const response = res.send.mock.calls[0][0];
    expect(response.reward).toEqual([{ type: "MATERIAL", id: "p_char_4134_cetsyr", count: 1 }]);
    expect(player._playerdata.mainline.charVoiceRecord["mission_archive_main_14"].nodes["main_node_2"]).toBe(2);
  });

  it("confirmCharVoiceRecordReward：节点已领取时幂等", async () => {
    player._playerdata.mainline = {
      charVoiceRecord: { mission_archive_main_14: { isOpen: true, confirmEnterReward: true, nodes: { main_node_2: 2 } } },
    };
    const res = await call(player, "/mainline/confirmCharVoiceRecordReward", {
      topicId: "mission_archive_main_14",
      nodeId: "main_node_2",
    });
    expect(res.send.mock.calls[0][0].reward).toEqual([]);
  });
});
```

- [x] **Step 2: 跑测试确认 RED**

Run: `pnpm exec vitest run tests/unit/router/user-char-voice-record.test.ts`
Expected: FAIL —— 现有代码写 `mainline.missionArchive`（字段名错）、不发奖励、响应无 `reward`。

- [x] **Step 3: 实现两个处理器**

替换 `routes.ts` 中对应处理器为：

```ts
/** 取语音档案 topic 的干员 id（取首个 clip 的 charId） */
function missionArchiveCharId(topicId: string): string | undefined {
  const ma = (excel.ActivityTable as any)?.missionArchives?.[topicId];
  const clips: Array<{ charId: string }> =
    ma?.nodes?.flatMap((n: any) => n?.clips ?? []) ?? ma?.hiddenClips ?? [];
  return clips[0]?.charId;
}

/**
 * 进入角色语音记录并领取入口奖励
 * CS: FifthAnnivService.MissionArchiveClaimEntryRewardRequest { topicId }
 * 响应 { reward: ItemGet[] }；写 mainline.charVoiceRecord[topicId]（isOpen/confirmEnterReward）
 */
rootRouter.post("/mainline/enterCharVoiceRecord", validateBody(enterCharVoiceRecordSchema), async (req, res) => {
  const player = getPlayer();
  const { topicId } = req.body as EnterCharVoiceRecordRequest;
  const charId = missionArchiveCharId(topicId);
  let granted = false;
  await player.update(async (draft) => {
    const mainline = draft.mainline as any;
    mainline.charVoiceRecord = mainline.charVoiceRecord ?? {};
    const archive = (mainline.charVoiceRecord[topicId] ??= { isOpen: false, confirmEnterReward: false, nodes: {} });
    if (archive.confirmEnterReward) return;
    archive.isOpen = true;
    archive.confirmEnterReward = true;
    granted = true;
  });
  const reward: ItemGet[] = [];
  if (granted && charId) {
    player.gainItem.setTarget(charId, "CHAR", 1);
    await player.gainItem.handle();
    reward.push({ type: "CHAR", id: charId, count: 1 });
  }
  res.send({ reward, ...player.delta } satisfies EnterCharVoiceRecordResponse);
});

/**
 * 领取语音记录节点奖励
 * CS: FifthAnnivService.MissionArchiveClaimNodeRewardRequest { topicId, nodeId }
 * 响应 { reward: ItemGet[] }；写 mainline.charVoiceRecord[topicId].nodes[nodeId]=2（CLAIMED）
 */
rootRouter.post("/mainline/confirmCharVoiceRecordReward", validateBody(confirmCharVoiceRecordRewardSchema), async (req, res) => {
  const player = getPlayer();
  const { topicId, nodeId } = req.body as ConfirmCharVoiceRecordRewardRequest;
  const topic = (excel.ActivityTable as any)?.missionArchives?.[topicId];
  const node = topic?.nodes?.find((n: any) => n?.nodeId === nodeId);
  const charId = node?.clips?.[0]?.charId ?? topic?.hiddenClips?.[0]?.charId;
  let granted = false;
  await player.update(async (draft) => {
    const mainline = draft.mainline as any;
    mainline.charVoiceRecord = mainline.charVoiceRecord ?? {};
    const archive = (mainline.charVoiceRecord[topicId] ??= { isOpen: false, confirmEnterReward: false, nodes: {} });
    if (!node || archive.nodes[nodeId] === 2) return;
    archive.nodes[nodeId] = 2;
    granted = true;
  });
  const reward: ItemGet[] = [];
  if (granted && charId) {
    const tokenId = `p_char_${charId}`;
    player.gainItem.setTarget(tokenId, "MATERIAL", 1);
    await player.gainItem.handle();
    reward.push({ type: "MATERIAL", id: tokenId, count: 1 });
  }
  res.send({ reward, ...player.delta } satisfies ConfirmCharVoiceRecordRewardResponse);
});
```

同时更新 routes.ts 顶部 import：加入 `EnterCharVoiceRecordRequest/Response`、`ConfirmCharVoiceRecordRewardRequest/Response`、`ItemGet`。

- [x] **Step 4: 跑测试确认 GREEN**

Run: `pnpm exec vitest run tests/unit/router/user-char-voice-record.test.ts`
Expected: PASS。

---

### Task 4: CG 收藏持久化（cg-store + 路由接入）

**Files:**
- Create: `app/game/modules/user/cg-store.ts`
- Modify: `app/game/modules/user/routes.ts`（删除模块级 `cgCollection` Set，改接 store）
- Test: `tests/unit/router/user-cg.test.ts`

**Interfaces:**
- Produces: `cgCollectionStore.list(uid): string[]`、`cgCollectionStore.add(uid, cgId): void`、`cgCollectionStore.remove(uid, cgId): void`（惰性加载 + 每次变更落盘 `data/user/cgCollection.json`，结构 `{ user: { [uid]: string[] } }`）。

- [x] **Step 1: 写失败测试**

```ts
// tests/unit/router/user-cg.test.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
const fsMock = vi.hoisted(() => ({
  existsSync: vi.fn(),
  readFileSync: vi.fn(),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  unlinkSync: vi.fn(),
}));
vi.mock("node:fs", () => fsMock);
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() { return { send: vi.fn(), status: vi.fn().mockReturnThis(), type: vi.fn().mockReturnThis(), json: vi.fn() }; }
async function call(player: any, url: string, body: any) {
  const res = mockRes();
  (httpContext.get as any).mockReturnValue(player);
  rootRouter({ method: "POST", url, body } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("CG 收藏持久化", () => {
  let player: any;
  beforeEach(() => {
    vi.clearAllMocks();
    fsMock.existsSync.mockReset().mockReturnValue(false);
    fsMock.readFileSync.mockReset();
    fsMock.writeFileSync.mockReset();
    fsMock.mkdirSync.mockReset();
    player = mockPlayerData({ status: { uid: "1" } as any });
  });

  it("add 后 cgList 含新 id 并落盘", async () => {
    const res = await call(player, "/cg/addCgCollection", { cgId: "66_i02" });
    expect(res.send.mock.calls[0][0].cgList).toEqual(["66_i02"]);
    const written = JSON.parse(fsMock.writeFileSync.mock.calls.at(-1)[1] as string);
    expect(written.user["1"]).toEqual(["66_i02"]);
  });

  it("get 返回该 uid 已收藏列表", async () => {
    fsMock.existsSync.mockReturnValue(true);
    fsMock.readFileSync.mockReturnValue(JSON.stringify({ user: { "1": ["66_i02"] } }));
    const res = await call(player, "/cg/getCgCollection", {});
    expect(res.send.mock.calls[0][0].cgList).toEqual(["66_i02"]);
  });

  it("remove 后列表移除并落盘", async () => {
    fsMock.existsSync.mockReturnValue(true);
    fsMock.readFileSync.mockReturnValue(JSON.stringify({ user: { "1": ["66_i02", "66_i03"] } }));
    await call(player, "/cg/removeCgCollection", { cgId: "66_i02" });
    const written = JSON.parse(fsMock.writeFileSync.mock.calls.at(-1)[1] as string);
    expect(written.user["1"]).toEqual(["66_i03"]);
  });
});
```

- [x] **Step 2: 跑测试确认 RED**

Run: `pnpm exec vitest run tests/unit/router/user-cg.test.ts`
Expected: FAIL —— 现为进程级 Set，无持久化、add 后落盘断言失败。

- [x] **Step 3: 新建 cg-store.ts**

```ts
/**
 * CG 收藏持久化存储（按 uid 独立文件，仿 data/user/mails.json）
 *
 * 数据文件：data/user/cgCollection.json，结构 { user: { [uid]: string[] } }。
 * 惰性加载 + 变更即写；与 gallery 缩略图一样属持久化用户数据。
 */
import { dirname, join } from "node:path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

interface CgCollectionDB {
  user: Record<string, string[]>;
}

const CG_COLLECTION_PATH = join(__dirname, "../../../../data/user/cgCollection.json");

export class CgCollectionStore {
  private _db: CgCollectionDB = { user: {} };
  private _loaded = false;

  constructor(private readonly _filepath: string = CG_COLLECTION_PATH) {}

  private _load(): void {
    if (this._loaded) return;
    this._loaded = true;
    try {
      if (existsSync(this._filepath)) {
        this._db = JSON.parse(readFileSync(this._filepath, "utf8")) as CgCollectionDB;
      }
    } catch {
      this._db = { user: {} };
    }
  }

  private _persist(): void {
    mkdirSync(dirname(this._filepath), { recursive: true });
    writeFileSync(this._filepath, JSON.stringify(this._db));
  }

  /** 查询指定 uid 的 CG 收藏列表（副本） */
  list(uid: string): string[] {
    this._load();
    return [...(this._db.user[uid] ?? [])];
  }

  /** 添加 CG 到收藏（幂等）并落盘 */
  add(uid: string, cgId: string): void {
    this._load();
    const list = (this._db.user[uid] ??= []);
    if (!list.includes(cgId)) {
      list.push(cgId);
      this._persist();
    }
  }

  /** 从收藏移除 CG 并落盘 */
  remove(uid: string, cgId: string): void {
    this._load();
    const list = this._db.user[uid];
    if (!list) return;
    const idx = list.indexOf(cgId);
    if (idx >= 0) {
      list.splice(idx, 1);
      this._persist();
    }
  }
}

/** 全局单例（routes 挂载期惰性加载文件） */
export const cgCollectionStore = new CgCollectionStore();
```

- [x] **Step 4: 接入 routes.ts**

删除模块级 `const cgCollection = new Set<string>();`，在文件顶部 import：

```ts
import { cgCollectionStore } from "./cg-store";
```

三个 CG 处理器改为（以 add 为例）：

```ts
rootRouter.post("/cg/addCgCollection", validateBody(cgCollectionSchema), async (req, res) => {
  const player = getPlayer();
  const { cgId } = req.body as AddCgCollectionRequest;
  cgCollectionStore.add(String(player.uid), cgId);
  res.send({
    ...player.delta,
    cgList: cgCollectionStore.list(String(player.uid)),
  } satisfies AddCgCollectionResponse);
});
```

`getCgCollection` 与 `removeCgCollection` 同理（get：仅 list；remove：remove 后 list）。

- [x] **Step 5: 跑测试确认 GREEN**

Run: `pnpm exec vitest run tests/unit/router/user-cg.test.ts`
Expected: PASS。

---

### Task 5: 长期签到 recvLongTermCheckInReward + showCount 维护

**Files:**
- Modify: `app/game/modules/checkin/checkin.ts`（`dailyRefresh` 幂等守卫 + `showCount` 递增；新增 `ensureShowCount()`）
- Modify: `app/game/modules/user/routes.ts`（`/user/recvLongTermCheckInReward` 完整实现）
- Test: `tests/unit/manager/checkin.test.ts`（扩展）、`tests/unit/router/user-long-term-checkin.test.ts`

**Interfaces:**
- Consumes: `RecvLongTermCheckInRewardRequest/Response`、`recvLongTermCheckInRewardSchema`、`excel.OpenServerTable.longTermCheckInData`、`player.checkIn.ensureShowCount()`。
- Produces: `CheckInManager.ensureShowCount(): Promise<void>`（showCount 缺失时按 registerTs 回填）；`dailyRefresh` 内 showCount+1；`checkIn.longTermRecvRecord[groupId]=now` + 响应 `{ rewards, ...delta }`。

- [x] **Step 1: 扩展 checkin 测试（RED）**

在 `tests/unit/manager/checkin.test.ts` 的 `describe("dailyRefresh")` 中追加：

```ts
it("dailyRefresh 应递增 showCount（累计签到天数）", async () => {
  const manager = new CheckInManager(mockPlayer as any, mockTrigger as any);
  mockPlayer._playerdata.checkIn!.canCheckIn = 0;
  mockPlayer._playerdata.checkIn!.showCount = 10;
  await manager.dailyRefresh();
  expect(mockPlayer._playerdata.checkIn!.showCount).toBe(11);
});

it("老档缺失 showCount 时按注册时长回填（不再重复 +1）", async () => {
  const manager = new CheckInManager(mockPlayer as any, mockTrigger as any);
  mockPlayer._playerdata.checkIn!.canCheckIn = 0;
  delete (mockPlayer._playerdata.checkIn as any).showCount;
  (mockPlayer._playerdata.status as any).registerTs = 1234567890 - 180 * 86400; // 180 天前注册
  await manager.dailyRefresh();
  expect(mockPlayer._playerdata.checkIn!.showCount).toBe(180);
});

it("每日重复触发 dailyRefresh（canCheckIn 已为 1）时不再重复递增", async () => {
  const manager = new CheckInManager(mockPlayer as any, mockTrigger as any);
  mockPlayer._playerdata.checkIn!.canCheckIn = 1;
  mockPlayer._playerdata.checkIn!.showCount = 10;
  await manager.dailyRefresh();
  expect(mockPlayer._playerdata.checkIn!.showCount).toBe(10);
});
```

- [x] **Step 2: 跑 checkin 测试确认 RED**

Run: `pnpm exec vitest run tests/unit/manager/checkin.test.ts`
Expected: FAIL —— dailyRefresh 未维护 showCount。

- [x] **Step 3: 实现 checkin.ts 改动**

将 `dailyRefresh` 替换为：

```ts
async dailyRefresh() {
  await this._player.update(async (draft) => {
    // 幂等：同日重复触发（周一/月初 daily+weekly 并发）不重复计数
    if (draft.checkIn.canCheckIn === 1) return;
    draft.checkIn.canCheckIn = 1;
    draft.checkIn.checkInRewardIndex += 1;
    // 累计签到天数（长期签到进度）：官服"登录即自动签到"语义，每日 +1
    this._bumpShowCount(draft);
  });
}

/**
 * 递增累计签到天数；老档缺失时按注册时长回填（满配号可直接领取长期签到档位）
 * @param draft - 可写草稿
 */
private _bumpShowCount(draft: Draft<PlayerDataModel>) {
  if (draft.checkIn.showCount == null) {
    draft.checkIn.showCount = Math.max(
      0,
      Math.floor((now() - (draft.status.registerTs ?? now())) / 86400),
    );
  } else {
    draft.checkIn.showCount += 1;
  }
}

/**
 * 确保累计签到天数存在（长期签到路由读取前调用）
 */
async ensureShowCount() {
  await this._player.update(async (draft) => {
    if (draft.checkIn.showCount == null) {
      draft.checkIn.showCount = Math.max(
        0,
        Math.floor((now() - (draft.status.registerTs ?? now())) / 86400),
      );
    }
  });
}
```

注意：`Draft` 已由 checkin.ts import；`PlayerDataModel` 需补 import（`import type { PlayerDataModel } from "../../kernel/playerdata";`）。

- [x] **Step 4: 跑 checkin 测试确认 GREEN**

Run: `pnpm exec vitest run tests/unit/manager/checkin.test.ts`
Expected: PASS。

- [x] **Step 5: 写长期签到路由测试（RED）**

```ts
// tests/unit/router/user-long-term-checkin.test.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
vi.mock("@excel/excel", () => ({
  default: {
    OpenServerTable: {
      longTermCheckInData: {
        groupList: [
          {
            groupId: "signin_1",
            level: 80,
            days: 180,
            rewardList: [{ id: "avatar_dyn_01", count: 1, type: "PLAYER_AVATAR" }],
          },
        ],
        constData: { startTs: 1000000000 },
      },
    },
  },
}));
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() { return { send: vi.fn(), status: vi.fn().mockReturnThis(), type: vi.fn().mockReturnThis(), json: vi.fn() }; }
async function call(player: any, body: any) {
  const res = mockRes();
  (httpContext.get as any).mockReturnValue(player);
  rootRouter({ method: "POST", url: "/user/recvLongTermCheckInReward", body } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("recvLongTermCheckInReward", () => {
  let player: any;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1", level: 90 } as any,
      checkIn: { showCount: 200, longTermRecvRecord: {} } as any,
    });
  });

  it("达标时发放奖励、记录领取并返回 rewards", async () => {
    const res = await call(player, { groupId: "signin_1" });
    expect(res.send.mock.calls[0][0].rewards).toEqual([{ type: "PLAYER_AVATAR", id: "avatar_dyn_01", count: 1 }]);
    expect(player._playerdata.checkIn.longTermRecvRecord["signin_1"]).toBe(1234567890);
    expect(player.gainItem.handle).toHaveBeenCalled();
  });

  it("等级不足时不发放", async () => {
    player._playerdata.status.level = 70;
    const res = await call(player, { groupId: "signin_1" });
    expect(res.send.mock.calls[0][0].rewards).toEqual([]);
    expect(player._playerdata.checkIn.longTermRecvRecord["signin_1"]).toBeUndefined();
  });

  it("累计天数不足时不发放", async () => {
    player._playerdata.checkIn.showCount = 100;
    const res = await call(player, { groupId: "signin_1" });
    expect(res.send.mock.calls[0][0].rewards).toEqual([]);
  });

  it("已领取时不重复发放", async () => {
    player._playerdata.checkIn.longTermRecvRecord["signin_1"] = 1;
    const res = await call(player, { groupId: "signin_1" });
    expect(res.send.mock.calls[0][0].rewards).toEqual([]);
  });

  it("未知 groupId 返回空奖励", async () => {
    const res = await call(player, { groupId: "nope" });
    expect(res.send.mock.calls[0][0].rewards).toEqual([]);
  });
});
```

- [x] **Step 6: 跑长期签到路由测试确认 RED**

Run: `pnpm exec vitest run tests/unit/router/user-long-term-checkin.test.ts`
Expected: FAIL —— 现有实现恒返回 `rewards: []`。

- [x] **Step 7: 实现 recvLongTermCheckInReward**

替换 `routes.ts` 中对应处理器：

```ts
/**
 * 领取长期签到奖励
 * CS: Torappu.UI.LongTermCheckIn.ReceiveLongTermCheckInRewardRequest { groupId }
 * 条件：活动已开启（now >= constData.startTs）且 status.level >= group.level
 * 且 checkIn.showCount >= group.days 且 longTermRecvRecord 未领。
 * 发放后写 longTermRecvRecord[groupId]（幂等），响应 { rewards, ...delta }。
 */
rootRouter.post("/user/recvLongTermCheckInReward", validateBody(recvLongTermCheckInRewardSchema), async (req, res) => {
  const player = getPlayer();
  const { groupId } = req.body as RecvLongTermCheckInRewardRequest;
  const ltData = excel.OpenServerTable?.longTermCheckInData as
    | {
        groupList?: Array<{ groupId: string; level: number; days: number; rewardList: ItemBundle[] }>;
        constData?: { startTs: number };
      }
    | undefined;
  const group = ltData?.groupList?.find((g) => g.groupId === groupId);
  if (!group || !ltData?.constData || now() < ltData.constData.startTs) {
    return res.send({ ...player.delta, rewards: [] } as RecvLongTermCheckInRewardResponse);
  }
  await player.checkIn.ensureShowCount();
  let granted = false;
  await player.update(async (draft) => {
    draft.checkIn.longTermRecvRecord = draft.checkIn.longTermRecvRecord ?? {};
    if (draft.checkIn.longTermRecvRecord[groupId] != null) return;
    const days = draft.checkIn.showCount ?? 0;
    const level = draft.status.level ?? 0;
    if (level < group.level || days < group.days) return;
    draft.checkIn.longTermRecvRecord[groupId] = now();
    granted = true;
  });
  const rewards: RewardItemModel[] = [];
  if (granted) {
    for (const item of group.rewardList ?? []) player.gainItem.add(item);
    await player.gainItem.handle();
    for (const item of group.rewardList ?? []) {
      rewards.push({ type: item.type, id: item.id, count: item.count });
    }
  }
  res.send({ rewards, ...player.delta } satisfies RecvLongTermCheckInRewardResponse);
});
```

同时 routes.ts 顶部 import 补充 `RecvLongTermCheckInRewardRequest/Response`、`RewardItemModel`。

- [x] **Step 8: 跑测试确认 GREEN**

Run: `pnpm exec vitest run tests/unit/router/user-long-term-checkin.test.ts tests/unit/manager/checkin.test.ts`
Expected: PASS。

---

### Task 6: 特勤干员板 spOperator 结构修正

**Files:**
- Modify: `app/game/modules/user/routes.ts`（`/troop/SpecialOperatorUnlockNode`）
- Test: `tests/unit/router/user-troop.test.ts`

**Interfaces:**
- Consumes: `SpecialOperatorUnlockNodeRequest`、`specialOperatorUnlockNodeSchema`、`excel.SpecialOperatorTable.operatorDetailData`。
- Produces: `troop.spOperator[charId][nodeType][nodeId] = { id, state: 1, type: nodeType }`。

- [x] **Step 1: 写失败测试**

```ts
// tests/unit/router/user-troop.test.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
vi.mock("@excel/excel", () => ({
  default: {
    SpecialOperatorTable: {
      operatorDetailData: {
        char_4230_mcnist: {
          nodeUnlockData: { mcnist_n_skill1_6: { nodeType: "SKILL" } },
        },
      },
    },
  },
}));
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() { return { send: vi.fn(), status: vi.fn().mockReturnThis(), type: vi.fn().mockReturnThis(), json: vi.fn() }; }
async function call(player: any, body: any) {
  const res = mockRes();
  (httpContext.get as any).mockReturnValue(player);
  rootRouter({ method: "POST", url: "/troop/SpecialOperatorUnlockNode", body } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("SpecialOperatorUnlockNode", () => {
  let player: any;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1" } as any,
      troop: { chars: { "374": { charId: "char_4230_mcnist" } }, spOperator: {} } as any,
    });
  });

  it("写 spOperator[charId][nodeType][nodeId] 节点对象", async () => {
    await call(player, { instId: "374", nodeId: "mcnist_n_skill1_6" });
    const so = player._playerdata.troop.spOperator;
    expect(so["char_4230_mcnist"]["SKILL"]["mcnist_n_skill1_6"]).toEqual({
      id: "mcnist_n_skill1_6",
      state: 1,
      type: "SKILL",
    });
  });

  it("未知 instId 不写状态", async () => {
    await call(player, { instId: "999", nodeId: "mcnist_n_skill1_6" });
    expect(player._playerdata.troop.spOperator["char_4230_mcnist"]).toBeUndefined();
  });

  it("未知 nodeId 不写状态", async () => {
    await call(player, { instId: "374", nodeId: "nope" });
    expect(player._playerdata.troop.spOperator["char_4230_mcnist"]).toBeUndefined();
  });
});
```

- [x] **Step 2: 跑测试确认 RED**

Run: `pnpm exec vitest run tests/unit/router/user-troop.test.ts`
Expected: FAIL —— 现写 `troop.specialOperator`（字段名错）+ `unlockedNodes` 结构错。

- [x] **Step 3: 实现处理器**

替换 `routes.ts` 中对应处理器：

```ts
/**
 * 特勤干员解锁节点（CS: SpecialOperatorBoardUnlockNodeRequest { instId, nodeId }）
 * 写 troop.spOperator[charId][nodeType][nodeId] = { id, state: 1, type: nodeType }
 *（抓包 R-1787477989284-0439：delta 为 troop.spOperator.char_4230_mcnist.SKILL.mcnist_n_skill1_6）
 */
rootRouter.post("/troop/SpecialOperatorUnlockNode", validateBody(specialOperatorUnlockNodeSchema), async (req, res) => {
  const player = getPlayer();
  const { instId, nodeId } = req.body as SpecialOperatorUnlockNodeRequest;
  await player.update(async (draft) => {
    const char = draft.troop.chars[instId];
    if (!char) return;
    const nodeCfg = excel.SpecialOperatorTable?.operatorDetailData?.[char.charId]?.nodeUnlockData?.[nodeId];
    const nodeType = nodeCfg?.nodeType;
    if (!nodeType) return;
    draft.troop.spOperator ??= {};
    draft.troop.spOperator[char.charId] ??= {};
    draft.troop.spOperator[char.charId][nodeType] ??= {};
    draft.troop.spOperator[char.charId][nodeType][nodeId] = { id: nodeId, state: 1, type: nodeType };
  });
  res.send(player.delta);
});
```

- [x] **Step 4: 跑测试确认 GREEN**

Run: `pnpm exec vitest run tests/unit/router/user-troop.test.ts`
Expected: PASS。

---

### Task 7: performanceStory / share 结构对齐

**Files:**
- Modify: `app/game/modules/user/routes.ts`（`/performanceStory/startStory`、`/share/confirmShareMission`）
- Test: `tests/unit/router/user-misc.test.ts`

**Interfaces:**
- Consumes: `StartStoryRequest`、`ConfirmShareMissionRequest` 及对应 schema。
- Produces: `performanceStory.unlock[storyId]=1`；`share.shareMissions[shareMissionId].counter+1`。

- [x] **Step 1: 写失败测试**

```ts
// tests/unit/router/user-misc.test.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() { return { send: vi.fn(), status: vi.fn().mockReturnThis(), type: vi.fn().mockReturnThis(), json: vi.fn() }; }
async function call(player: any, url: string, body: any) {
  const res = mockRes();
  (httpContext.get as any).mockReturnValue(player);
  rootRouter({ method: "POST", url, body } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("performanceStory / share", () => {
  let player: any;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({ status: { uid: "1" } as any });
  });

  it("startStory 写 performanceStory.unlock[storyId]=1", async () => {
    await call(player, "/performanceStory/startStory", { storyId: "p_story_001" });
    expect(player._playerdata.performanceStory.unlock["p_story_001"]).toBe(1);
  });

  it("confirmShareMission 递增 share.shareMissions[counter]", async () => {
    player._playerdata.share = { shareMissions: { namecardshare: { counter: 0 } } } as any;
    await call(player, "/share/confirmShareMission", { shareMissionId: "namecardshare" });
    expect(player._playerdata.share.shareMissions["namecardshare"].counter).toBe(1);
    await call(player, "/share/confirmShareMission", { shareMissionId: "namecardshare" });
    expect(player._playerdata.share.shareMissions["namecardshare"].counter).toBe(2);
  });
});
```

- [x] **Step 2: 跑测试确认 RED**

Run: `pnpm exec vitest run tests/unit/router/user-misc.test.ts`
Expected: FAIL —— startStory 现为空桩；confirmShareMission 写 `share[id]=2` 结构错。

- [x] **Step 3: 实现两个处理器**

替换 `routes.ts` 中对应处理器：

```ts
/**
 * 演出剧情开始
 * CS: PerformanceStoryRequest { storyId }（ServiceCode REFRESH_PERFORMANCE_STORY_BEFORE_START）
 * 写 performanceStory.unlock[storyId]
 */
rootRouter.post("/performanceStory/startStory", validateBody(startStorySchema), async (req, res) => {
  const player = getPlayer();
  const { storyId } = req.body as StartStoryRequest;
  await player.update(async (draft) => {
    draft.performanceStory ??= { unlock: {} };
    draft.performanceStory.unlock[storyId] = 1;
  });
  res.send(player.delta);
});

/**
 * 确认分享任务
 * CS: CrossAppShare Mission（PlayerCrossAppShare.shareMissions[id].counter）
 * 每次确认 counter+1（当前 excel rewardsList 为空，仅计数；奖励逻辑留待活动数据补全）
 */
rootRouter.post("/share/confirmShareMission", validateBody(confirmShareMissionSchema), async (req, res) => {
  const player = getPlayer();
  const { shareMissionId } = req.body as ConfirmShareMissionRequest;
  await player.update(async (draft) => {
    draft.share ??= { shareMissions: {} };
    const entry = (draft.share.shareMissions[shareMissionId] ??= { counter: 0 });
    entry.counter += 1;
  });
  res.send(player.delta);
});
```

- [x] **Step 4: 跑测试确认 GREEN**

Run: `pnpm exec vitest run tests/unit/router/user-misc.test.ts`
Expected: PASS。

---

### Task 8: buyAp / exchange / useItem 管道规范化 + 错误码

**Files:**
- Modify: `app/game/modules/user/status.ts`（`buyAp`、`exchangeDiamondShard`）
- Modify: `app/game/modules/user/routes.ts`（`buyAp`、`useItem`、`useItems`、`useRenameCard` 处理器）
- Test: `tests/unit/manager/status.test.ts`（扩展）、`tests/unit/router/user-status.test.ts`

**Interfaces:**
- Produces: `StatusManager.buyAp(): Promise<boolean>`（false=额度耗尽）；`buyAp` 路由额度耗尽返回 `{ result: 1, ...delta }`；物品变更全部经 `player.gainItem`。

- [x] **Step 1: 扩展 status 测试（RED）**

在 `tests/unit/manager/status.test.ts` 中，将既有 buyAp 用例断言从 `items:use/items:get` emit 改为 gainItem 调用，并追加返回值断言：

```ts
it("buyAp 扣次数、经 gainItem 消耗 1 源石并回满体力，返回 true", async () => {
  const manager = new StatusManager(mockPlayer as any, mockTrigger as any);
  mockPlayer._playerdata.status!.buyApRemainTimes = 10;
  const ok = await manager.buyAp();
  expect(ok).toBe(true);
  expect(mockPlayer._playerdata.status!.buyApRemainTimes).toBe(9);
  expect(mockPlayer.gainItem.setTarget).toHaveBeenCalledWith("", "DIAMOND", 1);
  expect(mockPlayer.gainItem.setTarget).toHaveBeenCalledWith("", "AP_GAMEPLAY", 135);
  expect(mockPlayer.gainItem.use).toHaveBeenCalled();
  expect(mockPlayer.gainItem.handle).toHaveBeenCalled();
});

it("buyAp 额度耗尽返回 false 且不扣次数", async () => {
  const manager = new StatusManager(mockPlayer as any, mockTrigger as any);
  mockPlayer._playerdata.status!.buyApRemainTimes = 0;
  const ok = await manager.buyAp();
  expect(ok).toBe(false);
  expect(mockPlayer._playerdata.status!.buyApRemainTimes).toBe(0);
  expect(mockPlayer.gainItem.use).not.toHaveBeenCalled();
});
```

（原用例中 `expect(emitSpy).toHaveBeenCalledWith("items:use", ...)` 类断言同步删除/改写。）

- [x] **Step 2: 跑 status 测试确认 RED**

Run: `pnpm exec vitest run tests/unit/manager/status.test.ts`
Expected: FAIL —— 现有 buyAp 直发事件、无返回值。

- [x] **Step 3: 实现 status.ts**

替换 `buyAp` 与 `exchangeDiamondShard`：

```ts
/**
 * 购买理智
 * 每日次数（dailyRefresh 重置为 10）扣减；消耗 1 源石、发放 135 点理智（gainItem 管道）。
 * @returns 是否成功（false = 当日额度耗尽）
 */
async buyAp(): Promise<boolean> {
  const allowed = await this._player.update(async (draft) => {
    if ((draft.status.buyApRemainTimes ?? 10) <= 0) return false;
    draft.status.buyApRemainTimes -= 1;
    return true;
  });
  if (!allowed) return false;
  await this._player.gainItem.setTarget("", "DIAMOND", 1).use();
  await this._player.gainItem.setTarget("", "AP_GAMEPLAY", 135).handle();
  return true;
}

/**
 * 兑换源石碎片（1 源石 → diamondToShdRate 碎片，gainItem 管道）
 * @param args.count - 兑换次数（路由层已校验正整数）
 */
async exchangeDiamondShard(args: { count: number }) {
  const { count } = args;
  await this._player.gainItem
    .setTarget("", "DIAMOND_SHD", count * excel.GameDataConst.diamondToShdRate)
    .handle();
  await this._player.gainItem.setTarget("", "DIAMOND", count).use();
}
```

- [x] **Step 4: 写 buyAp/exchange/useItem 路由测试（RED）**

```ts
// tests/unit/router/user-status.test.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
import { router } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() { return { send: vi.fn(), status: vi.fn().mockReturnThis(), type: vi.fn().mockReturnThis(), json: vi.fn() }; }
async function call(player: any, url: string, body: any) {
  const res = mockRes();
  (httpContext.get as any).mockReturnValue(player);
  router({ method: "POST", url, body } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("user 基础端点管道", () => {
  let player: any;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1", buyApRemainTimes: 0 } as any,
    });
  });

  it("buyAp 额度耗尽返回 { result: 1 }", async () => {
    const res = await call(player, "/user/buyAp", {});
    expect(res.send.mock.calls[0][0].result).toBe(1);
  });

  it("useItem 经 gainItem 消耗（cnt 字段）", async () => {
    player._playerdata.status.buyApRemainTimes = 10;
    const res = await call(player, "/user/useItem", { instId: 830, itemId: "ap_supply_lt_120", cnt: 1 });
    expect(player.gainItem.setTarget).toHaveBeenCalledWith("ap_supply_lt_120", undefined, 1, 830);
    expect(player.gainItem.use).toHaveBeenCalled();
    expect(res.send).toHaveBeenCalled();
  });

  it("exchangeDiamondShard 负数 count 返回 400", async () => {
    const res = await call(player, "/user/exchangeDiamondShard", { count: -1 });
    expect(res.status).toHaveBeenCalledWith(400);
  });
});
```

注意：`router` 需从 `routes.ts` 具名导出（当前为 `export default router`）。Task 8 Step 6 顺带改为 `export { router }; export default router;`，其余既有 import 不受影响。

- [x] **Step 5: 跑路由测试确认 RED**

Run: `pnpm exec vitest run tests/unit/router/user-status.test.ts`
Expected: FAIL —— 耗尽时返回空 delta（无 result）；useItem 直发事件。

- [x] **Step 6: 实现路由处理器**

`routes.ts` 中 `buyAp`：

```ts
router.post("/buyAp", validateBody(buyApSchema), async (req, res) => {
  const player = getPlayer();
  req.body as BuyApRequest;
  const ok = await player.status.buyAp();
  if (!ok) {
    return res.send({ result: 1, ...player.delta } satisfies BuyApResponse);
  }
  res.send(player.delta satisfies BuyApResponse);
});
```

`useItem`：

```ts
router.post("/useItem", validateBody(useItemSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as UseItemRequest;
  const count = body?.cnt ?? body?.count;
  if (typeof count !== "number" || !Number.isInteger(count) || count <= 0) {
    return res.status(400).send({ status: 1, msg: "非法参数" });
  }
  player.gainItem.setTarget(body.itemId, undefined, count, (body as any).instId);
  await player.gainItem.use();
  res.send(player.delta satisfies UseItemResponse);
});
```

`useItems`：

```ts
router.post("/useItems", validateBody(useItemsSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as UseItemsRequest;
  if (
    !Array.isArray(body?.items) ||
    body.items.some((item) => typeof item?.cnt !== "number" || !Number.isInteger(item.cnt) || item.cnt <= 0)
  ) {
    return res.status(400).send({ status: 1, msg: "非法参数" });
  }
  for (const item of body.items) {
    player.gainItem.setTarget(item.itemId, undefined, item.cnt, item.instId);
  }
  await player.gainItem.use();
  res.send(player.delta satisfies UseItemsResponse);
});
```

`useRenameCard`：

```ts
router.post("/useRenameCard", validateBody(useRenameCardSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as UseRenameCardRequest;
  await player.status.bindNickName({ nickname: body.nickName });
  player.gainItem.setTarget(body.itemId, undefined, 1, body.instId);
  await player.gainItem.use();
  res.send(player.delta satisfies UseRenameCardResponse);
});
```

- [x] **Step 7: 跑测试确认 GREEN**

Run: `pnpm exec vitest run tests/unit/router/user-status.test.ts tests/unit/manager/status.test.ts`
Expected: PASS。

---

### Task 9: medal setCustomData 补 currentIndex

**Files:**
- Modify: `app/game/modules/user/routes.ts`（`/medal/setCustomData`）
- Test: `tests/unit/router/user-medal.test.ts`（扩展）

**Interfaces:**
- Consumes: `MedalSetCustomDataRequest/Response`、`medalSetCustomDataSchema`。
- Produces: `medal.custom.currentIndex = index ?? "1"` + `customs[index] = data`。

- [x] **Step 1: 写失败测试（RED）**

在 `tests/unit/router/user-medal.test.ts` 追加：

```ts
it("setCustomData 写 currentIndex 与 customs[index]（对齐抓包 R-1707532038347.211-4603）", async () => {
  const res = mockRes();
  const player = mockPlayerData({
    status: { uid: "1" } as any,
    medal: { custom: { currentIndex: "", customs: {} } } as any,
  });
  (httpContext.get as any).mockReturnValue(player);
  rootRouter(
    { method: "POST", url: "/medal/setCustomData", body: { index: "1", data: { layout: [] } } } as any,
    res,
    () => {},
  );
  await new Promise((r) => setTimeout(r, 20));
  expect(player._playerdata.medal.custom.currentIndex).toBe("1");
  expect(player._playerdata.medal.custom.customs["1"]).toEqual({ layout: [] });
});
```

（若该文件当前无 `mockRes`/`httpContext` mock，按 user-gallery.test.ts 顶部模式补齐。）

- [x] **Step 2: 跑测试确认 RED**

Run: `pnpm exec vitest run tests/unit/router/user-medal.test.ts`
Expected: FAIL —— 当前只写 `customs["1"]`，不写 `currentIndex`。

- [x] **Step 3: 实现**

替换 `routes.ts` 中对应处理器：

```ts
/**
 * 设置勋章自定义数据
 * 对齐抓包 R-1707532038347.211-4603：delta 含 medal.custom.currentIndex 与 customs[index]
 */
rootRouter.post("/medal/setCustomData", validateBody(medalSetCustomDataSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as MedalSetCustomDataRequest;
  const index = body.index ?? "1";
  await player.update(async (draft) => {
    draft.medal.custom.currentIndex = index;
    draft.medal.custom.customs[index] = body.data;
  });
  res.send(player.delta satisfies MedalSetCustomDataResponse);
});
```

- [x] **Step 4: 跑测试确认 GREEN**

Run: `pnpm exec vitest run tests/unit/router/user-medal.test.ts`
Expected: PASS。

---

### Task 10: 全量验证

**Files:**
- Modify: 无（验证收尾）

- [x] **Step 1: 类型检查**

Run: `pnpm exec tsc --noEmit`
Expected: 0 错误。

- [x] **Step 2: 全量单测**

Run: `pnpm exec vitest run`
Expected: 全部 PASS（含既有 100+ 用例与新增用例）。

- [x] **Step 3: 架构守卫**

Run: `pnpm exec vitest run tests/unit/architecture`
Expected: PASS（module-boundary / schema-first / file-size / composition-order 均不回归）。

- [x] **Step 4: 收尾核对**

- `git status` 仅含本计划涉及文件 + 两个文档（spec/plan）；不自动 commit（AGENTS.md）。
- 向用户汇报：设计文档、计划、实现清单、测试结果、遗留说明（showCount 周一/月初并发双触发边界、线索解锁宽松校验、CG 按 uid 持久化）。
