/**
 * 第五周年探索（explore）活动路由
 *
 * 对应客户端 Torappu.FifthAnnivService 系列接口（客户端路径 /explore/*）。
 * 数据写 mainline.explore（防御性初始化缺失子结构）；私服做轻量状态记录，
 * 返回 playerDataDelta，客户端正常收包不崩溃。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { validateBody } from "../model/protocol/validate-body";
import {
  confirmMissionListSchema,
  confirmMissionSchema,
  confirmPassTargetSchema,
  giveUpGameSchema,
  selectEventChoiceSchema,
  selectInitGroupSchema,
  selectTargetChoiceSchema,
  settleGameSchema,
} from "../model/protocol/explore.schema";

const router = Router();

/** 防御性取 explore.outer 子结构 */
function ensureOuter(draft: any): any {
  const explore = (draft.mainline.explore = draft.mainline.explore ?? {
    game: {},
    outer: {},
  });
  explore.outer = explore.outer ?? {};
  return explore.outer;
}

/** 领取单个探索任务奖励（CS: ExploreClaimSingleMissionRequest { id }） */
router.post("/confirmMission", validateBody(confirmMissionSchema), async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { id } = req.body as { id: string };
  await player.update(async (draft) => {
    const outer = ensureOuter(draft);
    outer.missions = outer.missions ?? {};
    outer.missions[id] = 2;
  });
  res.send(player.delta);
});

/** 批量领取探索任务奖励（CS: ExploreClaimAllMissionRequest { idList }） */
router.post("/confirmMissionList", validateBody(confirmMissionListSchema), async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { idList = [] } = req.body as { idList?: string[] };
  await player.update(async (draft) => {
    const outer = ensureOuter(draft);
    outer.missions = outer.missions ?? {};
    for (const id of idList) outer.missions[id] = 2;
  });
  res.send(player.delta);
});

/** 选择初始探索组（CS: ExploreSelectInitGroupRequest { groupId, heritage }） */
router.post("/selectInitGroup", validateBody(selectInitGroupSchema), async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { groupId } = req.body as { groupId: string; heritage?: boolean };
  await player.update(async (draft) => {
    const outer = ensureOuter(draft);
    outer.initGroupId = groupId;
  });
  res.send(player.delta);
});

/** 事件选项选择（CS: ExploreSelectEventOptionRequest { index }） */
router.post("/selectEventChoice", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { index } = req.body as { index: number };
  await player.update(async (draft) => {
    const explore = (draft.mainline.explore = draft.mainline.explore ?? { game: {}, outer: {} });
    explore.game = explore.game ?? {};
    (explore.game as any).eventChoice = index;
  });
  res.send(player.delta);
});

/** 目标选项选择（CS: ExploreSelectTargetOptionRequest { index }） */
router.post("/selectTargetChoice", validateBody(selectTargetChoiceSchema), async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { index } = req.body as { index: number };
  await player.update(async (draft) => {
    const explore = (draft.mainline.explore = draft.mainline.explore ?? { game: {}, outer: {} });
    explore.game = explore.game ?? {};
    (explore.game as any).targetChoice = index;
  });
  res.send(player.delta);
});

/** 确认通过目标（CS: ExploreConfirmPassTargetRequest） */
router.post("/confirmPassTarget", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Record<string, unknown>;
  await player.update(async (draft) => {
    const explore = (draft.mainline.explore = draft.mainline.explore ?? { game: {}, outer: {} });
    explore.game = explore.game ?? {};
    (explore.game as any).passTarget = 1;
  });
  res.send(player.delta);
});

/** 放弃探索（CS: ExploreGiveUpGameRequest） */
router.post("/giveUpGame", validateBody(giveUpGameSchema), async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Record<string, unknown>;
  await player.update(async (draft) => {
    const explore = (draft.mainline.explore = draft.mainline.explore ?? { game: {}, outer: {} });
    explore.game = explore.game ?? {};
    (explore.game as any).gaveUp = 1;
  });
  res.send(player.delta);
});

/** 探索结算（CS: ExploreSettleGameRequest） */
router.post("/settleGame", validateBody(settleGameSchema), async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Record<string, unknown>;
  await player.update(async (draft) => {
    const explore = (draft.mainline.explore = draft.mainline.explore ?? { game: {}, outer: {} });
    explore.game = explore.game ?? {};
    (explore.game as any).settled = 1;
  });
  res.send(player.delta);
});

export default router;
