import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { now } from "@utils/time";
import {
  VecBreakV2ChangeBuffRequest,
  VecBreakV2ChangeBuffResponse,
  VecBreakV2DefenseStartBattleRequest,
  VecBreakV2FinishBattleRequest,
  VecBreakV2FinishBattleResponse,
  VecBreakV2OffenseStartBattleRequest,
  VecBreakV2SeasonRecordRequest,
  VecBreakV2SeasonRecordResponse,
  VecBreakV2SetDefendRequest,
  VecBreakV2SetDefendResponse,
  VecBreakV2StartBattleResponse,
} from "../model/protocol/vecbreak";

const router = Router();

/** 驻防战斗上下文（defendBattleStart 记录 → defendBattleFinish 消费，参考 ODPY global battle_data） */
// 修复：模块级单例在多账号下互相串扰（A 开战 B 结算用错队伍）→ 按 uid 存储
const vecBreakBattleCtxs = new Map<
  string,
  { activityId: string; stageId: string; squad: any }
>();

/** 按需初始化 VEC_BREAK_V2 活动数据 */
function ensureVecBreakData(draft: any, activityId: string): any {
  const vb = (draft.activity as any).VEC_BREAK_V2 as any;
  if (!vb) (draft.activity as any).VEC_BREAK_V2 = {};
  if (!vb[activityId]) {
    vb[activityId] = {
      activatedBuff: [],
      defendStages: {},
      milestone: { point: 0, got: [] },
    };
  }
  return vb[activityId];
}

router.post("/vecBreakV2/getSeasonRecord", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as VecBreakV2SeasonRecordRequest;
  // 参考 ODPY：stageInfo 来自 dungeon.stages（act1break_* → COMPLETE），
  // bestRecord 用 VEC_BREAK_V2 当前 buff/编队
  const stageInfo: Record<string, any> = {};
  for (const stageId of Object.keys(player._playerdata.dungeon.stages)) {
    if (stageId.startsWith("act1break_")) {
      // CS: PlayerStageState 数值枚举（COMPLETE=3），非字符串
      stageInfo[stageId] = { stageId, state: 3 };
    }
  }
  const vb = (player._playerdata.activity as any)?.VEC_BREAK_V2?.["act1break"];
  res.send({
    ...player.delta,
    seasons: {
      act1break: {
        bestRecord: {
          stageId: "act1break_12",
          buff: vb?.activatedBuff ?? [],
          showTs: now(),
          squad: vb?.squads ?? [],
          assistChar: {} as any,
        },
        stageInfo,
      },
    },
  } satisfies VecBreakV2SeasonRecordResponse);
});

router.post("/vecBreakV2/changeBuffList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as VecBreakV2ChangeBuffRequest;
  // 参考 ODPY：写入 activity.VEC_BREAK_V2[activityId].activatedBuff
  await player.update(async (draft) => {
    const data = ensureVecBreakData(draft, body.activityId);
    if (Array.isArray(body.buffList)) data.activatedBuff = body.buffList;
  });
  res.send(player.delta satisfies VecBreakV2ChangeBuffResponse);
});

router.post("/vecBreakV2/defendBattleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as VecBreakV2DefenseStartBattleRequest;
  // 参考 ODPY：记录战斗上下文并复用标准战斗开始
  vecBreakBattleCtxs.set(player.uid, {
    activityId: body.activityId,
    stageId: body.stageId,
    squad: body.squad,
  });
  const start = await player.battle.start({
    stageId: body.stageId,
    squad: body.squad as any,
    usePracticeTicket: 0,
    assistFriend: null,
  } as any);
  res.send({
    ...start,
    ...player.delta,
  } satisfies VecBreakV2StartBattleResponse);
});

router.post("/vecBreakV2/defendBattleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as VecBreakV2FinishBattleRequest;
  // 参考 ODPY：通关后写入 defendStages + activatedBuff 追加 stageId
  const ctx = vecBreakBattleCtxs.get(player.uid);
  let msBefore = 0;
  if (ctx) {
    await player.update(async (draft) => {
      const data = ensureVecBreakData(draft, ctx.activityId);
      const defend = data.defendStages[ctx.stageId];
      if (!defend) {
        data.defendStages[ctx.stageId] = {
          stageId: ctx.stageId,
          defendSquad: (ctx.squad?.slots ?? []).map((s: any) => ({
            charInstId: s?.charInstId,
            currentTmpl: null,
          })),
          recvTimeLimited: true,
          recvNormal: true,
        };
        if (!data.activatedBuff.includes(ctx.stageId)) {
          data.activatedBuff.push(ctx.stageId);
        }
      }
      msBefore = data.milestone?.point ?? 0;
    });
    vecBreakBattleCtxs.delete(player.uid);
  }
  const finishBody = {
    result: 0,
    apFailReturn: 0,
    goldScale: 0,
    expScale: 0,
    suggestFriend: false,
    msBefore,
    msAfter: msBefore,
    finTs: now(),
    ...player.delta,
  };
  res.send(finishBody satisfies VecBreakV2FinishBattleResponse);
});

router.post("/vecBreakV2/setDefend", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as VecBreakV2SetDefendRequest;
  // 参考 ODPY：写入 defendStages[stageId].defendSquad
  await player.update(async (draft) => {
    const data = ensureVecBreakData(draft, body.activityId);
    if (!data.defendStages[body.stageId]) {
      data.defendStages[body.stageId] = { stageId: body.stageId, defendSquad: [], recvTimeLimited: false, recvNormal: false };
    }
    data.defendStages[body.stageId].defendSquad = body.squadSlots;
  });
  res.send(player.delta satisfies VecBreakV2SetDefendResponse);
});

router.post("/vecBreakV2/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as VecBreakV2OffenseStartBattleRequest;

  res.send({
    ...player.delta,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    result: 0,
  } satisfies VecBreakV2StartBattleResponse);
});

router.post("/vecBreakV2/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as VecBreakV2FinishBattleRequest;
  // 与驻防结算同形状（result/msBefore/msAfter/finTs）
  res.send({
    result: 0,
    apFailReturn: 0,
    goldScale: 0,
    expScale: 0,
    suggestFriend: false,
    msBefore: 0,
    msAfter: 0,
    finTs: now(),
    ...player.delta,
  } satisfies VecBreakV2FinishBattleResponse);
});

export default router;
