/**
 * 自走棋（AutoChess）赛季路由
 * 请求/响应类型见 @game/domain/autochess/autochess（参考 CS 2.7.61 协议类）
 */
import { Router } from "express";
import { getPlayer, getPlayerOptional } from "../../kernel/http/request-context";
import { PlayerDataManager } from "../../kernel/PlayerDataManager";
import {
  ActAutoChessSyncInfoRequest,
  ActAutoChessSyncInfoResponse,
  AutoChessCreateTeamRequest,
  AutoChessCreateTeamResponse,
  AutoChessGetFriendAssistListRequest,
  AutoChessGetFriendAssistListResponse,
  AutoChessJoinTeamRequest,
  AutoChessJoinTeamResponse,
  AutoChessMultiBattleFinishRequest,
  AutoChessMultiBattleFinishResponse,
  AutoChessMultiBattleStartRequest,
  AutoChessMultiBattleStartResponse,
  AutoChessQueryMatchRequest,
  AutoChessQueryMatchResponse,
  AutoChessQuitSingleGameRequest,
  AutoChessQuitSingleGameResponse,
  AutoChessRemoveChessPoolCharRequest,
  AutoChessRemoveChessPoolCharResponse,
  AutoChessReportRequest,
  AutoChessReportResponse,
  AutoChessSetChessPoolDeployRequest,
  AutoChessSetChessPoolDeployResponse,
  AutoChessSetChessPoolDiyCharRequest,
  AutoChessSetChessPoolDiyCharResponse,
  AutoChessSetFriendAssistRequest,
  AutoChessSetFriendAssistResponse,
  AutoChessSettleGameRequest,
  AutoChessSettleGameResponse,
  AutoChessSettleLikeRequest,
  AutoChessSettleLikeResponse,
  AutoChessStartMatchRequest,
  AutoChessStartMatchResponse,
  AutoChessTrainingBattleFinishRequest,
  AutoChessTrainingBattleFinishResponse,
  AutoChessTrainingBattleStartRequest,
  AutoChessTrainingBattleStartResponse,
} from "./autochess";
import { emptyRequestSchema } from "./autochess.schema";
import { validateBody } from "../../kernel/http/validate-body";

const router = Router();

/** 同步赛季信息（CS: ActAutoChessSyncInfoRequest） */
router.post("/autochessSeason/syncInfo", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as ActAutoChessSyncInfoRequest;

  res.send({
    ...player.delta,
    info: {},
  } satisfies ActAutoChessSyncInfoResponse);
});

/** 设置棋子池部署（CS: AutoChessSetChessPoolDeployRequest） */
router.post("/autochessSeason/setChessPoolDeploy", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessSetChessPoolDeployRequest;

  res.send(player.delta satisfies AutoChessSetChessPoolDeployResponse);
});

/** 完成引导战斗（CS: AutoChessTrainingBattleFinishRequest） */
router.post("/autochessSeason/finishGuideBattle", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessTrainingBattleFinishRequest;

  res.send(player.delta satisfies AutoChessTrainingBattleFinishResponse);
});

/** 获取好友助战列表（CS: AutoChessGetFriendAssistListRequest） */
router.post("/autochessSeason/getFriendCharAssistList", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessGetFriendAssistListRequest;

  res.send({
    ...player.delta,
    charList: [],
  } satisfies AutoChessGetFriendAssistListResponse);
});

/** 加入队伍（CS: AutoChessJoinTeamRequest） */
router.post("/autochessSeason/joinTeam", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessJoinTeamRequest;

  res.send(player.delta satisfies AutoChessJoinTeamResponse);
});

/** 多人战斗结束（CS: AutoChessMultiBattleFinishRequest） */
router.post("/autochessSeason/multiBattleFinish", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessMultiBattleFinishRequest;

  res.send(player.delta satisfies AutoChessMultiBattleFinishResponse);
});

/** 多人战斗开始（CS: AutoChessMultiBattleStartRequest） */
router.post("/autochessSeason/multiBattleStart", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessMultiBattleStartRequest;

  res.send({
    ...player.delta,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    result: 0,
  } satisfies AutoChessMultiBattleStartResponse);
});

/** 查询匹配（CS: AutoChessQueryMatchRequest） */
router.post("/autochessSeason/queryMatch", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessQueryMatchRequest;

  res.send({
    ...player.delta,
    matchInfo: null,
    result: 1,
  } satisfies AutoChessQueryMatchResponse);
});

/** 退出单机游戏（CS: AutoChessQuitSingleGameRequest） */
router.post("/autochessSeason/quitSingleGame", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessQuitSingleGameRequest;

  res.send(player.delta satisfies AutoChessQuitSingleGameResponse);
});

/** 移除棋子池角色（CS: AutoChessRemoveChessPoolCharRequest） */
router.post("/autochessSeason/removeChessPoolChar", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessRemoveChessPoolCharRequest;

  res.send(player.delta satisfies AutoChessRemoveChessPoolCharResponse);
});

/** 上报战斗结果（服务端自定义） */
router.post("/autochessSeason/report", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessReportRequest;

  res.send(player.delta satisfies AutoChessReportResponse);
});

/** 设置棋子池助战（CS: AutoChessSetFriendAssistRequest） */
router.post("/autochessSeason/setChessPoolAssist", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessSetFriendAssistRequest;

  res.send(player.delta satisfies AutoChessSetFriendAssistResponse);
});

/** 设置棋子池自定角色（CS: AutoChessSetChessPoolDiyCharRequest） */
router.post("/autochessSeason/setChessPoolDiyChar", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessSetChessPoolDiyCharRequest;

  res.send(player.delta satisfies AutoChessSetChessPoolDiyCharResponse);
});

/** 结算游戏（CS: AutoChessSettleGameRequest） */
router.post("/autochessSeason/settleGame", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessSettleGameRequest;

  res.send({
    ...player.delta,
    result: 0,
  } satisfies AutoChessSettleGameResponse);
});

/** 点赞结算（CS: AutoChessSettleLikeRequest） */
router.post("/autochessSeason/settleLike", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessSettleLikeRequest;

  res.send(player.delta satisfies AutoChessSettleLikeResponse);
});

/** 开始匹配（CS: AutoChessStartMatchRequest） */
router.post("/autochessSeason/startMatch", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessStartMatchRequest;

  res.send(player.delta satisfies AutoChessStartMatchResponse);
});

/** 创建队伍（CS: AutoChessCreateTeamRequest） */
router.post("/autochessSeason/createTeam", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessCreateTeamRequest;

  res.send({
    ...player.delta,
    teamId: "team_" + Math.random().toString(36).substr(2, 9),
  } satisfies AutoChessCreateTeamResponse);
});

/** 开始引导战斗（CS: AutoChessTrainingBattleStartRequest） */
router.post("/autochessSeason/startGuideBattle", validateBody(emptyRequestSchema), async (req, res) => {
  const player = getPlayer();
  req.body as AutoChessTrainingBattleStartRequest;

  res.send({
    ...player.delta,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    result: 0,
  } satisfies AutoChessTrainingBattleStartResponse);
});

/** 自走棋赛季信息（客户端路由 /autoChess/act1autochess|act2autochess；stub 返回空增量） */
for (const autoChessSeason of ["act1autochess", "act2autochess"]) {
  router.post(`/${autoChessSeason}`, validateBody(emptyRequestSchema), async (req, res) => {
    const player = getPlayer();
    res.send(player.delta satisfies { playerDataDelta: unknown });
  });
}

export default router;
