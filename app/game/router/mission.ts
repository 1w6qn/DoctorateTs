/**
 * 任务路由
 * 请求/响应类型见 @game/model/protocol/mission（参考 CS 2.7.61 协议类）
 */
import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import {
  AutoConfirmMissionsRequest,
  AutoConfirmMissionsResponse,
  ConfirmMissionGroupRequest,
  ConfirmMissionGroupResponse,
  ConfirmMissionRequest,
  ConfirmMissionResponse,
  ExchangeMissionRewardsRequest,
  ExchangeMissionRewardsResponse,
} from "../model/protocol/mission";

const router = Router();

/** 确认单个任务（CS: ConfirmMissionRequest） */
router.post("/confirmMission", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ConfirmMissionRequest;
  res.send({
    items: await player.mission.confirmMission(body),
    ...player.delta,
  } satisfies ConfirmMissionResponse);
});

/** 确认任务组（CS: ConfirmMissionGroupRequest） */
router.post("/confirmMissionGroup", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ConfirmMissionGroupRequest;
  await player.mission.confirmMissionGroup(body);
  res.send(player.delta satisfies ConfirmMissionGroupResponse);
});

/** 自动确认任务（CS: AutoConfirmMissionsRequest） */
router.post("/autoConfirmMissions", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as AutoConfirmMissionsRequest;
  res.send({
    items: await player.mission.autoConfirmMissions(body),
    ...player.delta,
  } satisfies AutoConfirmMissionsResponse);
});

/** 兑换任务奖励（CS: ExchangeMissionRewardsRequest） */
router.post("/exchangeMissionRewards", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ExchangeMissionRewardsRequest;
  await player.mission.exchangeMissionRewards(body);
  res.send({ ...player.delta } satisfies ExchangeMissionRewardsResponse);
});

export default router;
