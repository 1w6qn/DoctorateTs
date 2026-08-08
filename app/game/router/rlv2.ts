/**
 * 肉鸽V2（集成战略）路由
 * 请求/响应类型见 @game/model/protocol/rlv2（参考 CS 2.7.61 协议类）
 */
import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import {
  FinishBattleRewardRequest,
  FinishBattleRewardResponse,
  RL03ConfirmPredictRequest,
  RL03ConfirmPredictResponse,
  RL03UseTotemRequest,
  RL03UseTotemResponse,
  RL04LoseFragmentRequest,
  RL04LoseFragmentResponse,
  RL04UseInspirationRequest,
  RL04UseInspirationResponse,
  RoguelikeActivateTicketRequest,
  RoguelikeActivateTicketResponse,
  RoguelikeCloseTicketRequest,
  RoguelikeCloseTicketResponse,
  RoguelikeFinishBattleRequest,
  RoguelikeFinishBattleResponse,
  RoguelikeFinishEventRequest,
  RoguelikeFinishEventResponse,
  RoguelikeSelectChoiceRequest,
  RoguelikeSelectChoiceResponse,
  RoguelikeMoveToRequest,
  RoguelikeMoveToResponse,
  RoguelikePinTopicRequest,
  RoguelikePinTopicResponse,
  RoguelikeRecruitCharRequest,
  RoguelikeRecruitCharResponse,
  RoguelikeSelectInitialRecruitSetRequest,
  RoguelikeSelectInitialRecruitSetResponse,
  RoguelikeSelectInitialRelicRequest,
  RoguelikeSelectInitialRelicResponse,
  RoguelikeSelectRewardRequest,
  RoguelikeSelectRewardResponse,
  RoguelikeShopActionRequest,
  RoguelikeShopActionResponse,
  RoguelikeShopRefreshRequest,
  RoguelikeShopRefreshResponse,
  RoguelikeStepMoveToAndStartBattleRequest,
  RoguelikeStepMoveToAndStartBattleResponse,
  RoguelikeTopicCreateGameRequest,
  RoguelikeTopicCreateGameResponse,
  RoguelikeTopicGiveUpGameRequest,
  RoguelikeTopicGiveUpGameResponse,
  SetTroopCarryRequest,
  SetTroopCarryResponse,
} from "../model/protocol/rlv2";

const router = Router();

/** 放弃游戏（CS: RoguelikeTopicGiveUpGameRequest） */
router.post("/giveUpGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeTopicGiveUpGameRequest;
  player.rlv2.giveUpGame();
  res.send(player.delta satisfies RoguelikeTopicGiveUpGameResponse);
});

/** 创建游戏（CS: RoguelikeTopicCreateGameRequest） */
router.post("/createGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeTopicCreateGameRequest;
  await player.rlv2.createGame(body);
  res.send(player.delta satisfies RoguelikeTopicCreateGameResponse);
});

/** 选择初始密文（CS: RoguelikeSelectInitialRelicRequest） */
router.post("/chooseInitialRelic", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeSelectInitialRelicRequest;
  await player.rlv2.chooseInitialRelic(body);
  res.send(player.delta satisfies RoguelikeSelectInitialRelicResponse);
});

/** 选择初始招募组（CS: RoguelikeSelectInitialRecruitSetRequest） */
router.post("/chooseInitialRecruitSet", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeSelectInitialRecruitSetRequest;
  await player.rlv2.chooseInitialRecruitSet(body);
  res.send(player.delta satisfies RoguelikeSelectInitialRecruitSetResponse);
});

/** 激活招募票（CS: RoguelikeActivateTicketRequest） */
router.post("/activeRecruitTicket", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeActivateTicketRequest;
  await player.rlv2.activeRecruitTicket(body);
  res.send(player.delta satisfies RoguelikeActivateTicketResponse);
});

/** 招募干员（CS: RoguelikeRecruitCharRequest） */
router.post("/recruitChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeRecruitCharRequest;
  res.send({
    chars: await player.rlv2.recruitChar(body),
    ...player.delta,
  } satisfies RoguelikeRecruitCharResponse);
});

/** 结束事件（CS: RoguelikeFinishEventRequest） */
router.post("/finishEvent", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeFinishEventRequest;
  await player.rlv2.finishEvent();
  res.send(player.delta satisfies RoguelikeFinishEventResponse);
});

/**
 * 选择事件选项（CS: RoguelikeSelectChoiceRequest）
 * 控制器 selectChoice 已实现（buff/遗物/下一场景构建），此前漏接线
 */
router.post("/selectChoice", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeSelectChoiceRequest;
  await player.rlv2.selectChoice(body);
  res.send(player.delta satisfies RoguelikeSelectChoiceResponse);
});

/** 移动（CS: RoguelikeMoveToRequest） */
router.post("/moveTo", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeMoveToRequest;
  await player.rlv2.moveTo(body);
  res.send(player.delta satisfies RoguelikeMoveToResponse);
});

/** 移动并开始战斗（CS: RoguelikeStepMoveToAndStartBattleRequest） */
router.post("/moveAndBattleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeStepMoveToAndStartBattleRequest;
  await player.rlv2.moveAndBattleStart(body);
  res.send(player.delta satisfies RoguelikeStepMoveToAndStartBattleResponse);
});

/** 战斗结算（CS: RoguelikeFinishBattleRequest） */
router.post("/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeFinishBattleRequest;
  await player.rlv2.battleFinish(body);
  res.send(player.delta satisfies RoguelikeFinishBattleResponse);
});

/** 选择战斗奖励（CS: RoguelikeSelectRewardRequest） */
router.post("/chooseBattleReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeSelectRewardRequest;
  player.rlv2.chooseBattleReward(body);
  res.send(player.delta satisfies RoguelikeSelectRewardResponse);
});

/** 完成战斗奖励（服务端自定义） */
router.post("/finishBattleReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as FinishBattleRewardRequest;
  await player.rlv2.finishBattleReward(body);
  res.send(player.delta satisfies FinishBattleRewardResponse);
});

/** 设置队伍携带（服务端自定义） */
router.post("/setTroopCarry", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as SetTroopCarryRequest;
  player.rlv2.setTroopCarry(body);
  res.send(player.delta satisfies SetTroopCarryResponse);
});

/** 丢失密文（CS: RL04LoseFragmentRequest） */
router.post("/loseFragment", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RL04LoseFragmentRequest;
  player.rlv2.loseFragment(body);
  res.send(player.delta satisfies RL04LoseFragmentResponse);
});

/** 使用灵感（CS: RL04UseInspirationRequest） */
router.post("/useInspiration", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RL04UseInspirationRequest;
  player.rlv2.useInspiration(body);
  res.send(player.delta satisfies RL04UseInspirationResponse);
});

/** 置顶主题（CS: RoguelikePinTopicRequest） */
router.post("/setPinned", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikePinTopicRequest;
  player.rlv2.setPinned(body);
  res.send(player.delta satisfies RoguelikePinTopicResponse);
});

/** 刷新商店（CS: RoguelikeShopRefreshRequest） */
router.post("/refreshShop", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeShopRefreshRequest;
  await player.rlv2.refreshShop();
  res.send(player.delta satisfies RoguelikeShopRefreshResponse);
});

/** 离开商店（CS: RoguelikeShopActionRequest） */
router.post("/leaveShop", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeShopActionRequest;
  await player.rlv2.leaveShop();
  res.send(player.delta satisfies RoguelikeShopActionResponse);
});

/** 使用图腾（CS: RL03UseTotemRequest） */
router.post("/useTotem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RL03UseTotemRequest;
  await player.rlv2.useTotem(body);
  res.send(player.delta satisfies RL03UseTotemResponse);
});

/** 确认预言（CS: RL03ConfirmPredictRequest） */
router.post("/confirmPredict", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RL03ConfirmPredictRequest;
  await player.rlv2.confirmPredict();
  res.send(player.delta satisfies RL03ConfirmPredictResponse);
});

/** 关闭招募票（CS: RoguelikeCloseTicketRequest） */
router.post("/closeRecruitTicket", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeCloseTicketRequest;
  await player.rlv2.closeRecruitTicket(body);
  res.send(player.delta satisfies RoguelikeCloseTicketResponse);
});

export default router;
