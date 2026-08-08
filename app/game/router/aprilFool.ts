import httpContext from "express-http-context2";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { Router } from "express";
import { decryptBattleData } from "@utils/crypt";
import {
  Act3FunBattleFinishRequest,
  Act3FunBattleFinishResponse,
  Act3FunBattleStartRequest,
  Act3FunBattleStartResponse,
  Act3FunScoreBattleFinishResponse,
  Act4FunBattleFinishRequest,
  Act4FunBattleFinishResponse,
  Act4FunBattleStartRequest,
  Act4FunBattleStartResponse,
  Act4FunLiveSettleRequest,
  Act4FunLiveSettleResponse,
  Act6FunBattleFinishRequest,
  Act6FunBattleFinishResponse,
  Act6FunBattleStartRequest,
  Act6FunBattleStartResponse,
  Act7FunBattleFinishRequest,
  Act7FunBattleFinishResponse,
  Act7FunBattleStartRequest,
  Act7FunBattleStartResponse,
} from "@game/model/protocol/aprilFool";

const router = Router();

/** 愚人节通用开始战斗 stub（固定 battleId，参考 ODPY/OBS） */
function aprilFoolBattleStart() {
  return {
    result: 0,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    apFailReturn: 0,
    isApProtect: 0,
    inApProtectPeriod: false,
    notifyPowerScoreNotEnoughIfFailed: false,
  };
}

/** 解密战斗数据（失败时返回 null，调用方回退默认值） */
async function tryDecryptBattle(
  player: PlayerDataManager,
  data: string,
): Promise<any | null> {
  try {
    return await decryptBattleData(data, player._playerdata.pushFlags.status);
  } catch {
    return null;
  }
}

router.post("/act5fun/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act3FunBattleStartRequest;
  res.send({
    ...aprilFoolBattleStart(),
    ...player.delta,
  } satisfies Act3FunBattleStartResponse);
});
router.post("/act5fun/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act3FunBattleFinishRequest;
  res.send({
    ...(await player.aprilFool.act5funBattleFinish(body)),
    ...player.delta,
  } satisfies Act3FunBattleFinishResponse);
});

/** act3fun 开始战斗（CS: Act3FunBattleStartRequest） */
router.post("/act3fun/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act3FunBattleStartRequest;
  res.send({
    ...aprilFoolBattleStart(),
    ...player.delta,
  } satisfies Act3FunBattleStartResponse);
});

/**
 * act3fun 战斗结算（CS: Act3FunBattleFinishResponse : DefaultFinishBattleResponse
 * { score, inRank, scoreItem, rank }）
 */
router.post("/act3fun/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act3FunBattleFinishRequest;
  await tryDecryptBattle(player, body.data);
  res.send({
    score: 0,
    inRank: false,
    scoreItem: [],
    rank: [],
    ...player.delta,
  } satisfies Act3FunScoreBattleFinishResponse);
});

/** act4fun 开始战斗（CS: Act4FunBattleStartRequest） */
router.post("/act4fun/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act4FunBattleStartRequest;
  res.send({
    ...aprilFoolBattleStart(),
    ...player.delta,
  } satisfies Act4FunBattleStartResponse);
});

/**
 * act4fun 战斗结算（CS: Act4FunBattleFinishResponse : DefaultFinishBattleResponse
 * { liveId, materials }；私服返回空材料列表）
 */
router.post("/act4fun/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act4FunBattleFinishRequest;
  res.send({
    liveId: "",
    materials: [],
    ...player.delta,
  } satisfies Act4FunBattleFinishResponse);
});

/** act4fun 直播结算（服务端自定义 stub） */
router.post("/act4fun/liveSettle", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act4FunLiveSettleRequest;
  res.send(player.delta satisfies Act4FunLiveSettleResponse);
});

/** act6fun 开始战斗（CS: Act6FunBattleStartRequest） */
router.post("/act6fun/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act6FunBattleStartRequest;
  res.send({
    ...aprilFoolBattleStart(),
    ...player.delta,
  } satisfies Act6FunBattleStartResponse);
});

/**
 * act6fun 战斗结算（CS: Act6FunBattleFinishResponse : DefaultFinishBattleResponse
 * { completeState, passSec, newRecord, coin }）
 * 参考 ODPY act6fun_questBattleFinish：从战斗数据解析完成状态/耗时/金币
 */
router.post("/act6fun/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act6FunBattleFinishRequest;
  const battleData = await tryDecryptBattle(player, body.data);
  let completeState = 0;
  let passSec = 0;
  let coin = 0;
  if (battleData) {
    completeState = battleData.completeState ?? 0;
    passSec = battleData.battleData?.completeTime ?? 0;
    const extra = battleData.battleData?.stats?.extraBattleInfo ?? {};
    for (const [key, value] of Object.entries(extra)) {
      if (key.startsWith("coin_collect_cnt")) {
        coin = Number(value);
      }
    }
  }
  res.send({
    completeState,
    passSec,
    newRecord: false,
    coin,
    ...player.delta,
  } satisfies Act6FunBattleFinishResponse);
});

/** act7fun 开始战斗（CS: Act7FunBattleStartRequest） */
router.post("/act7fun/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act7FunBattleStartRequest;
  res.send({
    ...aprilFoolBattleStart(),
    ...player.delta,
  } satisfies Act7FunBattleStartResponse);
});

/**
 * act7fun 战斗结算（CS: Act7FunBattleFinishResponse : DefaultFinishBattleResponse
 * { completeState, rewards, unlockedStages }）
 * 参考 ODPY act7fun_questBattleFinish：解析完成状态，奖励/解锁关卡返回空
 */
router.post("/act7fun/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act7FunBattleFinishRequest;
  const battleData = await tryDecryptBattle(player, body.data);
  res.send({
    completeState: battleData?.completeState ?? 0,
    rewards: [],
    unlockedStages: [],
    ...player.delta,
  } satisfies Act7FunBattleFinishResponse);
});

export default router;
