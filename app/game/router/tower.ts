/**
 * 爬塔路由模块
 * 
 * 处理保全派驻相关的 HTTP 请求，包括游戏创建、神卡初始化、战斗处理等功能。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { now } from "@utils/time";

const router = Router();

/**
 * 创建爬塔游戏
 * @route POST /tower/createGame
 * @param req.body.tower - 塔ID
 * @param req.body.isHard - 是否困难模式
 * @returns 玩家增量数据
 */
router.post("/createGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { tower, isHard } = req.body;

  res.send({
    playerDataDelta: {
      modified: {
        tower: {
          current: {
            cards: {},
            godCard: {
              id: "",
              subGodCardId: "",
            },
            halftime: {
              canGiveUp: false,
              candidate: [],
              count: 0,
            },
            layer: [],
            reward: {
              high: 0,
              low: 0,
            },
            status: {
              coord: 0,
              isHard: isHard === 1,
              start: Math.round(now()),
              state: "INIT_GOD_CARD",
              strategy: "OPTIMIZE",
              tactical: {
                CASTER: "",
                MEDIC: "",
                PIONEER: "",
                SNIPER: "",
                SPECIAL: "",
                SUPPORT: "",
                TANK: "",
                WARRIOR: "",
              },
              tower,
            },
            trap: [],
          },
        },
      },
      deleted: {},
    },
  });
});

/**
 * 初始化神卡
 * @route POST /tower/initGodCard
 * @param req.body.godCardId - 神卡ID
 * @returns 玩家增量数据
 */
router.post("/initGodCard", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { godCardId } = req.body;

  res.send({
    playerDataDelta: {
      modified: {
        tower: {
          current: {
            godCard: {
              id: godCardId,
              subGodCardId: "",
            },
            status: {
              state: "INIT_BUFF",
            },
          },
        },
      },
      deleted: {},
    },
  });
});

/**
 * 初始化游戏
 * @route POST /tower/initGame
 * @param req.body.strategy - 策略
 * @param req.body.tactical - 战术配置
 * @returns 玩家增量数据
 */
router.post("/initGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { strategy, tactical } = req.body;

  res.send({
    playerDataDelta: {
      modified: {
        tower: {
          current: {
            status: {
              state: "INIT_CARD",
              strategy,
              tactical,
            },
          },
        },
      },
      deleted: {},
    },
  });
});

/**
 * 初始化卡牌
 * @route POST /tower/initCard
 * @param req.body.slots - 槽位列表
 * @returns 玩家增量数据
 */
router.post("/initCard", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { slots } = req.body;

  res.send({
    playerDataDelta: {
      modified: {
        tower: {
          current: {
            status: {
              state: "STANDBY",
            },
          },
        },
      },
      deleted: {},
    },
  });
});

/**
 * 爬塔战斗开始
 * @route POST /tower/battleStart
 * @param req.body.stageId - 关卡ID
 * @returns 玩家增量数据
 */
router.post("/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { stageId } = req.body;

  res.send({
    playerDataDelta: {
      modified: {},
      deleted: {},
    },
  });
});

/**
 * 爬塔战斗结束
 * @route POST /tower/battleFinish
 * @param req.body.data - 战斗数据
 * @returns 战斗结果和玩家增量数据
 */
router.post("/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;

  res.send({
    drop: [],
    isNewRecord: false,
    trap: [],
    playerDataDelta: {
      modified: {},
      deleted: {},
    },
  });
});

/**
 * 爬塔招募
 * @route POST /tower/recruit
 * @param req.body.charId - 干员ID
 * @param req.body.giveUp - 是否放弃
 * @returns 玩家增量数据
 */
router.post("/recruit", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;

  res.send({
    playerDataDelta: {
      modified: {},
      deleted: {},
    },
  });
});

/**
 * 选择副神卡
 * @route POST /tower/chooseSubGodCard
 * @param req.body.subGodCardId - 副神卡ID
 * @returns 玩家增量数据
 */
router.post("/chooseSubGodCard", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { subGodCardId } = req.body;

  res.send({
    playerDataDelta: {
      modified: {
        tower: {
          current: {
            godCard: {
              subGodCardId,
            },
            status: {
              state: "STANDBY",
            },
          },
        },
      },
      deleted: {},
    },
  });
});

/**
 * 爬塔结算
 * @route POST /tower/settleGame
 * @returns 奖励和玩家增量数据
 */
router.post("/settleGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;

  res.send({
    reward: {
      high: { cnt: 0, from: 24, to: 24 },
      low: { cnt: 0, from: 60, to: 60 },
    },
    ts: Math.round(now()),
    playerDataDelta: {
      modified: {
        tower: {
          current: {
            status: {
              state: "NONE",
              tower: "",
              coord: 0,
              tactical: {
                PIONEER: "",
                WARRIOR: "",
                TANK: "",
                SNIPER: "",
                CASTER: "",
                SUPPORT: "",
                MEDIC: "",
                SPECIAL: "",
              },
              strategy: "OPTIMIZE",
              start: 0,
              isHard: false,
            },
            layer: [],
            cards: {},
            godCard: {
              id: "",
              subGodCardId: "",
            },
            halftime: { count: 0, candidate: [], canGiveUp: false },
            trap: [],
            reward: {},
          },
        },
      },
      deleted: {},
    },
  });
});

/**
 * 获取层奖励
 * @route POST /tower/layerReward
 * @returns 空响应（202）
 */
router.post("/layerReward", async (req, res) => {
  res.sendStatus(202);
});

/**
 * 获取赛季任务奖励
 * @route POST /tower/seasonMissionsAward
 * @returns 空响应（202）
 */
router.post("/seasonMissionsAward", async (req, res) => {
  res.sendStatus(202);
});

/**
 * 扫荡游戏
 * @route POST /tower/sweepGame
 * @returns 空响应（202）
 */
router.post("/sweepGame", async (req, res) => {
  res.sendStatus(202);
});

export default router;