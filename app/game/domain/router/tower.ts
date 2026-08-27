/**
 * 爬塔路由模块
 *
 * 处理保全派驻相关的 HTTP 请求，包括游戏创建、神卡初始化、战斗处理等功能。
 * 请求/响应类型见 @game/domain/tower/tower（参考 CS 2.7.61 协议类）。
 *
 * 实现说明：
 * - 路由处理函数通过 PlayerDataManager.update() 修改玩家数据，并使用 player.delta 返回增量。
 * - 爬塔状态保存在 player.tower.current 中，所有变更均通过 Immer 跟踪。
 * - 战斗结果与随机招募逻辑相比 Python 参考实现有所简化，但保证玩家数据正确更新。
 */

import { Router } from "express";
import { getPlayer, getPlayerOptional } from "../../request-context";
import { PlayerDataManager } from "@game/service/PlayerDataManager";
import { now } from "@utils/time";
import { decryptBattleData } from "@utils/crypt";
import { randomSample } from "@utils/random";
import excel from "@excel/excel";
import { logger } from "@utils/logger";
import {
  ClimbTowerBattleFinishRequest,
  ClimbTowerBattleFinishResponse,
  ClimbTowerBattleStartRequest,
  ClimbTowerBattleStartResponse,
  ClimbTowerCreateGameRequest,
  ClimbTowerCreateGameResponse,
  ClimbTowerHalftimeRecruitRequest,
  ClimbTowerHalftimeRecruitResponse,
  ClimbTowerInitGameRequest,
  ClimbTowerInitGameResponse,
  ClimbTowerInitGodCardRequest,
  ClimbTowerInitGodCardResponse,
  ClimbTowerInitSquadRequest,
  ClimbTowerInitSquadResponse,
  ClimbTowerLayerFirstPassRewardRequest,
  ClimbTowerLayerFirstPassRewardResponse,
  ClimbTowerRecruitSubGodCardRequest,
  ClimbTowerRecruitSubGodCardResponse,
  ClimbTowerSeasonMissionAwardRequest,
  ClimbTowerSeasonMissionAwardResponse,
  ClimbTowerSettleGameRequest,
  ClimbTowerSettleGameResponse,
  ClimbTowerSweepRequest,
  ClimbTowerSweepResponse,
} from "../../domain/tower/tower";
import { validateBody } from "../../domain/contracts/validate-body";
import {
  battleFinishSchema,
  battleStartSchema,
  chooseSubGodCardSchema,
  createGameSchema,
  initCardSchema,
  initGameSchema,
  initGodCardSchema,
  layerRewardSchema,
  recruitSchema,
  seasonMissionsAwardSchema,
  settleGameSchema,
  sweepGameSchema,
} from "../../domain/tower/tower.schema";

const router = Router();

/**
 * 生成爬塔招募候选列表
 *
 * 从玩家未在当前爬塔卡组中使用的干员里随机抽取 5 名，构造候选列表。
 * 简化实现：与 Python 参考相比不依赖 dexNav，直接遍历 troop.chars。
 *
 * @param draft - 玩家数据的 Immer 草稿
 * @returns 候选干员列表（结构同协议中 halftime.candidate）
 */
function buildRecruitCandidate(draft: any): any[] {
  const allCards = Object.keys(draft.troop.chars);
  const usedCards = Object.values(draft.tower.current.cards).map(
    (c: any) => c.relation,
  );
  const available = allCards.filter((c) => !usedCards.includes(c));
  // 候选数量上限为 5，不足时返回全部可用干员
  const picked = randomSample(
    [...available],
    Math.min(5, available.length),
  );
  return picked.map((charInstId) => {
    const char = draft.troop.chars[charInstId];
    return {
      groupId: char.charId,
      type: "CHAR",
      cards: [
        {
          instId: "0",
          type: "CHAR",
          charId: char.charId,
          relation: charInstId,
          evolvePhase: char.evolvePhase,
          level: char.level,
          favorPoint: char.favorPoint,
          potentialRank: char.potentialRank,
          mainSkillLvl: char.mainSkillLvl,
          skills: char.skills ?? [],
          defaultSkillIndex: char.defaultSkillIndex ?? 0,
          currentEquip: char.currentEquip ?? null,
          equip: char.equip ?? {},
          skin: char.skin ?? "",
        },
      ],
    };
  });
}

/**
 * 创建爬塔游戏
 *
 * 根据 tower 与 isHard 参数从塔表中读取关卡列表，初始化爬塔状态机。
 * 状态切换为 INIT_GOD_CARD，等待玩家选择主神卡。
 *
 * @route POST /tower/createGame
 * @param req.body.tower - 塔ID
 * @param req.body.isHard - 是否困难模式（1 表示困难）
 * @returns 玩家增量数据，包含完整的 tower.current 初始化结构
 */
router.post("/createGame", validateBody(createGameSchema), async (req, res) => {
  const player = getPlayer();
  const { tower, isHard } = req.body as ClimbTowerCreateGameRequest;

  // 缺参校验：tower 为必填字段
  if (tower == null) {
    res.send({ result: 1, ...player.delta } as ClimbTowerCreateGameResponse);
    return;
  }

  // 从塔表中读取对应模式（普通/困难）的关卡列表
  const towerData = excel.ClimbTowerTable.towers[tower];
  const levels =
    isHard === 1 ? towerData.hardLevels : towerData.levels;

  // 构造层数列表，每层初始尝试次数为 0 且未通过
  const layer = levels.map((level: string) => ({
    id: level,
    tryNum: 0,
    pass: 0,
  }));

  await player.update(async (draft) => {
    draft.tower.current = {
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
      layer,
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
    };
  });

  res.send(player.delta satisfies ClimbTowerCreateGameResponse);
});

/**
 * 初始化神卡
 *
 * 设置玩家选择的主神卡 ID，状态由 INIT_GOD_CARD 切换为 INIT_BUFF。
 *
 * @route POST /tower/initGodCard
 * @param req.body.godCardId - 神卡ID
 * @returns 玩家增量数据
 */
router.post("/initGodCard", validateBody(initGodCardSchema), async (req, res) => {
  const player = getPlayer();
  const { godCardId } = req.body as ClimbTowerInitGodCardRequest;

  await player.update(async (draft) => {
    draft.tower.current.status.state = "INIT_BUFF";
    draft.tower.current.godCard.id = godCardId;
  });

  res.send(player.delta satisfies ClimbTowerInitGodCardResponse);
});

/**
 * 初始化游戏
 *
 * 设置策略与战术配置，状态由 INIT_BUFF 切换为 INIT_CARD，等待玩家选卡。
 *
 * @route POST /tower/initGame
 * @param req.body.strategy - 策略（如 OPTIMIZE）
 * @param req.body.tactical - 战术配置，按职业映射战术 buff ID
 * @returns 玩家增量数据
 */
router.post("/initGame", validateBody(initGameSchema), async (req, res) => {
  const player = getPlayer();
  const { strategy, tactical } = req.body as ClimbTowerInitGameRequest;

  await player.update(async (draft) => {
    draft.tower.current.status.state = "INIT_CARD";
    draft.tower.current.status.strategy = strategy;
    draft.tower.current.status.tactical = tactical;
  });

  res.send(player.delta satisfies ClimbTowerInitGameResponse);
});

/**
 * 初始化卡牌
 *
 * 根据玩家选择的槽位列表，从 troop.chars 中读取对应干员数据，
 * 复制到爬塔卡组 tower.current.cards 中。状态由 INIT_CARD 切换为 STANDBY。
 *
 * @route POST /tower/initCard
 * @param req.body.slots - 槽位数组，每项包含 charInstId、skillIndex、currentEquip
 * @returns 玩家增量数据
 */
router.post("/initCard", validateBody(initCardSchema), async (req, res) => {
  const player = getPlayer();
  const { slots } = req.body as ClimbTowerInitSquadRequest;

  // 缺参校验：slots 必须为非空数组
  if (!Array.isArray(slots) || slots.length === 0) {
    res.send({ result: 1, ...player.delta } as ClimbTowerInitSquadResponse);
    return;
  }

  await player.update(async (draft) => {
    draft.tower.current.status.state = "STANDBY";

    let cnt = 1;
    for (const slot of slots) {
      const charInstId = String(slot.charInstId);
      const char = draft.troop.chars[charInstId];
      draft.tower.current.cards[String(cnt)] = {
        charId: char.charId,
        currentEquip: slot.currentEquip ?? null,
        // 注意：协议字段为 defaultSkillIndex，对应请求中的 skillIndex
        defaultSkillIndex: slot.skillIndex ?? char.defaultSkillIndex ?? 0,
        equip: char.equip ?? {},
        evolvePhase: char.evolvePhase,
        favorPoint: char.favorPoint,
        instId: String(cnt),
        level: char.level,
        mainSkillLvl: char.mainSkillLvl,
        potentialRank: char.potentialRank,
        relation: charInstId,
        skills: char.skills ?? [],
        skin: char.skin ?? "",
        type: "CHAR",
      };
      cnt += 1;
    }
  });

  res.send(player.delta satisfies ClimbTowerInitSquadResponse);
});

/**
 * 爬塔战斗开始
 *
 * 记录当前关卡在 layer 列表中的索引到 status.coord，并增加该关卡的尝试次数。
 *
 * @route POST /tower/battleStart
 * @param req.body.stageId - 关卡ID
 * @returns 玩家增量数据
 */
router.post("/battleStart", validateBody(battleStartSchema), async (req, res) => {
  const player = getPlayer();
  const { stageId } = req.body as ClimbTowerBattleStartRequest;

  await player.update(async (draft) => {
    // 计算当前关卡在层数列表中的索引（0-based）
    const coord = draft.tower.current.layer.findIndex(
      (l: any) => l.id === stageId,
    );
    if (coord >= 0) {
      draft.tower.current.status.coord = coord;
    }
    // 增加当前关卡的尝试次数
    for (const stage of draft.tower.current.layer) {
      if (stage.id === stageId) {
        stage.tryNum += 1;
        break;
      }
    }
  });

  res.send(player.delta satisfies ClimbTowerBattleStartResponse);
});

/**
 * 爬塔战斗结束
 *
 * 解密战斗数据并根据 completeState 处理结果：
 * - completeState === 1：失败，仅增加尝试次数。
 * - 其他值：成功，根据当前关卡位置切换状态：
 *   - 第三层（索引 2）：进入 SUB_GOD_CARD_RECRUIT，解析 trap 信息。
 *   - 最后一层：进入 END 状态。
 *   - 其他层：进入 RECRUIT 状态。
 * 成功时还会推进 coord、增加 halftime.count 并刷新招募候选列表。
 *
 * @route POST /tower/battleFinish
 * @param req.body.data - 加密的战斗数据
 * @returns 战斗结果（drop/isNewRecord/trap）与玩家增量数据
 */
router.post("/battleFinish", validateBody(battleFinishSchema), async (req, res) => {
  const player = getPlayer();
  const { data } = req.body as ClimbTowerBattleFinishRequest;

  // 解密战斗数据（失败时不影响主流程，按失败处理）
  let battleData: any;
  try {
    battleData = await decryptBattleData(data, player.loginTime);
  } catch (err) {
    logger.error("tower/battleFinish", "decrypt failed:", err);
    res.send({
      drop: [],
      isNewRecord: false,
      trap: [],
      ...player.delta,
    } satisfies ClimbTowerBattleFinishResponse);
    return;
  }

  const trap: { id: string; alias: string }[] = [];

  await player.update(async (draft) => {
    const current = draft.tower.current;
    const coord = current.status.coord;

    if (battleData.completeState === 1) {
      // 战斗失败：tryNum 已在 battleStart 计入（修复：原实现 start 与 finish 双计 → 2 倍）
      return;
    }

    // 战斗成功
    const currentStage = current.layer[coord]?.id;
    const layerCount = current.layer.length;

    if (layerCount >= 3 && coord === 2) {
      // 第三层：进入副神卡招募阶段
      current.status.state = "SUB_GOD_CARD_RECRUIT";
      // 解析 trap 信息：键名格式形如 "DETAILED,<id>,<alias>,legion_gain_reward_trap"
      const stats = battleData?.battleData?.stats ?? {};
      const extraBattleInfo = stats.extraBattleInfo ?? {};
      for (const key of Object.keys(extraBattleInfo)) {
        if (
          key.startsWith("DETAILED") &&
          key.endsWith("legion_gain_reward_trap")
        ) {
          const parts = key.split(",");
          if (parts.length >= 3) {
            trap.push({
              id: parts[1],
              alias: parts[2],
            });
          }
        }
      }
      current.trap = trap;
    } else if (coord === layerCount - 1) {
      // 最后一层：游戏结束
      current.status.state = "END";
    } else {
      // 其他层：进入招募阶段
      current.status.state = "RECRUIT";
    }

    // 增加当前层尝试次数：已由 battleStart 计入（修复：原实现 start 与 finish 双计 → 2 倍）
    // for (const stage of current.layer) { if (stage.id === currentStage) { stage.tryNum += 1; break; } }

    // 推进坐标与中场计数，并刷新招募候选
    current.status.coord += 1;
    current.halftime.count += 1;
    current.halftime.candidate = buildRecruitCandidate(draft);
  });

  res.send({
    drop: [],
    isNewRecord: false,
    trap,
    ...player.delta,
  } satisfies ClimbTowerBattleFinishResponse);
});

/**
 * 爬塔招募
 *
 * 处理玩家在招募阶段的选择：
 * - halftime.count === 1 时保持 RECRUIT 状态并重置 count（用于连续招募）。
 * - 否则切换到 STANDBY 状态，继续推进关卡。
 * - giveUp !== 1 时，根据 charId 在 troop.chars 中查找干员并加入爬塔卡组。
 * 最后刷新招募候选列表。
 *
 * @route POST /tower/recruit
 * @param req.body.charId - 干员ID
 * @param req.body.giveUp - 是否放弃（1 表示放弃招募）
 * @returns 玩家增量数据
 */
router.post("/recruit", validateBody(recruitSchema), async (req, res) => {
  const player = getPlayer();
  const { charId, giveUp } = req.body as ClimbTowerHalftimeRecruitRequest;

  await player.update(async (draft) => {
    const current = draft.tower.current;

    // 根据 halftime 计数切换状态
    if (current.halftime.count === 1) {
      current.status.state = "RECRUIT";
      current.halftime.count = 0;
    } else {
      current.status.state = "STANDBY";
    }

    if (giveUp !== 1) {
      // 招募指定干员到爬塔卡组：instId 接在已有卡组末尾（+2 与参考实现保持一致）
      const cnt = Object.keys(current.cards).length + 2;
      // 通过 charId 在 troop.chars 中查找第一个匹配的 instId
      let charInstId = "";
      for (const [instId, char] of Object.entries(draft.troop.chars)) {
        if ((char as any).charId === charId) {
          charInstId = instId;
          break;
        }
      }
      const char = draft.troop.chars[charInstId];
      if (char) {
        current.cards[String(cnt)] = {
          charId,
          currentEquip: char.currentEquip ?? null,
          defaultSkillIndex: char.defaultSkillIndex ?? 0,
          equip: char.equip ?? {},
          evolvePhase: char.evolvePhase,
          favorPoint: char.favorPoint,
          instId: String(cnt),
          level: char.level,
          mainSkillLvl: char.mainSkillLvl,
          potentialRank: char.potentialRank,
          relation: charInstId,
          skills: char.skills ?? [],
          skin: char.skin ?? "",
          type: "CHAR",
        };
      }
    }

    // 重新生成招募候选列表
    current.halftime.candidate = buildRecruitCandidate(draft);
  });

  res.send(player.delta satisfies ClimbTowerHalftimeRecruitResponse);
});

/**
 * 选择副神卡
 *
 * 设置玩家选择的副神卡 ID，状态由 SUB_GOD_CARD_RECRUIT 切换为 STANDBY。
 *
 * @route POST /tower/chooseSubGodCard
 * @param req.body.subGodCardId - 副神卡ID
 * @returns 玩家增量数据
 */
router.post("/chooseSubGodCard", validateBody(chooseSubGodCardSchema), async (req, res) => {
  const player = getPlayer();
  const { subGodCardId } = req.body as ClimbTowerRecruitSubGodCardRequest;

  await player.update(async (draft) => {
    draft.tower.current.status.state = "STANDBY";
    draft.tower.current.godCard.subGodCardId = subGodCardId;
  });

  res.send(player.delta satisfies ClimbTowerRecruitSubGodCardResponse);
});

/**
 * 爬塔结算
 *
 * 重置 tower.current 全部字段到初始状态，状态切换为 NONE。
 * 返回结算奖励（简化为固定数值）与时间戳。
 *
 * @route POST /tower/settleGame
 * @returns 奖励信息、时间戳与玩家增量数据
 */
router.post("/settleGame", validateBody(settleGameSchema), async (req, res) => {
  const player = getPlayer();
  req.body as ClimbTowerSettleGameRequest;

  await player.update(async (draft) => {
    draft.tower.current.status = {
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
    };
    draft.tower.current.layer = [];
    draft.tower.current.cards = {};
    draft.tower.current.godCard = {
      id: "",
      subGodCardId: "",
    };
    draft.tower.current.halftime = {
      count: 0,
      candidate: [],
      canGiveUp: false,
    };
    draft.tower.current.trap = [];
    draft.tower.current.reward = { high: 0, low: 0 };
  });

  res.send({
    reward: {
      high: { cnt: 0, from: 24, to: 24 },
      low: { cnt: 0, from: 60, to: 60 },
    },
    ts: Math.round(now()),
    ...player.delta,
  } satisfies ClimbTowerSettleGameResponse);
});

/**
 * 获取层奖励
 *
 * 简化实现：参考 Python 实现直接返回 202，无实际奖励发放。
 *
 * @route POST /tower/layerReward
 * @returns 空响应（202）
 */
router.post("/layerReward", validateBody(layerRewardSchema), async (req, res) => {
  req.body as ClimbTowerLayerFirstPassRewardRequest;
  res.sendStatus(202);
});

/**
 * 获取赛季任务奖励
 *
 * 简化实现：参考 Python 实现直接返回 202，无实际奖励发放。
 *
 * @route POST /tower/seasonMissionsAward
 * @returns 空响应（202）
 */
router.post("/seasonMissionsAward", validateBody(seasonMissionsAwardSchema), async (req, res) => {
  req.body as ClimbTowerSeasonMissionAwardRequest;
  res.sendStatus(202);
});

/**
 * 赛季任务奖励（客户端拼写别名）
 * 客户端实际调用 /tower/seasonMissonsAward（CS 类名同此拼写），既有 /seasonMissionsAward 命中不到
 */
router.post("/seasonMissonsAward", validateBody(seasonMissionsAwardSchema), async (req, res) => {
  req.body as ClimbTowerSeasonMissionAwardRequest;
  res.sendStatus(202);
});

/**
 * 扫荡游戏
 *
 * 简化实现：参考 Python 实现直接返回 202，无实际扫荡逻辑。
 *
 * @route POST /tower/sweepGame
 * @returns 空响应（202）
 */
router.post("/sweepGame", validateBody(sweepGameSchema), async (req, res) => {
  req.body as ClimbTowerSweepRequest;
  res.sendStatus(202);
});

export default router;
