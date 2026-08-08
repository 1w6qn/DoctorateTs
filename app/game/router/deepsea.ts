/**
 * 深海路由模块
 * 
 * 处理深海猎人相关的 HTTP 请求，包括科技树分支选择等功能。
 * 请求/响应类型见 @game/model/protocol/deepsea（参考 CS 2.7.61 协议类）。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import {
  DeepSeaChangeTechBranchRequest,
  DeepSeaChangeTechBranchResponse,
  DeepSeaReadEventRequest,
  DeepSeaReadEventResponse,
} from "../model/protocol/deepsea";

const router = Router();

/**
 * 设置深海科技树分支
 * @route POST /deepsea/branch
 * @param req.body.branches - 分支列表
 * @returns 玩家增量数据
 */
router.post("/branch", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { branches = [] } = req.body as DeepSeaChangeTechBranchRequest;

  const techTrees: { [key: string]: { branch: string; state: number } } = {};
  for (const branch of branches) {
    techTrees[branch.techTreeId] = {
      branch: branch.branchId,
      state: 2,
    };
  }

  res.send({
    playerDataDelta: {
      deleted: {},
      modified: {
        deepSea: {
          techTrees,
        },
      },
    },
  } satisfies DeepSeaChangeTechBranchResponse);
});

/**
 * 深海事件处理
 * @route POST /deepsea/event
 * @returns 玩家增量数据
 */
router.post("/event", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as DeepSeaReadEventRequest;

  res.send({
    playerDataDelta: {
      deleted: {},
      modified: {},
    },
  } satisfies DeepSeaReadEventResponse);
});

export default router;
