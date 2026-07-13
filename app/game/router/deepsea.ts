/**
 * 深海路由模块
 * 
 * 处理深海猎人相关的 HTTP 请求，包括科技树分支选择等功能。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

/**
 * 设置深海科技树分支
 * @route POST /deepsea/branch
 * @param req.body.branches - 分支列表
 * @returns 玩家增量数据
 */
router.post("/branch", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const branches = req.body.branches || [];

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
  });
});

/**
 * 深海事件处理
 * @route POST /deepsea/event
 * @returns 玩家增量数据
 */
router.post("/event", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;

  res.send({
    playerDataDelta: {
      deleted: {},
      modified: {},
    },
  });
});

export default router;