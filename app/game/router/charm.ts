/**
 * 干员编队路由模块
 * 
 * 处理干员基建技能组合设置相关的 HTTP 请求。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

/**
 * 设置编队
 * @route POST /charm/setSquad
 * @param req.body.squad - 编队数据
 * @returns 玩家增量数据
 */
router.post("/setSquad", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { squad } = req.body;

  res.send({
    playerDataDelta: {
      deleted: {},
      modified: {
        charm: {
          squad,
        },
      },
    },
  });
});

export default router;