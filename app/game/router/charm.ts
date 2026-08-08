/**
 * 干员编队路由模块
 * 
 * 处理干员基建技能组合设置相关的 HTTP 请求。
 * 请求/响应类型见 @game/model/protocol/charm（参考 CS 2.7.61 协议类）。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { CharmSetSquadRequest, CharmSetSquadResponse } from "../model/protocol/charm";

const router = Router();

/**
 * 设置编队
 * @route POST /charm/setSquad
 * @param req.body.squad - 编队数据
 * @returns 玩家增量数据
 */
router.post("/setSquad", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { squad } = req.body as CharmSetSquadRequest;

  res.send({
    playerDataDelta: {
      deleted: {},
      modified: {
        charm: {
          squad,
        },
      },
    },
  } satisfies CharmSetSquadResponse);
});

export default router;
