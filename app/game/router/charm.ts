/**
 * 干员编队路由模块
 * 
 * 处理干员基建技能组合设置相关的 HTTP 请求。
 * 请求/响应类型见 @game/model/protocol/charm（参考 CS 2.7.61 协议类）。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { validateBody } from "../model/protocol/validate-body";
import { setSquadSchema } from "../model/protocol/charm.schema";
import { CharmSetSquadRequest, CharmSetSquadResponse } from "../model/protocol/charm";

const router = Router();

/**
 * 设置编队
 * @route POST /charm/setSquad
 * @param req.body.squad - 编队数据
 * @returns 玩家增量数据
 */
router.post("/setSquad", validateBody(setSquadSchema), async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { squad } = req.body as CharmSetSquadRequest;

  // 修复：原实现只返回假 delta 从不落盘（客户端显示已设置、刷新即回退）——
  // 写入玩家数据（charm.squad 为客户端所需字段，类型未声明用 any）
  await player.update(async (draft) => {
    (draft as any).charm.squad = squad;
  });
  res.send(player.delta satisfies CharmSetSquadResponse);
});

export default router;
