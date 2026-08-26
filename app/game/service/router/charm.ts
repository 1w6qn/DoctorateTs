/**
 * 干员编队路由模块
 * 
 * 处理干员基建技能组合设置相关的 HTTP 请求。
 * 请求/响应类型见 @game/domain/contracts/charm（参考 CS 2.7.61 协议类）。
 */

import { Router } from "express";
import { getPlayer, getPlayerOptional } from "../../request-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { validateBody } from "../../domain/contracts/validate-body";
import { setSquadSchema } from "../../domain/contracts/charm.schema";
import { CharmSetSquadRequest, CharmSetSquadResponse } from "../../domain/contracts/charm";

const router = Router();

/**
 * 设置编队
 * @route POST /charm/setSquad
 * @param req.body.squad - 编队数据
 * @returns 玩家增量数据
 */
router.post("/setSquad", validateBody(setSquadSchema), async (req, res) => {
  const player = getPlayer();
  const { squad } = req.body as CharmSetSquadRequest;

  // 修复：原实现只返回假 delta 从不落盘（客户端显示已设置、刷新即回退）——
  // 写入玩家数据（charm.squad 为客户端所需字段，类型未声明用 any）
  await player.update(async (draft) => {
    (draft as any).charm.squad = squad;
  });
  res.send(player.delta satisfies CharmSetSquadResponse);
});

export default router;
