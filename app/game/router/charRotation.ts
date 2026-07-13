/**
 * 干员轮换路由模块
 * 
 * 处理干员轮换预设管理相关的 HTTP 请求，包括设置当前轮换、创建/删除/更新预设等功能。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

/**
 * 设置当前轮换配置
 * @route POST /charRotation/setCurrent
 * @param req.body.instId - 预设实例ID
 * @returns 玩家增量数据和推送消息
 */
router.post("/setCurrent", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { instId } = req.body;

  res.send({
    playerDataDelta: {
      modified: {
        charRotation: {
          current: String(instId),
        },
        status: {
          secretary: "",
          secretarySkinId: "",
        },
        background: {
          selected: "",
        },
        homeTheme: {
          selected: "",
        },
      },
      deleted: {},
    },
    pushMessage: [],
  });
});

/**
 * 创建轮换预设
 * @route POST /charRotation/createPreset
 * @returns 玩家增量数据、推送消息和实例ID
 */
router.post("/createPreset", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;

  res.send({
    playerDataDelta: {
      modified: {
        charRotation: {},
      },
      deleted: {},
    },
    pushMessage: [],
    instId: 2,
  });
});

/**
 * 删除轮换预设
 * @route POST /charRotation/deletePreset
 * @param req.body.instId - 预设实例ID
 * @returns 玩家增量数据和推送消息
 */
router.post("/deletePreset", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { instId } = req.body;

  res.send({
    playerDataDelta: {
      modified: {},
      deleted: {
        charRotation: {
          preset: instId,
        },
      },
    },
    pushMessage: [],
  });
});

/**
 * 更新轮换预设
 * @route POST /charRotation/updatePreset
 * @param req.body.instId - 预设实例ID
 * @param req.body.data - 更新数据
 * @returns 更新结果、玩家增量数据和推送消息
 */
router.post("/updatePreset", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;

  res.send({
    playerDataDelta: {
      modified: {
        charRotation: {},
      },
      deleted: {},
    },
    pushMessage: [],
    result: 0,
  });
});

export default router;