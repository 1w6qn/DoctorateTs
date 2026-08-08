import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";
import { now } from "@utils/time";

const router = Router();
router.post("/changeSecretary", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.status.changeSecretary(req.body);
  res.send(player.delta);
});
router.post("/changeAvatar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.status.changeAvatar(req.body);
  res.send(player.delta);
});
router.post("/changeResume", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  if ((req.body!.resume as string).slice(0) == "@") {
    await player._trigger.emit(
      req.body!.resume.slice(1, req.body!.resume.length),
      [],
    );
  } else {
    await player.status.changeResume(req.body);
  }
  res.send(player.delta);
});
router.post("/bindNickName", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const nickName = req.body!.nickName;
  let result = 0;
  const specialChars = "~!@#$%^&*()_+{}|:\"<>?[]\\;',./";
  if (nickName.length > 16) {
    result = 1;
  }

  if (Array.from(specialChars).some((char) => nickName.includes(char))) {
    result = 2;
  }

  const sensitiveWords = ["admin", "ban", "banned", "forbidden", "root"];
  if (sensitiveWords.includes(nickName.toLowerCase())) {
    result = 3;
  }
  if (result !== 0) res.send({ result });
  else {
    await player.status.bindNickName(req.body);
    res.send(player.delta);
  }
});
router.post("/useRenameCard", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.status.bindNickName(req.body);
  await player._trigger.emit("items:use", [
    [
      {
        id: req.body!.itemId,
        count: 1,
        instId: req.body!.instId,
      } as ItemBundle,
    ],
  ]);
  res.send(player.delta);
});
router.post("/receiveTeamCollectionReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.status.receiveTeamCollectionReward(req.body);
  res.send(player.delta);
});
router.post("/buyAp", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.status.buyAp();
  res.send(player.delta);
});
router.post("/exchangeDiamondShard", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  if (player._playerdata.status.androidDiamond < req.body!.count) {
    res.send({
      result: 1,
      errMsg: "至纯源石不足，是否前往商店购买至纯源石？",
    });
  } else {
    await player.status.exchangeDiamondShard(req.body);
    res.send(player.delta);
  }
});
router.post("/useItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const item = {
    id: req.body!.itemId,
    count: req.body!.count,
    instId: req.body!.instId,
  } as ItemBundle;
  await player._trigger.emit("items:use", [[item]]);
  res.send(player.delta);
});
router.post("/useItems", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const items: {
    itemId: string;
    cnt: number;
    instId: number;
  }[] = req.body!.items;
  await player._trigger.emit("items:use", [
    items.map((item) => {
      return {
        id: item.itemId,
        count: item.cnt,
        instId: item.instId,
      };
    }),
  ]);
  res.send(player.delta);
});
router.post("/checkIn", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...(await player.checkIn.checkIn()),
    ...player.delta,
  });
});
// ==================== 新增路由 ====================

/**
 * 绑定生日
 *
 * 设置玩家 status 中的生日信息（月份与日期）。
 * 参考实现：reference/opendoctoratepy-ex-public/server/user.py bindBirthday
 *
 * 路径：POST /user/bindBirthday
 * @param req.body.month - 生日月份
 * @param req.body.day - 生日日期
 * @returns playerDataDelta（包含 status.birthday 的变更）
 */
router.post("/bindBirthday", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { month, day } = req.body;
  await player.update(async (draft) => {
    draft.status.birthday = {
      month: Number(month),
      day: Number(day),
    };
  });
  res.send(player.delta);
});

export default router;

// ==================== 根级路由 ====================
//
// 以下路由在参考实现（user.py）中定义，但其 URL 路径并不挂在 /user 前缀下
// （例如 /gallery/*、/cg/*、/medal/*、/mainlineClue/*、/general/v1/server_time）。
// 因此通过独立的 rootRouter 导出，并在 app.ts 中挂载到根路径 "/"。
//
// 注意：gallery 与 mainline.clue 字段在当前手写的 PlayerDataModel 中尚未声明，
// 但在实际玩家数据 JSON 与 excel 生成的类型（types-playerdata.ts）中均存在对应结构。
// 此处使用 `(draft as any)` 访问这些字段，以确保 Immer 能够追踪变更并生成 delta。

/**
 * 服务器内 CG 收藏集合（内存态）
 *
 * 参考实现中 cgList 存储于 server_data（SERVER_DATA_PATH），为全服共享数据。
 * 此处简化为模块级内存 Set，进程重启后不持久化。
 */
const cgCollection = new Set<string>();

/** 根级路由实例，挂载非 /user 前缀的用户相关接口 */
export const rootRouter = Router();

/**
 * 领取勋章奖励
 *
 * 调用 MedalManager.rewardMedal 发放对应奖励组物品（items:get），
 * 并记录领取时间戳 rts（防重复领取）。
 *
 * 路径：POST /medal/rewardMedal
 */
rootRouter.post("/medal/rewardMedal", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const items = await player.medal.rewardMedal(req.body);
  res.send({
    items,
    ...player.delta,
  });
});

/**
 * 解锁主线线索
 *
 * 将指定线索的解锁状态设置为 2（已解锁）。
 * 参考实现：reference/opendoctoratepy-ex-public/server/user.py mainlineClue.unlockClue
 *
 * 路径：POST /mainlineClue/unlockClue
 * @param req.body.id - 线索 ID
 * @returns playerDataDelta（包含 mainline.clue.state 的变更）
 */
rootRouter.post("/mainlineClue/unlockClue", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { id } = req.body;
  await player.update(async (draft) => {
    const mainline = draft.mainline as any;
    if (!mainline.clue) {
      mainline.clue = { unlock: false, state: {}, reward: {} };
    }
    mainline.clue.state[id] = 2;
  });
  res.send(player.delta);
});

/**
 * 获取 CG 收藏列表
 *
 * 返回当前服务器已收藏的 CG 列表。
 * 参考实现：reference/opendoctoratepy-ex-public/server/user.py CG.getCgCollection
 *
 * 路径：POST /cg/getCgCollection
 * @returns playerDataDelta 与 cgList
 */
rootRouter.post("/cg/getCgCollection", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...player.delta,
    cgList: Array.from(cgCollection),
  });
});

/**
 * 添加 CG 到收藏列表
 *
 * 参考实现：reference/opendoctoratepy-ex-public/server/user.py CG.addCgCollection
 *
 * 路径：POST /cg/addCgCollection
 * @param req.body.cgId - CG ID
 * @returns playerDataDelta 与更新后的 cgList
 */
rootRouter.post("/cg/addCgCollection", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { cgId } = req.body;
  cgCollection.add(cgId);
  res.send({
    ...player.delta,
    cgList: Array.from(cgCollection),
  });
});

/**
 * 从 CG 收藏列表移除
 *
 * 参考实现：reference/opendoctoratepy-ex-public/server/user.py CG.removeCgCollection
 *
 * 路径：POST /cg/removeCgCollection
 * @param req.body.cgId - CG ID
 * @returns playerDataDelta 与更新后的 cgList
 */
rootRouter.post("/cg/removeCgCollection", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { cgId } = req.body;
  cgCollection.delete(cgId);
  res.send({
    ...player.delta,
    cgList: Array.from(cgCollection),
  });
});

/**
 * 初始化或获取玩家 gallery 数据
 *
 * 辅助函数：在 Immer draft 中确保 gallery 字段存在，
 * 若不存在则初始化默认结构。gallery 字段在手写 PlayerDataModel 中未声明，
 * 但在 excel 生成的类型与实际玩家数据中存在对应结构。
 *
 * @param draft - Immer 可写草稿
 * @returns gallery 数据对象
 */
function ensureGallery(draft: any): any {
  if (!draft.gallery) {
    draft.gallery = {
      firstRewards: false,
      leafMap: {},
    };
  }
  return draft.gallery;
}

/**
 * 领取画廊首通奖励
 *
 * 标记首通奖励已领取，并初始化默认杂志页（leaf_default2）。
 * 参考实现：reference/opendoctoratepy-ex-public/server/user.py gallery.getFirstRewards
 *
 * 路径：POST /gallery/getFirstRewards
 * @returns playerDataDelta（包含 gallery 的变更）
 */
rootRouter.post("/gallery/getFirstRewards", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.update(async (draft) => {
    const gallery = ensureGallery(draft);
    gallery.firstRewards = true;
    gallery.leafMap["leaf_default2"] = {
      charSkin: null,
      decorList: [],
      getTs: now(),
      leafId: "leaf_default2",
      version: 0,
    };
  });
  res.send(player.delta);
});

/**
 * 获取杂志缩略图 URL 列表
 *
 * 参考实现根据 leafMap 中的内容生成缩略图 URL。
 * 此处简化实现：返回与请求 idList 等长的 null 占位数组，
 * 同时同步 gallery 数据到 delta。
 *
 * 路径：POST /gallery/getThumbnailUrl
 * @param req.body.idList - 杂志页 ID 列表
 * @returns playerDataDelta 与 url 列表
 */
rootRouter.post("/gallery/getThumbnailUrl", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const idList: string[] = req.body?.idList || [];
  await player.update(async (draft) => {
    ensureGallery(draft);
  });
  res.send({
    ...player.delta,
    url: idList.map(() => null),
  });
});

/**
 * 修改杂志编队
 *
 * 参考实现仅返回当前 gallery 数据而不实际修改编队。
 * 此处同步 gallery 数据到 delta。
 *
 * 路径：POST /gallery/changeMagazineSquad
 * @returns playerDataDelta（包含 gallery 的变更）
 */
rootRouter.post("/gallery/changeMagazineSquad", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.update(async (draft) => {
    ensureGallery(draft);
  });
  res.send(player.delta);
});

/**
 * 保存自定义杂志（V1）
 *
 * 更新指定杂志页的装饰列表与角色皮肤。
 * 参考实现中还处理 base64 缩略图图片的保存，此处简化为仅更新数据结构。
 * 参考实现：reference/opendoctoratepy-ex-public/server/user.py gallery.saveDiyMagazineV1
 *
 * 路径：POST /gallery/saveDiyMagazineV1
 * @param req.body.magazine.leafId - 杂志页 ID
 * @param req.body.magazine.decorList - 装饰列表
 * @param req.body.magazine.charSkin - 角色皮肤
 * @returns playerDataDelta（包含 gallery.leafMap 的变更）
 */
rootRouter.post("/gallery/saveDiyMagazineV1", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { magazine } = req.body;
  await player.update(async (draft) => {
    saveDiyMagazine(draft, magazine);
  });
  res.send(player.delta);
});

/**
 * 保存自定义杂志（V2）
 *
 * 与 V1 相同的 leafMap 更新逻辑（OBS misc_bp.saveDiyMagazineV2 字段一致），
 * 客户端 V2 走 form-data 的 json 字段，DTS bodyParser.json 已解析为 JSON body。
 *
 * 路径：POST /gallery/saveDiyMagazineV2
 * @param req.body.magazine - 杂志数据（leafId/charSkin/decorList）
 * @returns playerDataDelta（包含 gallery.leafMap 的变更）
 */
rootRouter.post("/gallery/saveDiyMagazineV2", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { magazine } = req.body;
  await player.update(async (draft) => {
    saveDiyMagazine(draft, magazine);
  });
  res.send(player.delta);
});

/**
 * 保存自定义杂志公共逻辑（V1/V2 共用）
 *
 * @param draft - Immer 可写草稿
 * @param magazine - 杂志数据（leafId/charSkin/decorList）
 */
function saveDiyMagazine(draft: any, magazine: any): void {
  const gallery = ensureGallery(draft);
  if (magazine?.leafId) {
    if (!gallery.leafMap[magazine.leafId]) {
      gallery.leafMap[magazine.leafId] = {
        charSkin: null,
        decorList: [],
        getTs: now(),
        leafId: magazine.leafId,
        version: 0,
      };
    }
    gallery.leafMap[magazine.leafId].decorList = magazine.decorList || [];
    gallery.leafMap[magazine.leafId].charSkin = magazine.charSkin || null;
  }
}

/**
 * 设置勋章自定义数据
 *
 * 参考 OBS misc_bp.medal_setCustomData：写入 medal.custom.customs["1"]。
 *
 * 路径：POST /medal/setCustomData
 * @param req.body.data - 自定义布局数据
 * @returns playerDataDelta（包含 medal.custom 的变更）
 */
rootRouter.post("/medal/setCustomData", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const customData = req.body.data;
  await player.update(async (draft) => {
    draft.medal.custom.customs["1"] = customData;
  });
  res.send(player.delta);
});

/**
 * 领取画廊收集奖励
 *
 * 参考实现中为占位接口（返回 {}, 202）。
 *
 * 路径：POST /gallery/getCollectionRewards
 */
rootRouter.post("/gallery/getCollectionRewards", async (req, res) => {
  res.sendStatus(202);
});

/**
 * 获取服务器时间
 *
 * 返回当前服务器时间戳。该接口为 SDK/门户类接口，
 * 响应格式使用 status/msg/data 包裹，而非游戏协议的 playerDataDelta。
 * 参考实现：reference/opendoctoratepy-ex-public/server/user.py server_time
 *
 * 路径：GET /general/v1/server_time
 * @returns 服务器时间与节日标识
 */
rootRouter.get("/general/v1/server_time", async (req, res) => {
  res.send({
    status: 0,
    msg: "OK",
    data: {
      serverTime: now(),
      isHoliday: false,
    },
  });
});
