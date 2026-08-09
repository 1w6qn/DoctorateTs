/**
 * 用户路由
 * 请求/响应类型见 @game/model/protocol/user（参考 CS 2.7.61 协议类）
 */
import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";
import { now } from "@utils/time";
import {
  AddCgCollectionRequest,
  AddCgCollectionResponse,
  BindBirthdayRequest,
  BindBirthdayResponse,
  BindNickNameRequest,
  BindNickNameResponse,
  BuyApRequest,
  BuyApResponse,
  ChangeAvatarRequest,
  ChangeAvatarResponse,
  ChangeMagazineSquadRequest,
  ChangeMagazineSquadResponse,
  ChangeResumeRequest,
  ChangeResumeResponse,
  ChangeSecretaryRequest,
  ChangeSecretaryResponse,
  CheckInHomeRequest,
  CheckInHomeResponse,
  ExchangeDiamondShardRequest,
  ExchangeDiamondShardResponse,
  GetCgCollectionRequest,
  GetCgCollectionResponse,
  GetFirstRewardsRequest,
  GetFirstRewardsResponse,
  GetThumbnailUrlRequest,
  GetThumbnailUrlResponse,
  MedalSetCustomDataRequest,
  MedalSetCustomDataResponse,
  ReceiveTeamCollectionRewardRequest,
  ReceiveTeamCollectionRewardResponse,
  RemoveCgCollectionRequest,
  RemoveCgCollectionResponse,
  RewardMedalRequest,
  RewardMedalResponse,
  SaveDiyMagazineRequest,
  SaveDiyMagazineResponse,
  ServerTimeResponse,
  UnlockClueRequest,
  UnlockClueResponse,
  UseItemRequest,
  UseItemResponse,
  UseItemsRequest,
  UseItemsResponse,
  UseRenameCardRequest,
  UseRenameCardResponse,
} from "../model/protocol/user";


/** 1x1 透明 PNG（静态图片占位） */
const PLACEHOLDER_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
  "base64",
);

const router = Router();

/** 更换秘书干员（CS: ChangeSecretaryRequest） */
router.post("/changeSecretary", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ChangeSecretaryRequest;
  await player.status.changeSecretary(body);
  res.send(player.delta satisfies ChangeSecretaryResponse);
});

/** 更换头像（CS: ChangeAvatarRequest） */
router.post("/changeAvatar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ChangeAvatarRequest;
  await player.status.changeAvatar(body);
  res.send(player.delta satisfies ChangeAvatarResponse);
});

/** 更换简介（CS: ChangeResumeRequest） */
router.post("/changeResume", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ChangeResumeRequest;
  if ((body?.resume as string).slice(0) == "@") {
    // 动态事件名（resume 以 @ 开头时触发对应事件），绕过 EventMap 静态键检查
    player._trigger.emit(body.resume.slice(1, body.resume.length) as any, []);
  } else {
    await player.status.changeResume(body);
  }
  res.send(player.delta satisfies ChangeResumeResponse);
});

/** 绑定昵称（服务端自定义） */
router.post("/bindNickName", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BindNickNameRequest;
  const nickName = body.nickName;
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
  if (result !== 0) res.send({ result } satisfies BindNickNameResponse);
  else {
    // 注意：客户端字段为 nickName，管理器契约读取 nickname（既有不一致，保持原行为）
    await player.status.bindNickName(body as unknown as { nickname: string });
    res.send(player.delta satisfies BindNickNameResponse);
  }
});

/** 使用改名卡（CS: UseRenameCardRequest） */
router.post("/useRenameCard", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as UseRenameCardRequest;
  await player.status.bindNickName({ nickname: body.nickName });
  await player._trigger.emit("items:use", [
    [
      {
        id: body.itemId,
        count: 1,
        instId: body.instId,
      } as ItemBundle,
    ],
  ]);
  res.send(player.delta satisfies UseRenameCardResponse);
});

/** 领取团队收集奖励（CS: ReceiveTeamCollectionRewardRequest） */
router.post("/receiveTeamCollectionReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ReceiveTeamCollectionRewardRequest;
  await player.status.receiveTeamCollectionReward(body);
  res.send(player.delta satisfies ReceiveTeamCollectionRewardResponse);
});

/** 购买理智（CS: BuyApRequest） */
router.post("/buyAp", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as BuyApRequest;
  await player.status.buyAp();
  res.send(player.delta satisfies BuyApResponse);
});

/** 兑换源石碎片（CS: ExchangeDiamondShardRequest） */
router.post("/exchangeDiamondShard", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ExchangeDiamondShardRequest;
  if (player._playerdata.status.androidDiamond < body.count) {
    res.send({
      result: 1,
      errMsg: "至纯源石不足，是否前往商店购买至纯源石？",
    } satisfies ExchangeDiamondShardResponse);
  } else {
    await player.status.exchangeDiamondShard(body);
    res.send(player.delta satisfies ExchangeDiamondShardResponse);
  }
});

/** 使用单个物品（CS: UseItemRequest） */
router.post("/useItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as UseItemRequest;
  const item = {
    id: body.itemId,
    count: body.count,
    instId: body.instId,
  } as ItemBundle;
  await player._trigger.emit("items:use", [[item]]);
  res.send(player.delta satisfies UseItemResponse);
});

/** 使用多个物品（CS: UseItemsRequest） */
router.post("/useItems", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as UseItemsRequest;
  const items: {
    itemId: string;
    cnt: number;
    instId: number;
  }[] = body.items;
  await player._trigger.emit("items:use", [
    items.map((item) => {
      return {
        id: item.itemId,
        count: item.cnt,
        instId: item.instId,
      };
    }),
  ]);
  res.send(player.delta satisfies UseItemsResponse);
});

/** 签到（CS ServiceCode: CHECKIN_HOME） */
router.post("/checkIn", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as CheckInHomeRequest;
  res.send({
    ...(await player.checkIn.checkIn()),
    ...player.delta,
  } satisfies CheckInHomeResponse);
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
  const body = req.body as BindBirthdayRequest;
  const { month, day } = body;
  await player.update(async (draft) => {
    draft.status.birthday = {
      month: Number(month),
      day: Number(day),
    };
  });
  res.send(player.delta satisfies BindBirthdayResponse);
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
  const body = req.body as RewardMedalRequest;
  const items = await player.medal.rewardMedal(body);
  res.send({
    items,
    ...player.delta,
  } satisfies RewardMedalResponse);
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
  const body = req.body as UnlockClueRequest;
  const { id } = body;
  await player.update(async (draft) => {
    const mainline = draft.mainline as any;
    if (!mainline.clue) {
      mainline.clue = { unlock: false, state: {}, reward: {} };
    }
    mainline.clue.state[id] = 2;
  });
  res.send(player.delta satisfies UnlockClueResponse);
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
  req.body as GetCgCollectionRequest;
  res.send({
    ...player.delta,
    cgList: Array.from(cgCollection),
  } satisfies GetCgCollectionResponse);
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
  const body = req.body as AddCgCollectionRequest;
  const { cgId } = body;
  cgCollection.add(cgId);
  res.send({
    ...player.delta,
    cgList: Array.from(cgCollection),
  } satisfies AddCgCollectionResponse);
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
  const body = req.body as RemoveCgCollectionRequest;
  const { cgId } = body;
  cgCollection.delete(cgId);
  res.send({
    ...player.delta,
    cgList: Array.from(cgCollection),
  } satisfies RemoveCgCollectionResponse);
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
/** 画廊杂志图片（客户端 /gallery/jpg/<name>；私服无素材文件，返回 1x1 透明占位图避免客户端报错） */
/** 公告图片（客户端 /announce/images/<subpath>；私服无素材文件，返回 1x1 占位图） */
rootRouter.get("/announce/images/:subpath", async (_req, res) => {
  res.type("png").send(PLACEHOLDER_PNG);
});
rootRouter.get("/gallery/jpg/:jpgName", async (_req, res) => {
  res.type("png").send(PLACEHOLDER_PNG);
});
rootRouter.get("/gallery/jpg/:jpgName.png", async (_req, res) => {
  res.type("png").send(PLACEHOLDER_PNG);
});

rootRouter.post("/gallery/getFirstRewards", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetFirstRewardsRequest;
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
  res.send(player.delta satisfies GetFirstRewardsResponse);
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
  const body = req.body as GetThumbnailUrlRequest;
  const idList: string[] = body?.idList || [];
  await player.update(async (draft) => {
    ensureGallery(draft);
  });
  res.send({
    ...player.delta,
    url: idList.map(() => null),
  } satisfies GetThumbnailUrlResponse);
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
  req.body as ChangeMagazineSquadRequest;
  await player.update(async (draft) => {
    ensureGallery(draft);
  });
  res.send(player.delta satisfies ChangeMagazineSquadResponse);
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
  const body = req.body as SaveDiyMagazineRequest;
  const { magazine } = body;
  await player.update(async (draft) => {
    saveDiyMagazine(draft, magazine);
  });
  res.send(player.delta satisfies SaveDiyMagazineResponse);
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
  const body = req.body as SaveDiyMagazineRequest;
  const { magazine } = body;
  await player.update(async (draft) => {
    saveDiyMagazine(draft, magazine);
  });
  res.send(player.delta satisfies SaveDiyMagazineResponse);
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
  const body = req.body as MedalSetCustomDataRequest;
  const customData = body.data;
  await player.update(async (draft) => {
    draft.medal.custom.customs["1"] = customData;
  });
  res.send(player.delta satisfies MedalSetCustomDataResponse);
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
  } satisfies ServerTimeResponse);
});
