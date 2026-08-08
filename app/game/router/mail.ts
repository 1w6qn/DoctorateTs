/**
 * 邮件路由
 * 请求/响应类型见 @game/model/protocol/mail（参考 CS 2.7.61 协议类）
 */
import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { mailManager } from "../manager/mail";
import {
  GetMetaInfoListRequest,
  GetMetaInfoListResponse,
  ListMailBoxRequest,
  ListMailBoxResponse,
  ReceiveAllMailRequest,
  ReceiveAllMailResponse,
  ReceiveMailRequest,
  ReceiveMailResponse,
  RemoveAllReceivedMailRequest,
  RemoveAllReceivedMailResponse,
} from "../model/protocol/mail";

const router = Router();

/** 一键删除已读邮件（CS: RemoveAllRecievedMailRequest） */
router.post("/removeAllReceivedMail", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RemoveAllReceivedMailRequest;
  await mailManager.removeAllReceivedMail(player.uid, body);
  res.send({ ...player.delta } satisfies RemoveAllReceivedMailResponse);
});

/** 一键领取邮件（CS: ReceiveAllMailRequest） */
router.post("/receiveAllMail", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ReceiveAllMailRequest;
  res.send({
    items: await mailManager.receiveAllMail(player.uid, body),
    ...player.delta,
  } satisfies ReceiveAllMailResponse);
});

/** 获取邮件元信息列表（CS: GetMetaInfoListRequest） */
router.post("/getMetaInfoList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetMetaInfoListRequest;
  res.send({
    result: await mailManager.getMetaInfoList(player.status.uid, body),
    ...player.delta,
  } satisfies GetMetaInfoListResponse);
});

/** 领取单封邮件（CS: ReceiveMailRequest） */
router.post("/receiveMail", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ReceiveMailRequest;
  res.send({
    result: 0,
    items: await mailManager.receiveMail(player.status.uid, body),
    ...player.delta,
  } satisfies ReceiveMailResponse);
});

/** 获取邮件列表（CS: ListMailBoxRequest） */
router.post("/listMailBox", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ListMailBoxRequest;
  res.send({
    mailList: await mailManager.listMailbox(player.status.uid, body),
    ...player.delta,
  } satisfies ListMailBoxResponse);
});

export default router;
