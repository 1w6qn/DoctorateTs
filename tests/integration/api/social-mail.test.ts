/**
 * 游戏 API「社交 / 邮件」流程集成测试
 *
 * 两个账号走好友申请 → 同意 → 双向好友列表闭环；邮件端点验证列表契约。
 */
import { describe, beforeAll, afterAll, it, expect } from "vitest";
import { startApiFixture, type ApiFixture } from "../../helpers/apiServer";

describe("游戏 API 社交 / 邮件流程", () => {
  let fx: ApiFixture;
  let aUid: string;
  let aSecret: string;
  let bUid: string;
  let bSecret: string;

  beforeAll(async () => {
    fx = await startApiFixture();
    const A = await fx.register("social_a_account", "Ab12cd34");
    const B = await fx.register("social_b_account", "Ef56gh78");
    aUid = A.uid;
    aSecret = A.secret;
    bUid = B.uid;
    bSecret = B.secret;
  });

  afterAll(async () => {
    await fx.close();
  });

  it("A 向 B 发送好友申请", async () => {
    const res = await fx.post(
      "/social/sendFriendRequest",
      { friendId: bUid, afterBattle: 0, originType: 0, battleOrigin: null },
      aSecret,
    );
    expect(res.status).toBe(200);
  });

  it("B 的待处理申请列表中出现 A", async () => {
    const res = await fx.post("/social/getFriendRequestList", { idList: [aUid] }, bSecret);
    expect(res.status).toBe(200);
    expect(res.body.requestList).toEqual(
      expect.arrayContaining([expect.objectContaining({ uid: aUid })]),
    );
  });

  it("B 同意 A 的申请 → 好友数 +1", async () => {
    const res = await fx.post(
      "/social/processFriendRequest",
      { friendId: aUid, action: 1 },
      bSecret,
    );
    expect(res.status).toBe(200);
    expect(res.body.friendNum).toBe(1);
  });

  it("双向好友列表各自包含对方", async () => {
    const bList = await fx.post("/social/getFriendList", { idList: [aUid] }, bSecret);
    expect(bList.body.friends).toEqual(
      expect.arrayContaining([expect.objectContaining({ uid: aUid })]),
    );
    const aList = await fx.post("/social/getFriendList", { idList: [bUid] }, aSecret);
    expect(aList.body.friends).toEqual(
      expect.arrayContaining([expect.objectContaining({ uid: bUid })]),
    );
  });

  it("邮件列表 /mail/listMailBox 返回数组契约", async () => {
    const res = await fx.post(
      "/mail/listMailBox",
      { mailIdList: [], sysMailIdList: [], surveyMailIdList: [] },
      aSecret,
    );
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.mailList)).toBe(true);
  });
});