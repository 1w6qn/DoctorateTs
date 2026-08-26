import { describe, it, expect, beforeEach, vi } from "vitest";
import { SocialManager } from "../../../app/game/service/player/social";
import { accountManager } from "../../../app/game/service/player/AccountManager";
import { mockPlayerData } from "../../helpers";

describe("SocialManager 双向好友", () => {
  let social: SocialManager;

  beforeEach(() => {
    vi.restoreAllMocks();
    const pd: any = mockPlayerData({
      status: { uid: "1" as any, nickName: "A" } as any,
      pushFlags: { hasFriendRequest: 1 } as any,
    });
    social = new SocialManager(pd, pd._trigger);
    vi.spyOn(accountManager, "deleteFriendRequest").mockResolvedValue(undefined as any);
    vi.spyOn(accountManager, "getFriendRequests").mockResolvedValue([]);
    vi.spyOn(accountManager, "getSocial").mockResolvedValue({
      friends: [],
      friendRequests: [],
      visited: [],
    });
  });

  it("同意申请（action=1）应双向加好友", async () => {
    const addFriend = vi
      .spyOn(accountManager, "addFriend")
      .mockResolvedValue(undefined as any);
    await social.processFriendRequest({ friendId: "2", action: 1 });
    // 己方加对方 + 对方加己方
    expect(addFriend).toHaveBeenCalledWith("1", "2");
    expect(addFriend).toHaveBeenCalledWith("2", "1");
  });

  it("拒绝申请（action=0）不应加好友", async () => {
    const addFriend = vi
      .spyOn(accountManager, "addFriend")
      .mockResolvedValue(undefined as any);
    await social.processFriendRequest({ friendId: "2", action: 0 });
    expect(addFriend).not.toHaveBeenCalled();
  });
});

describe("SocialManager 其他方法", () => {
  let social: SocialManager;
  let pd: any;

  beforeEach(() => {
    vi.restoreAllMocks();
    pd = mockPlayerData({
      status: { uid: "1" as any, nickName: "A" } as any,
      pushFlags: { hasFriendRequest: 1 } as any,
      social: {
        yesterdayReward: { canReceive: 1, assistAmount: 10, comfortAmount: 5 },
      } as any,
    });
    social = new SocialManager(pd, pd._trigger);
    pd.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(pd._playerdata));
          const result = await recipe(draft);
          Object.assign(pd._playerdata, draft);
          return result;
        }
      );
  });

  it("getSortListInfo GET_FRIEND_REQUEST 应返回申请者信息", async () => {
    vi.spyOn(accountManager, "getFriendRequests").mockResolvedValue(["2"] as any);
    vi.spyOn(accountManager, "getPlayerFriendInfo").mockResolvedValue({
      uid: "2",
      nickName: "B",
      nickNumber: "1",
      level: 1,
    } as any);
    const result = await social.getSortListInfo({
      type: 2 as any,
      sortKeyList: [],
      param: {},
    });
    expect(result).toHaveLength(1);
    expect(result![0].uid).toBe("2");
  });

  it("getSortListInfo SEARCH_FRIEND 应返回搜索结果", async () => {
    vi.spyOn(accountManager, "searchPlayer").mockResolvedValue(["3"] as any);
    vi.spyOn(accountManager, "getPlayerFriendInfo").mockResolvedValue({
      uid: "3",
      nickName: "C",
      nickNumber: "1",
      level: 2,
    } as any);
    const result = await social.getSortListInfo({
      type: 0 as any,
      sortKeyList: [],
      param: { nickName: "C", nickNumber: "1" },
    });
    expect(result).toEqual([{ uid: "3", level: 2 }]);
  });

  it("getSortListInfo GET_FRIEND_LIST 应按 sortKeyList 返回好友", async () => {
    vi.spyOn(accountManager, "getSocial").mockResolvedValue({
      friends: [{ uid: "2", alias: "好友2" }],
      friendRequests: [],
      visited: [],
    } as any);
    vi.spyOn(accountManager, "getPlayerFriendInfo").mockResolvedValue({
      uid: "2",
      nickName: "B",
      nickNumber: "1",
      level: 1,
    } as any);
    const result = await social.getSortListInfo({
      type: 1 as any,
      sortKeyList: ["nickName"],
      param: {},
    });
    expect(result).toEqual([{ uid: "2", nickName: "B" }]);
  });

  it("getFriendList 应返回好友信息与别名", async () => {
    vi.spyOn(accountManager, "getPlayerFriendInfo").mockResolvedValue({
      uid: "2",
      nickName: "B",
      nickNumber: "1",
      level: 1,
    } as any);
    vi.spyOn(accountManager, "getSocial").mockResolvedValue({
      friends: [{ uid: "2", alias: "阿米娅" }],
      friendRequests: [],
      visited: [],
    } as any);
    const result = await social.getFriendList({ idList: ["2"] });
    expect(result.friends).toHaveLength(1);
    expect(result.friendAlias).toContain("阿米娅");
  });

  it("receiveSocialPoint 应发放昨日信用点并关闭领取", async () => {
    const emitSpy = vi.spyOn(pd._trigger, "emit");
    await social.receiveSocialPoint();
    expect(emitSpy).toHaveBeenCalledWith("items:get", [
      [{ id: "", type: "SOCIAL_PT", count: 15 }],
    ]);
    expect(pd._playerdata.social!.yesterdayReward.canReceive).toBe(0);
  });

  it("deleteFriend 应委托 accountManager 删除好友", async () => {
    const del = vi.spyOn(accountManager, "deleteFriend").mockResolvedValue(undefined as any);
    await social.deleteFriend({ id: "2" });
    expect(del).toHaveBeenCalledWith("1", "2");
  });
});
