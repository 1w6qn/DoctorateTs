import { describe, it, expect, beforeEach, vi } from "vitest";
import { SocialManager } from "../../../app/game/manager/social";
import { accountManager } from "../../../app/game/manager/AccountManger";
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
