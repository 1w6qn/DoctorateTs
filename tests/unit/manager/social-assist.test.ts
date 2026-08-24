import { describe, it, expect, beforeEach, vi } from "vitest";
import { SocialManager } from "../../../app/game/manager/social";
import { accountManager } from "../../../app/game/manager/AccountManager";
import { mockPlayerData } from "../../helpers";

vi.mock("@excel/excel", () => ({
  default: {
    CharacterTable: {
      char_001: { profession: "WARRIOR" },
      char_002: { profession: "CASTER" },
      char_003: { profession: "WARRIOR" },
    },
  },
}));

describe("SocialManager.getAssistList 随机补位", () => {
  let social: SocialManager;

  function friendInfo(uid: string, charIds: string[]) {
    return {
      uid,
      nickName: `玩家${uid}`,
      nickNumber: "1000",
      level: 60,
      avatar: { type: "SYSTEM", id: "avatar_1" },
      lastOnlineTime: new Date(),
      assistCharList: charIds.map((charId, i) => ({
        charId,
        charInstId: i + 1,
        skills: [],
        mainSkillLvl: 7,
        skillIndex: 0,
        evolvePhase: 2,
        favorPoint: 100,
        potentialRank: 0,
        level: 50,
        crisisRecord: {},
        crisisV2Record: {},
        currentEquip: null,
        equip: [],
      })),
    };
  }

  beforeEach(() => {
    vi.restoreAllMocks();
    const pd: any = mockPlayerData({
      status: { uid: "1" as any, nickName: "A" } as any,
    });
    social = new SocialManager(pd, pd._trigger);
    vi.spyOn(accountManager, "getPlayerUidList").mockReturnValue(["1", "2", "3"]);
  });

  it("好友助战不足时应从其他账号随机补位", async () => {
    // 好友 uid=2 有匹配助战；其他账号 uid=3 也有匹配（补位来源）
    vi.spyOn(accountManager, "getSocial").mockResolvedValue({
      friends: [{ uid: "2", alias: "好友B" }],
      friendRequests: [],
      visited: [],
    });
    vi.spyOn(accountManager, "getPlayerFriendInfo").mockImplementation(
      async (uid: string) => friendInfo(uid, uid === "2" ? ["char_001"] : ["char_003"]),
    );
    const list = await social.getAssistList({ profession: "WARRIOR" });
    expect(list.length).toBe(2);
    // 好友在列表中
    expect(list.some((item: any) => item.uid === "2" && item.isFriend === true)).toBe(true);
    // 补位项标记为非好友、可请求
    const fill = list.find((item: any) => item.uid === "3");
    expect(fill).toBeDefined();
    expect(fill.isFriend).toBe(false);
    expect(fill.canRequestFriend).toBe(true);
    expect(fill.aliasName).toBeNull();
  });

  it("无匹配职业时应返回空列表（不补位到错误职业）", async () => {
    vi.spyOn(accountManager, "getSocial").mockResolvedValue({
      friends: [{ uid: "2", alias: "好友B" }],
      friendRequests: [],
      visited: [],
    });
    vi.spyOn(accountManager, "getPlayerFriendInfo").mockImplementation(
      async (uid: string) => friendInfo(uid, ["char_002"]), // CASTER 不匹配 WARRIOR
    );
    const list = await social.getAssistList({ profession: "WARRIOR" });
    expect(list).toHaveLength(0);
  });

  it("玩家过少（无好友、无其他账号）时应回退自己助战补位", async () => {
    // 单账号私服：池子只有自己，好友为空 → 借不到助战则用自己补位
    vi.spyOn(accountManager, "getSocial").mockResolvedValue({
      friends: [],
      friendRequests: [],
      visited: [],
    });
    vi.spyOn(accountManager, "getPlayerUidList").mockReturnValue(["1"]);
    vi.spyOn(accountManager, "getPlayerFriendInfo").mockImplementation(
      async (uid: string) => friendInfo(uid, ["char_001"]),
    );
    const list = await social.getAssistList({ profession: "WARRIOR" });
    expect(list.length).toBe(1);
    const self = list[0] as any;
    expect(self.uid).toBe("1");
    // 自己不可请求好友
    expect(self.isFriend).toBe(true);
    expect(self.canRequestFriend).toBe(false);
  });

  it("排除自己与其他账号重复干员", async () => {
    vi.spyOn(accountManager, "getSocial").mockResolvedValue({
      friends: [],
      friendRequests: [],
      visited: [],
    });
    // uid=2 和 uid=3 都是 WARRIOR 且同 charId
    vi.spyOn(accountManager, "getPlayerFriendInfo").mockImplementation(
      async (uid: string) => friendInfo(uid, ["char_001"]),
    );
    const list = await social.getAssistList({ profession: "WARRIOR" });
    // 只保留 1 个（charId 去重）
    expect(list.length).toBe(1);
  });
});
