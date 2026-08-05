import { describe, it, expect, beforeEach } from "vitest";
import { AdminService } from "../../../app/admin/AdminService";
import { accountManager } from "../../../app/game/manager/AccountManger";
import { mockPlayerData } from "../../helpers";

describe("AdminService 只读能力", () => {
  let service: AdminService;

  beforeEach(() => {
    service = new AdminService();
    // 用内存 stub 替代真实账户数据（避免读写 data/user 真实文件）
    (accountManager as any).configs = {
      "1": {
        uid: "1",
        password: "1",
        auth: {
          phone: "13800000000",
          hgId: "1",
          email: "",
          identityNum: "",
          identityName: "",
          isMinor: false,
          isLatestUserAgreement: true,
        },
        social: { friends: [], friendRequests: [], visited: [] },
        battle: { stageId: "", replays: {}, infos: {} },
        gacha: {},
        rlv2: {},
      },
    };
    const pd = mockPlayerData({
      status: {
        uid: "1" as any,
        nickName: "阿米娅",
        nickNumber: "1",
        level: 60,
        exp: 100,
        gold: 99999,
        registerTs: 1000,
        lastOnlineTs: 2000,
      } as any,
      troop: { curCharInstId: 5 } as any,
    });
    (accountManager as any).data = { "1": pd };
  });

  it("listUsers 应返回 uid/昵称/等级摘要", async () => {
    const users = await service.listUsers();
    expect(users).toHaveLength(1);
    expect(users[0]).toMatchObject({ uid: "1", nickName: "阿米娅", level: 60 });
  });

  it("getUserInfo 应返回资金与道具摘要", async () => {
    const info = await service.getUserInfo("1");
    expect(info!.gold).toBe(99999);
    expect(info!.nickName).toBe("阿米娅");
  });

  it("getUserInfo 对不存在用户应返回 null", async () => {
    expect(await service.getUserInfo("999")).toBeNull();
  });

  it("status 应返回用户数与端口信息", async () => {
    const st = await service.status();
    expect(st.userCount).toBe(1);
    expect(typeof st.port).toBe("number");
    expect(st.dataFiles.length).toBeGreaterThan(0);
  });
});
