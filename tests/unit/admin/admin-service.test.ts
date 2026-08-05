import { describe, it, expect, beforeEach, vi } from "vitest";
import { AdminService } from "../../../app/admin/AdminService";
import { accountManager } from "../../../app/game/manager/AccountManger";
import { mailManager } from "../../../app/game/manager/mail";
import { mockPlayerData } from "../../helpers";

// 拦截所有 fs/promises.writeFile，避免 createUser 写真实存档文件
vi.mock("fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs/promises")>();
  return { ...actual, writeFile: vi.fn().mockResolvedValue(undefined) };
});

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

describe("AdminService 发放物品", () => {
  let service: AdminService;
  let pd: any;

  beforeEach(() => {
    vi.restoreAllMocks();
    service = new AdminService();
    pd = mockPlayerData({
      status: { uid: "1" as any, nickName: "阿米娅", level: 1, gold: 0 } as any,
      troop: { curCharInstId: 2 } as any,
    });
    // mock 的 PlayerDataManager 没有 inventory 管理器，附加 stub 模拟 GOLD 分支
    pd.inventory = {
      gainItem: vi.fn().mockImplementation(async (item: any) => {
        pd._playerdata.status.gold += item.count;
      }),
    };
    (accountManager as any).data = { "1": pd };
    (accountManager as any).configs = {
      "1": { uid: "1", auth: { phone: "" }, social: {}, battle: {}, gacha: {}, rlv2: {} },
    };
    // 拦截落盘，避免写真实文件
    vi.spyOn(accountManager, "savePlayerData").mockResolvedValue(undefined as any);
    vi.spyOn(accountManager, "saveUserConfig").mockResolvedValue(undefined as any);
  });

  it("发放金币应累加到 status.gold 并落盘", async () => {
    await service.grantItem("1", "4001", 5000);
    expect(pd._playerdata.status.gold).toBe(5000);
    expect(pd.inventory.gainItem).toHaveBeenCalledWith({ id: "4001", count: 5000 });
    expect(accountManager.savePlayerData).toHaveBeenCalledWith("1");
  });

  it("对不存在用户应抛出明确错误", async () => {
    await expect(service.grantItem("999", "4001", 1)).rejects.toThrow(/不存在/);
  });

  it("数量必须为正整数", async () => {
    await expect(service.grantItem("1", "4001", -1)).rejects.toThrow(/数量/);
  });
});

describe("AdminService 邮件与建号", () => {
  let service: AdminService;

  beforeEach(() => {
    vi.restoreAllMocks();
    service = new AdminService();
    const pd = mockPlayerData({
      status: {
        uid: "1" as any,
        nickName: "阿米娅",
        nickNumber: "1",
        level: 1,
        registerTs: 0,
        lastOnlineTs: 0,
      } as any,
      troop: { curCharInstId: 2 } as any,
    });
    (accountManager as any).data = { "1": pd };
    (accountManager as any).configs = {
      "1": {
        uid: "1",
        password: "1",
        auth: { phone: "13800000000" },
        social: {},
        battle: {},
        gacha: {},
        rlv2: {},
      },
    };
    vi.spyOn(accountManager, "savePlayerData").mockResolvedValue(undefined as any);
    vi.spyOn(accountManager, "saveUserConfig").mockResolvedValue(undefined as any);
  });

  it("sendMail 应调用 mailManager 并返回邮件", async () => {
    const spy = vi
      .spyOn(mailManager, "sendMail")
      .mockResolvedValue({ mailId: 1000000 } as any);
    const mail = await service.sendMail("1", {
      subject: "欢迎",
      content: "你好",
      items: [{ id: "4001", count: 100 }],
    });
    expect(spy).toHaveBeenCalledWith(
      "1",
      expect.objectContaining({ subject: "欢迎" }),
    );
    expect(mail.mailId).toBe(1000000);
  });

  it("sendMail 对不存在用户应报错", async () => {
    await expect(
      service.sendMail("999", { subject: "x", content: "", items: [] }),
    ).rejects.toThrow(/不存在/);
  });

  it("createUser 应生成新 uid 并更新 configs", async () => {
    const uid = await service.createUser("13900000000", "pw123");
    expect(uid).toBe("2");
    expect((accountManager as any).configs[uid]).toBeDefined();
    expect((accountManager as any).configs[uid].auth.phone).toBe("13900000000");
    expect(accountManager.saveUserConfig).toHaveBeenCalled();
  });

  it("createUser 对重复手机号应报错", async () => {
    await expect(service.createUser("13800000000", "pw123")).rejects.toThrow(
      /手机号/,
    );
  });

  it("createUser 对空手机号应报错", async () => {
    await expect(service.createUser("", "pw123")).rejects.toThrow(/手机号/);
  });
});
