import { describe, it, expect, beforeEach, vi } from "vitest";
import { AdminService } from "../../../app/admin/AdminService";
import { accountManager } from "../../../app/game/manager/AccountManger";
import { mailManager } from "../../../app/game/manager/mail";
import { mockPlayerData } from "../../helpers";
import config from "../../../app/config";
import { appendFile, mkdir } from "fs/promises";

// excel 表桩（名称解析/物品校验/满配/干员属性共用）
vi.mock("@excel/excel", () => ({
  default: {
    ItemTable: {
      items: {
        "4001": { name: "龙门币", classifyType: "NORMAL", sortId: 100 },
        "4003": { name: "合成玉", classifyType: "NORMAL", sortId: 100 },
        "9999": { name: "未知材料", classifyType: "MATERIAL", sortId: 100 },
        "consumable_x": { name: "消耗券", classifyType: "CONSUME", sortId: 100 },
      },
    },
    CharacterTable: {
      char_002_amiya: {
        name: "阿米娅",
        rarity: 4,
        maxPotentialLevel: 5,
        phases: [{ maxLevel: 30 }, { maxLevel: 55 }, { maxLevel: 90 }],
        skills: [{ skillId: "skill_amiya_1" }],
      },
    },
    SkinTable: {
      charSkins: {
        "char_002_amiya#2": { charId: "char_002_amiya", displaySkin: { skinName: "开初" } },
      },
    },
    UniequipTable: { charEquip: { char_002_amiya: [] } },
    BuildingData: { rooms: { room_1: { phases: [{}, {}, {}] } } },
  },
}));

// 拦截所有 fs/promises 写操作（createUser 走 .tmp+rename 原子写；_audit 走 mkdir+appendFile，
// 均避免写真实文件/目录）
vi.mock("fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs/promises")>();
  return {
    ...actual,
    writeFile: vi.fn().mockResolvedValue(undefined),
    rename: vi.fn().mockResolvedValue(undefined),
    appendFile: vi.fn().mockResolvedValue(undefined),
    mkdir: vi.fn().mockResolvedValue(undefined),
    copyFile: vi.fn().mockResolvedValue(undefined),
  };
});

/** 构造带完整结构的 mock 玩家（满配/基建/干员用例共用） */
function makeFullPd() {
  return mockPlayerData({
    status: {
      uid: "1" as any,
      nickName: "阿米娅",
      nickNumber: "1",
      level: 60,
      exp: 100,
      gold: 99999,
      androidDiamond: 100,
      iosDiamond: 0,
      maxAp: 135,
      ap: 0,
      registerTs: 1000,
      lastOnlineTs: 2000,
    } as any,
    troop: {
      curCharInstId: 5,
      chars: {
        "1": {
          instId: 1,
          charId: "char_002_amiya",
          level: 1,
          exp: 0,
          evolvePhase: 0,
          potentialRank: 0,
          favorPoint: 0,
          mainSkillLvl: 1,
          gainTime: 0,
          voiceLan: "CN_MANDARIN",
          skills: [{ skillId: "skill_amiya_1", unlock: 1, state: 0, specializeLevel: 0, completeUpgradeTime: -1 }],
        },
      },
    } as any,
    inventory: {},
    consumable: {},
    skin: { characterSkins: {}, skinTs: {} } as any,
    building: {
      roomSlots: {
        slot_1: { level: 1, state: 1, roomId: "room_1", charInstIds: [], completeConstructTime: 0 },
      },
    } as any,
  });
}

/** 基本账号桩（listUsers/getUserInfo/sendMail 等只读与邮件路径用） */
function stubAccounts(pd: any) {
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
  (accountManager as any).data = { "1": pd };
}

describe("AdminService 只读能力", () => {
  let service: AdminService;

  beforeEach(() => {
    service = new AdminService();
    const pd = makeFullPd();
    stubAccounts(pd);
  });

  it("listUsers 应返回 uid/昵称/等级摘要", async () => {
    const users = await service.listUsers();
    expect(users).toHaveLength(1);
    expect(users[0]).toMatchObject({ uid: "1", nickName: "阿米娅", level: 60 });
  });

  it("getUserInfo 应返回资金与带中文名的道具摘要", async () => {
    const pd = (accountManager as any).data["1"];
    pd._playerdata.inventory = { "4001": 100, "9999": 5 };
    const info = await service.getUserInfo("1");
    expect(info!.gold).toBe(99999);
    expect(info!.nickName).toBe("阿米娅");
    expect(info!.inventoryInfo).toEqual([
      { id: "4001", name: "龙门币", count: 100 },
      { id: "9999", name: "未知材料", count: 5 },
    ]);
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
    stubAccounts(pd);
    // 拦截落盘与审计，避免写真实文件
    vi.spyOn(accountManager, "savePlayerData").mockResolvedValue(undefined as any);
    vi.spyOn(accountManager, "saveUserConfig").mockResolvedValue(undefined as any);
    vi.mocked(appendFile).mockResolvedValue(undefined);
    vi.mocked(mkdir).mockResolvedValue(undefined);
  });

  it("发放金币应累加到 status.gold 并落盘", async () => {
    await service.grantItem("1", "4001", 5000);
    expect(pd._playerdata.status.gold).toBe(5000);
    expect(pd.inventory.gainItem).toHaveBeenCalledWith({ id: "4001", count: 5000 });
    expect(accountManager.savePlayerData).toHaveBeenCalledWith("1");
  });

  it("支持中文名/别名发放（如 合成玉）", async () => {
    await service.grantItem("1", "合成玉", 10);
    expect(pd.inventory.gainItem).toHaveBeenCalledWith({ id: "4003", count: 10 });
  });

  it("对未知物品应抛错", async () => {
    await expect(service.grantItem("1", "no_such_item", 1)).rejects.toThrow(/未知物品/);
  });

  it("对不在 ItemTable 的 ID 应抛错", async () => {
    await expect(service.grantItem("1", "7777", 1)).rejects.toThrow(/不在 ItemTable/);
  });

  it("对不存在用户应抛出明确错误", async () => {
    await expect(service.grantItem("999", "4001", 1)).rejects.toThrow(/不存在/);
  });

  it("数量必须为正整数", async () => {
    await expect(service.grantItem("1", "4001", -1)).rejects.toThrow(/数量/);
  });
});

describe("AdminService 干员/皮肤发放", () => {
  let service: AdminService;
  let pd: any;

  beforeEach(() => {
    vi.restoreAllMocks();
    service = new AdminService();
    pd = makeFullPd();
    pd.char = {
      onCharGet: vi.fn().mockResolvedValue({ charInstId: 5, charId: "char_002_amiya", isNew: 1, itemGet: [] }),
    };
    pd.inventory = {
      gainItem: vi.fn().mockResolvedValue(undefined),
    };
    stubAccounts(pd);
    vi.spyOn(accountManager, "savePlayerData").mockResolvedValue(undefined as any);
    vi.spyOn(accountManager, "saveUserConfig").mockResolvedValue(undefined as any);
    vi.mocked(appendFile).mockResolvedValue(undefined);
    vi.mocked(mkdir).mockResolvedValue(undefined);
  });

  it("grantChar 应调用 onCharGet（不走 char:get 事件）", async () => {
    const res = await service.grantChar("1", "char_002_amiya");
    expect(pd.char.onCharGet).toHaveBeenCalledWith([
      "char_002_amiya",
      { from: "ADMIN" },
    ]);
    expect(res).toMatchObject({ isNew: 1, name: "阿米娅" });
  });

  it("grantChar 支持中文名", async () => {
    await service.grantChar("1", "阿米娅");
    expect(pd.char.onCharGet).toHaveBeenCalledWith([
      "char_002_amiya",
      { from: "ADMIN" },
    ]);
  });

  it("grantChar 对未知干员应抛错", async () => {
    await expect(service.grantChar("1", "char_999")).rejects.toThrow(/未知干员/);
  });

  it("grantSkin 应以 CHAR_SKIN 类型解锁皮肤", async () => {
    await service.grantSkin("1", "char_002_amiya#2");
    expect(pd.inventory.gainItem).toHaveBeenCalledWith({
      id: "char_002_amiya#2",
      count: 1,
      type: "CHAR_SKIN",
    });
  });

  it("grantSkin 对未知皮肤应抛错", async () => {
    await expect(service.grantSkin("1", "char_999#1")).rejects.toThrow(/未知皮肤/);
  });
});

describe("AdminService 干员管理", () => {
  let service: AdminService;
  let pd: any;

  beforeEach(() => {
    vi.restoreAllMocks();
    service = new AdminService();
    pd = makeFullPd();
    stubAccounts(pd);
    vi.spyOn(accountManager, "savePlayerData").mockResolvedValue(undefined as any);
    vi.spyOn(accountManager, "saveUserConfig").mockResolvedValue(undefined as any);
    vi.mocked(appendFile).mockResolvedValue(undefined);
    vi.mocked(mkdir).mockResolvedValue(undefined);
  });

  it("listChars 应返回带中文名/星级/最大等级的摘要", async () => {
    const chars = await service.listChars("1");
    expect(chars).toHaveLength(1);
    expect(chars[0]).toMatchObject({
      instId: 1,
      charId: "char_002_amiya",
      name: "阿米娅",
      rarity: 4,
      level: 1,
      maxLevel: 30,
    });
  });

  it("setCharAttrs 应钳制越界值（精二/等级/潜能/技能）", async () => {
    await service.setCharAttrs("1", 1, {
      level: 999,
      evolvePhase: 5,
      potentialRank: 9,
      mainSkillLvl: 9,
    });
    const ch = pd._playerdata.troop.chars["1"];
    expect(ch.evolvePhase).toBe(2); // phases.length-1
    expect(ch.level).toBe(90); // phases[2].maxLevel
    expect(ch.potentialRank).toBe(5); // maxPotentialLevel
    expect(ch.mainSkillLvl).toBe(7);
    expect(ch.exp).toBe(0);
  });

  it("setCharAttrs 不提供任何属性应抛错", async () => {
    await expect(service.setCharAttrs("1", 1, {})).rejects.toThrow(/未提供/);
  });

  it("setCharAttrs 对不存在干员应抛错", async () => {
    await expect(service.setCharAttrs("1", 99, { level: 10 })).rejects.toThrow(/干员不存在/);
  });
});

describe("AdminService 一键满配与基建", () => {
  let service: AdminService;
  let pd: any;

  beforeEach(() => {
    vi.restoreAllMocks();
    service = new AdminService();
    pd = makeFullPd();
    stubAccounts(pd);
    vi.spyOn(accountManager, "savePlayerData").mockResolvedValue(undefined as any);
    vi.spyOn(accountManager, "saveUserConfig").mockResolvedValue(undefined as any);
    vi.mocked(appendFile).mockResolvedValue(undefined);
    vi.mocked(mkdir).mockResolvedValue(undefined);
  });

  it("maxOutAccount 应拉满资源/干员/背包/皮肤/基建", async () => {
    const stats = await service.maxOutAccount("1");
    const d = pd._playerdata;
    // 资源
    expect(d.status.gold).toBe(99999999);
    expect(d.status.androidDiamond).toBe(99999);
    expect(d.status.level).toBe(120);
    expect(d.status.ap).toBe(135);
    // 背包：NORMAL/MATERIAL → inventory，CONSUME → consumable
    expect(d.inventory["4001"]).toBe(999);
    expect(d.consumable["consumable_x"]).toEqual({ "0": { ts: -1, count: 999 } });
    // 干员：精二满级/满潜/满技能
    const ch = d.troop.chars["1"];
    expect(ch.evolvePhase).toBe(2);
    expect(ch.level).toBe(90);
    expect(ch.potentialRank).toBe(5);
    expect(ch.mainSkillLvl).toBe(7);
    expect(ch.favorPoint).toBe(25570);
    expect(ch.skills![0].specializeLevel).toBe(3);
    // 皮肤解锁
    expect(d.skin.characterSkins["char_002_amiya#2"]).toBe(1);
    // 基建满级（room_1 有 3 个相位）
    expect(d.building.roomSlots.slot_1.level).toBe(3);
    expect(stats).toMatchObject({ chars: 1, rooms: 1, skins: 1 });
  });

  it("buildingMax 应把房间升到最高相位等级", async () => {
    const result = await service.buildingMax("1");
    expect(pd._playerdata.building.roomSlots.slot_1.level).toBe(3);
    expect(result).toEqual({ rooms: 1 });
  });
});

describe("AdminService 邮件（群发/查看/删除）", () => {
  let service: AdminService;

  beforeEach(() => {
    vi.restoreAllMocks();
    service = new AdminService();
    const pd = makeFullPd();
    stubAccounts(pd);
    vi.spyOn(accountManager, "savePlayerData").mockResolvedValue(undefined as any);
    vi.spyOn(accountManager, "saveUserConfig").mockResolvedValue(undefined as any);
    vi.mocked(appendFile).mockResolvedValue(undefined);
    vi.mocked(mkdir).mockResolvedValue(undefined);
  });

  it("sendMailAll 应遍历所有用户发送", async () => {
    const spy = vi
      .spyOn(mailManager, "sendMail")
      .mockResolvedValue({ mailId: 1000000 } as any);
    const result = await service.sendMailAll({ subject: "公告", content: "hi", items: [] });
    expect(result).toEqual({ sent: 1 });
    expect(spy).toHaveBeenCalledWith(
      "1",
      expect.objectContaining({ subject: "公告" }),
    );
  });

  it("listMails 应返回带中文附件名的邮件摘要", async () => {
    vi.spyOn(mailManager, "listAllMail").mockReturnValue([
      {
        mailId: 1000001,
        subject: "欢迎",
        content: "",
        createAt: 100,
        expireAt: 200,
        receiveAt: -1,
        state: 0,
        hasItem: 1,
        items: [{ id: "4001", type: "GOLD", count: 100 }],
      } as any,
    ]);
    const mails = await service.listMails("1");
    expect(mails).toHaveLength(1);
    expect(mails[0].subject).toBe("欢迎");
    expect(mails[0].items).toEqual([{ id: "4001", name: "龙门币", count: 100 }]);
  });

  it("deleteMail 应透传删除结果", async () => {
    const spy = vi.spyOn(mailManager, "deleteMail").mockResolvedValue(true);
    expect(await service.deleteMail("1", 1000001)).toBe(true);
    expect(spy).toHaveBeenCalledWith("1", 1000001);
    spy.mockResolvedValue(false);
    expect(await service.deleteMail("1", 999)).toBe(false);
  });
});

describe("AdminService 服务器控制与数据导出", () => {
  let service: AdminService;
  let pd: any;

  beforeEach(() => {
    vi.restoreAllMocks();
    service = new AdminService();
    pd = makeFullPd();
    pd.status = { refreshTime: vi.fn().mockResolvedValue(undefined) } as any;
    pd.mission = { dailyRefresh: vi.fn().mockResolvedValue(undefined) } as any;
    stubAccounts(pd);
    vi.spyOn(accountManager, "savePlayerData").mockResolvedValue(undefined as any);
    vi.spyOn(accountManager, "saveUserConfig").mockResolvedValue(undefined as any);
    vi.mocked(appendFile).mockResolvedValue(undefined);
    vi.mocked(mkdir).mockResolvedValue(undefined);
  });

  it("refreshUser 应触发每日刷新并落盘", async () => {
    await service.refreshUser("1");
    expect(pd.status.refreshTime).toHaveBeenCalled();
    expect(pd.mission.dailyRefresh).toHaveBeenCalled();
    expect(accountManager.savePlayerData).toHaveBeenCalledWith("1");
  });

  it("refreshUser 对不存在用户应抛错", async () => {
    await expect(service.refreshUser("999")).rejects.toThrow(/不存在/);
  });

  it("saveUser 应立即保存", async () => {
    await service.saveUser("1");
    expect(accountManager.savePlayerData).toHaveBeenCalledWith("1");
  });

  it("getRawJson 应返回完整玩家数据", async () => {
    const raw = await service.getRawJson("1");
    expect(raw).toEqual(pd._playerdata);
  });
});

describe("AdminService 统计", () => {
  let service: AdminService;

  beforeEach(() => {
    vi.restoreAllMocks();
    service = new AdminService();
    const pd = makeFullPd();
    stubAccounts(pd);
    vi.mocked(appendFile).mockResolvedValue(undefined);
    vi.mocked(mkdir).mockResolvedValue(undefined);
  });

  it("stats 应聚合等级分布/注册分布/资源合计", async () => {
    const s = await service.stats();
    expect(s.userCount).toBe(1);
    expect(s.levelDist).toEqual({ "60-69": 1 });
    expect(s.totalGold).toBe(99999);
    expect(s.totalDiamond).toBe(100);
    expect(s.totalChars).toBe(4); // curCharInstId - 1
    expect(s.avgLevel).toBe(60);
  });

  it("stats 对空用户表应返回零值", async () => {
    (accountManager as any).data = {};
    const s = await service.stats();
    expect(s.userCount).toBe(0);
    expect(s.avgLevel).toBe(0);
  });
});

describe("AdminService 邮件与建号", () => {
  let service: AdminService;

  beforeEach(() => {
    vi.restoreAllMocks();
    // createUser 走 real 模式建号（single 模式下 registerUser 已短路为收敛固定账号）
    (config as any).authMode = "real";
    service = new AdminService();
    const pd = makeFullPd();
    stubAccounts(pd);
    vi.spyOn(accountManager, "savePlayerData").mockResolvedValue(undefined as any);
    vi.spyOn(accountManager, "saveUserConfig").mockResolvedValue(undefined as any);
    vi.mocked(appendFile).mockResolvedValue(undefined);
    vi.mocked(mkdir).mockResolvedValue(undefined);
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
