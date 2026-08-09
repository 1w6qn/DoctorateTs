import { describe, it, expect, beforeEach, vi } from "vitest";
import { AdminService } from "../../../app/admin/AdminService";
import { accountManager } from "../../../app/game/manager/AccountManger";
import { mailManager } from "../../../app/game/manager/mail";
import { mockPlayerData } from "../../helpers";
import config from "../../../app/config";
import { appendFile, mkdir } from "fs/promises";
import { runMigration } from "../../../scripts/migrate-official";

// 官服迁移 mock（不真实联网/写库）
vi.mock("../../../scripts/migrate-official", () => ({
  runMigration: vi.fn(),
  parseAccounts: vi.fn(),
}));

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
    GachaTable: {
      gachaPoolClient: [
        {
          gachaPoolId: "NORMAL_0_1",
          gachaPoolName: "测试卡池",
          gachaRuleType: "NORMAL",
          openTime: 0,
          endTime: 9999999999,
          guarantee5Count: 10,
          guarantee5Avail: 1,
          gachaPoolSummary: "test",
        },
      ],
    },
    GachaDetailTable: {
      details: {
        NORMAL_0_1: {
          upCharInfo: {
            perCharList: [
              { rarityRank: 5, charIdList: ["char_002_amiya"], percent: 2, count: 1 },
            ],
          },
          availCharInfo: {
            perAvailList: [
              { rarityRank: 4, charIdList: ["char_002_amiya"], totalPercent: 50 },
            ],
          },
          limitedChar: [],
        },
      },
    },
    StageTable: {
      stages: {
        "main_01-01": {},
        "main_01-02": {},
      },
    },
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
    gacha: { normal: {}, limit: {} } as any,
    dungeon: { stages: {} } as any,
    mission: { missions: {}, missionRewards: {}, missionGroups: {} } as any,
    medal: { medals: {}, custom: {} } as any,
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

  it("listUsers 应支持按昵称/手机号/uid 过滤", async () => {
    expect(await service.listUsers("阿米娅")).toHaveLength(1);
    expect(await service.listUsers("13800000000")).toHaveLength(1);
    expect(await service.listUsers("99999")).toHaveLength(0);
    expect(await service.listUsers("")).toHaveLength(1);
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

describe("AdminService 游戏协议代理", () => {
  let service: AdminService;

  beforeEach(() => {
    vi.restoreAllMocks();
    service = new AdminService();
    const pd = makeFullPd();
    stubAccounts(pd);
    vi.mocked(appendFile).mockResolvedValue(undefined);
    vi.mocked(mkdir).mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("gameProxy 应以玩家 secret 转发请求并返回解析后的 JSON", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      status: 200,
      text: vi.fn().mockResolvedValue('{"playerDataDelta":{"modified":{}}}'),
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await service.gameProxy("1", "/user/info", "GET");
    expect(result).toMatchObject({ status: 200, uid: "1" });
    expect(result.data).toEqual({ playerDataDelta: { modified: {} } });
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/user/info"),
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({ secret: "1" }),
      }),
    );
  });

  it("gameProxy 应带 JSON body 转发 POST", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      status: 200,
      text: vi.fn().mockResolvedValue("{}"),
    });
    vi.stubGlobal("fetch", fetchMock);

    await service.gameProxy("1", "/gacha/advancedGacha", "POST", {
      poolId: "p1",
      useTkt: 0,
      itemId: null,
    });
    const [, opts] = fetchMock.mock.calls[0];
    expect(JSON.parse(opts.body)).toEqual({ poolId: "p1", useTkt: 0, itemId: null });
  });

  it("gameProxy 应拒绝代理控制面路径", async () => {
    await expect(service.gameProxy("1", "/admin/api/status")).rejects.toThrow(
      /不允许代理控制面路径/,
    );
    await expect(service.gameProxy("1", "/auth/login")).rejects.toThrow(
      /不允许代理控制面路径/,
    );
  });

  it("gameProxy 对不以 / 开头的路径应抛错", async () => {
    await expect(service.gameProxy("1", "user/info")).rejects.toThrow(/必须以 \//);
  });

  it("gameProxy 对服务器内部请求失败应抛明确错误", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    await expect(service.gameProxy("1", "/user/info")).rejects.toThrow(
      /服务器内部请求失败/,
    );
  });

  it("gameProxy 对非 JSON 响应应原样返回文本", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ status: 500, text: vi.fn().mockResolvedValue("<html>err</html>") }),
    );
    const result = await service.gameProxy("1", "/user/info");
    expect(result.status).toBe(500);
    expect(result.data).toBe("<html>err</html>");
  });
});

describe("AdminService 卡池管理", () => {
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

  it("listPools 应返回卡池清单并映射 gachaType", () => {
    const pools = service.listPools();
    expect(pools).toHaveLength(1);
    expect(pools[0]).toMatchObject({
      poolId: "NORMAL_0_1",
      name: "测试卡池",
      ruleType: "NORMAL",
      gachaType: "normal",
      guarantee5Count: 10,
    });
  });

  it("poolDetail 应返回 UP/可用干员中文名与概率", () => {
    const detail = service.poolDetail("NORMAL_0_1");
    expect(detail!.upChars).toEqual([
      { charId: "char_002_amiya", name: "阿米娅", percent: 2, count: 1, rarityRank: 5 },
    ]);
    expect(detail!.availChars).toHaveLength(1);
    expect(detail!.limitedChars).toEqual([]);
  });

  it("poolDetail 对不存在卡池应返回 null", () => {
    expect(service.poolDetail("NO_SUCH")).toBeNull();
  });

  it("getPlayerPoolState 应返回 UP 选择与保底计数", async () => {
    (pd._playerdata.gacha as any).normal["NORMAL_0_1"] = { upChar: ["char_002_amiya"] };
    const st = await service.getPlayerPoolState("1", "NORMAL_0_1");
    expect(st.upCharIds).toEqual(["char_002_amiya"]);
    expect(st.upChars).toEqual([{ charId: "char_002_amiya", name: "阿米娅" }]);
    expect(st.beforeNonHitCnt).toBe(0);
    expect(st.guarantee5Count).toBe(10);
  });

  it("setPlayerPoolUp 应写入 gacha[gachaType][poolId].upChar 并支持中文名", async () => {
    await service.setPlayerPoolUp("1", "NORMAL_0_1", ["阿米娅"]);
    expect((pd._playerdata.gacha as any).normal["NORMAL_0_1"].upChar).toEqual([
      "char_002_amiya",
    ]);
    expect(accountManager.savePlayerData).toHaveBeenCalledWith("1");
  });

  it("setPlayerPoolUp 空数组应清除 UP", async () => {
    (pd._playerdata.gacha as any).normal["NORMAL_0_1"] = { upChar: ["char_002_amiya"] };
    await service.setPlayerPoolUp("1", "NORMAL_0_1", []);
    expect((pd._playerdata.gacha as any).normal["NORMAL_0_1"].upChar).toEqual([]);
  });

  it("setPlayerPoolUp 对不存在卡池应抛错", async () => {
    await expect(service.setPlayerPoolUp("1", "NO_SUCH", ["char_002_amiya"])).rejects.toThrow(
      /卡池不存在/,
    );
  });

  it("setPlayerPity 应写入账号配置并落盘", async () => {
    const r = await service.setPlayerPity("1", "normal", 42);
    expect(r).toEqual({ uid: "1", ruleType: "NORMAL", beforeNonHitCnt: 42 });
    expect((accountManager as any).configs["1"].gacha.NORMAL.beforeNonHitCnt).toBe(42);
    expect(accountManager.savePlayerData).toHaveBeenCalledWith("1");
  });

  it("setPlayerPity 对负数应抛错", async () => {
    await expect(service.setPlayerPity("1", "NORMAL", -1)).rejects.toThrow(/非负整数/);
  });

  it("getPlayerPity / listPlayerPity 应读取保底", async () => {
    (accountManager as any).configs["1"].gacha = { NORMAL: { beforeNonHitCnt: 5 } };
    expect((await service.getPlayerPity("1", "NORMAL")).beforeNonHitCnt).toBe(5);
    expect(await service.listPlayerPity("1")).toEqual([
      { ruleType: "NORMAL", beforeNonHitCnt: 5 },
    ]);
  });
});

describe("AdminService 批量工具", () => {
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

  it("grantAllItems 应把全部物品写入背包/消耗品", async () => {
    const r = await service.grantAllItems("1", 999);
    expect(r).toEqual({ items: 4 }); // mock ItemTable: 3 个 NORMAL/MATERIAL + 1 个 CONSUME
    const d = pd._playerdata;
    expect(d.inventory["4001"]).toBe(999);
    expect(d.inventory["4003"]).toBe(999);
    expect(d.inventory["9999"]).toBe(999);
    expect(d.consumable["consumable_x"]).toEqual({ "0": { ts: -1, count: 999 } });
    expect(accountManager.savePlayerData).toHaveBeenCalledWith("1");
  });

  it("grantAllItems 数量非法应抛错", async () => {
    await expect(service.grantAllItems("1", 0)).rejects.toThrow(/正整数/);
  });

  it("maxAllChars 应拉满全部已有干员", async () => {
    const r = await service.maxAllChars("1");
    expect(r).toEqual({ chars: 1 });
    const ch = pd._playerdata.troop.chars["1"];
    expect(ch.evolvePhase).toBe(2);
    expect(ch.level).toBe(90);
    expect(ch.potentialRank).toBe(5);
    expect(ch.mainSkillLvl).toBe(7);
    expect(ch.skills![0].specializeLevel).toBe(3);
  });

  it("listStages 应返回推图进度统计", async () => {
    (pd._playerdata.dungeon as any).stages = {
      "main_01-01": { stageId: "main_01-01", completeTimes: 3, startTimes: 3, practiceTimes: 0, state: 3, hasBattleReplay: 1, noCostCnt: 0 },
      "main_01-02": { stageId: "main_01-02", completeTimes: 0, startTimes: 1, practiceTimes: 0, state: 1, hasBattleReplay: 0, noCostCnt: 0 },
    };
    const st = await service.listStages("1");
    expect(st.total).toBe(2);
    expect(st.done).toBe(1);
    expect(st.stages[0].stageId).toBe("main_01-01");
  });

  it("repairChars 应补齐缺失字段与阿米娅 tmpl", async () => {
    const ch = pd._playerdata.troop.chars["1"];
    delete ch.voiceLan;
    delete ch.skills;
    // starMark/equip/currentEquip 本就不存在，阿米娅无 currentTmpl/tmpl
    const r = await service.repairChars("1");
    expect(r.chars).toBe(1);
    expect(r.fields).toBeGreaterThanOrEqual(5);
    const fixed = pd._playerdata.troop.chars["1"];
    expect(fixed.voiceLan).toBe("CN_MANDARIN");
    expect(fixed.starMark).toBe(0);
    expect(fixed.skills!.length).toBeGreaterThan(0);
    expect(fixed.currentTmpl).toBe("char_002_amiya");
    expect(fixed.tmpl).toBeDefined();
    expect(accountManager.savePlayerData).toHaveBeenCalledWith("1");
  });

  it("repairChars 对完整干员应无改动", async () => {
    const ch = pd._playerdata.troop.chars["1"];
    // 补齐 mock 干员自然缺失的字段，构成"完整"干员
    ch.starMark = 0;
    ch.currentEquip = null;
    ch.equip = {};
    ch.currentTmpl = "char_002_amiya";
    ch.tmpl = {};
    const before = JSON.stringify(ch);
    const r = await service.repairChars("1");
    expect(r.fields).toBe(0);
    expect(JSON.stringify(pd._playerdata.troop.chars["1"])).toBe(before);
  });
});

describe("AdminService 关卡/物品/任务", () => {
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

  it("unlockStage 应写入关卡完成状态", async () => {
    const r = await service.unlockStage("1", "main_01-01");
    expect(r).toEqual({ stageId: "main_01-01" });
    const s = pd._playerdata.dungeon.stages["main_01-01"];
    expect(s.state).toBe(3);
    expect(s.completeTimes).toBe(1);
    expect(accountManager.savePlayerData).toHaveBeenCalledWith("1");
  });

  it("unlockStage 对未知关卡应抛错", async () => {
    await expect(service.unlockStage("1", "no_such_stage")).rejects.toThrow(/关卡不存在/);
  });

  it("unlockAllStages 应补全缺失关卡并跳过已有进度", async () => {
    (pd._playerdata.dungeon as any).stages["main_01-01"] = { state: 3, completeTimes: 3 };
    const r = await service.unlockAllStages("1");
    expect(r).toEqual({ stages: 1, total: 2 });
    expect(pd._playerdata.dungeon.stages["main_01-02"].state).toBe(3);
    expect(pd._playerdata.dungeon.stages["main_01-01"].completeTimes).toBe(3);
  });

  it("searchItems 应按名称/ID 过滤", () => {
    expect(service.searchItems("龙门币").map((i) => i.id)).toEqual(["4001"]);
    expect(service.searchItems("4003").map((i) => i.id)).toEqual(["4003"]);
    expect(service.searchItems("不存在")).toEqual([]);
    expect(service.searchItems("").length).toBeGreaterThan(0);
  });

  it("listMissionStats 应统计各组完成数", async () => {
    (pd._playerdata.mission as any).missions = {
      daily: {
        m1: { state: 2, progress: [] },
        m2: { state: 0, progress: [] },
      },
    };
    const st = await service.listMissionStats("1");
    expect(st.total).toBe(2);
    expect(st.done).toBe(1);
    expect(st.groups).toEqual([{ group: "daily", total: 2, done: 1 }]);
  });

  it("listMedals 应统计已解锁勋章（fts>0）", async () => {
    (pd._playerdata.medal as any).medals = {
      medal_1: { id: "medal_1", val: [], fts: 100, rts: 0 },
      medal_2: { id: "medal_2", val: [], fts: 0, rts: 0 },
    };
    const st = await service.listMedals("1");
    expect(st.total).toBe(2);
    expect(st.unlocked).toBe(1);
    expect(st.medals[0]).toMatchObject({ id: "medal_1", unlocked: true });
  });
});

describe("AdminService 官服迁移", () => {
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
    vi.mocked(runMigration).mockResolvedValue([
      { phone: "13800000000", uid: "2", nickName: "A" },
      { phone: "13900000000", error: "登录失败" },
    ]);
  });

  it("migrateOfficial 应透传账号文本、热加载成功用户并审计", async () => {
    const reloadSpy = vi.spyOn(service, "reloadUser").mockResolvedValue(undefined);
    const results = await service.migrateOfficial(
      "13800000000 pwd\n13900000000 pwd2",
      "1",
    );
    expect(runMigration).toHaveBeenCalledWith({
      accounts: "13800000000 pwd\n13900000000 pwd2",
      templateUid: "1",
    });
    expect(results).toHaveLength(2);
    // 仅成功账号热加载
    expect(reloadSpy).toHaveBeenCalledTimes(1);
    expect(reloadSpy).toHaveBeenCalledWith("2");
    // 审计日志写入
    expect(appendFile).toHaveBeenCalled();
  });

  it("migrateOfficial 空账号应抛错", async () => {
    await expect(service.migrateOfficial("  \n  ", "1")).rejects.toThrow(
      /账号内容为空/,
    );
  });

  it("migrateOfficial 成功账号热加载失败不应中断", async () => {
    vi.mocked(runMigration).mockResolvedValue([
      { phone: "13800000000", uid: "2", nickName: "A" },
    ]);
    vi.spyOn(service, "reloadUser").mockRejectedValue(new Error("文件缺失"));
    const results = await service.migrateOfficial("13800000000 pwd", "1");
    expect(results).toHaveLength(1);
    expect(results[0].uid).toBe("2");
  });
});

describe("AdminService checkData 干员校验", () => {
  let service: AdminService;

  beforeEach(() => {
    vi.restoreAllMocks();
    service = new AdminService();
  });

  const validChar = {
    instId: 1,
    charId: "char_002_amiya",
    level: 1,
    evolvePhase: 0,
    potentialRank: 0,
    mainSkillLvl: 1,
    favorPoint: 0,
    gainTime: 0,
    voiceLan: "CN_MANDARIN",
  };

  it("正常干员应通过（含阿米娅三形态结构）", async () => {
    (accountManager as any).data = {
      "1": {
        _playerdata: {
          status: { uid: "1" },
          troop: { chars: { "1": { ...validChar, currentTmpl: "char_002_amiya", tmpl: {} } } },
        },
      },
    };
    const r = await service.checkData();
    expect(r.ok).toBe(true);
  });

  it("干员缺字段应报错", async () => {
    const { mainSkillLvl, ...noSkill } = validChar;
    (accountManager as any).data = {
      "1": { _playerdata: { status: { uid: "1" }, troop: { chars: { "1": noSkill as any } } } },
    };
    const r = await service.checkData();
    expect(r.ok).toBe(false);
    expect(r.users[0].error).toContain("缺少 mainSkillLvl");
  });

  it("干员不在 CharacterTable 应报错", async () => {
    (accountManager as any).data = {
      "1": { _playerdata: { status: { uid: "1" }, troop: { chars: { "1": { ...validChar, charId: "char_999" } } } } },
    };
    const r = await service.checkData();
    expect(r.ok).toBe(false);
    expect(r.users[0].error).toContain("不在 CharacterTable");
  });

  it("阿米娅缺 currentTmpl/tmpl 应报错", async () => {
    (accountManager as any).data = {
      "1": { _playerdata: { status: { uid: "1" }, troop: { chars: { "1": validChar } } } },
    };
    const r = await service.checkData();
    expect(r.ok).toBe(false);
    expect(r.users[0].error).toContain("阿米娅");
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
