import { describe, it, expect, beforeEach, vi } from "vitest";
import { AdminService } from "../../../app/admin/AdminService";
import { accountManager } from "../../../app/game/manager/AccountManger";
import { PlayerDataManager } from "../../../app/game/manager/PlayerDataManager";
import { exists, readJson } from "@utils/file";
import { copyFile, mkdir, readFile, readdir, appendFile } from "fs/promises";

// 备份/恢复/审计日志：全部文件操作走 mock，不落盘、不读真实存档
vi.mock("@utils/file", () => ({
  exists: vi.fn(),
  size: vi.fn(),
  readJson: vi.fn(),
  // config.ts 模块加载时经 readJsonSync 读配置（返回合法对象避免加载崩溃）
  readJsonSync: vi.fn(() => ({
    Host: "http://127.0.0.1",
    PORT: 8443,
    version: { resVersion: "test", clientVersion: "test" },
  })),
}));
vi.mock("fs/promises", () => ({
  mkdir: vi.fn().mockResolvedValue(undefined),
  copyFile: vi.fn().mockResolvedValue(undefined),
  appendFile: vi.fn().mockResolvedValue(undefined),
  readFile: vi.fn().mockRejectedValue({ code: "ENOENT" }),
  readdir: vi.fn().mockRejectedValue({ code: "ENOENT" }),
}));
// restore 用 new PlayerDataManager 替换内存；mock 类避免真实构造副作用
vi.mock("@game/manager/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));

describe("AdminService 备份/恢复", () => {
  let service: AdminService;

  beforeEach(() => {
    vi.restoreAllMocks();
    service = new AdminService();
    (accountManager as any).data = { "1": {} };
    (accountManager as any).configs = { "1": { uid: "1", auth: { phone: "" } } };
    vi.spyOn(accountManager, "savePlayerData").mockResolvedValue(undefined as any);
    vi.spyOn(accountManager, "saveUserConfig").mockResolvedValue(undefined as any);
    // 恢复默认 mock 行为（restoreAllMocks 会清空实现）
    vi.mocked(mkdir).mockResolvedValue(undefined);
    vi.mocked(copyFile).mockResolvedValue(undefined);
    vi.mocked(appendFile).mockResolvedValue(undefined);
    vi.mocked(readFile).mockRejectedValue({ code: "ENOENT" });
    vi.mocked(readdir).mockRejectedValue({ code: "ENOENT" });
    vi.mocked(exists).mockResolvedValue(true);
  });

  it("backup 应复制存档到备份目录并返回文件信息", async () => {
    vi.mocked(readFile).mockResolvedValue(Buffer.from("{}"));
    const info = await service.backup("1");
    expect(info.name).toMatch(/^1-\d{8}-\d{6}\.json$/);
    expect(info.size).toBe(2);
    expect(copyFile).toHaveBeenCalledWith(
      "./data/user/databases/1.json",
      "./data/user/backups/" + info.name,
    );
    expect(mkdir).toHaveBeenCalledWith("./data/user/backups", { recursive: true });
    // 审计日志
    expect(appendFile).toHaveBeenCalled();
  });

  it("backup 对无存档用户应抛错", async () => {
    vi.mocked(exists).mockResolvedValue(false);
    await expect(service.backup("999")).rejects.toThrow(/用户不存在/);
  });

  it("listBackups 应只列出该用户备份并按时间倒序", async () => {
    vi.mocked(readdir).mockResolvedValue([
      "1-20250102000000.json",
      "2-20250101000000.json",
      "readme.txt",
    ]);
    vi.mocked(readFile).mockResolvedValue(Buffer.from("{}"));
    const list = await service.listBackups("1");
    expect(list).toHaveLength(1);
    expect(list[0].name).toBe("1-20250102000000.json");
    expect(list[0].ts).toBeGreaterThan(0);
  });

  it("listBackups 备份目录不存在应返回空数组", async () => {
    expect(await service.listBackups("1")).toEqual([]);
  });

  it("restore 应拒绝路径穿越文件名", async () => {
    await expect(service.restore("1", "../../etc/passwd")).rejects.toThrow(
      /非法的备份文件名/,
    );
  });

  it("restore 对不存在备份应抛错", async () => {
    vi.mocked(exists).mockResolvedValue(false);
    await expect(service.restore("1", "1-20250101000000.json")).rejects.toThrow(
      /备份不存在/,
    );
  });

  it("restore 应加载备份替换内存并落盘", async () => {
    const backupData = { status: { uid: "1", nickName: "恢复号" } };
    vi.mocked(readJson).mockResolvedValue(backupData as any);
    await service.restore("1", "1-20250101000000.json");
    expect(PlayerDataManager).toHaveBeenCalledWith(backupData);
    expect(accountManager.savePlayerData).toHaveBeenCalledWith("1");
  });
});

describe("AdminService 审计日志", () => {
  let service: AdminService;

  beforeEach(() => {
    vi.restoreAllMocks();
    service = new AdminService();
    vi.mocked(readFile).mockRejectedValue({ code: "ENOENT" });
  });

  it("logs 应解析 JSONL 并返回最新在前", async () => {
    vi.mocked(readFile).mockResolvedValue(
      '{"ts":100,"action":"grantItem","uid":"1","detail":"a"}\n' +
        '{"ts":200,"action":"grantChar","uid":"1","detail":"b"}\n',
    );
    const entries = await service.logs(50);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ ts: 200, action: "grantChar" });
    expect(entries[1]).toMatchObject({ ts: 100, action: "grantItem" });
  });

  it("logs 应跳过损坏行并截断到 limit", async () => {
    vi.mocked(readFile).mockResolvedValue(
      '{"ts":1,"action":"a","uid":"1","detail":"x"}\nbroken-line\n{"ts":2,"action":"b","uid":"1","detail":"y"}\n',
    );
    const entries = await service.logs(1);
    expect(entries).toHaveLength(1);
    expect(entries[0].action).toBe("b");
  });

  it("logs 无日志文件时应返回空数组", async () => {
    expect(await service.logs()).toEqual([]);
  });
});
