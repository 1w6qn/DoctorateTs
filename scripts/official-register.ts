/**
 * 迁移账号注册与存档写入
 *
 * 将转换后的私服存档写入 data/user/databases/{newUid}.json，
 * 并在 data/user/users.json 中注册账号（auth.phone 用官服手机号、auth.hgId 保留官服 uid）。
 * 新 uid 从现有账号最大值递增。
 */
import { readFileSync, writeFile } from "fs";
import { writeFile as writeFileAsync } from "fs/promises";
import * as path from "path";

const DATA_USER_DIR = path.join(__dirname, "../data/user");
const USERS_FILE = path.join(DATA_USER_DIR, "users.json");

/** 读取 users.json（若不存在返回空） */
export function loadUsers(): { [key: string]: any } {
  try {
    return JSON.parse(readFileSync(USERS_FILE, "utf8"));
  } catch {
    return {};
  }
}

/** 计算下一个新 uid（现有数字最大 +1，最小 2） */
export function nextUid(users: { [key: string]: any }): string {
  let max = 0;
  for (const key of Object.keys(users)) {
    const n = Number(key);
    if (!Number.isNaN(n) && n > max) max = n;
  }
  return String(max + 1);
}

/** 构造注册项（password 随机、auth 关联官服账号、社交/战斗等空结构） */
export function buildUserEntry(
  newUid: string,
  opts: { phone: string; officialUid: string },
): { [key: string]: any } {
  return {
    password: Math.random().toString(36).slice(2, 10),
    auth: {
      hgId: opts.officialUid,
      phone: opts.phone,
      email: "",
      identityNum: "",
      identityName: "",
      isMinor: false,
      isLatestUserAgreement: true,
    },
    uid: newUid,
    social: { friends: [], friendRequests: [], visited: [] },
    battle: { stageId: "", replays: {}, infos: {} },
    gacha: {},
    rlv2: {},
  };
}

/**
 * 注册迁移账号
 * @returns 新 uid
 */
export async function registerImportedUser(opts: {
  phone: string;
  officialUid: string;
  convertedData: { [key: string]: any };
}): Promise<{ uid: string; nickName: string }> {
  const users = loadUsers();
  const newUid = nextUid(users);
  const entry = buildUserEntry(newUid, opts);

  // 1. 写入存档
  await writeFileAsync(
    path.join(DATA_USER_DIR, "databases", `${newUid}.json`),
    JSON.stringify(opts.convertedData),
    "utf8",
  );

  // 2. 注册账号
  users[newUid] = entry;
  await writeFileAsync(USERS_FILE, JSON.stringify(users), "utf8");

  return {
    uid: newUid,
    nickName: opts.convertedData?.status?.nickName ?? "",
  };
}
