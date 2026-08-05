/**
 * 官服数据 → 私服存档转换器
 *
 * 官服 syncData 的 user 字段与私服存档同源（status/troop/dungeon/activity/shop/mission/
 * social/building/medal 等主体直接沿用）；私服特有字段（recruit/checkIn/openServer/
 * campaignsV2/aprilFool/charm 等）从模板存档（通常为 uid=1）复制兜底；
 * uid 替换为私服新 uid；移除官服连接态字段（secret/seqnum 等）。
 */

/** 私服特有字段（官服数据通常不含，需从模板兜底） */
export const PRIVATE_ONLY_FIELDS: string[] = [
  "recruit",
  "checkIn",
  "openServer",
  "campaignsV2",
  "aprilFool",
  "charm",
  "carousel",
  "car",
  "templateTrap",
  "checkMeta",
  "limitedBuff",
  "trainingGround",
  "charRotation",
  "setting",
  "collectionReward",
  "inventory",
  "consumable",
  "nameCardStyle",
  "skin",
];

/** 官服连接态字段（迁移时移除） */
const SESSION_FIELDS = ["secret", "seqnum", "networkVersion"];

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/**
 * 转换官服玩家数据为私服存档
 * @param official - 官服 syncData 的 user 字段
 * @param opts.newUid - 私服新 uid
 * @param opts.template - 模板存档（私服特有字段兜底来源，通常为 uid=1 存档）
 * @returns 私服存档数据
 */
export function convertOfficialData(
  official: { [key: string]: any },
  opts: { newUid: string; template: { [key: string]: any } },
): { [key: string]: any } {
  const data = deepClone(official);

  // 1. uid 替换
  if (data.status) {
    data.status.uid = opts.newUid;
  }

  // 2. 移除连接态字段
  for (const field of SESSION_FIELDS) {
    delete data[field];
  }

  // 3. 私服特有字段兜底（官方已有则优先保留）
  for (const field of PRIVATE_ONLY_FIELDS) {
    if (data[field] === undefined && opts.template[field] !== undefined) {
      data[field] = deepClone(opts.template[field]);
    }
  }

  return data;
}
