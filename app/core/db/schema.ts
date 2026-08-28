/**
 * SQLite 建表 SQL（好友系统）
 *
 * 表结构：
 * - friends：好友关系（uid -> friend_uid，alias 备注）
 * - friend_requests：好友申请（from_uid -> to_uid）
 * - visited：访问记录（uid -> visited_uid）
 */
export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS friends (
  uid        TEXT NOT NULL,
  friend_uid TEXT NOT NULL,
  alias      TEXT NOT NULL DEFAULT '',
  create_ts  INTEGER NOT NULL,
  PRIMARY KEY (uid, friend_uid)
);
CREATE INDEX IF NOT EXISTS idx_friends_friend ON friends(friend_uid);

CREATE TABLE IF NOT EXISTS friend_requests (
  from_uid   TEXT NOT NULL,
  to_uid     TEXT NOT NULL,
  create_ts  INTEGER NOT NULL,
  PRIMARY KEY (from_uid, to_uid)
);
CREATE INDEX IF NOT EXISTS idx_friend_requests_to ON friend_requests(to_uid);

CREATE TABLE IF NOT EXISTS visited (
  uid         TEXT NOT NULL,
  visited_uid TEXT NOT NULL,
  ts          INTEGER NOT NULL,
  PRIMARY KEY (uid, visited_uid)
);

-- 用户账号配置（users.json 迁移目标——SQLite 为唯一事实源，users.json 仅首次迁移种子）
CREATE TABLE IF NOT EXISTS users (
  uid        TEXT PRIMARY KEY,
  data       TEXT NOT NULL,
  updated_ts INTEGER NOT NULL
);

-- 战斗回放（独立于用户配置存储——大字符串不再塞进 users 表 JSON，避免每次配置保存全量重写）
CREATE TABLE IF NOT EXISTS replays (
  uid        TEXT NOT NULL,
  stage_id   TEXT NOT NULL,
  replay     TEXT NOT NULL,
  updated_ts INTEGER NOT NULL,
  PRIMARY KEY (uid, stage_id)
);

-- 战斗结算信息（独立于用户配置存储——避免每次战斗结算全量重写 users 表）
CREATE TABLE IF NOT EXISTS battle_infos (
  uid       TEXT NOT NULL,
  battle_id TEXT NOT NULL,
  info      TEXT NOT NULL,
  updated_ts INTEGER NOT NULL,
  PRIMARY KEY (uid, battle_id)
);

-- 战斗结束记录（完整结算数据留存，供未来分析——按 uid 建索引便于历史检索）
CREATE TABLE IF NOT EXISTS battle_records (
  battle_id   TEXT NOT NULL,
  uid         TEXT NOT NULL,
  stage_id    TEXT NOT NULL,
  record      TEXT NOT NULL,
  created_ts  INTEGER NOT NULL,
  PRIMARY KEY (battle_id, uid)
);
CREATE INDEX IF NOT EXISTS idx_battle_records_uid ON battle_records(uid);

-- 玩家存档（方案 A+C：gzip BLOB 文档存储，替代 data/user/databases/*.json）
CREATE TABLE IF NOT EXISTS player_data (
  uid       TEXT PRIMARY KEY,
  data      BLOB NOT NULL,          -- gzip(JSON)
  updated_ts INTEGER NOT NULL
);
`;

