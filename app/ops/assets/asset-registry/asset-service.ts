/**
 * 一体化可溯源资产系统 —— 统一资产注册表（AssetService 单例）
 *
 * 把「所有可从官服上游获取的资源 + 资源清单」收拢为一个可溯源、便于管理的注册表：
 * - 资产索引：assets 表（分类/名称/来源/上游版本/hash/大小/时序元数据）
 * - 全链路审计：asset_events 表（acquire 获取 → transform 转换 → modify 修改 → deliver 下发）
 *
 * 设计要点：
 * - 存储于 tmp/asset/index.db（SQLite，gitignored；复用 capture/log 的模式）。
 * - 写入全程 fire-and-forget + 内部 catch，异常绝不阻断主业务。
 * - registerAsset 按 key(name#category#version) 幂等 upsert；recordEvent 记录事件并 emit 供 SSE。
 * - subscribe() 提供新事件订阅，供 Dashboard「资产」Tab 实时尾随。
 */
import { DatabaseSync } from "node:sqlite";
import { mkdir } from "fs/promises";
import * as path from "path";
import { openAssetDb, ASSET_DB_FILENAME } from "./asset-db";
import { logger } from "@utils/logger";

/** 资产分类（一体化资产范围） */
export type AssetCategory = "manifest" | "excel" | "file" | "mod" | "version";
/** 生命周期事件类型（溯源链） */
export type AssetAction = "acquire" | "transform" | "modify" | "deliver";

/** 资产注册行（DB 行形态） */
export interface AssetRecord {
  id: number;
  key: string;
  name: string;
  category: AssetCategory;
  source: string | null;
  version: string | null;
  hash: string | null;
  size: number | null;
  firstSeenAt: number;
  updatedAt: number;
  extra: string | null;
}

/** 审计事件行（DB 行形态） */
export interface AssetEventRecord {
  id: number;
  eid: string;
  assetId: number;
  ts: number;
  action: AssetAction;
  actor: string | null;
  source: string | null;
  version: string | null;
  hashBefore: string | null;
  hashAfter: string | null;
  sizeBefore: number | null;
  sizeAfter: number | null;
  detail: string | null;
}

/** 注册资产输入 */
export interface AssetInput {
  /** 资产名/路径（如 hot_update_list.json 或 data/excel/char_table.json） */
  name: string;
  category: AssetCategory;
  /** 来源（官服 CDN URL / 本地脚本 / 端点） */
  source?: string | null;
  /** 上游版本（resVersion / versionId） */
  version?: string | null;
  /** 当前 hash/md5 */
  hash?: string | null;
  /** 大小（字节） */
  size?: number | null;
  /** 附加元数据（JSON 可序列化对象） */
  extra?: Record<string, unknown> | null;
}

/** 审计事件输入 */
export interface AssetEventInput {
  /** 目标资产（缺失则先自动注册） */
  asset: AssetInput & { name: string; category: AssetCategory };
  action: AssetAction;
  /** 触发者（system / update-data / pack-lua-bundle / 用户操作等） */
  actor?: string | null;
  /** 事件来源（URL/脚本/说明） */
  source?: string | null;
  version?: string | null;
  /** 变更前 hash/大小（溯源 diff） */
  hashBefore?: string | null;
  sizeBefore?: number | null;
  /** 变更后 hash/大小 */
  hashAfter?: string | null;
  sizeAfter?: number | null;
  /** 说明/明细（如 mod 注入列表、表数量） */
  detail?: Record<string, unknown> | null;
  /** 抽样时间（epoch ms；缺省 Date.now()） */
  ts?: number;
}

/** 查询过滤条件 */
export interface AssetQuery {
  category?: AssetCategory;
  /** 按 name 模糊（LIKE %name%） */
  name?: string;
  limit?: number;
  offset?: number;
}

/** 事件查询过滤 */
export interface AssetEventQuery {
  action?: AssetAction;
  assetId?: number;
  limit?: number;
  offset?: number;
}

/** 默认存储根目录（gitignored） */
const DEFAULT_ROOT = "tmp/asset";

/** SQL 参数类型（node:sqlite 接受的输入类型） */
type SqlParam = string | number | null | bigint | Uint8Array;

/** 把 DB 行的 snake_case 行映射为 camelCase 记录（node:sqlite 默认返回空对象键名——需显式取值） */
type AnyRow = Record<string, unknown>;

/** 资产分类的合法枚举（防御非法输入） */
const ASSET_CATEGORIES: readonly AssetCategory[] = [
  "manifest",
  "excel",
  "file",
  "mod",
  "version",
];
/** 事件动作的合法枚举 */
const ASSET_ACTIONS: readonly AssetAction[] = [
  "acquire",
  "transform",
  "modify",
  "deliver",
];

/**
 * 统一资产注册与审计管理器
 *
 * 单例 assetRegistry：configure() 注入测试目录后 init()；生产路径 index.ts 启动时 init()；
 * 写入方（app/ops/assets/asset.ts / scripts/*）经 register/recordEvent 统一落库。
 * 未 init 时写入方调用会触发惰性 init（ensureInit），保证独立工具（CLI 等）开箱即用。
 */
class AssetRegistry {
  private _root = DEFAULT_ROOT;
  private _dbPath = path.join(DEFAULT_ROOT, ASSET_DB_FILENAME);
  private _db: DatabaseSync | null = null;
  /** eid 序号（同毫秒多条事件保证唯一、可排序） */
  private _eidSeq = 0;
  private _listeners = new Set<(e: AssetEventRecord) => void>();

  /**
   * 注入存储配置（测试用：独立临时根目录 + DB 路径，绝不碰真实 tmp/asset/）
   * 已 init 时先关闭旧连接，下次 init 生效。
   */
  configure(opts: { root?: string; dbPath?: string }): void {
    if (opts.root) {
      this._root = opts.root;
      if (!opts.dbPath) this._dbPath = path.join(opts.root, ASSET_DB_FILENAME);
    }
    if (opts.dbPath) this._dbPath = opts.dbPath;
    this.close();
  }

  /** 当前存储根目录 */
  get root(): string {
    return this._root;
  }

  /** DB 是否已打开 */
  isReady(): boolean {
    return this._db !== null;
  }

  /**
   * 初始化（幂等）：建目录 + 开库建表
   * 服务器启动（index.ts）与独立工具（CLI）均调用。
   */
  async init(): Promise<void> {
    if (this._db) return;
    await mkdir(this._root, { recursive: true });
    this._db = openAssetDb(this._dbPath);
  }

  /** 惰性初始化（写入方安全调用：未 init 时补 init） */
  async ensureInit(): Promise<void> {
    if (!this._db) await this.init();
  }

  /** 关闭连接（测试用；configure 更换目录时自动调用） */
  close(): void {
    if (this._db) {
      try {
        this._db.close();
      } catch {
        /* 已关闭忽略 */
      }
      this._db = null;
    }
  }

  /** 重置（测试用：关闭 + 清订阅 + 清序号） */
  reset(): void {
    this.close();
    this._listeners.clear();
    this._eidSeq = 0;
  }

  /** 订阅新审计事件；返回退订函数 */
  subscribe(fn: (e: AssetEventRecord) => void): () => void {
    this._listeners.add(fn);
    return () => this._listeners.delete(fn);
  }

  /** 广播新事件给订阅者（异常不影响存储） */
  private emit(e: AssetEventRecord): void {
    for (const fn of this._listeners) {
      try {
        fn(e);
      } catch {
        /* 订阅者异常不影响存储 */
      }
    }
  }

  /**
   * 安全执行器：任何写操作都被包裹，异常 catch 后记 warn，绝不抛给调用方。
   * 保证「审计写入失败不阻断主业务」这一契约。
   */
  private async safeRun(action: string, fn: () => Promise<void>): Promise<void> {
    try {
      if (!this._db) await this.init();
      await fn();
    } catch (error) {
      logger.warn("AssetRegistry", `${action} 失败（已降级，不影响主业务）: ${(error as Error).message}`);
    }
  }

  /** 生成事件 eid：E-{ts}-{seq}（可排序、唯一） */
  private nextEid(ts: number): string {
    this._eidSeq++;
    return `E-${ts}-${String(this._eidSeq).padStart(4, "0")}`;
  }

  /** 行映射：snake_case DB 行 → camelCase 记录 */
  private mapAsset(row: AnyRow): AssetRecord {
    return {
      id: Number(row.id),
      key: String(row.key),
      name: String(row.name),
      category: row.category as AssetCategory,
      source: row.source == null ? null : String(row.source),
      version: row.version == null ? null : String(row.version),
      hash: row.hash == null ? null : String(row.hash),
      size: row.size == null ? null : Number(row.size),
      firstSeenAt: Number(row.first_seen_at),
      updatedAt: Number(row.updated_at),
      extra: row.extra == null ? null : String(row.extra),
    };
  }

  /** 行映射：事件行 */
  private mapEvent(row: AnyRow): AssetEventRecord {
    return {
      id: Number(row.id),
      eid: String(row.eid),
      assetId: Number(row.asset_id),
      ts: Number(row.ts),
      action: row.action as AssetAction,
      actor: row.actor == null ? null : String(row.actor),
      source: row.source == null ? null : String(row.source),
      version: row.version == null ? null : String(row.version),
      hashBefore: row.hash_before == null ? null : String(row.hash_before),
      hashAfter: row.hash_after == null ? null : String(row.hash_after),
      sizeBefore: row.size_before == null ? null : Number(row.size_before),
      sizeAfter: row.size_after == null ? null : Number(row.size_after),
      detail: row.detail == null ? null : String(row.detail),
    };
  }

  /** 非法输入防护：category 必须命中枚举，缺省规则化 */
  private normCategory(category: AssetCategory): AssetCategory {
    return ASSET_CATEGORIES.includes(category) ? category : "file";
  }

  /** 非法输入防护：action 必须命中枚举 */
  private normAction(action: AssetAction): AssetAction {
    return ASSET_ACTIONS.includes(action) ? action : "modify";
  }

  /** 组装资产幂等 key：name#category#version */
  private assetKey(input: AssetInput): string {
    return `${input.name}#${this.normCategory(input.category)}#${input.version ?? ""}`;
  }

  /**
   * 注册一条资产（幂等 upsert）
   *
   * 按 key(name#category#version) 判定：已存在则更新 hash/size/updated_at，否则插入。
   * 失败静默降级，不抛错。
   */
  register(input: AssetInput): Promise<void> {
    const key = this.assetKey(input);
    const category = this.normCategory(input.category);
    const ts = Date.now();
    return this.safeRun("注册资产", async () => {
      const insert = this._db!.prepare(
        `INSERT INTO assets (key, name, category, source, version, hash, size, first_seen_at, updated_at, extra)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET
           source=excluded.source, version=excluded.version, hash=excluded.hash,
           size=excluded.size, updated_at=excluded.updated_at, extra=excluded.extra`,
      );
      insert.run(
        key,
        input.name,
        category,
        input.source ?? null,
        input.version ?? null,
        input.hash ?? null,
        input.size ?? null,
        ts,
        ts,
        input.extra != null ? JSON.stringify(input.extra) : null,
      );
    });
  }

  /**
   * 查询资产列表（支持按分类/名称过滤 + 分页）
   */
  async listAssets(query: AssetQuery = {}): Promise<{ items: AssetRecord[]; total: number }> {
    const conds: string[] = [];
    const params: SqlParam[] = [];
    if (query.category) {
      conds.push("category = ?");
      params.push(query.category);
    }
    if (query.name) {
      conds.push("name LIKE ?");
      params.push(`%${query.name}%`);
    }
    const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
    const limit = Math.min(query.limit ?? 100, 500);
    const offset = Math.max(query.offset ?? 0, 0);
    try {
      if (!this._db) await this.init();
      const countRow = this._db!.prepare(`SELECT COUNT(*) AS c FROM assets ${where}`).get(...params) as AnyRow;
      const rows = this._db!
        .prepare(`SELECT * FROM assets ${where} ORDER BY updated_at DESC LIMIT ? OFFSET ?`)
        .all(...params, limit, offset) as AnyRow[];
      return {
        items: rows.map((r) => this.mapAsset(r)),
        total: Number(countRow?.c ?? 0),
      };
    } catch (error) {
      logger.warn("AssetRegistry", `查询资产列表失败: ${(error as Error).message}`);
      return { items: [], total: 0 };
    }
  }

  /**
   * 查询单个资产的完整溯源链（事件按时间升序）
   *
   * @param name - 资产名（按 name 精确查；同名多版本取 id 最大者）
   */
  async getAssetLineage(name: string): Promise<{ asset: AssetRecord | null; events: AssetEventRecord[] }> {
    try {
      if (!this._db) await this.init();
      const assetRow = this._db!
        .prepare(`SELECT * FROM assets WHERE name = ? ORDER BY id DESC LIMIT 1`)
        .get(name) as AnyRow | undefined;
      if (!assetRow) return { asset: null, events: [] };
      const asset = this.mapAsset(assetRow);
      const evRows = this._db!
        .prepare(`SELECT * FROM asset_events WHERE asset_id = ? ORDER BY ts ASC, id ASC`)
        .all(asset.id) as AnyRow[];
      return { asset, events: evRows.map((r) => this.mapEvent(r)) };
    } catch (error) {
      logger.warn("AssetRegistry", `查询资产溯源链失败: ${(error as Error).message}`);
      return { asset: null, events: [] };
    }
  }

  /**
   * 查询审计事件流（支持按动作/资产过滤 + 分页，时间降序）
   */
  async listEvents(query: AssetEventQuery = {}): Promise<{ items: AssetEventRecord[]; total: number }> {
    const conds: string[] = [];
    const params: SqlParam[] = [];
    if (query.action) {
      conds.push("action = ?");
      params.push(query.action);
    }
    if (query.assetId != null) {
      conds.push("asset_id = ?");
      params.push(query.assetId);
    }
    const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
    const limit = Math.min(query.limit ?? 100, 500);
    const offset = Math.max(query.offset ?? 0, 0);
    try {
      if (!this._db) await this.init();
      const countRow = this._db!.prepare(`SELECT COUNT(*) AS c FROM asset_events ${where}`).get(...params) as AnyRow;
      const rows = this._db!
        .prepare(`SELECT * FROM asset_events ${where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`)
        .all(...params, limit, offset) as AnyRow[];
      return {
        items: rows.map((r) => this.mapEvent(r)),
        total: Number(countRow?.c ?? 0),
      };
    } catch (error) {
      logger.warn("AssetRegistry", `查询审计事件失败: ${(error as Error).message}`);
      return { items: [], total: 0 };
    }
  }

  /**
   * 记录一条生命周期审计事件（历史事件链的原子一环）
   *
   * 自动确保目标资产已注册（缺失则先注册），写入事件并广播给订阅者。
   * 失败静默降级，不抛错。
   *
   * @param input - 事件输入
   */
  async recordEvent(input: AssetEventInput): Promise<void> {
    // 先注册资产（幂等），再插事件；整体经 safeRun 兜底
    await this.register(input.asset);

    const action = this.normAction(input.action);
    const ts = input.ts ?? Date.now();
    const eid = this.nextEid(ts);
    const key = this.assetKey(input.asset);

    await this.safeRun("记录审计事件", async () => {
      const assetRow = this._db!
        .prepare(`SELECT * FROM assets WHERE key = ? ORDER BY id DESC LIMIT 1`)
        .get(key) as AnyRow | undefined;
      if (!assetRow) return;
      const assetId = Number((assetRow as AnyRow).id);

      const insert = this._db!.prepare(
        `INSERT INTO asset_events
           (eid, asset_id, ts, action, actor, source, version, hash_before, hash_after, size_before, size_after, detail)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );
      const runResult = insert.run(
        eid,
        assetId,
        ts,
        action,
        input.actor ?? null,
        input.source ?? null,
        input.version ?? null,
        input.hashBefore ?? null,
        input.hashAfter ?? null,
        input.sizeBefore ?? null,
        input.sizeAfter ?? null,
        input.detail != null ? JSON.stringify(input.detail) : null,
      );

      this.emit(this.mapEvent({
        id: Number(runResult.lastInsertRowid as bigint),
        eid,
        asset_id: assetId,
        ts,
        action,
        actor: input.actor ?? null,
        source: input.source ?? null,
        version: input.version ?? null,
        hash_before: input.hashBefore ?? null,
        hash_after: input.hashAfter ?? null,
        size_before: input.sizeBefore ?? null,
        size_after: input.sizeAfter ?? null,
        detail: input.detail != null ? JSON.stringify(input.detail) : null,
      } as AnyRow));
    });
  }
}

/** 统一资产注册表单例 */
export const assetRegistry = new AssetRegistry();