/**
 * CG 收藏持久化存储（按 uid 独立文件，仿 data/user/mails.json）
 *
 * 数据文件：data/user/cgCollection.json，结构 { user: { [uid]: string[] } }。
 * 每次读取与磁盘同步（文件存在则重新加载，损坏时回退空库），变更即落盘。
 * 与 gallery 缩略图一样属持久化用户数据。
 */
import { dirname, join } from "node:path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

interface CgCollectionDB {
  user: Record<string, string[]>;
}

const CG_COLLECTION_PATH = join(__dirname, "../../../../data/user/cgCollection.json");

export class CgCollectionStore {
  private _db: CgCollectionDB = { user: {} };

  constructor(private readonly _filepath: string = CG_COLLECTION_PATH) {}

  /** 从磁盘加载（文件存在时覆盖内存态；不存在/损坏时保留内存态） */
  private _load(): void {
    try {
      if (existsSync(this._filepath)) {
        this._db = JSON.parse(readFileSync(this._filepath, "utf8")) as CgCollectionDB;
      }
    } catch {
      // 文件损坏/不可读：保留内存态
    }
  }

  /** 落盘当前内存库 */
  private _persist(): void {
    mkdirSync(dirname(this._filepath), { recursive: true });
    writeFileSync(this._filepath, JSON.stringify(this._db));
  }

  /** 查询指定 uid 的 CG 收藏列表（副本） */
  list(uid: string): string[] {
    this._load();
    return [...(this._db.user[uid] ?? [])];
  }

  /** 添加 CG 到收藏（幂等）并落盘 */
  add(uid: string, cgId: string): void {
    this._load();
    const list = (this._db.user[uid] ??= []);
    if (!list.includes(cgId)) {
      list.push(cgId);
      this._persist();
    }
  }

  /** 从收藏移除 CG 并落盘 */
  remove(uid: string, cgId: string): void {
    this._load();
    const list = this._db.user[uid];
    if (!list) return;
    const idx = list.indexOf(cgId);
    if (idx >= 0) {
      list.splice(idx, 1);
      this._persist();
    }
  }
}

/** 全局单例（routes 挂载期惰性加载文件） */
export const cgCollectionStore = new CgCollectionStore();
