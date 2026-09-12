/**
 * 适配表重复键扫描器（纯函数，零依赖）
 *
 * 背景：`scripts/playerdata-server-adapt.ts` / `scripts/excel-server-adapt.ts` 里的
 * 覆盖表（`SERVER_ADD_FIELDS` / `SERVER_OVERRIDE_FIELDS` / `EXCEL_*` 等）是
 * 生成器（`pnpm run generate:types`）的**唯一输入**，决定生成的玩家/表数据类型。
 * 这些表是几百行的对象字面量，复制粘贴极易产生**同名键**；JS 语义下「后者胜」，
 * 被覆盖的声明会**静默失效**——生成出来的类型与作者意图不一致，且 tsc 只在
 * 同一字面量内报 TS1117，跨行/嵌套场景不一定暴露。
 *
 * 历史实例：`SERVER_ADD_FIELDS.PlayerCharPatch` 声明两次
 * （117 行 `skills: "PlayerSkill[]"` 与 177 行内联线格式），后者静默覆盖前者。
 *
 * 因此本扫描器按「源码文本 → 对象字面量嵌套形状」解析并报告重复键，
 * 作为守卫测试（tests/unit/scripts/adapt-table-keys.test.ts）的度量基础。
 *
 * 关键点：**注释必须剥离，字符串必须保留**——键既可能是标识符，也可能是
 * `"[server]"` 这类引号字符串；同时字符串里的 `{`/`}`/`:` 不得干扰深度判定。
 */

/** 单个重复键发现 */
export interface DuplicateKeyFinding {
  /** 所属导出表名（如 SERVER_ADD_FIELDS） */
  table: string;
  /** 键路径（顶层键为 `Key`，嵌套为 `Parent.Key`） */
  path: string;
  /** 该路径出现的次数 */
  count: number;
}

/** 剥离注释、保留字符串的源码 */
export function stripComments(src: string): string {
  let out = "";
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") {
      while (i < n && src[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) i++;
      i += 2;
      out += " ";
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      out += c;
      i++;
      while (i < n) {
        if (src[i] === "\\") {
          out += src[i] + (src[i + 1] ?? "");
          i += 2;
          continue;
        }
        out += src[i];
        if (src[i] === quote) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/**
 * 读取 `from` 处的对象字面量，返回其 body 与右花括号下标
 * @param src - 已剥离注释的源码
 * @param from - `{` 的下标
 * @returns body 文本与结束下标（未找到配对时 end 为 -1）
 */
function readObjectBody(src: string, from: number): { body: string; end: number } {
  let depth = 0;
  let i = from;
  const start = from + 1;
  while (i < src.length) {
    const c = src[i];
    if (c === '"' || c === "'" || c === "`") {
      i = skipString(src, i);
      continue;
    }
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return { body: src.slice(start, i), end: i };
    }
    i++;
  }
  return { body: "", end: -1 };
}

/**
 * 跳过一段字符串字面量
 * @param src - 源码
 * @param from - 引号下标
 * @returns 字符串结束后的下标
 */
function skipString(src: string, from: number): number {
  const quote = src[from];
  let i = from + 1;
  while (i < src.length) {
    if (src[i] === "\\") {
      i += 2;
      continue;
    }
    if (src[i] === quote) return i + 1;
    i++;
  }
  return i;
}

/**
 * 收集对象字面量 body 的直接子键（深度 1），并递归收集嵌套子键路径
 *
 * 只把「`key:` 出现在当前层」的片段当作键：先按深度切分当前层的段落，
 * 每段的首个 `key:` 即该层的一个键。
 * @param body - 对象字面量内部文本（不含外层花括号）
 * @param prefix - 已有的键路径前缀（顶层为空串）
 * @param out - 收集结果（键路径数组，允许重复）
 */
function collectKeys(body: string, prefix: string, out: string[]): void {
  let depth = 0;
  let i = 0;
  /** 当前段的起始下标 */
  let segStart = 0;
  /** 当前层已消费到下一个键 */
  const segments: string[] = [];
  while (i < body.length) {
    const c = body[i];
    if (c === '"' || c === "'" || c === "`") {
      i = skipString(body, i);
      continue;
    }
    if (c === "{" || c === "[" || c === "(") depth++;
    else if (c === "}" || c === "]" || c === ")") depth--;
    else if (c === "," && depth === 0) {
      segments.push(body.slice(segStart, i));
      segStart = i + 1;
    }
    i++;
  }
  segments.push(body.slice(segStart));
  for (const seg of segments) {
    const parsed = parseSegment(seg);
    if (!parsed) continue;
    const path = prefix ? `${prefix}.${parsed.key}` : parsed.key;
    out.push(path);
    if (parsed.valueBody) {
      const nested: { body: string; end: number } = parsed.valueBody;
      collectKeys(nested.body, path, out);
    }
  }
}

/**
 * 解析单个「键: 值」段
 *
 * 键支持标识符与引号字符串两种写法（后者见 `SERVER_FIELD_TYPE_OVERRIDES`
 * 的 `"Iface.field": "type"`）；值以 `{` 起始时返回其对象字面量 body 以便递归。
 * @param seg - 段文本（顶层逗号切分所得）
 * @returns 键名与该值为对象字面量时的 body（否则 valueBody 为 null）
 */
function parseSegment(seg: string): { key: string; valueBody: { body: string; end: number } | null } | null {
  const trimmed = seg.trim();
  if (!trimmed) return null;
  let key = "";
  let rest = "";
  if (trimmed.startsWith('"') || trimmed.startsWith("'")) {
    const quote = trimmed[0];
    let i = 1;
    let raw = "";
    while (i < trimmed.length) {
      if (trimmed[i] === "\\") {
        raw += trimmed[i + 1] ?? "";
        i += 2;
        continue;
      }
      if (trimmed[i] === quote) break;
      raw += trimmed[i];
      i++;
    }
    key = raw;
    rest = trimmed.slice(i + 1);
  } else {
    const m = /^([A-Za-z_$][\w$]*)\s*:/.exec(trimmed);
    if (!m) return null;
    key = m[1];
    rest = trimmed.slice(m[0].length);
  }
  const value = rest.replace(/^:\s*/, "").trim();
  if (!value) return null;
  if (value.startsWith("{")) {
    const inner = readObjectBody(value, 0);
    return { key, valueBody: inner.end >= 0 ? inner : null };
  }
  return { key, valueBody: null };
}

/**
 * 扫描源码中所有 `export const <NAME> ... = { ... }` 表的重复键
 * @param src - 源码全文
 * @returns 重复键发现（按出现顺序；count ≥ 2 才返回）
 */
export function scanDuplicateTableKeys(src: string): DuplicateKeyFinding[] {
  const code = stripComments(src);
  const findings: DuplicateKeyFinding[] = [];
  const re = /export\s+const\s+([A-Za-z_$][\w$]*)\s*(?::[^=]*)?=\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code))) {
    const table = m[1];
    const braceIndex = m.index + m[0].length - 1;
    const { body, end } = readObjectBody(code, braceIndex);
    if (end < 0) continue;
    const keys: string[] = [];
    collectKeys(body, "", keys);
    const seen = new Map<string, number>();
    for (const k of keys) seen.set(k, (seen.get(k) ?? 0) + 1);
    for (const [path, count] of seen) {
      if (count > 1) findings.push({ table, path, count });
    }
    re.lastIndex = end;
  }
  return findings;
}
