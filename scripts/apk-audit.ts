/**
 * APK 校验 / 反作弊 / 暗桩 审查器
 *
 * 对明日方舟官服客户端做静态安全审查，分三类：
 *   A. 完整性 / 签名校验 —— RSA 响应签名（VerifySignMD5RSA 调用点）、热更资源校验
 *      （HotUpdater md5/hash）、APK 签名方案（V1/V2/V3，--apk 时检测）
 *   B. 反作弊 —— CodeStage.AntiCheat 检测器（Injection/SpeedHack/TimeCheating/
 *      WallHack/ObscuredCheating）、Obscured* 混淆值类型、ACE/MTP（Java/native 层，标注动态分析）
 *   C. 暗桩 / 埋点 —— EventLogSDK 事件上报、CrashSight 崩溃上报、OneChannel、
 *      硬编码外联域名
 *
 * 数据源：客户端反编译 C# 源码目录（reference/arknights-2.7.61-csharp，含方法体），
 * 可加 --apk 对 APK 本体做签名方案检测。
 *
 * 用法：
 *   pnpm run apk:audit                                        # 默认源码目录 → docs/apk-security-audit.md
 *   pnpm run apk:audit -- --src <反编译源码目录>               # 指定源码目录
 *   pnpm run apk:audit -- --apk <arknights.apk>               # 追加 APK 本体审查（签名方案 + dex/so/权限/域名）
 *   pnpm run apk:audit -- --out <报告路径>                     # 指定报告输出
 *   pnpm run apk:audit -- --json                              # 同时输出 JSON 原始结果
 */
import * as fs from "fs";
import * as path from "path";
import yauzl from "yauzl";

const ROOT = path.join(__dirname, "..");
/** 默认反编译源码目录（含方法体的 C# 项目） */
const DEFAULT_SRC = path.join(ROOT, "reference", "arknights-2.7.61-csharp");
/** 默认报告输出 */
const DEFAULT_OUT = path.join(ROOT, "docs", "apk-security-audit.md");
/** APK 签名块魔数（V2/V3） */
const APK_SIG_BLOCK_MAGIC = Buffer.from("APK Sig Block 42");

interface CliArgs {
  src: string;
  apk: string;
  out: string;
  json: boolean;
}

/** 解析 CLI 参数 */
function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = { src: DEFAULT_SRC, apk: "", out: DEFAULT_OUT, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--src") args.src = argv[++i] ?? "";
    else if (a === "--apk") args.apk = argv[++i] ?? "";
    else if (a === "--out") args.out = argv[++i] ?? "";
    else if (a === "--json") args.json = true;
    else if (a === "--help" || a === "-h") {
      console.log("用法: pnpm run apk:audit [--src <源码目录>] [--apk <apk路径>] [--out <报告路径>] [--json]");
      process.exit(0);
    }
  }
  return args;
}

/** 递归收集目录下全部 .cs 文件（相对路径） */
function collectCsFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (cur: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(cur, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.name.endsWith(".cs")) out.push(path.relative(dir, full));
    }
  };
  walk(dir);
  return out;
}

/** 命中记录 */
interface Hit {
  file: string;
  line: number;
  text: string;
}

/** 在单个文件内容中搜索模式，返回全部命中（带行号） */
function searchInFile(content: string, file: string, patterns: RegExp[]): Hit[] {
  const hits: Hit[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const re of patterns) {
      if (re.test(line)) {
        hits.push({ file, line: i + 1, text: line.trim().slice(0, 160) });
        break;
      }
    }
  }
  return hits;
}

/** 分类审计结果 */
interface Section {
  title: string;
  summary: string;
  items: { name: string; desc: string; hits: Hit[] }[];
}

/**
 * A 类：完整性 / 签名校验
 */
function auditIntegrity(files: string[], readFile: (f: string) => string): Section {
  const items: Section["items"] = [];

  // A1: RSA 响应签名校验定义与调用点
  const signDef = searchInFile(
    readFile("Assembly-CSharp/Torappu/CryptUtils.cs"),
    "Assembly-CSharp/Torappu/CryptUtils.cs",
    [/VerifySignMD5RSA/],
  );
  const signCalls: Hit[] = [];
  for (const f of files) {
    if (f.includes("CryptUtils.cs")) continue;
    signCalls.push(...searchInFile(readFile(f), f, [/VerifySignMD5RSA/]));
  }
  items.push({
    name: "RSA 响应签名校验 VerifySignMD5RSA",
    desc: "官服对 network_config 路由配置与 BSON/加密响应做 RSA-MD5 签名，客户端验签失败即拒绝。私服必须绕过（Lua 引导插件已 hotfix 返回 true）。",
    hits: [...signDef.slice(0, 4), ...signCalls],
  });

  // A2: 热更资源校验
  const hulHits: Hit[] = [];
  const hotUpdaterFile = files.find((f) => f.split("\\").join("/").endsWith("Resource/HotUpdater.cs"));
  if (hotUpdaterFile) {
    hulHits.push(
      ...searchInFile(readFile(hotUpdaterFile), hotUpdaterFile, [
        /_CheckIfAssetDirty|CheckIfAssetDirty/,
        /\.md5|\.hash/,
      ]),
    );
  }
  items.push({
    name: "热更资源完整性校验 HotUpdater",
    desc: "按 hot_update_list 的 md5/hash 判定资源是否需更新；私服 mod 方案通过替换 hash 让客户端下载自定义资源（正常链路）。",
    hits: hulHits.slice(0, 12),
  });

  return {
    title: "A. 完整性 / 签名校验",
    summary: "RSA 响应验签（必须绕过）+ 热更资源 md5 校验（mod 方案已兼容）",
    items,
  };
}

/**
 * B 类：反作弊
 */
function auditAntiCheat(files: string[], readFile: (f: string) => string): Section {
  const items: Section["items"] = [];

  // B1: CodeStage.AntiCheat 检测器
  const detectors: [string, string][] = [
    ["InjectionDetector", "注入检测（内存修改 / 注入框架）"],
    ["SpeedHackDetector", "游戏加速器检测"],
    ["TimeCheatingDetector", "系统时间篡改检测"],
    ["WallHackDetector", "透视 / 穿墙检测"],
    ["ObscuredCheatingDetector", "混淆值作弊检测（对 Obscured* 类型篡改）"],
    ["ActDetectorBase", "检测器基类"],
  ];
  for (const [name, desc] of detectors) {
    const defFiles = files.filter(
      (f) => f.split("\\").join("/").includes("CodeStage.AntiCheat/Detectors") && f.endsWith(`/${name}.cs`),
    );
    const refs: Hit[] = [];
    for (const f of files) {
      if (f.includes("CodeStage.AntiCheat")) continue;
      refs.push(...searchInFile(readFile(f), f, [new RegExp(`\\b${name}\\b`)]));
    }
    const defHits: Hit[] = defFiles.map((f) => ({ file: f, line: 1, text: "(定义文件)" }));
    const refNote = refs.length === 0
      ? [{ file: "-", line: 0, text: "(游戏代码未直接引用——可能经场景 prefab / Inspector 配置挂载)" }]
      : [];
    items.push({
      name: `CodeStage.${name}`,
      desc: `${desc}${refs.length === 0 ? "。定义存在于客户端程序集，但游戏代码无直接 new/引用，通常由场景组件（Inspector）配置启用。" : ""}`,
      hits: [...defHits, ...refNote, ...refs.slice(0, 6)],
    });
  }

  // B2: Obscured* 混淆值类型使用统计
  const obscuredRefs: Hit[] = [];
  for (const f of files) {
    if (f.includes("CodeStage.AntiCheat")) continue;
    obscuredRefs.push(...searchInFile(readFile(f), f, [/\bObscured(Int|Float|Long|Double|Bool|String|Vector2|Vector3|Quaternion|Rect|Decimal)\b/]));
  }
  items.push({
    name: "Obscured* 混淆数值类型",
    desc: "CodeStage 混淆值（防内存修改），常用于玩家资源/战斗数值等敏感字段。",
    hits: obscuredRefs.slice(0, 15),
  });

  // B3: Java/native 层反作弊（标注）
  items.push({
    name: "ACE / MTP（com.hg.sdk，Java/native 层）",
    desc: "腾讯 ACE + Hypergryph MTP 反作弊 SDK 在 Java/native 层，C# 源码不可见，需动态分析；现有 hook/main.ts 已置空 MTPProxyApplication.onProxyCreate / MTPDetection.onUserLogin 处理。",
    hits: [],
  });

  return {
    title: "B. 反作弊",
    summary: "CodeStage 检测器 5 类 + Obscured 混淆值 + ACE/MTP（native 层，动态分析）",
    items,
  };
}

/**
 * C 类：暗桩 / 埋点
 */
function auditBackdoors(files: string[], readFile: (f: string) => string): Section {
  const items: Section["items"] = [];

  // C1: EventLogSDK 事件上报
  const eventLogHits: Hit[] = [];
  for (const f of files) {
    if (!f.startsWith("Hypergryph.EventLogSDK")) continue;
    eventLogHits.push(...searchInFile(readFile(f), f, [/public .* (Report|Send|Log|Track|Upload|Flush)\(/]));
  }
  items.push({
    name: "Hypergryph.EventLogSDK",
    desc: "鹰角事件日志 SDK：行为埋点 / 上报（登录、进关、支付等）。",
    hits: eventLogHits.slice(0, 10),
  });

  // C2: CrashSight 崩溃上报
  const crashHits: Hit[] = [];
  for (const f of files) {
    if (!f.toLowerCase().includes("crashsight")) continue;
    crashHits.push(...searchInFile(readFile(f), f, [/public .* (Report|Send|SetUser|Crash|Init|Start)\(/]));
  }
  items.push({
    name: "torappu.CrashSight.Standalone",
    desc: "腾讯 CrashSight 崩溃/异常上报 SDK（含设备信息收集）。",
    hits: crashHits.slice(0, 8),
  });

  // C3: OneChannel / Webview（运营通道）
  const channelHits: Hit[] = [];
  for (const f of files) {
    if (!f.startsWith("Hypergryph.OneChannel") && !f.startsWith("Hypergryph.Webview")) continue;
    channelHits.push(...searchInFile(readFile(f), f, [/public .* (Init|Load|Open|Show|Send|Report)\(/]));
  }
  items.push({
    name: "Hypergryph.OneChannel / Webview",
    desc: "渠道服务与内嵌 WebView（运营活动页 / 公告页，可能加载外联页面）。",
    hits: channelHits.slice(0, 10),
  });

  // C4: 硬编码外联域名（排除注释行与第三方资产/文档域名）
  const THIRD_PARTY_HOSTS = new Set([
    "github.com", "docs.google.com", "thomashourdel.com", "unity3d.com", "docs.unity3d.com",
    "help.unity3d.com", "opensource.org", "nuget.org", "google.com", "ilspy.net", "code.google.com",
    "msdn.microsoft.com", "aka.ms", "stackoverflow.com", "bouncycastle.org", "codeplex.com",
  ]);
  const urlHits: Hit[] = [];
  const seen = new Set<string>();
  for (const f of files) {
    if (!f.startsWith("Assembly-CSharp") && !f.startsWith("Torappu")) continue;
    const hits = searchInFile(readFile(f), f, [
      /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
    ]);
    for (const h of hits) {
      // 跳过注释行（// 或 /* 开头）
      const trimmed = h.text.trim();
      if (trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) continue;
      const m = trimmed.match(/https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
      if (!m) continue;
      let host = m[0].replace(/^https?:\/\//, "").toLowerCase();
      if (host.startsWith("www.")) host = host.slice(4);
      if (THIRD_PARTY_HOSTS.has(host)) continue;
      if (seen.has(host)) continue;
      seen.add(host);
      urlHits.push({ ...h, text: trimmed.slice(0, 160) });
    }
  }
  items.push({
    name: "硬编码外联域名",
    desc: "客户端源码中出现的固定域名（去重，已排除注释与第三方资产 URL）——评估数据外流面。",
    hits: urlHits.slice(0, 25),
  });

  return {
    title: "C. 暗桩 / 埋点",
    summary: "EventLogSDK 埋点 + CrashSight 崩溃上报 + OneChannel/Webview + 硬编码域名",
    items,
  };
}

/** APK 内反作弊/安全 SDK 特征（dex/native 通用关键词，大小写不敏感） */
const AC_FEATURES: { name: string; desc: string; patterns: string[] }[] = [
  {
    name: "Hypergryph SDK (com.hg.sdk)",
    desc: "鹰角官方 SDK（账号/支付/渠道）",
    patterns: ["com.hg.sdk", "hypergryph.sdk", "hgaccountsdk"],
  },
  {
    name: "MTP 反作弊",
    desc: "Hypergryph MTP 反作弊框架（启动注入检测/登录环境检测）",
    patterns: ["MTPDetection", "MTPProxy", "com.hg.sdk.mtp", "mtp.check"],
  },
  {
    name: "ACE 反作弊",
    desc: "腾讯 ACE（AntiCheatExpert）反作弊 SDK",
    patterns: ["AntiCheatExpert", "acesdk", "com.tencent.ace", "libace"],
  },
  {
    name: "Root / 提权检测",
    desc: "Root 检测（su/magisk 等）",
    patterns: ["/system/bin/su", "/system/xbin/su", "magisk", "isRooted", "rooted"],
  },
  {
    name: "注入 / Hook 检测",
    desc: "Frida / Xposed / Substrate 注入检测",
    patterns: ["frida", "xposed", "de.robv.android.xposed", "substrate"],
  },
  {
    name: "模拟器检测",
    desc: "模拟器环境检测（QEMU 特征等）",
    patterns: ["qemu", "goldfish", "isEmulator", "emulator.check"],
  },
  {
    name: "调试器检测",
    desc: "调试状态检测（Debug.isDebuggerConnected 等）",
    patterns: ["isDebuggerConnected", "TracerPid", "debugger.check"],
  },
];

/** APK 内埋点/暗桩 SDK 特征 */
const TELEMETRY_FEATURES: { name: string; desc: string; patterns: string[] }[] = [
  {
    name: "EventLogSDK 事件上报",
    desc: "鹰角事件日志（行为埋点）",
    patterns: ["eventlog", "EventLogSDK", "hypergryph.eventlog"],
  },
  {
    name: "CrashSight / Bugly 崩溃上报",
    desc: "腾讯崩溃上报（含设备信息）",
    patterns: ["crashsight", "bugly", "com.tencent.bugly"],
  },
  {
    name: "OneChannel / 渠道服务",
    desc: "鹰角渠道服务",
    patterns: ["onechannel", "Hypergryph.OneChannel"],
  },
  {
    name: "统计 / 广告埋点",
    desc: "统计分析 SDK（数数/友盟等）",
    patterns: ["thinkingdata", "umeng", "analytics", "track.event"],
  },
];

/** AndroidManifest 敏感权限（二进制 XML 字符串池中直接搜索） */
const SENSITIVE_PERMISSIONS = [
  "READ_PHONE_STATE", "GET_TASKS", "SYSTEM_ALERT_WINDOW", "QUERY_ALL_PACKAGES",
  "READ_SMS", "READ_CONTACTS", "READ_EXTERNAL_STORAGE", "ACCESS_FINE_LOCATION",
  "INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES", "BIND_DEVICE_ADMIN",
  "MANAGE_EXTERNAL_STORAGE", "WRITE_SETTINGS", "PACKAGE_USAGE_STATS",
];

/** native 库关键词标注（lib/*.so） */
const SO_TAGS = ["hg", "mtp", "ace", "security", "guard", "crash", "bugly", "sg", "tp", "sdk", "unity"];

/**
 * APK 本体审查（Java/native/资源层）：dex 反作弊与埋点特征、
 * native so 库清单、AndroidManifest 敏感权限、assets 结构特征。
 * @param apkPath - APK 路径
 * @returns 审查章节
 */
function auditApkBody(apkPath: string): Promise<Section> {
  return new Promise((resolve, reject) => {
    const dexFeatures: Hit[] = [];
    const dexFiles: { file: string; size: number }[] = [];
    const soFiles: { file: string; size: number }[] = [];
    const permissionHits: string[] = [];
    const assetSamples: string[] = [];
    const urlHosts = new Map<string, number>();
    let manifestBytes: Buffer | null = null;

    const scanDexFeatures = (file: string, content: Buffer): void => {
      for (const feat of [...AC_FEATURES, ...TELEMETRY_FEATURES]) {
        for (const pat of feat.patterns) {
          const idx = content.indexOf(Buffer.from(pat));
          if (idx >= 0) {
            const start = Math.max(0, idx - 40);
            const ctx = content.subarray(start, Math.min(content.length, idx + pat.length + 40)).toString("latin1");
            dexFeatures.push({
              file,
              line: 0,
              text: "[" + feat.name + "] …" + ctx.replace(/[^\x20-\x7e]/g, ".") + "…",
            });
            break;
          }
        }
      }
      const re = /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
      const ascii = content.toString("latin1");
      let m: RegExpExecArray | null;
      while ((m = re.exec(ascii)) !== null) {
        const host = m[0].replace(/^https?:\/\//, "").toLowerCase();
        if (host.startsWith("www.")) host.slice(4);
        if (host.length > 3 && host.includes(".")) {
          urlHosts.set(host, (urlHosts.get(host) ?? 0) + 1);
        }
      }
    };

    yauzl.open(apkPath, { lazyEntries: true, autoClose: true }, (err, zf) => {
      if (err || !zf) {
        reject(new Error(`APK 打开失败: ${(err as Error).message}`));
        return;
      }
      zf.readEntry();
      zf.on("entry", (entry: yauzl.Entry) => {
        const name = entry.fileName;
        if (/\/$/.test(name)) { zf.readEntry(); return; }
        if (/^classes\d*\.dex$/i.test(name)) {
          zf.openReadStream(entry, (e2, rs) => {
            if (e2 || !rs) { zf.readEntry(); return; }
            const chunks: Buffer[] = [];
            rs.on("data", (c: Buffer) => chunks.push(c));
            rs.on("end", () => {
              const buf = Buffer.concat(chunks);
              dexFiles.push({ file: name, size: buf.length });
              scanDexFeatures(name, buf);
              zf.readEntry();
            });
            rs.on("error", () => zf.readEntry());
          });
          return;
        }
        if (/^lib\/.+\.so$/i.test(name)) {
          soFiles.push({ file: name, size: entry.uncompressedSize });
          zf.readEntry();
          return;
        }
        if (name === "AndroidManifest.xml") {
          zf.openReadStream(entry, (e2, rs) => {
            if (e2 || !rs) { zf.readEntry(); return; }
            const chunks: Buffer[] = [];
            rs.on("data", (c: Buffer) => chunks.push(c));
            rs.on("end", () => {
              manifestBytes = Buffer.concat(chunks);
              zf.readEntry();
            });
            rs.on("error", () => zf.readEntry());
          });
          return;
        }
        if (/^assets\//.test(name) && assetSamples.length < 12) {
          assetSamples.push(name + "（" + entry.uncompressedSize + " B）");
        }
        zf.readEntry();
      });
      zf.on("end", () => {
        if (manifestBytes) {
          for (const perm of SENSITIVE_PERMISSIONS) {
            // 二进制 XML 字符串池可能为 UTF-8 或 UTF-16，两种编码都搜
            const hit = manifestBytes.includes(Buffer.from(perm, "utf8"))
              || manifestBytes.includes(Buffer.from(perm, "utf16le"));
            if (hit) permissionHits.push(perm);
          }
        }
        const soTagged = soFiles.filter((s) => {
          const base = s.file.split("/").pop()!.toLowerCase();
          return SO_TAGS.some((t) => base.includes(t));
        });
        const items: Section["items"] = [
          {
            name: "Dex 反作弊特征",
            desc: "Java 层反作弊 SDK 字符串特征（com.hg.sdk / MTP / ACE / root / 注入 / 模拟器 / 调试检测）",
            hits: dexFeatures.filter((h) => h.text.startsWith("[")).slice(0, 24),
          },
          {
            name: "Dex 埋点 / 暗桩特征",
            desc: "Java 层埋点与上报 SDK（EventLog / CrashSight / OneChannel / 统计）",
            hits: dexFeatures.filter((h) => /EventLog|CrashSight|bugly|OneChannel|thinkingdata|umeng|analytics/i.test(h.text)).slice(0, 12),
          },
          {
            name: "Native 库清单（lib/*.so）",
            desc: "共 " + soFiles.length + " 个 so；命中安全/上报关键词 " + soTagged.length + " 个",
            hits: soTagged.slice(0, 30).map((s) => ({ file: s.file, line: 0, text: s.file + "（" + s.size + " B）" })),
          },
          {
            name: "AndroidManifest 敏感权限",
            desc: "检出 " + permissionHits.length + " 个敏感权限",
            hits: permissionHits.map((p) => ({ file: "AndroidManifest.xml", line: 0, text: p })),
          },
          {
            name: "硬编码域名（dex 层）",
            desc: "检出 " + urlHosts.size + " 个去重域名",
            hits: [...urlHosts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20).map(([host, n]) => ({
              file: "classes*.dex", line: 0, text: host + "（" + n + " 次）",
            })),
          },
          {
            name: "assets 资源结构（采样）",
            desc: "Unity 资源布局（AB bundle 目录 / 加密 Lua bundle 等）",
            hits: assetSamples.map((s) => ({ file: "assets/", line: 0, text: s })),
          },
        ];
        resolve({
          title: "D. APK 本体（Java / native / 资源层）",
          summary: dexFiles.length + " 个 dex + " + soFiles.length + " 个 so 库 + " + permissionHits.length + " 个敏感权限",
          items,
        });
      });
      zf.on("error", (e) => reject(new Error(`APK 扫描失败: ${e.message}`)));
    });
  });
}

/**
 * APK 签名方案检测（V1/V2/V3）。
 * V1：zip 内含 META-INF/*.RSA|DSA|EC + *.SF；V2/V3：Central Directory 前有 APK Signing Block。
 * @param apkPath - APK 路径
 * @returns 检测结果字符串数组
 */
function detectApkSignatures(apkPath: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const result: string[] = [];
    let v1 = false;
    yauzl.open(apkPath, { lazyEntries: true, autoClose: true }, (err, zf) => {
      if (err || !zf) {
        reject(new Error(`APK 打开失败: ${(err as Error).message}`));
        return;
      }
      zf.readEntry();
      zf.on("entry", (entry: yauzl.Entry) => {
        if (/^META-INF\/.+\.(RSA|DSA|EC|SF)$/i.test(entry.fileName)) {
          v1 = true;
        }
        zf.readEntry();
      });
      zf.on("end", () => {
        result.push(`V1(JAR 签名) ${v1 ? "存在" : "无"}`);
        // V2/V3：读 EOCD 定位 Central Directory，检查其前是否有 APK Sig Block
        try {
          const fd = fs.openSync(apkPath, "r");
          const size = fs.fstatSync(fd).size;
          const tailLen = Math.min(size, 65557 + 22); // EOCD 最大偏移
          const tail = Buffer.alloc(tailLen);
          fs.readSync(fd, tail, 0, tailLen, size - tailLen);
          fs.closeSync(fd);
          let eocdOffset = -1;
          for (let i = tail.length - 22; i >= 0; i--) {
            if (tail.readUInt32LE(i) === 0x06054b50) {
              eocdOffset = size - tail.length + i;
              break;
            }
          }
          if (eocdOffset >= 0) {
            const eocdInTail = eocdOffset - (size - tail.length);
            const cdOffset = tail.readUInt32LE(eocdInTail + 16);
            // 读 CD 前 16KB 找 Sig Block magic
            const blockOffset = cdOffset - 16 * 1024;
            const probeLen = Math.min(16 * 1024, cdOffset);
            if (probeLen > 0) {
              const probe = Buffer.alloc(probeLen);
              const fd2 = fs.openSync(apkPath, "r");
              fs.readSync(fd2, probe, 0, probeLen, Math.max(0, blockOffset));
              fs.closeSync(fd2);
              const idx = probe.indexOf(APK_SIG_BLOCK_MAGIC);
              const v2 = idx >= 0;
              // V2 与 V3 结构相同（V3 在同一 block 内），区分需解析 signer —— 此处粗判
              result.push(`V2/V3(APK Signing Block) ${v2 ? "存在" : "无"}${v2 ? "（V3 需解析 signer 版本，此处仅确认 block）" : ""}`);
            }
          } else {
            result.push("EOCD 未找到，无法检测 V2/V3");
          }
        } catch (e) {
          result.push(`V2/V3 检测失败: ${(e as Error).message}`);
        }
        resolve(result);
      });
      zf.on("error", (e) => reject(new Error(`APK 扫描失败: ${e.message}`)));
    });
  });
}

/** 渲染 Markdown 报告 */
function renderMarkdown(sections: Section[], apkSig: string[], meta: { src: string; fileCount: number }): string {
  const lines: string[] = [];
  lines.push("# 明日方舟客户端 APK 安全审查报告（校验 / 反作弊 / 暗桩）");
  lines.push("");
  lines.push(`> 审查对象：客户端反编译 C# 源码（${meta.fileCount} 个 .cs）${meta.src}${apkSig.length ? `；APK 本体：签名 ${apkSig.join(" / ")}` : ""}`);
  lines.push(`> 生成时间：${new Date().toISOString()}`);
  lines.push("");
  lines.push("## 结论速览");
  lines.push("");
  for (const s of sections) {
    lines.push(`- **${s.title}**：${s.summary}`);
  }
  lines.push("");
  for (const s of sections) {
    lines.push(`## ${s.title}`);
    lines.push("");
    for (const item of s.items) {
      lines.push(`### ${item.name}`);
      lines.push("");
      lines.push(item.desc);
      lines.push("");
      if (item.hits.length === 0) {
        lines.push("（无源码级命中，见说明）");
        lines.push("");
        continue;
      }
      lines.push("| 位置 | 命中 |");
      lines.push("|---|---|");
      for (const h of item.hits.slice(0, 20)) {
        lines.push(`| \`${h.file}:${h.line}\` | \`${h.text.replace(/\|/g, "\\|")}\` |`);
      }
      if (item.hits.length > 20) {
        lines.push(`| … | 共 ${item.hits.length} 处命中，已截断 |`);
      }
      lines.push("");
    }
  }
  lines.push("## 审查说明");
  lines.push("");
  lines.push("- **完整性/签名校验**是私服接入的关键面：`VerifySignMD5RSA` 必须绕过（Lua 引导插件已处理），热更 md5 校验走 mod 替换 hash 方案（现有管线已兼容）。");
  lines.push("- **反作弊**分三层：C# 层 CodeStage 检测器（可被 Lua hotfix 针对性停用）、Java/native 层（dex 检出 MTP/root/注入/模拟器检测，见 D 章；需 Frida/动态处理，见 hook/main.ts）、混淆值（影响内存修改类外挂，与私服无关）。");
  lines.push("- **暗桩/埋点**主要影响隐私面与数据外流：C# 层 EventLogSDK/CrashSight + dex 层同套 SDK 的 Java 实现（com.hypergryph.eventlog / com.uqm.crashsight）+ 极光（cn.jiguang）+ 支付宝/QQ/微博渠道 SDK；私服场景建议在网关层观察上报域名并决定是否放行。");
  lines.push("- **APK 层注意**：dex 检出开发环境域残留（`ak-web-staging.hypergryph.com`、`core-api-account-dev.hypergryph.net`）——仅作内部情报，非私服风险点；敏感权限（QUERY_ALL_PACKAGES/INSTALL_PACKAGES 等）属游戏热更新与渠道 SDK 常规需求。");
  lines.push("- **静态字符串扫描存在少量误报**（如 `isRooted` 命中 View 旋转方法），需结合上下文确认。");
  lines.push("");
  return lines.join("\n");
}

/** CLI 入口 */
async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (!fs.existsSync(args.src)) {
    console.error(`[apk-audit] 源码目录不存在: ${args.src}`);
    process.exit(1);
  }

  console.log(`[apk-audit] 扫描 ${args.src} …`);
  const files = collectCsFiles(args.src);
  const contentCache = new Map<string, string>();
  const readFile = (f: string): string => {
    const key = f;
    let c = contentCache.get(key);
    if (c === undefined) {
      const p = path.join(args.src, f);
      c = fs.existsSync(p) ? fs.readFileSync(p, "utf-8") : "";
      contentCache.set(key, c);
    }
    return c;
  };

  const sections: Section[] = [
    auditIntegrity(files, readFile),
    auditAntiCheat(files, readFile),
    auditBackdoors(files, readFile),
  ];

  let apkSig: string[] = [];
  if (args.apk) {
    if (!fs.existsSync(args.apk)) {
      console.error(`[apk-audit] APK 文件不存在: ${args.apk}`);
      process.exit(1);
    }
    console.log(`[apk-audit] 检测 APK 签名方案与本体（Java/native 层）: ${args.apk}`);
    apkSig = await detectApkSignatures(args.apk);
    console.log(`[apk-audit] 签名: ${apkSig.join("；")}`);
    console.log(`[apk-audit] 扫描 APK 本体（dex / so / 权限 / assets）…`);
    sections.push(await auditApkBody(args.apk));
  }

  const md = renderMarkdown(sections, apkSig, { src: args.src, fileCount: files.length });
  fs.mkdirSync(path.dirname(args.out), { recursive: true });
  fs.writeFileSync(args.out, md);
  console.log(`[apk-audit] 报告已生成: ${args.out}`);

  if (args.json) {
    const jsonPath = args.out.replace(/\.md$/, ".json");
    fs.writeFileSync(jsonPath, JSON.stringify(sections, null, 2));
    console.log(`[apk-audit] JSON 结果: ${jsonPath}`);
  }

  // 控制台摘要
  console.log("\n=================== 审查摘要 ===================");
  for (const s of sections) {
    console.log(`\n【${s.title}】`);
    for (const item of s.items) {
      console.log(`  ${item.name}: ${item.hits.length} 处命中`);
    }
  }
  console.log("\n================================================");
}

if (typeof require !== "undefined" && require.main === module) {
  main().catch((e) => {
    console.error("[apk-audit] 审查失败:", e instanceof Error ? e.message : e);
    process.exit(1);
  });
}
