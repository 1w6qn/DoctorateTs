import { Router } from "express";
import { basename, join, relative } from "path";
import { createHash } from "crypto";
import { crc32 } from "crc";
import axios from "axios";
import { EventEmitter } from "events";
import yauzl, { ZipFile } from "yauzl";
import { mkdir, readdir, readFile, writeFile, stat } from "fs/promises";
import config from "./config";
import { exists, size } from "@utils/file";
import { logger } from "@utils/logger";

const router = Router();

router.get(
  // fileName 用通配捕获多段：mod 清单 name 含子路径（如 anon/7d91430e114d86fef7d3b3511151e12d.bin），
  // 客户端按清单 name 构造下载路径，需能匹配 assets/.../<子路径>（path-to-regexp v8 命名通配 *name）
  "/official/:platform/assets/:assetsHash/*fileName",
  async (req, res) => {
    const { assetsHash, platform: platformParam } = req.params;
    // 平台决定用哪套 mod（Windows/Android 各自独立；未知平台回退 Android）
    const platform = platformParam ?? "Android";
    // 通配段（命名通配 *fileName 捕获为 string[]，含斜杠子路径）；空数组兜底（仅 assets/<hash>/ 无文件名）
    let fileName = (req.params.fileName as string[] | undefined ?? []).join("/" );
    // 资源版本跟随客户端请求路径（资源按版本存储——客户端从 hv 拿到 resVersion 拼路径）；
    // CDN 平台跟随客户端请求的 platform（Windows/Android 资源各自独立 CDN 目录，
    // 版本号不同——Windows 版本仅在 Windows CDN 可下载，Android 版本仅在 Android CDN 可下载）
    const version = assetsHash;
    const cdnPlatform = platform;
    // CDN 下载用去 mod 后缀的原始版本（官方 CDN 无 mod 版本；后缀仅用于本地缓存目录区分）
    const cdnVersion = stripModSuffix(version);
    let basePath = join(__dirname, "..", "assets", version, "redirect");

    if (fileName === "hot_update_list.json" && config.assets.enableMods) {
      try {
        stateFor(platform).list = await loadMods(platform);
      } catch (error) {
        // 容错：mod 扫描异常（权限/损坏）不阻断清单服务——记录并置空
        logger.error("Asset", `mod 列表刷新失败: ${(error as Error).message}`);
        stateFor(platform).list = emptyModsList();
      }
    } else if (config.assets.enableMods && !stateFor(platform).loaded) {
      // 容错：mod 文件请求早于热更清单（客户端缓存清单直连下载）——补齐初始加载
      await ensureModsLoaded(platform);
    }
    const mods = getModsList(platform);

    // odpy 代理模式（downloadPeoxy）：直接转发官服 CDN（支持 Range 断点续传，不落盘）
    if (
      (config.assets as any).downloadPeoxy &&
      fileName !== "hot_update_list.json" &&
      !mods.download.includes(fileName)
    ) {
      const forwardHeaders: Record<string, string> = {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
      };
      const rangeHeader = req.headers.range as string | undefined;
      if (rangeHeader) forwardHeaders.Range = rangeHeader;
      const resp = await fetch(
        `https://ak.hycdn.cn/assetbundle/official/${cdnPlatform}/assets/${cdnVersion}/${fileName}`,
        { headers: forwardHeaders, signal: AbortSignal.timeout(CDN_TIMEOUT) },
      );
      const body = Buffer.from(await resp.arrayBuffer());
      res.status(resp.status);
      resp.headers.forEach((value, key) => {
        if (key.toLowerCase() !== "transfer-encoding") res.setHeader(key, value);
      });
      res.send(body);
      return;
    }

    if (!config.assets.downloadLocally) {
      basePath = join(__dirname, "..", "assets", version);
      if (
        fileName !== "hot_update_list.json" &&
        !mods.download.includes(fileName)
      ) {
        return res.redirect(
          `https://ak.hycdn.cn/assetbundle/official/${cdnPlatform}/assets/${version}/${fileName}`,
        );
      }
    }
    if (!(await exists(basePath))) {
      await mkdir(basePath, { recursive: true });
    }

    let filePath = join(basePath, fileName);

    let wrongSize = false;
    if (fileName !== "hot_update_list.json") {
      const tempHotUpdatePath = join(basePath, "hot_update_list.json");
      // 容错：版本目录缺 hot_update_list（客户端直连 .dat 等）时跳过尺寸校验——防 ENOENT 500
      if (await exists(tempHotUpdatePath)) {
        const hotUpdate = JSON.parse(await readFile(tempHotUpdatePath, "utf-8"));
        if (await exists(filePath)) {
          for (const pack of hotUpdate.packInfos) {
            if (pack.name === fileName.split(".")[0]) {
              wrongSize = (await size(filePath)) !== pack.totalSize;
              break;
            }
          }
        }
      }
    }

    if (config.assets.enableMods) {
      // 客户端把清单 name（含子路径 anon/xxx.bin）扁平化为下载名（anon_xxx.dat，/→_、去后缀加.dat）
      // 请求路径即 download 名；个别场景也可能直接请求原始 name（含子路径），两者都兼容。
      // download/name/path 按下标一一对应。
      const idx = mods.download.indexOf(fileName);
      const modPath = idx >= 0 ? mods.path[idx] : mods.name.indexOf(fileName) >= 0 ? mods.path[mods.name.indexOf(fileName)] : undefined;
      if (modPath && (await exists(modPath))) {
        logger.debug("Asset", "use mod file", fileName, modPath);
        wrongSize = false;
        filePath = modPath;
        basePath = join(__dirname, "..", "mods");
        fileName = basename(filePath);
      }
    }
    const fp = await exportFile(
      `https://ak.hycdn.cn/assetbundle/official/${cdnPlatform}/assets/${cdnVersion}/${fileName}`,
      basePath,
      fileName,
      filePath,
      assetsHash,
      wrongSize,
      mods,
    );
    logger.debug("Asset", "serve", fp);
    res.sendFile(fp);
  },
);

interface ModsList {
  mods: object[];
  name: string[];
  path: string[];
  download: string[];
}

function emptyModsList(): ModsList {
  return { mods: [], name: [], path: [], download: [] };
}

/** mods 目录（.gitignore；仅 mods/.placeholder 与平台子目录占位入 git） */
const MODS_DIR = join(__dirname, "..", "mods");

/** 平台 → 专属 mod 子目录（小写）；未知平台无专属目录（仅共享根目录） */
const PLATFORM_DIRS: Record<string, string> = { Windows: "windows", Android: "android" };

/** 单平台 mod 状态 */
interface ModsState {
  list: ModsList;
  loaded: boolean;
  fingerprint: string;
}

/** 各平台 mod 状态（懒初始化；未知平台回退 Android） */
const MODS_STATES: Record<string, ModsState> = {};

function stateFor(platform: string): ModsState {
  const key = platform || "Android";
  if (!MODS_STATES[key]) {
    MODS_STATES[key] = { list: emptyModsList(), loaded: false, fingerprint: "" };
  }
  return MODS_STATES[key];
}

/** 某平台加载的 mod 目录：平台专属目录优先，共享根目录回退（既支持平台 mod 也兼容历史根目录 mod） */
function platformModDirs(platform: string): string[] {
  const dirs: string[] = [];
  const sub = PLATFORM_DIRS[platform];
  if (sub) dirs.push(join(MODS_DIR, sub));
  dirs.push(MODS_DIR);
  return dirs;
}

/**
 * 轻量扫描某平台 mod 目录的 .dat 文件指纹（仅 stat，不读内容）。
 * 用于版本端点检测资源变更：避免每次请求全量读 .dat 重算 md5。
 * @param platform - 平台键（Windows/Android）
 * @returns 指纹串（path|mtimeMs|size，按路径排序）；目录不存在/IO 异常跳过对应目录
 */
async function computeModsFingerprint(platform: string): Promise<string> {
  const parts: string[] = [];
  for (const dir of platformModDirs(platform)) {
    let entries: string[];
    try {
      entries = await readdir(dir);
    } catch {
      continue;
    }
    for (const f of entries) {
      if (!f.endsWith(".dat")) continue;
      try {
        const st = await stat(join(dir, f));
        parts.push(`${dir}/${f}:${st.mtimeMs}:${st.size}`);
      } catch {
        parts.push(`${dir}/${f}:missing`);
      }
    }
  }
  parts.sort();
  return parts.join(",");
}

/**
 * 运行时 mod 变更检测：某平台 mod 目录指纹变化时重载其列表。
 * 重打包 Lua 资源（替换/新增 .dat）后，无需重启服务即可让该平台 resVersion 后缀变化，
 * 从而提示客户端重新拉取热更清单并下载新资源。
 * @param platform - 平台键（Windows/Android）
 * @returns 本次是否发生了重载
 */
export async function refreshModsIfChanged(platform: string): Promise<boolean> {
  if (!config.assets.enableMods) return false;
  const state = stateFor(platform);
  const fp = await computeModsFingerprint(platform);
  if (fp === state.fingerprint) return false;
  state.fingerprint = fp;
  try {
    state.list = await loadMods(platform);
    logger.info(
      "Asset",
      `[${platform}] mod 变更检测到，已重载：${state.list.mods.length} 个`,
    );
  } catch (error) {
    logger.error("Asset", `[${platform}] mod 变更重载失败: ${(error as Error).message}`);
    state.list = emptyModsList();
  }
  return true;
}

/**
 * 加载某平台 mod 列表（启动预热/缺省加载用）。失败不阻塞——记录错误并置空列表。
 * @param platform - 平台键；缺省时预热全部已知平台
 */
export async function initMods(platform?: string): Promise<void> {
  const keys = platform ? [platform] : Object.keys(PLATFORM_DIRS);
  for (const p of keys) {
    const state = stateFor(p);
    if (state.loaded) continue;
    state.loaded = true;
    try {
      state.list = await loadMods(p);
      // 同步指纹基线，避免启动后首个版本请求触发一次无意义的重复重载
      state.fingerprint = await computeModsFingerprint(p);
      logger.info(
        "Asset",
        `[${p}] mod 加载完成：${state.list.mods.length} 个（enableMods=${config.assets.enableMods}）`,
      );
    } catch (error) {
      logger.error("Asset", `[${p}] mod 加载失败: ${(error as Error).message}`);
      state.list = emptyModsList();
    }
  }
}

export function getModsList(platform: string): ModsList {
  return stateFor(platform).list;
}

export async function ensureModsLoaded(platform: string): Promise<void> {
  const state = stateFor(platform);
  if (!state.loaded) await initMods(platform);
}

/**
 * 确定性 resVersion 后缀：mod 集合不变 → 后缀不变（客户端不重复全量重下）；
 * mod 变更 → 后缀变化（触发热更清单重新拉取）。无 mod 时返回 ""（保持原版行为）。
 * @param platform - 平台键（Windows/Android），后缀按平台独立计算
 */
export function getModVersionSuffix(platform: string): string {
  const list = stateFor(platform).list;
  if (list.mods.length === 0) return "";
  // 签名含内容指纹（md5）：插件/内置 bundle 内容变更必然改变 md5 → 后缀变化 → 客户端重新拉取热更清单并下载。
  // 仅用 name|totalSize 时，repack 后 totalSize 未必变（zip 压缩后尺寸巧合相等），客户端会因后缀未变而误用本地缓存旧 bundle。
  const sig = list.mods
    .map((m) => `${(m as { name: string }).name}|${(m as { md5: string }).md5}`)
    .sort()
    .join(",");
  return "-m" + createHash("md5").update(sig).digest("hex").slice(0, 6);
}

/**
 * 去除资源版本号的 mod 后缀（`-m{6位hex}`）。
 * 客户端从 hv 拿到带 mod 后缀的 resVersion 拼资源路径；官方 CDN 无 mod 版本，
 * 下载官方资源时须用去后缀的原始版本。无后缀时原样返回。
 */
export function stripModSuffix(version: string): string {
  return version.replace(/-m[0-9a-fA-F]{6}$/, "");
}

const downloadingFiles: { [key: string]: EventEmitter } = {};

/** CDN 下载超时（毫秒）——官服 CDN 不可达时快速失败（5xx），避免客户端请求挂起致界面卡死 */
const CDN_TIMEOUT = 10000;

async function downloadFile(url: string, filePath: string): Promise<void> {
  logger.info("Asset", `Download ${filePath.split("/").pop()}`);
  const response = await axios.get(url, {
    responseType: "arraybuffer",
    timeout: CDN_TIMEOUT,
  });
  await writeFile(filePath, response.data);
}

async function exportFile(
  url: string,
  basePath: string,
  fileName: string,
  filePath: string,
  assetsHash: string,
  reDownload = false,
  mods?: ModsList,
): Promise<string> {
  if (basename(filePath) === "hot_update_list.json") {
    let hotUpdateList;
    if (await exists(filePath)) {
      hotUpdateList = JSON.parse(await readFile(filePath, "utf-8"));
    } else {
      const response = await axios.get(url, { timeout: CDN_TIMEOUT });
      hotUpdateList = response.data;
      await writeFile(filePath, JSON.stringify(hotUpdateList));
    }

    const abInfoList = hotUpdateList.abInfos;
    const newAbInfos = [];

    for (const abInfo of abInfoList) {
      if (config.assets.enableMods) {
        hotUpdateList.versionId = assetsHash;
        if (abInfo.hash.length === 24) {
          abInfo.hash = assetsHash;
        }
        if (!mods!.name.includes(abInfo.name)) {
          newAbInfos.push(abInfo);
        }
      } else {
        newAbInfos.push(abInfo);
      }
    }

    if (config.assets.enableMods) {
      for (const mod of mods!.mods) {
        newAbInfos.push(mod);
      }
    }

    hotUpdateList.abInfos = newAbInfos;

    const cachePath = join(__dirname, "..", "./assets/cache/");
    const savePath = join(cachePath, "hot_update_list.json");
    logger.debug("Asset", "cache path", cachePath);
    if (!(await exists(cachePath))) {
      await mkdir(cachePath, { recursive: true });
    }
    await writeFile(savePath, JSON.stringify(hotUpdateList));

    return join(__dirname, "../assets/cache/hot_update_list.json");
  }

  let downloadingThread = null;
  if (
    !downloadingFiles[filePath] &&
    (!(await exists(filePath)) || reDownload)
  ) {
    downloadingFiles[filePath] = new EventEmitter();
    downloadingThread = (async () => {
      await downloadFile(url, filePath);
      downloadingFiles[filePath].emit("downloaded");
    })();
  }

  if (downloadingThread) {
    await downloadingThread;
    delete downloadingFiles[filePath];
  } else {
    if (downloadingFiles[filePath]) {
      await new Promise((resolve) =>
        downloadingFiles[filePath].once("downloaded", resolve),
      );
    }
  }

  return join(basePath, fileName);
}

async function loadMods(platform: string): Promise<ModsList> {
  const loadedModList: ModsList = emptyModsList();

  // 收集所有 .dat：平台专属目录在前（平台 mod 优先去重），共享根目录在后（回退）
  const fileList: string[] = [];
  for (const dir of platformModDirs(platform)) {
    let dirEntries: string[];
    try {
      dirEntries = await readdir(dir);
    } catch (error) {
      // 容错：目录不存在（未创建/未启用）跳过——避免 readdir ENOENT 使清单请求 500
      logger.warn(
        "Asset",
        `mods 目录不存在（${dir}），跳过: ${(error as Error).message}`,
      );
      continue;
    }
    for (const file of dirEntries) {
      if (file !== ".placeholder" && file.endsWith(".dat")) {
        fileList.push(join(dir, file));
      }
    }
  }
  if (fileList.length === 0) return loadedModList;

  const datFileInfos: { [key: string]: { size: number; crc32: number } } = {};

  for (const filePath of fileList) {
    // 容错：单个 .dat 读取失败（权限/占用）跳过，不阻断整体加载
    try {
      const fileContent = await readFile(filePath);
      const fileSize = fileContent.length;
      const fileCrc32 = crc32(fileContent);
      datFileInfos[filePath] = {
        size: fileSize,
        crc32: fileCrc32,
      };
    } catch (error) {
      logger.warn(
        "Asset",
        `${basename(filePath)} 读取失败，跳过: ${(error as Error).message}`,
      );
    }
  }

  // 平台隔离缓存文件（避免 Windows/Android 互踩覆盖）
  const modCachePath = join(__dirname, "..", `mods.${platform}.json`);
  let modCache = null;

  if (await exists(modCachePath)) {
    modCache = JSON.parse(await readFile(modCachePath, "utf-8"));
  }

  let modCacheValid = false;

  if (modCache) {
    const cachedDatFileInfos = modCache.file;
    // 指纹比对：键为绝对路径（含平台子目录）——旧缓存（异地/旧项目路径/旧单一结构）键不匹配 → 自动判失效重建
    if (JSON.stringify(datFileInfos) === JSON.stringify(cachedDatFileInfos)) {
      modCacheValid = true;
    }
  }

  if (modCacheValid && modCache) {
    const cached = modCache.mod;
    loadedModList.mods = cached.mods;
    loadedModList.name = cached.name;
    // 缓存 path 相对 MODS_DIR（如 windows/foo.dat 或 foo.dat）→ 还原绝对路径
    loadedModList.path = (cached.path as string[]).map((p) => join(MODS_DIR, p));
    loadedModList.download = cached.download;
    logger.info("Asset", `[${platform}] ${fileList[0] ?? "mods"} - Using Cached Mod...`);
    return loadedModList;
  }

  const seenDownloads = new Set<string>();
  for (const filePath of fileList) {
    if ((await size(filePath)) === 0) {
      continue;
    }
    let modFile: yauzl.ZipFile;
    try {
      modFile = await openZipFile(filePath);
    } catch (error) {
      // 容错：损坏/非 zip 的 .dat 跳过（不再 throw 炸进程）
      logger.warn(
        "Asset",
        `${basename(filePath)} - mod 解析失败，跳过: ${(error as Error).message}`,
      );
      continue;
    }
    modFile.readEntry();
    modFile.on("entry", (entry) => {
      if (!/\/$/.test(entry.fileName)) {
        const modName = entry.fileName;
        if (loadedModList.name.includes(modName)) {
          logger.warn(
            "Asset",
            `${filePath} - Conflict with other mods...`,
          );
          modFile.readEntry();
          return;
        }
        const downloadName =
          modName.replace(/\//g, "_").replace(/#/g, "__").split(".")[0] +
          ".dat";
        if (seenDownloads.has(downloadName)) {
          logger.warn(
            "Asset",
            `${filePath} - ${modName} 与其它 mod 映射到同一下载名 ${downloadName}，跳过`,
          );
          modFile.readEntry();
          return;
        }
        seenDownloads.add(downloadName);
        modFile.openReadStream(entry, (err, readStream) => {
          if (err) {
            logger.warn(
              "Asset",
              `${filePath} - 读取条目失败: ${err.message}`,
            );
            modFile.readEntry();
            return;
          }
          const chunks: Buffer[] = [];
          readStream!.on("data", (chunk) => chunks.push(chunk));
          readStream!.on("error", (streamErr) => {
            logger.warn(
              "Asset",
              `${filePath} - 读取条目出错，跳过: ${streamErr.message}`,
            );
            modFile.readEntry();
          });
          readStream!.on("end", async () => {
            const byteBuffer = Buffer.concat(chunks);
            // 官方语义：totalSize = 可下载的 .dat(zip) 实际大小（客户端按此判定下载完成），
            // abSize = 解压后 bundle 大小（客户端一致性校验 fileInfo.Length==abSize）。
            // 曾错把两者都设成 bundle 大小 → 客户端按更大的 totalSize 等待下载，实际收不到 → "下载失败"
            const totalSize = datFileInfos[filePath]?.size ?? byteBuffer.length;
            const abSize = byteBuffer.length;
            const modMd5 = createHash("md5").update(byteBuffer).digest("hex");

            const abInfo = {
              name: modName,
              hash: modMd5,
              md5: modMd5,
              totalSize: totalSize,
              abSize: abSize,
            };

            logger.info(
              "Asset",
              `${filePath} - Mod loaded successfully...`,
            );

            loadedModList.mods.push(abInfo);
            loadedModList.name.push(modName);
            // 运行时 path 为绝对路径；落盘缓存转存相对 MODS_DIR 的路径（含平台子目录，可移植）
            loadedModList.path.push(relative(MODS_DIR, filePath));
            loadedModList.download.push(downloadName);
            await writeFile(
              modCachePath,
              JSON.stringify(
                {
                  file: datFileInfos,
                  mod: {
                    mods: loadedModList.mods,
                    name: loadedModList.name,
                    path: loadedModList.path.map((p) => relative(MODS_DIR, p)),
                    download: loadedModList.download,
                  },
                },
                null,
                4,
              ),
            );
            modFile.readEntry();
          });
        });
      } else {
        modFile.readEntry();
      }
    });
  }

  return loadedModList;
}

function openZipFile(filePath: string): Promise<ZipFile> {
  return new Promise((resolve, reject) => {
    yauzl.open(filePath, { lazyEntries: true }, (err, zipFile) => {
      if (err) reject(err);
      else resolve(zipFile);
    });
  });
}

export default router;
