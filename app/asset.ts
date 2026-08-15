import { Router } from "express";
import { basename, join } from "path";
import { createHash } from "crypto";
import { crc32 } from "crc";
import axios from "axios";
import { EventEmitter } from "events";
import yauzl, { ZipFile } from "yauzl";
import { mkdir, readdir, readFile, writeFile } from "fs/promises";
import config from "./config";
import { exists, size } from "@utils/file";
import { logger } from "@utils/logger";

const router = Router();

router.get(
  "/official/:platform/assets/:assetsHash/:fileName",
  async (req, res) => {
    const { assetsHash, platform } = req.params;
    let { fileName } = req.params;
    // 资源版本跟随客户端请求路径（资源按版本存储——客户端从 hv 拿到 resVersion 拼路径）；
    // CDN 平台跟随客户端请求的 platform（Windows/Android 资源各自独立 CDN 目录，
    // 版本号不同——Windows 版本仅在 Windows CDN 可下载，Android 版本仅在 Android CDN 可下载）
    const version = assetsHash;
    const cdnPlatform = platform ?? "Android";
    // CDN 下载用去 mod 后缀的原始版本（官方 CDN 无 mod 版本；后缀仅用于本地缓存目录区分）
    const cdnVersion = stripModSuffix(version);
    let basePath = join(__dirname, "..", "assets", version, "redirect");

    if (fileName === "hot_update_list.json" && config.assets.enableMods) {
      try {
        MODS_LIST = await loadMods();
      } catch (error) {
        // 容错：mod 扫描异常（权限/损坏）不阻断清单服务——记录并置空
        logger.error("Asset", `mod 列表刷新失败: ${(error as Error).message}`);
        MODS_LIST = emptyModsList();
      }
    } else if (config.assets.enableMods && !MODS_LOADED) {
      // 容错：mod 文件请求早于热更清单（客户端缓存清单直连下载）——补齐初始加载
      await ensureModsLoaded();
    }

    // odpy 代理模式（downloadPeoxy）：直接转发官服 CDN（支持 Range 断点续传，不落盘）
    if (
      (config.assets as any).downloadPeoxy &&
      fileName !== "hot_update_list.json" &&
      !MODS_LIST.download.includes(fileName)
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
        !MODS_LIST.download.includes(fileName)
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

    if (config.assets.enableMods && MODS_LIST.download.includes(fileName)) {
      for (const [mod, path] of MODS_LIST.download.map((m, i) => [
        m,
        MODS_LIST.path[i],
      ])) {
        if (fileName === mod && (await exists(path))) {
          logger.debug("Asset", "use mod file", mod, path);
          wrongSize = false;
          filePath = path;
          basePath = join(__dirname, "..", "mods");
          fileName = basename(filePath);
        }
      }
    }
    const fp = await exportFile(
      `https://ak.hycdn.cn/assetbundle/official/${cdnPlatform}/assets/${cdnVersion}/${fileName}`,
      basePath,
      fileName,
      filePath,
      assetsHash,
      wrongSize,
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

/** mods 目录（.gitignore；仅 mods/.placeholder 入 git 保留目录） */
const MODS_DIR = join(__dirname, "..", "mods");

let MODS_LIST: ModsList = emptyModsList();

/** mod 列表是否已尝试加载（ensureModsLoaded 幂等用——避免空 mods 目录时每请求重复扫描） */
let MODS_LOADED = false;

/**
 * 加载 mod 列表（启动预热/缺省加载用）。失败不阻塞——记录错误并置空列表
 */
export async function initMods(): Promise<void> {
  if (MODS_LOADED) return;
  MODS_LOADED = true;
  try {
    MODS_LIST = await loadMods();
    logger.info(
      "Asset",
      `mod 加载完成：${MODS_LIST.mods.length} 个（enableMods=${config.assets.enableMods}）`,
    );
  } catch (error) {
    logger.error("Asset", `mod 加载失败: ${(error as Error).message}`);
    MODS_LIST = emptyModsList();
  }
}

export function getModsList(): ModsList {
  return MODS_LIST;
}

export async function ensureModsLoaded(): Promise<void> {
  if (!MODS_LOADED) await initMods();
}

/**
 * 确定性 resVersion 后缀：mod 集合不变 → 后缀不变（客户端不重复全量重下）；
 * mod 变更 → 后缀变化（触发热更清单重新拉取）。无 mod 时返回 ""（保持原版行为）
 */
export function getModVersionSuffix(): string {
  if (MODS_LIST.mods.length === 0) return "";
  const sig = MODS_LIST.mods
    .map((m) => `${(m as { name: string }).name}|${(m as { totalSize: number }).totalSize}`)
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
        if (!MODS_LIST.name.includes(abInfo.name)) {
          newAbInfos.push(abInfo);
        }
      } else {
        newAbInfos.push(abInfo);
      }
    }

    if (config.assets.enableMods) {
      for (const mod of MODS_LIST.mods) {
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

async function loadMods(): Promise<ModsList> {
  const fileList: string[] = [];
  const loadedModList: ModsList = emptyModsList();
  const modsDir = MODS_DIR;

  // 容错：mods 目录不存在（未创建/未启用）时返回空列表——避免 readdir ENOENT 使清单请求 500
  let dirEntries: string[];
  try {
    dirEntries = await readdir(modsDir);
  } catch (error) {
    logger.warn(
      "Asset",
      `mods 目录不存在（${modsDir}），跳过 mod 加载: ${(error as Error).message}`,
    );
    return loadedModList;
  }
  for (const file of dirEntries) {
    if (file !== ".placeholder" && file.endsWith(".dat")) {
      fileList.push(join(modsDir, file));
    }
  }

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

  const modCachePath = join(__dirname, "..", "mods.json");
  let modCache = null;

  if (await exists(modCachePath)) {
    modCache = JSON.parse(await readFile(modCachePath, "utf-8"));
  }

  let modCacheValid = false;

  if (modCache) {
    const cachedDatFileInfos = modCache.file;
    // 指纹比对：键为绝对路径——旧缓存（异地/旧项目路径）键不匹配 → 自动判失效重建
    if (JSON.stringify(datFileInfos) === JSON.stringify(cachedDatFileInfos)) {
      // 新格式缓存 path 存相对文件名（可移植）；旧格式为绝对路径（含盘符/分隔符）→ 失效
      const cachedPaths: unknown[] = modCache.mod?.path ?? [];
      const isLegacyPath = cachedPaths.some(
        (p) => typeof p !== "string" || p.includes(":") || p.includes("/") || p.includes("\\"),
      );
      if (!isLegacyPath) modCacheValid = true;
    }
  }

  if (modCacheValid && modCache) {
    const cached = modCache.mod;
    // 相对文件名 → 绝对路径（mods/ 目录整体迁移后仍正确指向新位置）
    loadedModList.mods = cached.mods;
    loadedModList.name = cached.name;
    loadedModList.path = (cached.path as string[]).map((p) => join(modsDir, p));
    loadedModList.download = cached.download;
    logger.info("Asset", `${fileList[0] ?? "mods"} - Using Cached Mod...`);
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
            // 运行时 path 为绝对路径；落盘缓存转存相对文件名（可移植）
            loadedModList.path.push(join(modsDir, basename(filePath)));
            loadedModList.download.push(downloadName);
            await writeFile(
              modCachePath,
              JSON.stringify(
                {
                  file: datFileInfos,
                  mod: {
                    mods: loadedModList.mods,
                    name: loadedModList.name,
                    path: loadedModList.path.map((p) => basename(p)),
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
