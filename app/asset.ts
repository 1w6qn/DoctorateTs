import { Router } from "express";
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, promises } from 'fs';
import { basename, join } from 'path';
import { createHash } from 'crypto';
import { crc32 } from 'crc';
import axios from 'axios';
import { EventEmitter } from 'events';
import yauzl, { ZipFile } from 'yauzl';

import config from "./config"
const router = Router();

router.get("/official/Android/assets/:assetsHash/:fileName", async (req, res) => {

    let { assetsHash, fileName } = req.params;
    const version = config.version.resVersion;
    let basePath = join(__dirname, '..', 'assets', version, 'redirect');

    if (fileName === 'hot_update_list.json' && config.assets.enableMods) {
        MODS_LIST = await loadMods();
    }

    if (!config.assets.downloadLocally) {
        basePath = join(__dirname, '..', 'assets', version);
        if (fileName !== 'hot_update_list.json' && !MODS_LIST.download.includes(fileName)) {
            return res.redirect(`https://ak.hycdn.cn/assetbundle/official/Android/assets/${version}/${fileName}`);
        }
    }

    if (!existsSync(basePath)) {
        mkdirSync(basePath, { recursive: true });
    }
    let filePath = join(basePath, fileName);

    let wrongSize = false;
    if (fileName !== 'hot_update_list.json') {
        const tempHotUpdatePath = join(basePath, "hot_update_list.json");
        const hotUpdate = JSON.parse(readFileSync(tempHotUpdatePath, 'utf-8'));
        if (existsSync(filePath)) {
            for (const pack of hotUpdate.packInfos) {
                if (pack.name === fileName.split(".")[0]) {
                    wrongSize = (await getFileSize(filePath)) !== pack.totalSize;
                    break;
                }
            }
        }
    }

    if (config.assets.enableMods && MODS_LIST.download.includes(fileName)) {
        for (const [mod, path] of MODS_LIST.download.map((m, i) => [m, MODS_LIST.path[i]])) {
            if (fileName === mod && existsSync(path)) {
                console.log(mod, path)
                wrongSize = false;
                filePath = path;
                basePath = join(__dirname, '..', 'mods');
                fileName = basename(filePath);
            }
        }
    }
    let fp = await exportFile(`https://ak.hycdn.cn/assetbundle/official/Android/assets/${version}/${fileName}`, basePath, fileName, filePath, assetsHash, wrongSize);
    console.log(fp)
    res.sendFile(fp)

});

interface ModsList {
    mods: any[];
    name: string[];
    path: string[];
    download: string[];
}

let MODS_LIST: ModsList = {
    mods: [],
    name: [],
    path: [],
    download: []
};




const downloadingFiles: { [key: string]: EventEmitter } = {};

async function downloadFile(url: string, filePath: string): Promise<void> {
    console.log(`\x1b[1;33mDownload ${filePath.split("/").pop()}\x1b[0;0m`);
    const response = await axios.get(url, { responseType: 'arraybuffer' });
    writeFileSync(filePath, response.data);
}

async function exportFile(url: string, basePath: string, fileName: string, filePath: string, assetsHash: string, redownload = false): Promise<string> {

    if (basename(filePath) ==='hot_update_list.json') {
        let hotUpdateList;
        if (existsSync(filePath)) {
            hotUpdateList = JSON.parse(readFileSync(filePath, 'utf-8'));
        } else {
            const response = await axios.get(url);
            hotUpdateList = response.data;
            writeFileSync(filePath, JSON.stringify(hotUpdateList));
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

        const cachePath = join(__dirname, "..", './assets/cache/');
        const savePath = join(cachePath, 'hot_update_list.json');
        console.log(cachePath)
        if (!existsSync(cachePath)) {
            mkdirSync(cachePath, { recursive: true });
        }
        writeFileSync(savePath, JSON.stringify(hotUpdateList));

        return join(__dirname,'../assets/cache/hot_update_list.json');
    }

    let downloadingThread = null;
    if (!downloadingFiles[filePath] && (!existsSync(filePath) || redownload)) {
        downloadingFiles[filePath] = new EventEmitter();
        downloadingThread = (async () => {
            await downloadFile(url, filePath);
            downloadingFiles[filePath].emit('downloaded');
        })();
    }

    if (downloadingThread) {
        await downloadingThread;
        delete downloadingFiles[filePath];
    } else {
        if (downloadingFiles[filePath]) {
            await new Promise(resolve => downloadingFiles[filePath].once('downloaded', resolve));
        }

    }

    return join(basePath, fileName);
}

async function loadMods(log: boolean = true): Promise<ModsList> {
    const fileList: string[] = [];
    const loadedModList: ModsList = {
        mods: [],
        name: [],
        path: [],
        download: []
    };

    for (const file of readdirSync(join(__dirname, "..", "mods"))) {
        if (file !== ".placeholder" && file.endsWith(".dat")) {
            fileList.push(join(__dirname, "..", 'mods', file));
        }
    }

    const datFileInfos: { [key: string]: { size: number, crc32: number } } = {};

    for (const filePath of fileList) {
        const fileContent = readFileSync(filePath);
        const fileSize = fileContent.length;
        const fileCrc32 = crc32(fileContent);
        datFileInfos[filePath] = {
            size: fileSize,
            crc32: fileCrc32
        };
    }

    let modCache = null;

    if (existsSync(join(__dirname, "..", "mods.json"))) {
        modCache = JSON.parse(readFileSync(join(__dirname, "..", "mods.json"), 'utf-8'));
    }

    let modCacheValid = false;

    if (modCache) {
        const cachedDatFileInfos = modCache.file;
        if (JSON.stringify(datFileInfos) === JSON.stringify(cachedDatFileInfos)) {
            modCacheValid = true;
        }
    }

    if (modCacheValid) {
        console.log(`${fileList[0]} - \x1b[1;32mUsing Cached Mod...\x1b[0;0m`);
        return modCache.mod;
    }
    let modFile: yauzl.ZipFile
    for (const filePath of fileList) {
        if ((await getFileSize(filePath)) === 0) {
            continue;
        }
        modFile = await openZipFile(filePath);
        modFile.readEntry();
        modFile.on('entry', (entry) => {
            if (!/\/$/.test(entry.fileName)) {
                const modName = entry.fileName;
                if (loadedModList.name.includes(modName)) {
                    console.log(`${filePath} - \x1b[1;33mConflict with other mods...\x1b[0;0m`);
                    modFile.readEntry();
                    return;
                }
                modFile.openReadStream(entry, (err, readStream) => {
                    if (err) throw err;
                    const chunks: Buffer[] = [];
                    readStream!.on('data', (chunk) => chunks.push(chunk));
                    readStream!.on('end', () => {
                        const byteBuffer = Buffer.concat(chunks);
                        const totalSize = byteBuffer.length;
                        const abSize = byteBuffer.length;
                        const modMd5 = createHash('md5').update(byteBuffer).digest('hex');

                        const abInfo = {
                            name: modName,
                            hash: modMd5,
                            md5: modMd5,
                            totalSize: totalSize,
                            abSize: abSize
                        };

                        if (log) {
                            console.log(`${filePath} - \x1b[1;32mMod loaded successfully...\x1b[0;0m`);
                        }

                        loadedModList.mods.push(abInfo);
                        loadedModList.name.push(modName);
                        loadedModList.path.push(filePath);
                        const downloadName = modName.replace(/\//g, "_").replace(/#/g, "__").split(".")[0] + ".dat";
                        loadedModList.download.push(downloadName);
                        writeFileSync(join(__dirname, "..", "mods.json"), JSON.stringify({
                            file: datFileInfos,
                            mod: loadedModList
                        }, null, 4));
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

async function getFileSize(filePath: string): Promise<number> {
    return promises.stat(filePath).then(stat => stat.size);
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