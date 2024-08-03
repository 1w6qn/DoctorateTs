import crypto from 'crypto';
import * as zlib from 'zlib';
import * as base64 from 'base64-js';
import { promisify } from 'util';

const LOG_TOKEN_KEY = "pM6Umv*^hVQuB6t&";
export function decryptBattleData(data: string, loginTime: number) {
    const battleData = Buffer.from(data.slice(0, data.length - 32), 'hex');
    const src = LOG_TOKEN_KEY + loginTime.toString();
    const key = crypto.createHash('md5').update(src).digest();
    const iv = Buffer.from(data.slice(data.length - 32), 'hex');
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    let decryptedData = decipher.update(battleData);
    let decrypt = Buffer.concat([decryptedData, decipher.final()]).toString();
    return JSON.parse(decrypt)
}
export function encryptBattleData(data: any, loginTime: number): string {
    const jsonData = JSON.stringify(data);
    const src = LOG_TOKEN_KEY + loginTime.toString();
    const key = crypto.createHash('md5').update(src).digest();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    let encryptedData = cipher.update(jsonData, 'utf8', 'hex');
    encryptedData += cipher.final('hex');
    return encryptedData + iv.toString('hex');
}

export async function decryptBattleLog(battleReplay: string): Promise<any> {
    const data = base64.toByteArray(battleReplay);
    const unzip = promisify(zlib.unzip);
    const unzippedData = await unzip(data);
    const jsonData = JSON.parse(unzippedData.toString('utf-8'));
    console.debug(`- BattleLog -\n${JSON.stringify(jsonData)}`);
    return jsonData;
}
