import crypto from "crypto";
import JSZip from "jszip";

const LOG_TOKEN_KEY = "pM6Umv*^hVQuB6t&";
export function decryptBattleData(data: string, loginTime: number) {
  const battleData = Buffer.from(data.slice(0, data.length - 32), "hex");
  const src = LOG_TOKEN_KEY + loginTime.toString();
  const key = crypto.createHash("md5").update(src).digest();
  const iv = Buffer.from(data.slice(data.length - 32), "hex");
  const decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
  const decryptedData = decipher.update(battleData);
  const decrypt = Buffer.concat([decryptedData, decipher.final()]).toString();
  return JSON.parse(decrypt);
}

export function encryptBattleData(data: object, loginTime: number): string {
  const jsonData = JSON.stringify(data);
  const src = LOG_TOKEN_KEY + loginTime.toString();
  const key = crypto.createHash("md5").update(src).digest();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-128-cbc", key, iv);
  let encryptedData = cipher.update(jsonData, "utf8", "hex");
  encryptedData += cipher.final("hex");
  return encryptedData + iv.toString("hex");
}

export function encryptIsCheat(battleId: string): string {
  return btoa(
    Buffer.from(battleId)
      .map((v) => v + 7)
      .toString(),
  );
}

export function decryptIsCheat(isCheat: string): string {
  return Buffer.from(isCheat, "base64")
    .map((v) => v - 7)
    .toString();
}

export async function decryptBattleReplay(
  battleReplay: string,
): Promise<object> {
  const data = Buffer.from(battleReplay, "base64");
  const zip = await new JSZip().loadAsync(data);
  return JSON.parse(await zip.files["default_entry"].async("string"));
}
