import { access, readFile, stat, writeFile } from "fs/promises";
import { readFileSync } from "fs";

export async function exists(filePath: string): Promise<boolean> {
  return access(filePath)
    .then(() => true)
    .catch(() => false);
}

export async function size(filePath: string): Promise<number> {
  return stat(filePath).then((stats) => stats.size);
}

export async function readJson<T = object>(filePath: string): Promise<T> {
  console.time("[JSON][loaded][async] " + filePath);
  const data = await readFile(filePath, "utf-8");
  console.timeEnd("[JSON][loaded][async] " + filePath);
  return JSON.parse(data) as T;
}

export function readJsonSync<T = object>(filePath: string): T {
  console.time("[JSON][loaded][sync] " + filePath);
  const data = readFileSync(filePath, "utf-8");
  console.timeEnd("[JSON][loaded][sync] " + filePath);
  return JSON.parse(data) as T;
}

export async function writeJson(filePath: string, data: object): Promise<void> {
  console.time("[JSON][written] " + filePath);
  await writeFile(filePath, JSON.stringify(data, null, 4), "utf-8");
  console.timeEnd("[JSON][written] " + filePath);
}
