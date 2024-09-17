import { access, readFile, stat } from "fs/promises";

export async function exists(filePath: string): Promise<boolean> {
  return access(filePath)
    .then(() => true)
    .catch(() => false);
}

export async function size(filePath: string): Promise<number> {
  return stat(filePath).then((stats) => stats.size);
}

export async function readJson<T = object>(filePath: string): Promise<T> {
  console.time("[JSON][loaded] " + filePath);
  const data = await readFile(filePath, "utf-8");
  console.timeEnd("[JSON][loaded] " + filePath);
  return JSON.parse(data) as T;
}
