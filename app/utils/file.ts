import { access, readFile, stat } from "fs/promises";

export const exists = async (filePath: string): Promise<boolean> => {
  return access(filePath)
    .then(() => true)
    .catch(() => false);
};
export const size = async (filePath: string): Promise<number> => {
  return stat(filePath).then((stats) => stats.size);
};
export const readJson = async <T = object>(filePath: string): Promise<T> => {
  console.time("[JSON][loaded] " + filePath);
  const data = await readFile(filePath, "utf-8");
  console.timeEnd("[JSON][loaded] " + filePath);
  return JSON.parse(data) as T;
};
