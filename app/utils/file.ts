import { access, stat } from "fs/promises";

export const exists = async (filePath: string): Promise<boolean> => {
  return access(filePath)
    .then(() => true)
    .catch(() => false);
};
export const size = async (filePath: string): Promise<number> => {
  return stat(filePath).then((stats) => stats.size);
};
