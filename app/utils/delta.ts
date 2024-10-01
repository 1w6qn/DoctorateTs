import { Patch } from "immer";

const setNestedValue = (obj: any, path: (string | number)[], value: any) => {
  let current = obj;

  path.forEach((key, index) => {
    if (index === path.length - 1) {
      current[key] = value;
    } else {
      if (!current[key]) {
        current[key] = {};
      }
      current = current[key];
    }
  });
};

export function patchesToObject(patch: Patch[]) {
  const result = {
    modified: {},
    deleted: {},
  };
  patch.forEach((op) => {
    const path = op.path;
    if (op.op === "remove") {
      setNestedValue(result.deleted, path, null);
    } else {
      setNestedValue(result.modified, path, op.value);
    }
  });
  return result;
}
