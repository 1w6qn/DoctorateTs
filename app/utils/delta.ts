import { Patch } from "immer";

const setNestedValue = (obj: any, origin: any, path: (string | number)[], value: any) => {
  let current = obj;
  let originCurrent = origin;

  for (let index = 0; index < path.length; index++) {
    const key = path[index];
    if (Array.isArray(originCurrent)) {
      setNestedValue(obj, origin, path.slice(0, index), originCurrent);
      break;
    }
    if (index === path.length - 1) {
      current[key] = value;
    } else {
      if (!current[key]) {
        current[key] = {};
      }
      current = current[key];
      originCurrent = originCurrent[key] || {};
    }
  }
};

export function patchesToObject(patch: Patch[], origin: any) {
  const result = {
    modified: {},
    deleted: {},
  };
  patch.forEach((op) => {
    const path = op.path;
    if (op.op === "remove") {
      setNestedValue(result.deleted, origin, path, null);
    } else {
      setNestedValue(result.modified, origin, path, op.value);
    }
  });
  return result;
}