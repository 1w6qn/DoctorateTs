type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export function compareObjects<T extends object = object>(
  oldObj: T,
  newObj: T,
): { modified: DeepPartial<T>; deleted: DeepPartial<T> } {
  const modified: DeepPartial<T> = {};
  const deleted: DeepPartial<T> = {};

  function compare<K extends keyof T>(oldObj: T, newObj: T, key: K): void {
    if (oldObj[key] === newObj[key]) {
      return;
    }
    if (Array.isArray(oldObj[key]) || Array.isArray(newObj[key])) {
      return;
    }
    if (
      typeof oldObj[key] === "object" &&
      oldObj[key] !== null &&
      typeof newObj[key] === "object" &&
      newObj[key] !== null
    ) {
      compareObjects(
        oldObj[key] as unknown as object,
        newObj[key] as unknown as object,
      );
    } else {
      if (!(key in newObj)) {
        deleted[key] = oldObj[key];
      } else {
        if (!Object.prototype.hasOwnProperty.call(modified, key)) {
          modified[key] = {} as T[K];
        }
        modified[key] = newObj[key];
      }
    }
  }

  for (const key in oldObj) {
    if (Object.prototype.hasOwnProperty.call(oldObj, key)) {
      if (key in newObj) {
        compare(oldObj, newObj, key);
      } else {
        deleted[key] = oldObj[key];
      }
    }
  }

  return { modified, deleted };
}

export function applyModifications<T extends object = object>(
  targetObj: T,
  delta: { modified: DeepPartial<T>; deleted: DeepPartial<T> },
): void {
  for (const key in delta.modified) {
    if (Object.prototype.hasOwnProperty.call(delta.modified, key)) {
      if (
        typeof delta.modified[key] === "object" &&
        delta.modified[key] !== null &&
        !Array.isArray(delta.modified[key])
      ) {
        if (!targetObj[key]) {
          targetObj[key] = {} as never;
        }
        applyModifications(targetObj[key] as object, {
          modified: delta.modified[key] as DeepPartial<object>,
          deleted: {},
        });
      } else {
        targetObj[key] = delta.modified[key] as T[typeof key];
      }
    }
  }

  for (const key in delta.deleted) {
    if (Object.prototype.hasOwnProperty.call(delta.deleted, key)) {
      if (
        typeof delta.deleted[key] === "object" &&
        delta.deleted[key] !== null &&
        !Array.isArray(delta.deleted[key])
      ) {
        if (targetObj[key]) {
          applyModifications(targetObj[key] as object, {
            modified: {},
            deleted: delta.deleted[key] as DeepPartial<object>,
          });
        }
      } else {
        delete targetObj[key];
      }
    }
  }
}
