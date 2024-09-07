type DeepPartial<T> = {
    [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export function compareObjects<T extends object = object>(oldObj: T, newObj: T): { modified: DeepPartial<T>, deleted: DeepPartial<T> } {
    const modified: DeepPartial<T> = {};
    const deleted: DeepPartial<T> = {};

    function compare<K extends keyof T>(oldObj: T, newObj: T, key: K): void {
        if (oldObj[key] === newObj[key]) {
            return;
        }
        if (Array.isArray(oldObj[key]) || Array.isArray(newObj[key])) {
            // 如果键值是数组，则跳过比较
            return;
        }
        if (typeof oldObj[key] === 'object' && oldObj[key] !== null && typeof newObj[key] === 'object' && newObj[key] !== null) {
            // 递归比较子对象
            compareObjects(oldObj[key] as unknown as object, newObj[key] as unknown as object);
        } else {
            // 如果新对象中不存在该键，则认为是删除
            if (!(key in newObj)) {
                deleted[key] = oldObj[key];
            } else {
                // 否则认为是修改
                if (!modified.hasOwnProperty(key)) {
                    modified[key] = {} as T[K];
                }
                modified[key] = newObj[key];
            }
        }
    }

    for (const key in oldObj) {
        if (oldObj.hasOwnProperty(key)) {
            if (key in newObj) {
                compare(oldObj, newObj, key);
            } else {
                deleted[key] = oldObj[key];
            }
        }
    }

    return { modified, deleted };
}
export function applyModifications<T extends object = object>(targetObj: T, delta: { modified: DeepPartial<T>, deleted: DeepPartial<T> }): void {
    // 将 modified 的内容合并到 targetObj
    for (const key in delta.modified) {
        if (delta.modified.hasOwnProperty(key)) {
            if (typeof delta.modified[key] === 'object' && delta.modified[key] !== null && !Array.isArray(delta.modified[key])) {
                // 如果 modified[key] 是一个对象，递归调用 applyModifications
                if (!targetObj[key]) {
                    targetObj[key] = {} as any;
                }
                applyModifications(targetObj[key] as object, { modified: delta.modified[key] as DeepPartial<object>, deleted: {} });
            } else {
                // 否则直接赋值
                targetObj[key] = delta.modified[key] as T[typeof key];
            }
        }
    }

    // 从 targetObj 中删除 deleted 中指定的键
    for (const key in delta.deleted) {
        if (delta.deleted.hasOwnProperty(key)) {
            if (typeof delta.deleted[key] === 'object' && delta.deleted[key] !== null && !Array.isArray(delta.deleted[key])) {
                // 如果 deleted[key] 是一个对象，递归调用 applyModifications
                if (targetObj[key]) {
                    applyModifications(targetObj[key] as object, { modified: {}, deleted: delta.deleted[key] as DeepPartial<object> });
                }
            } else {
                // 否则直接删除键
                delete targetObj[key];
            }
        }
    }
}