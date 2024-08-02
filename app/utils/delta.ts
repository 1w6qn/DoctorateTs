type DeepPartial<T> = {
    [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export function compareObjects<T extends object=object>(oldObj: T, newObj: T): { modified: DeepPartial<T>, deleted: DeepPartial<T> } {
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