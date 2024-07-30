import { readFileSync } from "fs";

type Diff<T> = {
    path: string;
    value1: T;
    value2: T;
};

function isObject(obj: any): boolean {
    return obj !== null && typeof obj === 'object' && !Array.isArray(obj);
}

function compare<T extends object>(obj1: T, obj2: T): object {
    const diffs: Diff<any>[] = [];
    const newObject: any = { ...obj2 };

    function compareObjects(obj1: any, obj2: any, path: string = '') {
        const keys = new Set([...Object.keys(obj1), ...Object.keys(obj2)]);

        keys.forEach(key => {
            const value1 = obj1[key];
            const value2 = obj2[key];
            const currentPath = path ? `${path}.${key}` : key;

            if (isObject(value1) && isObject(value2)) {
                compareObjects(value1, value2, currentPath);
            } else if (value1 !== value2 && !Array.isArray(value1) && !Array.isArray(value2)) {
                diffs.push({
                    path: currentPath,
                    value1: value1,
                    value2: value2
                });
            }
        });
    }

    compareObjects(obj1, obj2);

    diffs.forEach(diff => {
        const paths = diff.path.split('.');
        let current = newObject;

        paths.forEach((path, index) => {
            if (index === paths.length - 1) {
                current[path] = diff.value2;
            } else {
                if (!current[path]) {
                    current[path] = {};
                }
                current = current[path];
            }
        });
    });

    return newObject;
}

const obj1 = JSON.parse(readFileSync(`${__dirname}/../../a.json`, 'utf-8'));

const obj2 = JSON.parse(readFileSync(`${__dirname}/../../1.json`, 'utf-8'));
let ts = new Date().getTime()
const o = compare(obj1, obj2);
let dt = new Date().getTime() - ts
console.log(o, dt);
