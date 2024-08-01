export namespace FileUtil {
    export function readFile(path: string): Il2Cpp.String {
        return Il2Cpp.corlib.class('System.IO.File').method<Il2Cpp.String>('ReadAllText').overload('System.String').invoke(Il2Cpp.string(path));
    }

    export function writeFile(path: string, text: string) {
        return Il2Cpp.corlib.class('System.IO.File').method<Il2Cpp.String>('WriteAllText').overload('System.String', 'System.String').invoke(Il2Cpp.string(path), Il2Cpp.string(text));
    }

    export function isFileExists(path: string): boolean {
        return Il2Cpp.corlib.class('System.IO.File').method<boolean>('Exists').invoke(Il2Cpp.string(path));
    }
}