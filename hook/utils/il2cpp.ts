import { log } from "./logger";

export function instantiate(
  klass: Il2Cpp.Class,
  ...parameters: Il2Cpp.Parameter.Type[]
): Il2Cpp.Object {
  const obj = klass.new();
  obj.method(".ctor").invoke(...parameters);
  return obj;
}

export function instantiateOverload(
  klass: Il2Cpp.Class,
  types: string[],
  ...parameters: Il2Cpp.Parameter.Type[]
): Il2Cpp.Object {
  const obj = klass.new();
  obj
    .method(".ctor")
    .overload(...types)
    .invoke(...parameters);
  return obj;
}

export function readCSharpString(s: NativePointer) {
  return s.isNull() ? "null" : new Il2Cpp.String(s).content;
}

export function getFunctionByAddress(
  module: Module,
  address: string | number | NativePointer | UInt64 | Int64,
) {
  const func = new NativePointer(module.base.add(address).toString());
  log(
    "[1;32m[√] Hook function[m [33m[" +
      address.toString() +
      "][m [1;32mat[m [1;30m" +
      func.toString() +
      "[m",
  );
  return func;
}

export function getModuleByName(name: string) {
  const module = Process.getModuleByName(name);
  log(
    "[1;32m[√] Find module[m [33m[" +
      name +
      "][m [1;32mat[m [1;30m" +
      module.base.toString() +
      "[m",
  );
  return module;
}

export function loadModuleByPath(path: string) {
  const module = Module.load(path);
  log(
    "[1;32m[√] Load module[m [33m[" +
      path +
      "][m [1;32mat[m [1;30m" +
      module.base.toString() +
      "[m",
  );
  return module;
}

export function getEnumName(value: number, klass: Il2Cpp.Class): string {
  const System_Enum = Il2Cpp.corlib.class("System.Enum");
  const GetEnumObject = System_Enum.method<Il2Cpp.Object>("ToObject");
  return new Il2Cpp.String(
    GetEnumObject.overload("System.Type", "System.Int32")
      .invoke(klass.type.object, value)
      .method<Il2Cpp.Object>("ToString")
      .invoke(),
  ).content as string;
}

export function getTypeString(obj: Il2Cpp.Object) {
  return obj
    .method<Il2Cpp.Object>("GetType")
    .invoke()
    .method<Il2Cpp.String>("ToString")
    .invoke().content as string;
}

export function traceClassByName(
  cls: string,
  filterMethods: (method: Il2Cpp.Method) => boolean = (method) =>
    method.name != "Update",
  dll = Il2Cpp.domain.assembly("Assembly-CSharp").image,
) {
  const CSharpClass = dll.class(cls);
  Il2Cpp.trace()
    .classes(CSharpClass)
    .filterMethods(filterMethods)
    .and()
    .attach();
  log("[1;36m[-] 跟踪类:[m [1;33m" + cls + "[m");
}

export function traceClass(
  cls: Il2Cpp.Class,
  filterMethods: (method: Il2Cpp.Method) => boolean = (method) =>
    method.name != "Update",
) {
  Il2Cpp.trace().classes(cls).filterMethods(filterMethods).and().attach();
  log("[1;36m[-] 跟踪类:[m [1;33m" + cls.name + "[m");
}

export function traceFunc(
  cls: string,
  methods: string[],
  dll = Il2Cpp.domain.assembly("Assembly-CSharp").image,
) {
  const CSharpClass = dll.class(cls);
  const tracer = Il2Cpp.trace();
  methods.forEach((method) => {
    tracer.methods(CSharpClass.method(method)).and().attach();
  });
}

export function dumpso(mod: Module) {
  const path =
    Il2Cpp.application.dataPath +
    "/" +
    mod.base.toString() +
    "_" +
    mod.size.toString() +
    "_" +
    mod.name;
  const file = new File(path, "wb");
  Memory.protect(mod.base, mod.size, "rwx");
  file.write(mod.base.readByteArray(mod.size) as ArrayBuffer);
  file.flush();
  file.close();
  log("[1;36m[" + mod.name + "] 已导出到路径:[m [1;34m" + path + "[m");
}
