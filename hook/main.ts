import "frida-il2cpp-bridge";

namespace Logger {
  export function formatDate(
    time: string | number | Date = new Date().getTime(),
    format: string = "YY-MM-DD hh:mm:ss",
  ): string {
    const date = new Date(time);
    const year = date.getFullYear(),
      month = date.getMonth() + 1,
      day = date.getDate(),
      hour = date.getHours(),
      min = date.getMinutes(),
      sec = date.getSeconds();
    const preArr = Array(Array(10)).map(
      (value: unknown, index: number) => "0" + index,
    );
    return format
      .replace(/YY/g, year.toString())
      .replace(/MM/g, (preArr[month] || month) as string)
      .replace(/DD/g, (preArr[day] || day) as string)
      .replace(/hh/g, (preArr[hour] || hour) as string)
      .replace(/mm/g, (preArr[min] || min) as string)
      .replace(/ss/g, (preArr[sec] || sec) as string);
  }

  export function l(s: string): void {
    console.log(s);
  }

  function getTime(): string {
    return "[1;30m[" + formatDate(new Date().getTime(), "hh:mm:ss") + "] -[m ";
  }

  function getTC(t: string | undefined = undefined): string {
    return t == undefined ? "" : `[1;35m${t} -[m `;
  }

  export function log(s: string, t: string | undefined = undefined): void {
    l(getTime() + getTC(t) + s);
  }

  export function logDebug(s: string, t: string | undefined = undefined): void {
    l(getTime() + getTC(t) + `[33;47m${s}[m`);
  }

  export function logNormal(
    s: string,
    t: string | undefined = undefined,
  ): void {
    l(getTime() + getTC(t) + `[1;34m${s}[m`);
  }

  export function logWell(s: string, t: string | undefined = undefined): void {
    l(getTime() + getTC(t) + `[1;32m${s}[m`);
  }

  export function logWarning(
    s: string,
    t: string | undefined = undefined,
  ): void {
    l(getTime() + getTC(t) + `[1;33m${s}[m`);
  }

  export function logError(s: string, t: string | undefined = undefined): void {
    l(getTime() + getTC(t) + `[1;31m${s}[m`);
  }

  export function formatLog(
    name: string,
    color: string,
    message: string,
    stackTrace: string,
  ) {
    return `[1;${color}<${name}> from Unity:\n${message}[m\n    [1;30m${stackTrace}[m`;
  }
}
namespace Il2CppUtils {
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
    Logger.log(
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
    Logger.log(
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
    Logger.log(
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
    Logger.log("[1;36m[-] 跟踪类:[m [1;33m" + cls + "[m");
  }

  export function traceClass(
    cls: Il2Cpp.Class,
    filterMethods: (method: Il2Cpp.Method) => boolean = (method) =>
      method.name != "Update",
  ) {
    Il2Cpp.trace().classes(cls).filterMethods(filterMethods).and().attach();
    Logger.log("[1;36m[-] 跟踪类:[m [1;33m" + cls.name + "[m");
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
}
namespace JavaUtils {
  export function getAppSignature(): string {
    const context: Java.Wrapper = Java.use("com.unity3d.player.UnityPlayer")
      .currentActivity.value;
    const packageInfo: Java.Wrapper = context
      .getPackageManager()
      .getPackageInfo(
        context.getPackageName(),
        Java.use("android.content.pm.PackageManager").GET_SIGNATURES.value,
      );
    const sign: Java.Wrapper = packageInfo.signatures.value[0];
    const md5: Int8Array = Java.use("java.security.MessageDigest")
      .getInstance("MD5")
      .digest(sign.toByteArray());
    return Array.prototype.map
      .call(md5, (x: { toString: (arg0: number) => string }) =>
        ("00" + x.toString(16)).slice(-2),
      )
      .join("");
  }
}

const getIPAdress = () => {
  return "192.168.0.100";
};
console.log(`[Main]IP Address: ${getIPAdress()}`);
const serverUrl = `http:` + `//${getIPAdress()}:8443`;
const logColors: { [key: string]: string } = {
  Error: "31m",
  Assert: "36m",
  Warning: "33m",
  Log: "34m",
  Exception: "31;43m",
};

Java.perform(() => {
  const sdk = Java.use(
    "com.hypergryph.platform.hgsdk.contants.SDKConst$UrlInfo",
  );
  sdk.getRemoteUrl.implementation = function () {
    Logger.log("[Java Layer]Changed Hypergryph SDK");
    return `${serverUrl}/auth`;
  };
  const sdk2 = Java.use(
    "com.hypergryph.platform.hguseragreement.contans.SDKConst$UrlInfo",
  );
  sdk2.getRemoteUrl.implementation = function () {
    Logger.log("[Java Layer]Changed Hypergryph user agreement");
    return `${serverUrl}/auth`;
  };
  //ACE SDK Hook
  const MTPProxyApplication = Java.use("com.hg.sdk.MTPProxyApplication");
  MTPProxyApplication.onProxyCreate.implementation = () => {};
  const MTPDetection = Java.use("com.hg.sdk.MTPDetection");
  MTPDetection.onUserLogin.implementation = () => {};
});
setTimeout(() =>
  Il2Cpp.perform(() => {
    Logger.log("[1;36m==========Programme started!==========[m");
    Logger.logNormal("[Il2CppHook] Starting il2cpp layer hook...");
    Logger.log(
      "[1;36m应用包名:[m [1;34m" + Il2Cpp.application.identifier + "[m",
    );
    Logger.log("[1;36m版本:[m [1;34m" + Il2Cpp.application.version + "[m");
    Logger.log("[1;36m路径:[m [1;34m" + Il2Cpp.application.dataPath + "[m");
    Logger.log("[1;36mUnity版本:[m [1;34m" + Il2Cpp.unityVersion + "[m");
    Logger.log("[1;36mPid:[m [1;34m" + Process.id.toString() + "[m");
    Logger.log("[1;36mAPK签名:[m [1;34m" + JavaUtils.getAppSignature() + "[m");
    //Network Config Hook
    const Networker = Il2Cpp.domain
      .assembly("Assembly-CSharp")
      .image.class("Torappu.Network.Networker");
    const GetOverrideRouterUrl = Networker.method<Il2Cpp.String>(
      "get_overrideRouterUrl",
    );
    GetOverrideRouterUrl.implementation = function (): Il2Cpp.String {
      return Il2Cpp.string(`${serverUrl}/config/prod/official/network_config`);
    };
    Logger.log("[Il2Cpp Layer]Hooked GetOverrideRouterUrl");
    //MD5 RSA Signature Hook
    const CryptUtils = Il2Cpp.domain
      .assembly("Assembly-CSharp")
      .image.class("Torappu.CryptUtils");
    const VerifySignMD5RSA = CryptUtils.method<boolean>("VerifySignMD5RSA");
    VerifySignMD5RSA.implementation = function (): boolean {
      Logger.log("[Il2Cpp Layer]Hooked VerifySignMD5RSA");
      return true;
    };
    //Log Callback Hook
    const UnityEngineCoreModule = Il2Cpp.domain.assembly(
      "UnityEngine.CoreModule",
    ).image;
    const UnityEngine_Application = UnityEngineCoreModule.class(
      "UnityEngine.Application",
    );
    const CallLogCallback = UnityEngine_Application.method("CallLogCallback");

    //Il2Cpp.trace(true).methods(CallLogCallback).and().attach();

    const UnityEngine_LogType = UnityEngineCoreModule.class(
      "UnityEngine.LogType",
    );
    Interceptor.attach(
      Il2CppUtils.getFunctionByAddress(
        Il2Cpp.module,
        CallLogCallback.relativeVirtualAddress,
      ),
      {
        onEnter: (args: NativePointer[]) => {
          const name = Il2CppUtils.getEnumName(
            args[3].toInt32(),
            UnityEngine_LogType,
          );
          const color = logColors[name] || "m"; // 默认颜色
          Logger.log(
            "[1;" +
              color +
              "<" +
              name +
              "> from Unity" +
              ":\n" +
              Il2CppUtils.readCSharpString(args[1])?.replace(
                /<\/*color.*?>/g,
                "",
              ) +
              "[m\n    " +
              "[1;30m" +
              Il2CppUtils.readCSharpString(args[2])?.replace(/\n/g, "\n    ") +
              "[m",
          );
        },
      },
    );
    //Il2Cpp.dump("d.cs");
  }),
);
