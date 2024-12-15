import "frida-il2cpp-bridge";
import {
  getEnumName,
  getFunctionByAddress,
  readCSharpString,
} from "./utils/il2cpp";

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

function cleanString(s: NativePointer) {
  return readCSharpString(s)?.replace(/<\/*color.*?>/g, "") || "";
}

function formatLog(
  name: string,
  color: string,
  message: string,
  stackTrace: string,
) {
  return `[1;${color}<${name}> from Unity:\n${message}[m\n    [1;30m${stackTrace}[m`;
}

const log = console.log;
Java.perform(() => {
  const sdk = Java.use(
    "com.hypergryph.platform.hgsdk.contants.SDKConst$UrlInfo",
  );
  sdk.getRemoteUrl.implementation = function () {
    log("[Java Layer]Changed Hypergryph SDK");
    return `${serverUrl}/auth`;
  };
  const sdk2 = Java.use(
    "com.hypergryph.platform.hguseragreement.contans.SDKConst$UrlInfo",
  );
  sdk2.getRemoteUrl.implementation = function () {
    log("[Java Layer]Changed Hypergryph user agreement");
    return `${serverUrl}/auth`;
  };
});
setTimeout(() =>
  Il2Cpp.perform(() => {
    //Il2Cpp.dump("d.cs");
    const Networker = Il2Cpp.domain
      .assembly("Torappu.Common")
      .image.class("Torappu.Network.Networker");
    const GetOverrideRouterUrl = Networker.method<Il2Cpp.String>(
      "get_overrideRouterUrl",
    );
    GetOverrideRouterUrl.implementation = function (): Il2Cpp.String {
      return Il2Cpp.string(`${serverUrl}/config/prod/official/network_config`);
    };
    log("[Il2Cpp Layer]Hooked GetOverrideRouterUrl");
    const CryptUtils = Il2Cpp.domain
      .assembly("Assembly-CSharp")
      .image.class("Torappu.CryptUtils");
    const VerifySignMD5RSA = CryptUtils.method<boolean>("VerifySignMD5RSA");
    VerifySignMD5RSA.implementation = function (): boolean {
      log("[Il2Cpp Layer]Hooked VerifySignMD5RSA");
      return true;
    };
    const UnityEngineCoreModule = Il2Cpp.domain.assembly(
      "UnityEngine.CoreModule",
    ).image;
    const UnityEngine_Application = UnityEngineCoreModule.class(
      "UnityEngine.Application",
    );
    const CallLogCallback = UnityEngine_Application.method("CallLogCallback");
    const UnityEngine_LogType = UnityEngineCoreModule.class(
      "UnityEngine.LogType",
    );
    Interceptor.attach(
      getFunctionByAddress(
        Il2Cpp.module,
        CallLogCallback.relativeVirtualAddress,
      ),
      {
        onEnter: ([, message, stackTrace, logType]: NativePointer[]) => {
          const name = getEnumName(logType.toInt32(), UnityEngine_LogType);
          const color = logColors[name] || "m"; // 默认颜色
          const cleanedMessage = cleanString(message);
          const cleanedStackTrace = cleanString(stackTrace);
          log(formatLog(name, color, cleanedMessage, cleanedStackTrace));
        },
      },
    );
  }),
);
