import 'frida-il2cpp-bridge';
const serverUrl = "192.168.0.6:8443"
let log = console.log
Java.perform(() => {
    const sdk = Java.use("com.hypergryph.platform.hgsdk.contants.SDKConst$UrlInfo")
    sdk.getRemoteUrl.implementation = function () {
        return `http://${serverUrl}`
    }
    const sdk2 = Java.use("com.hypergryph.platform.hguseragreement.contans.SDKConst$UrlInfo")
    sdk2.getRemoteUrl.implementation = function () {
        return `http://${serverUrl}`
    }
})

setTimeout(() => Il2Cpp.perform(() => {
    //Il2Cpp.dump("d.cs")
    const Networker = Il2Cpp.domain.assembly("Torappu.Common").image.class("Torappu.Network.Networker");
    const GetOverrideRouterUrl = Networker.method<Il2Cpp.String>("get_overrideRouterUrl");
    GetOverrideRouterUrl.implementation = function (): Il2Cpp.String {
        return Il2Cpp.string(`http://${serverUrl}/config/prod/official/network_config`);
    }
    log("[Il2Cpp Layer]Hooked GetOverrideRouterUrl")
    const CryptUtils = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Torappu.CryptUtils");
    const VerifySignMD5RSA = CryptUtils.method<boolean>("VerifySignMD5RSA");
    //@ts-ignore
    VerifySignMD5RSA.implementation = function (a: Il2Cpp.String, b: Il2Cpp.String, c: Il2Cpp.String): boolean {
        log("[Il2Cpp Layer]Hooked VerifySignMD5RSA")
        return true
    };
}), 5000);