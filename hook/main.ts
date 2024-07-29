import 'frida-il2cpp-bridge';
import os from 'os';

function getLocalIpAddress(): string {
    const interfaces = os.networkInterfaces();
    for (const interfaceName in interfaces) {
        const networkInterface = interfaces[interfaceName];
        if (networkInterface) {
            for (const iface of networkInterface) {
                // 检查是否是IPv4并且不是回环地址
                if (iface.family === 'IPv4' && !iface.internal) {
                    return iface.address;
                }
            }
        }
    }
    return "";
}

const serverUrl = `${getLocalIpAddress()}:8443`;
let log = console.log
Java.perform(() => {
    const sdk = Java.use("com.hypergryph.platform.hgsdk.contants.SDKConst$UrlInfo")
    sdk.getRemoteUrl.implementation = function () {
        log("[Java Layer]Changed Hypergryph SDK")
        return `http://${serverUrl}`
    }
    const sdk2 = Java.use("com.hypergryph.platform.hguseragreement.contans.SDKConst$UrlInfo")
    sdk2.getRemoteUrl.implementation = function () {
        log("[Java Layer]Changed Hypergryph user agreement")
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
    VerifySignMD5RSA.implementation = function (a: Il2Cpp.Parameter.Type, b: Il2Cpp.Parameter.Type, c: Il2Cpp.Parameter.Type): boolean {
        log("[Il2Cpp Layer]Hooked VerifySignMD5RSA")
        return true
    };
    
}), 5000);