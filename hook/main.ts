import 'frida-il2cpp-bridge';

const serverUrl = "192.168.0.6:8443"
function tryCallingHook(funcs: Function[], rawNames: string[], from: string) {
    for (let index = 0; index < funcs.length; index++) {
        try {
            funcs[index]();
            Logger.logWell(`${rawNames[index]}() is done.`, from);
        } catch (error: any) {
            Logger.logError(`An error occurred while calling ${rawNames[index]}(): ` + error.toString(), from);
        }
    }
}
namespace JavaUtil {
    /** 获得安装包签名*/
    export function getAppSignature(): string {
        let context: Java.Wrapper = Java.use('com.unity3d.player.UnityPlayer').currentActivity.value;
        let packageInfo: Java.Wrapper = context.getPackageManager().getPackageInfo(context.getPackageName(), Java.use('android.content.pm.PackageManager').GET_SIGNATURES.value);
        let sign: Java.Wrapper = packageInfo.signatures.value[0];
        let md5: Int8Array = Java.use('java.security.MessageDigest').getInstance('MD5').digest(sign.toByteArray());
        return Array.prototype.map
            .call(md5, (x: { toString: (arg0: number) => string; }) => ('00' + x.toString(16)).slice(-2))
            .join('');
    }

}
namespace JavaHook {
    function SDKConstHook(): void {
        const SDKConst = Java.use('com.hypergryph.platform.hgsdk.contants.SDKConst');
        const sdk2 = Java.use("com.hypergryph.platform.hguseragreement.contans.SDKConst$UrlInfo")
        SDKConst.getRemoteUrl.implementation = () => `http://${serverUrl}`;
        sdk2.getRemoteUrl.implementation = () => `http://${serverUrl}`;

    }
    function ACESDKHook(): void {
        const MTPProxyApplication = Java.use('com.hg.sdk.MTPProxyApplication');
        MTPProxyApplication.onProxyCreate.implementation = () => { };
        const MTPDetection = Java.use('com.hg.sdk.MTPDetection');
        MTPDetection.onUserLogin.implementation = (_accountType: number, _worldId: number, _openId: string, _roleId: string) => { };
    }
    export function main(): void {
        Logger.logNormal('[JavaHook] Starting java layer hook...');
        tryCallingHook([ACESDKHook,SDKConstHook],['ACESDKHook','SDKConstHook'],'[JavaHook]');
    }
}
namespace Il2CppUtil {
    export function instantiate(klass: Il2Cpp.Class, ...parameters: Il2Cpp.Parameter.Type[]): Il2Cpp.Object {
        let obj = klass.new();
        obj.method('.ctor').invoke(...parameters);
        return obj;
    }

    export function instantiateOverload(klass: Il2Cpp.Class, types: string[], ...parameters: Il2Cpp.Parameter.Type[]): Il2Cpp.Object {
        let obj = klass.new();
        obj.method('.ctor').overload(...types).invoke(...parameters);
        return obj;
    }

    export function readCSharpString(s: NativePointer) {
        return s.isNull() ? 'null' : new Il2Cpp.String(s).content;
    }

    export function getFunctionByAddress(module: Module, address: string | number | NativePointer | UInt64 | Int64) {
        let func = new NativePointer(module.base.add(address).toString());
        Logger.log('[1;32m[√] Hook function[m [33m[' + address.toString() + '][m [1;32mat[m [1;30m' + func.toString() + '[m');
        return func;
    }

    export function getModuleByName(name: string) {
        let module = Process.getModuleByName(name);
        Logger.log('[1;32m[√] Find module[m [33m[' + name + '][m [1;32mat[m [1;30m' + module.base.toString() + '[m');
        return module;
    }

    export function loadModuleByPath(path: string) {
        let module = Module.load(path);
        Logger.log('[1;32m[√] Load module[m [33m[' + path + '][m [1;32mat[m [1;30m' + module.base.toString() + '[m');
        return module;
    }

    export function getEnumName(value: number, klass: Il2Cpp.Class): string {
        const System_Enum = Il2Cpp.corlib.class('System.Enum');
        const GetEnumObject = System_Enum.method<Il2Cpp.Object>('ToObject');
        return new Il2Cpp.String(GetEnumObject.overload('System.Type', 'System.Int32').invoke(klass.type.object, value).method<Il2Cpp.Object>('ToString').invoke()).content as string;
    }

    export function getTypeString(obj: Il2Cpp.Object) {
        return obj.method<Il2Cpp.Object>('GetType').invoke().method<Il2Cpp.String>('ToString').invoke().content as string;
    }

    export function traceClassByName(cls: string, filterMethods: (method: Il2Cpp.Method<Il2Cpp.Method.ReturnType>) => boolean = method => method.name != 'Update', detailed = true, dll = Il2Cpp.domain.assembly("Assembly-CSharp").image) {
        let CSharpClass = dll.class(cls);
        Il2Cpp.trace()
            .classes(CSharpClass)
            .filterMethods(filterMethods)
            .and()
            .attach();
        Logger.log('[1;36m[-] 跟踪类:[m [1;33m' + cls + '[m')
    }

    export function traceClass(cls: Il2Cpp.Class, filterMethods: (method: Il2Cpp.Method<Il2Cpp.Method.ReturnType>) => boolean = method => method.name != 'Update', detailed = true) {
        Il2Cpp.trace()
            .classes(cls)
            .filterMethods(filterMethods)
            .and()
            .attach();
        Logger.log('[1;36m[-] 跟踪类:[m [1;33m' + cls.name + '[m')
    }

    export function traceFunc(cls: string, methods: string[], detailed = true, dll = Il2Cpp.domain.assembly("Assembly-CSharp").image) {
        let CSharpClass = dll.class(cls);
        let tracer = Il2Cpp.trace();
        methods.forEach(method => {
            tracer.methods(CSharpClass.method(method)).and().attach();
        });
    }
    /*
    export function dumpso(mod: Module) {
        let path = Il2Cpp.application.dataPath + '/' + mod.base.toString() + '_' + mod.size.toString() + '_' + mod.name;
        let file = new File(path, 'wb');
        Memory.protect(mod.base, mod.size, 'rwx');
        file.write(mod.base.readByteArray(mod.size) as ArrayBuffer);
        file.flush();
        file.close();
        Logger.log('[1;36m[' + mod.name + '] 已导出到路径:[m [1;34m' + path + '[m');
    }
    */
    
}
namespace Il2CppHook {
    const CryptUtils = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Torappu.CryptUtils");
    const UnityEngineCoreModule = Il2Cpp.domain.assembly('UnityEngine.CoreModule').image;
    function LogHook(): void {
        const UnityEngine_Application = UnityEngineCoreModule.class('UnityEngine.Application');
        const CallLogCallback = UnityEngine_Application.method('CallLogCallback');
        const UnityEngine_LogType = UnityEngineCoreModule.class('UnityEngine.LogType')
        Interceptor.attach(Il2CppUtil.getFunctionByAddress(Il2Cpp.module, CallLogCallback.relativeVirtualAddress), {
            onEnter: args => {
                let name = Il2CppUtil.getEnumName(args[3].toInt32(), UnityEngine_LogType);
                let color = 'm';
                switch (name) {
                    case 'Error':
                        color = '31m';
                        break;
                    case 'Assert':
                        color = '36m';
                        break;
                    case 'Warning':
                        color = '33m';
                        break;
                    case 'Log':
                        color = '34m';
                        break;
                    case 'Exception':
                        color = '31;43m';
                        break;
                }
                Logger.log('[1;' + color + '<' + name + '> from Unity' + ':\n' + Il2CppUtil.readCSharpString(args[1])?.replace(/<\/*color.*?>/g, '') + '[m\n    ' + '[1;30m' + Il2CppUtil.readCSharpString(args[2])?.replace(/\n/g, '\n    ') + '[m');
            }
        });
    }
    function CryptHook() {
        const VerifySignMD5RSA = CryptUtils.method<boolean>("VerifySignMD5RSA");
        VerifySignMD5RSA.implementation = function (...args): boolean {
            return true
        };
    }
    function NetworkHook() {
        const Networker = Il2Cpp.domain.assembly("Torappu.Common").image.class("Torappu.Network.Networker");
        const GetOverrideRouterUrl = Networker.method<Il2Cpp.String>("get_overrideRouterUrl");
        GetOverrideRouterUrl.implementation = function (): Il2Cpp.String {
            return Il2Cpp.string(`http://${serverUrl}/config/prod/official/network_config`);
        }
    }
    export function main(): void {
        Logger.logNormal('[Il2CppHook] Starting il2cpp layer hook...');
        Logger.log('[1;36m应用包名:[m [1;34m' + Il2Cpp.application.identifier + '[m');
        Logger.log('[1;36m版本:[m [1;34m' + Il2Cpp.application.version + '[m');
        Logger.log('[1;36m路径:[m [1;34m' + Il2Cpp.application.dataPath + '[m');
        Logger.log('[1;36mUnity版本:[m [1;34m' + Il2Cpp.unityVersion + '[m');
        Logger.log('[1;36mPid:[m [1;34m' + Process.id.toString() + '[m');
        Logger.log('[1;36mAPK签名:[m [1;34m' + JavaUtil.getAppSignature() + '[m');
        tryCallingHook(
            [NetworkHook, LogHook, CryptHook],
            ['NetworkHook', 'LogHook', 'CryptHook'],
            '[Il2CppHook]');
        //Logger.logNormal('[Il2CppHook] Starting UIBaseHook()...');
        //UIBaseHook();
    }
}
Java.perform(JavaHook.main);
setTimeout(Il2CppHook.main, 5000);