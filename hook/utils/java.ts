import { logError, logWell } from "./logger";

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

export function tryCallingHook(
  funcs: (() => void)[],
  rawNames: string[],
  from: string,
) {
  for (let index = 0; index < funcs.length; index++) {
    try {
      funcs[index]();
      logWell(`${rawNames[index]}() is done.`, from);
    } catch (error) {
      logError(
        `An error occurred while calling ${rawNames[index]}(): ` +
          (error as object).toString(),
        from,
      );
    }
  }
}
