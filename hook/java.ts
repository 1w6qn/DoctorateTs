import { tryCallingHook } from "./utils/java";
import { logNormal } from "./utils/logger";

export function biliGameSDKHook(): void {
  const reflectField = Java.use("java.lang.reflect.Field");
  // 取消sdk_ver请求头
  reflectField.isAnnotationPresent.implementation = function (
    klass: Java.Wrapper,
  ): boolean {
    if (
      klass.getName() == "com.gsc.base.annotations.RequestParam" &&
      this.getName() == "sdk_ver"
    )
      return false;
    return this.isAnnotationPresent(klass);
  };

  const requestModel = Java.use("com.http.lib.request.Request");
  // 跳过响应签名检验
  requestModel.a.overload("okhttp3.Response", "w7").implementation = () => {
    return true;
  };
}

function ACESDKHook(): void {
  const MTPProxyApplication = Java.use("com.hg.sdk.MTPProxyApplication");
  MTPProxyApplication.onProxyCreate.implementation = () => {};
  const MTPDetection = Java.use("com.hg.sdk.MTPDetection");
  MTPDetection.onUserLogin.implementation = () => {};
}

export function biliTrackHook(): void {
  Java.use("com.base.trackingdata.Track").init.implementation = () => {};
}

export function biliPaymentHook(): void {
  // 解决支付时缺少sdk_ver产生的错误
  Java.use("com.gsc.cashier_h5.mvp.b").a.overload(
    "java.lang.String",
    "com.gsc.base.model.OrderReqModel",
    "com.gsc.base.model.UserInfoModel",
  ).implementation = function (...args: never): Java.Wrapper {
    const map = this.a
      .overload(
        "java.lang.String",
        "com.gsc.base.model.OrderReqModel",
        "com.gsc.base.model.UserInfoModel",
      )
      .apply(this, args);
    map.put("sdk_ver", "5.6.2");
    return map;
  };

  // 过本地充值限制（仍然会在下一步受限，暂无解）
  const MinorAntiPayActivity = Java.use(
    "com.gsc.minor_anti_pay.MinorAntiPayActivity",
  );
  MinorAntiPayActivity.b.overload(
    "com.gsc.minor_anti_pay.model.AntiPayResModel",
  ).implementation = function () {
    this.b.overload("com.gsc.minor_anti_pay.model.AntiPayResModel").call(this);
  };
}

export function main(): void {
  logNormal("[JavaHook] Starting java layer hook...");
  tryCallingHook([ACESDKHook], ["ACESDKHook"], "[JavaHook]");
}
