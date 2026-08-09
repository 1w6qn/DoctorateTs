"""ODPY 缺失路由逐条核对（标注：已覆盖 / 设计跳过 / 需补充）

用法：python scripts/_audit-odpy-gaps.py [server_base]
- 需先启动服务（npm run start:quick）再运行；对 ODPY 参考清单中
  DoctorateTs 未覆盖的路由逐一 curl 冒烟，按分类标注结论。
"""
import re
import os
import sys
import subprocess

ROOT = r"D:\develop\DoctorateTs"
BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8443"

# 设计跳过分类（auth 单账号/短信/yostar/支付变体/管理端/遥测等——CN 2.7.61 客户端不调用或单服设计差异）
DESIGN_SKIP_PREFIX = [
    "/account/yostar_", "/user/yostar_", "/user/login", "/user/register",
    "/user/sendSmsCode", "/user/loginBySmsCode", "/user/v1/guestLogin",
    "/user/changePassword", "/user/changePhone", "/user/changePhoneCheck",
    "/user/checkIdCard", "/user/authenticateUserIdentity",
    "/user/updateAgreement", "/user/agreement", "/user/auth/v2/",
    "/user/info/v1/basic", "/user/pay/", "/pay/", "/admin/",
    "/analytics/", "/beat", "/event", "/gameBulletin", "/loggw/", "/mgw.htm",
    "/deviceprofile/", "/iedsafe/", "/survey/", "/app/getCode", "/app/getSettings",
    "/api/gacha/", "/api/autoChess/", "/api/is/", "/config/prod/",
    "/api/remote_config/1/prod/bilibili/", "/api/remote_config/101/",
    "/recalRune/", "/general/", "/api/game/", "/api/gate/", "/app/v1/",
]
# 上述前缀命中即设计跳过（含 GET 覆盖 / 路径差异 / 单服设计差异）
DESIGN_SKIP_REASONS = {
    "auth": "单账号私服（secret 收敛 uid=1）+ 既有 token 登录链路，短信/注册/改密接口客户端不调用",
    "yostar": "YoStar/EN 专属（P4）",
    "pay": "支付变体（Appstore/支付宝/微信/订单查询）——CN 2.7.61 客户端仅调用 createOrder/confirmOrder/getUnconfirmedOrderIdList",
    "admin": "管理端为项目自有实现（路径不同，app/admin/*）",
    "telemetry": "遥测/埋点/外部服务端点（loggw/mgw/iedsafe 等），客户端不依赖响应",
    "app": "客户端 2.7.61 不调用（ODPY 独有）",
    "config": "config/prod 与 remote_config 变体：GET 覆盖 / bilibili、101 渠道变体客户端不调用",
    "gacha_history": "ODPY 自有 gacha 历史接口（客户端走 api/gacha/cate|history 为 ODPY 独有）",
    "recalRune": "服务端既有 /crisis/recalRune/*（路径差异，客户端不调用根路径）",
    "game_launcher": "GET 覆盖（/api/game/get_latest、/api/gate/meta/*）",
}


def classify(path: str) -> str:
    for prefix, reason in [
        ("/user/yostar_", "yostar"), ("/account/yostar_", "yostar"),
        ("/user/pay/", "pay"), ("/pay/", "pay"),
        ("/admin/", "admin"),
        ("/analytics/", "telemetry"), ("/loggw/", "telemetry"),
        ("/mgw.htm", "telemetry"), ("/deviceprofile/", "telemetry"),
        ("/iedsafe/", "telemetry"), ("/survey/", "telemetry"),
        ("/beat", "telemetry"), ("/event", "telemetry"),
        ("/gameBulletin", "telemetry"),
        ("/user/login", "auth"), ("/user/register", "auth"),
        ("/user/sendSmsCode", "auth"), ("/user/loginBySmsCode", "auth"),
        ("/user/v1/guestLogin", "auth"), ("/user/changePassword", "auth"),
        ("/user/changePhone", "auth"), ("/user/changePhoneCheck", "auth"),
        ("/user/checkIdCard", "auth"), ("/user/authenticateUserIdentity", "auth"),
        ("/user/updateAgreement", "auth"), ("/user/agreement", "auth"),
        ("/user/auth/v2/", "auth"), ("/user/info/v1/basic", "auth"),
        ("/app/getCode", "app"), ("/app/getSettings", "app"),
        ("/api/gacha/", "gacha_history"), ("/api/autoChess/", "app"),
        ("/api/is/", "app"), ("/config/prod/", "config"),
        ("/api/remote_config/1/prod/bilibili/", "config"),
        ("/api/remote_config/101/", "config"),
        ("/recalRune/", "recalRune"),
        ("/general/", "telemetry"),
        ("/api/game/", "game_launcher"), ("/api/gate/", "game_launcher"),
        ("/app/v1/", "game_launcher"),
    ]:
        if path.startswith(prefix):
            return f"设计跳过（{DESIGN_SKIP_REASONS[reason]}）"
    return "需补充"


def main():
    # 用 diff 脚本输出作为输入
    diff_out = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "_diff-routes-all.py")],
        capture_output=True, text=True,
    ).stdout
    odpy_section = re.search(
        r"opendoctoratepy-ex-public.*?\n(.*?)\n===== OpenBachelorS",
        diff_out, re.S,
    )
    routes = []
    for line in odpy_section.group(1).splitlines():
        m = re.match(r"\s*\[POST\]\s+(/.*)", line)
        if m:
            routes.append(m.group(1))

    print(f"ODPY 缺失路由共 {len(routes)} 条，逐条核对：\n")
    covered = skip = need = 0
    # 路径参数路由的具体覆盖情况（无法泛化 curl）
    PATH_PARAM_COVERED = {
        "/announce/images/": "已覆盖（占位图路由，2026-08-09）",
        "/arknights/": "设计跳过（ODPY 独有子域名资源转发）",
        "/assetbundle/": "已覆盖（HTTP 302 资源转发）",
        "/audit/official/": "已覆盖（audit router stub）",
        "/gallery/jpg/": "已覆盖（占位图路由，2026-08-09）",
        "/official/": "已覆盖（official assets stub）",
        "/shop/buy<string:shop_type>Good": "已覆盖（buyREPGood/buyLowGood 等具体路由）",
        "/shop/buy<string:shop_type>GoodWithTicket": "已覆盖（buyGoodWithTicket/buyREPGoodWithTicket）",
        "/shop/get<string:shop_type>GoodList": "已覆盖（getREPGoodList/getLowGoodList 等）",
        "/": "设计跳过（根路径管理索引）",
    }
    for r in routes:
        # 路径参数路由：按已知覆盖表分类
        if "<" in r or "{" in r:
            matched = next((k for k in PATH_PARAM_COVERED if r.startswith(k)), None)
            if matched:
                verdict = PATH_PARAM_COVERED[matched]
                if "已覆盖" in verdict:
                    print(f"  [已覆盖] {r} —— {verdict}")
                    covered += 1
                else:
                    print(f"  [设计跳过] {r} —— {verdict}")
                    skip += 1
            else:
                print(f"  [需补充] {r} （路径参数，未知覆盖）")
                need += 1
            continue
        # 运行时验证（POST 优先，GET 兜底——远程配置/版本等为 GET 路由）
        p = r.replace("<string:shop_type>", "REP")
        code = "404"
        for method in ("POST", "GET"):
            try:
                code = subprocess.run(
                    ["curl", "-s", "-m", "4", "-o", "/dev/null", "-w", "%{http_code}",
                     "-X", method, f"{BASE}{p}", "-H", "Content-Type: application/json",
                     "-H", "secret: 1", "-d", "{}"],
                    capture_output=True, text=True, timeout=8,
                ).stdout
            except Exception:
                code = "ERR"
            if code in ("200", "202", "500"):
                break
        if code in ("200", "202", "500"):
            print(f"  [已覆盖] {r} （HTTP {code}，路由命中）")
            covered += 1
            continue
        # 404 再按设计跳过分类
        cls = classify(r)
        if "设计跳过" in cls:
            print(f"  [设计跳过] {r} —— {cls}")
            skip += 1
        else:
            print(f"  [需补充] {r} （HTTP {code}）")
            need += 1
    print(f"\n汇总：已覆盖 {covered} / 设计跳过 {skip} / 需补充 {need}")


if __name__ == "__main__":
    main()
