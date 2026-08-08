"""提取 OpenBachelorS 与 DoctorateTs 的路由清单并对比（感知挂载前缀）"""
import re
import os
import json

OBS = r"D:\develop\DoctorateTs\reference\OpenBachelorS-master\src\openbachelors"
DTS = r"D:\develop\DoctorateTs\app"

OBS_ROUTER = re.compile(r'@router\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']')
TS_ROUTER = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*outer|app|r)\.(get|post|put|delete|patch|use)\(\s*["\']([^"\']+)["\']')

# 根应用挂载点（index.ts）
ROOT_MOUNTS = [
    ("/config/prod", "config/prod.ts"),
    ("/api/remote_config", "config/remote-config.ts"),
    ("/api/gate", "config/gate.ts"),
    ("/api/game", "config/launcher.ts"),
    ("/assetbundle", "asset.ts"),
]
# game/app.ts 挂载点
GAME_MOUNTS = [
    ("/businessCard", "game/router/businessCard.ts"),
    ("/account", "game/router/account.ts"),
    ("/charBuild", "game/router/charBuild.ts"),
    ("/building", "game/router/building.ts"),
    ("/quest", "game/router/quest.ts"),
    ("/user", "game/router/user.ts"),
    ("/activity", "game/router/activity.ts"),
    ("/storyreview", "game/router/storyreview.ts"),
    ("/mission", "game/router/mission.ts"),
    ("/shop", "game/router/shop.ts"),
    ("/rlv2", "game/router/rlv2.ts"),
    ("/gacha", "game/router/gacha.ts"),
    ("/mail", "game/router/mail.ts"),
    ("/social", "game/router/social.ts"),
    ("/retro", "game/router/retro.ts"),
    ("/aprilFool", "game/router/aprilFool.ts"),
    ("/crisis", "game/router/crisis.ts"),
    ("/deepsea", "game/router/deepsea.ts"),
    ("/tower", "game/router/tower.ts"),
    ("/charm", "game/router/charm.ts"),
    ("/charRotation", "game/router/charRotation.ts"),
    ("/depot", "game/router/depot.ts"),
    ("/sandbox", "game/router/sandbox.ts"),
    ("/templateShop", "game/router/templateShop.ts"),
    ("/mailCollection", "game/router/mailCollection.ts"),
    ("/multiplayer", "game/router/multiplayer.ts"),
    ("/roguelike", "game/router/roguelike.ts"),
    ("/campaignV2", "game/router/campaignV2.ts"),
    ("/vecbreak", "game/router/vecbreak.ts"),
    ("/interlock", "game/router/interlock.ts"),
    ("/autochess", "game/router/autochess.ts"),
    ("/pay", "game/router/pay.ts"),
    # 挂根路径的
    ("/", "game/router/home.ts"),
    ("/", "game/router/user.ts"),  # rootRouter（gallery/cg/medal/mainlineClue/server_time 等）
    ("/", "auth/auth.ts"),
]
# auth/auth.ts 与 home.ts、user.ts 根路由里的绝对路径会被直接识别


def read(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


def obs_routes():
    routes = {}
    bp_dir = os.path.join(OBS, "bp")
    for fn in sorted(os.listdir(bp_dir)):
        if not fn.endswith(".py"):
            continue
        src = read(os.path.join(bp_dir, fn))
        found = [(m.group(1).upper(), m.group(2)) for m in OBS_ROUTER.finditer(src)]
        if found:
            routes[fn] = found
    return routes


def router_relative_routes(fn):
    """读取一个 router 文件的相对路径路由（app.get/router.get 等，排除 .use 挂载）"""
    p = os.path.join(DTS, fn)
    if not os.path.exists(p):
        return []
    src = read(p)
    out = []
    for m in TS_ROUTER.finditer(src):
        if m.group(2) == "use":
            continue
        path = m.group(3)
        if path.startswith("/"):
            out.append((m.group(2).upper(), path))
    return out


def dts_routes():
    routes = {}  # full_path -> set(methods)
    for prefix, fn in ROOT_MOUNTS + GAME_MOUNTS:
        for method, path in router_relative_routes(fn):
            full = prefix.rstrip("/") + path if prefix != "/" else path
            routes.setdefault(full, set()).add(method)
            routes.setdefault(full, set()).add(method)
    return routes


def main():
    obs = obs_routes()
    obs_all = {}
    for fn, rs in sorted(obs.items()):
        for method, path in rs:
            obs_all.setdefault(path, set()).add(method)

    dts = dts_routes()

    # 归一化路径参数 {x} -> :x
    def norm(p):
        return re.sub(r"\{([^}]+)\}", r":\1", p)

    missing = []
    for path, methods in sorted(obs_all.items()):
        np = norm(path)
        dts_methods = dts.get(np) or dts.get(path) or set()
        absent = methods - dts_methods
        if absent:
            missing.append((path, sorted(absent), sorted(dts_methods)))

    print("===== OpenBachelorS 有但 DoctorateTs 缺失的（按模块）=====")
    for path, absent, dts_m in missing:
        note = f"  [DTS 有 {dts_m} 但缺 {absent}]" if dts_m else ""
        print(f"  {'/'.join(absent):10s} {path}{note}")

    print()
    print(f"共 {len(missing)} 条 OBS 路由未完全覆盖")


if __name__ == "__main__":
    main()
