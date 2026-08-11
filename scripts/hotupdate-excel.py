# -*- coding: utf-8 -*-
"""
从官服热更清单下载并解码全部 excel 数据表（明日方舟）
链路：ark_assets.py 的下载 URL 转换 + scripts/vendor 的 lz4ak/FBO/FBS 解码（已集成，无外部仓库依赖）
用法:
  python scripts/hotupdate-excel.py --download   # 下载 excel bundle（缺则下）
  python scripts/hotupdate-excel.py --decode     # FBO 解码 → reference/hotupdate/excel_json/（原始结果）
  python scripts/hotupdate-excel.py --convert    # 原始结果 → 服务端格式（camelCase + 枚举字符串）→ data/excel/
  python scripts/hotupdate-excel.py --table X    # 仅处理指定表
"""
import sys, os, re, io, json, zipfile, subprocess, importlib, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts/vendor"))

from lz4ak.Block import decompress_lz4ak
from UnityPy.enums.BundleFile import CompressionFlags
from UnityPy.helpers import CompressionHelper
CompressionHelper.DECOMPRESSION_MAP[CompressionFlags.LZHAM] = decompress_lz4ak
CompressionHelper.DECOMPRESSION_MAP[CompressionFlags.LZMA] = decompress_lz4ak
import UnityPy
from fbo import FBOHandler

HU = "https://ak.hycdn.cn/assetbundle/official"
CONF_VERSION = "https://ak-conf.hypergryph.com/config/prod/official/Windows/version"
HUL_FILE = os.path.join(ROOT, "reference/hotupdate/hot_update_list_26-08-07-10-51-39.json")
DL_DIR = os.path.join(ROOT, "reference/hotupdate/downloads")
OUT_DIR = os.path.join(ROOT, "reference/hotupdate/excel_json")
DATA_EXCEL_DIR = os.path.join(ROOT, "data/excel")
RES_VERSION = "26-08-07-10-51-39_26e0fc"

# 服务端加载的全部 excel 表（app/excel/excel.ts + REQUIRED_DATA_FILES）。
# 发现阶段据此从 anon bundle 中识别表数据（无论 TextAsset 名是否带 6 位 hash 后缀）。
# 无 FBS schema 的表（range_table / player_avatar_table / roguelike_table / sandbox_table /
# uniequip_data / handbook_table / tech_buff_table 等）解码会失败并跳过，保留当前快照。
TABLE_WHITELIST = {
    "activity_table", "arkvent_table", "audio_data", "battle_equip_table",
    "building_data", "building_local_data", "campaign_table", "chapter_table",
    "char_master_table", "char_meta_table", "char_patch_table", "character_table",
    "charm_table", "charword_table", "checkin_table", "climb_tower_table",
    "clue_data", "cooperate_battle_table", "crisis_table", "crisis_v2_table",
    "display_meta_table", "enemy_database", "enemy_handbook_table",
    "ep_breakbuff_table", "extra_battlelog_table", "favor_table", "gacha_table",
    "gamedata_const", "handbook_info_table", "handbook_table", "handbook_team_table",
    "hotupdate_meta_table", "init_text", "item_table", "legion_mode_buff_table",
    "level_script_table", "main_text", "medal_table", "meta_ui_table",
    "mission_table", "open_server_table", "player_avatar_table", "range_table",
    "replicate_table", "retro_table", "roguelike_table", "roguelike_topic_table",
    "sandbox_perm_table", "sandbox_table", "shop_client_table", "skill_table",
    "skin_table", "special_operator_table", "stage_table", "story_review_meta_table",
    "story_review_table", "story_table", "tech_buff_table", "tip_table",
    "token_table", "uniequip_data", "uniequip_table", "zone_table",
}


def trans_name(path):
    """ark_assets.py 的 URL 文件名转换：扩展名→dat、/→_、#→__"""
    return re.sub(r'(?<=\.)((?!\.).)*$', 'dat', path).replace('/', '_').replace('#', '__')


def fetch_hot_update_list():
    """拉取官服最新热更清单：Windows resVersion + hot_update_list.json。
    返回 (hul 路径, resVersion)，失败返回 (None, None) 沿用本地快照。"""
    import urllib.request
    try:
        with urllib.request.urlopen(CONF_VERSION, timeout=30) as resp:
            ver = json.loads(resp.read().decode('utf-8'))
        res_version = ver['resVersion']  # 如 26-08-07-10-51-39
        version_id = f"{res_version}_{ver.get('hash', '') or ver.get('funcVer', '')}"
        url = f"{HU}/Windows/assets/{res_version}/hot_update_list.json"
        with urllib.request.urlopen(url, timeout=60) as resp:
            hul_path = os.path.join(ROOT, 'reference/hotupdate', f'hot_update_list_{res_version}.json')
            os.makedirs(os.path.dirname(hul_path), exist_ok=True)
            with open(hul_path, 'wb') as f:
                f.write(resp.read())
        return hul_path, version_id
    except Exception as e:
        print(f'  [warn] 拉取热更清单失败（沿用本地快照）: {str(e)[:80]}')
        return None, None


def download(ab, version=RES_VERSION):
    fn = trans_name(ab['name'])
    dat = os.path.join(DL_DIR, fn)
    if os.path.exists(dat) and os.path.getsize(dat) > 1000:
        return dat
    url = f"{HU}/Windows/assets/{version}/{fn}"
    subprocess.run(['curl', '-s', '-m', '120', '-H', 'User-Agent: BestHTTP', '-o', dat, url], check=False)
    return dat if os.path.exists(dat) and os.path.getsize(dat) > 1000 else None


def get_textasset_name(dat):
    try:
        with zipfile.ZipFile(dat) as z:
            inner = z.read(z.namelist()[0])
        env = UnityPy.load(io.BytesIO(inner))
        for o in env.objects:
            if o.type.name == 'TextAsset':
                return o.read().m_Name
    except Exception:
        pass
    return None


def _patch_schema_init_collision(schema):
    """flatbuffers 表类的 Init 若被同名字段访问器遮蔽（签名 (self, j)），恢复构造方法。
    Arknights schema 存在字段名 init 与 flatbuffers Init 构造方法冲突的生成 bug。"""
    import inspect
    import flatbuffers
    patched = 0
    for n in dir(schema):
        cls = getattr(schema, n)
        if isinstance(cls, type) and 'Init' in getattr(cls, '__dict__', {}):
            try:
                sig = inspect.signature(cls.Init)
                if len(sig.parameters) == 2:
                    cls._field_init = cls.Init
                    cls.Init = lambda self, buf, pos: setattr(self, '_tab', flatbuffers.table.Table(buf, pos))
                    patched += 1
            except (ValueError, TypeError):
                pass
    if patched:
        print(f'  [patch] {schema.__name__} 修复 {patched} 个 Init 遮蔽')
    return patched


def decode(dat):
    """解包 UnityFS bundle → 去 128 字节 RSA 头 → FlatBuffers 解码（原始 FBO 结果）"""
    with zipfile.ZipFile(dat) as z:
        inner = z.read(z.namelist()[0])
    env = UnityPy.load(io.BytesIO(inner))
    for o in env.objects:
        if o.type.name == 'TextAsset':
            t = o.read()
            script = t.m_Script.encode('utf-8', 'surrogateescape')
            base = re.sub(r'[0-9a-f]{6}$', '', t.m_Name)
            fbo = script[128:]
            # 部分表（range/avatar/roguelike/uniequip/handbook 等）是 AES-CBC 加密的 JSON，非 FBO
            if len(fbo) >= 4:
                import struct
                root_off = struct.unpack('<I', fbo[:4])[0]
                if not (0 < root_off < 4096):
                    dic, _ = decode_aes_json(script)
                    if dic is not None:
                        return dic, base
                    return None, f'{base} 非 FBO 且 AES 解密失败'
            schema = importlib.import_module(f'fbs.CN.{base}')
            _patch_schema_init_collision(schema)
            root = getattr(schema, 'ROOT_TYPE', None)
            if root is None:
                return None, f'{base} 无 schema ROOT_TYPE'
            dic = FBOHandler(bytearray(fbo), root).to_json_dict()
            return dic, base
    return None, '无 TextAsset'


def decode_aes_json(script):
    """AES-CBC 解密（官服 Mask）→ JSON 字典。
    仅部分表使用（range_table / player_avatar_table / roguelike_table / uniequip_data /
    handbook_table / tech_buff_table），解码结果即服务端格式（键名/枚举已对齐）。"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        mask = b"UITpAi82pHAWwnzqHRMCwPonJLIB3WCl"  # ArkAESLibrary.MASK_V2
        data = script[128:]
        key = mask[:16]
        iv = bytearray(d ^ m for d, m in zip(data[:16], mask[16:]))
        plain = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data[16:]), AES.block_size)
        try:
            return json.loads(plain), 'json'
        except Exception:
            import bson
            return bson.loads(plain), 'bson'
    except Exception as e:
        print(f'  [warn] AES 解密失败: {str(e)[:60]}')
        return None, None


def discover_bundles(hul):
    """从热更清单定位 excel 表 bundle（白名单 + TextAsset 名识别，兼容带/不带 hash 后缀）"""
    excel_bundles = {}  # base -> dat
    for ab in hul['abInfos']:
        if not ab['name'].startswith('anon/'):
            continue
        dat = os.path.join(DL_DIR, trans_name(ab['name']))
        if not os.path.exists(dat):
            continue
        name = get_textasset_name(dat)
        if not name:
            continue
        base = re.sub(r'[0-9a-f]{6}$', '', name)
        if base in TABLE_WHITELIST:
            excel_bundles[base] = dat
    return excel_bundles


# ---------- 枚举特殊支持 ----------

def _load_enum_maps():
    """FBS 枚举 + cs 枚举 → 全部 value→name 映射"""
    enum_maps = []
    for f in os.listdir(os.path.join(ROOT, 'scripts/vendor/fbs/CN')):
        if not f.endswith('.py') or f.startswith('__'):
            continue
        try:
            m = importlib.import_module(f'fbs.CN.{f[:-3]}')
        except Exception:
            continue
        for n in dir(m):
            if n.startswith('enum__'):
                cls = getattr(m, n)
                vmap = {getattr(cls, a): a for a in dir(cls) if a.isupper() and isinstance(getattr(cls, a), int)}
                if vmap:
                    enum_maps.append(vmap)
    cs_enums = []
    cs_path = os.path.join(ROOT, 'reference/com.hypergryph.arknights_2.7.61.cs')
    if os.path.exists(cs_path):
        cs = open(cs_path, encoding='utf-8').read()
        for m in re.finditer(r'public enum (Torappu\.[A-Za-z0-9_.]+)\s*:[^\{]*\{([^}]*)\}', cs):
            vals = re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+)', m.group(2))
            vmap = {int(v): k for k, v in vals}
            if vmap:
                cs_enums.append(vmap)
    return enum_maps + cs_enums


def convert_enums(dec_path, loc_path, out_path, table):
    """原始 FBO(数值枚举) → 服务端格式（字符串枚举）
    策略：本地 JSON 数据引导（对已有条目精确，路径 casefold 一致）+
          FBS/cs 枚举兜底（仅当值在全部枚举中唯一映射，避免误转普通数值字段）。
    键转换：PascalCase 首字母小写 + 丢弃 AsNumpy 字段 + 单键根解包。"""
    dec = json.load(open(dec_path, encoding='utf-8'))
    loc = json.load(open(loc_path, encoding='utf-8')) if loc_path and os.path.exists(loc_path) else None

    def norm_key(k):
        k = k[0].lower() + k[1:] if k and k[0].isupper() else k
        return k[:-1] if k.endswith('_') and k[:-1] in {
            'and', 'as', 'class', 'def', 'del', 'from', 'global', 'if', 'import',
            'in', 'is', 'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise',
            'return', 'try', 'while', 'with', 'yield', 'None', 'True', 'False',
        } else k

    def norm(d):
        if isinstance(d, dict):
            return {norm_key(k): norm(v) for k, v in d.items() if not k.endswith('AsNumpy')}
        if isinstance(d, list):
            return [norm(x) for x in d]
        return d

    def strip_idx(p):
        return re.sub(r'\[\d+\]', '', p)

    dec, loc = norm(dec), norm(loc) if loc else None

    def unwrap(d, l=None):
        if isinstance(d, dict) and len(d) == 1 and l and isinstance(l, dict) and len(l) != 1:
            return next(iter(d.values())), l
        if isinstance(d, dict) and len(d) == 1 and not l:
            return next(iter(d.values())), None
        return d, l
    dec, loc = unwrap(dec, loc)

    # 1. 本地数据引导：结构对齐处 int(dec) ↔ str(loc) 学习 value→name；
    #    同时学习 FBS 键名 → 本地(C#) 键名重命名（itemId→itemID、mDefined→m_defined 等）
    #    以及 null → 容器（FBO 空数组/空表编码为 null，服务端期望 [] / {}）
    value_map = {}  # 路径(casefold 键, 去掉索引) -> {value: name}
    rename_map = {}  # dec 键(casefold) -> 本地键
    empty_map = {}  # 路径 -> 容器类型 ('list' / 'dict')
    if loc:
        def walk_pairs(d, l, path):
            if isinstance(d, dict) and isinstance(l, dict):
                lm = {k.lower(): k for k in l}
                dm = {k.lower(): k for k in d}
                done = set()
                for lk in sorted(lm):
                    if lk in dm:
                        dk, lkv = dm[lk], lm[lk]
                        if dk != lkv:
                            rename_map[dk.lower()] = lkv  # FBS 键名 → 本地键名
                        walk_pairs(d[dk], l[lkv], f'{path}.{dk.lower()}')
                        done.add(lk)
                # 下划线剥离回退（ACT_FOOTBALL ↔ ActFootball），仅当本地键含下划线
                for lk in sorted(lm):
                    if lk in done or '_' not in lm[lk]:
                        continue
                    for dk in dm:
                        if dk.replace('_', '') == lk.replace('_', ''):
                            if dk != lm[lk]:
                                rename_map[dk.lower()] = lm[lk]
                            walk_pairs(d[dm[dk]], l[lm[lk]], f'{path}.{dk.lower()}')
                            break
            elif isinstance(d, list) and isinstance(l, list):
                for i in range(min(len(d), len(l))):
                    walk_pairs(d[i], l[i], f'{path}[{i}]')
            elif d is None and (isinstance(l, list) or isinstance(l, dict)):
                # FBO 空容器为 null → 记录应输出 [] / {}
                empty_map[strip_idx(path)] = 'list' if isinstance(l, list) else 'dict'
            elif isinstance(d, int) and isinstance(l, str) and not isinstance(d, bool):
                value_map.setdefault(strip_idx(path), {})[d] = l
        for k in list(loc.keys())[:2000]:
            walk_pairs(dec.get(k, {}), loc[k], table)

    # 通用键重命名规则（本地数据未覆盖处的 Undefinable / 常见后缀）
    GENERAL_RENAMES = {
        'mdefined': 'm_defined', 'mvalue': 'm_value',
    }
    rename_map.update(GENERAL_RENAMES)

    # 2. 唯一值兜底：值在全部枚举中仅映射一个名字 → 判定为枚举字段
    unique_name = {}  # value -> name
    for vmap in _load_enum_maps():
        for v, name in vmap.items():
            if v in unique_name and unique_name[v] != name:
                unique_name[v] = None  # 多义 → 弃
            elif v not in unique_name:
                unique_name[v] = name

    # 3. 转换（键重命名 + 枚举字符串 + null 空容器）
    def convert(d, path=''):
        if isinstance(d, dict):
            out = {}
            for k, v in d.items():
                nk = rename_map.get(k.lower(), k)
                out[nk] = convert(v, f'{path}.{k.lower()}')
            return out
        if isinstance(d, list):
            return [convert(x, f'{path}[{i}]') for i, x in enumerate(d)]
        if d is None:
            et = empty_map.get(strip_idx(path))
            if et == 'list':
                return []
            if et == 'dict':
                return {}
            return d
        if isinstance(d, int) and not isinstance(d, bool):
            vm = value_map.get(strip_idx(path), {})
            if d in vm:
                return vm[d]  # 本地引导（精确）
            if d in unique_name and unique_name[d] is not None:
                return unique_name[d]  # 唯一枚举兜底
        return d

    result = {k: convert(v, table) for k, v in dec.items()} if isinstance(dec, dict) else convert(dec, table)
    json.dump(result, open(out_path, 'w', encoding='utf-8'), ensure_ascii=False)
    return result


def main():
    global HUL_FILE, RES_VERSION
    ap = argparse.ArgumentParser()
    ap.add_argument('--download', action='store_true', help='下载 excel bundle（缺则下，自动拉取最新热更清单）')
    ap.add_argument('--decode', action='store_true', help='FBO 解码 → 原始 JSON')
    ap.add_argument('--convert', action='store_true', help='原始 JSON → 服务端格式（camelCase + 枚举）→ data/excel/')
    ap.add_argument('--table', default=None, help='仅处理指定表（如 character_table）')
    ap.add_argument('--offline', action='store_true', help='不拉取热更清单（用本地快照）')
    args = ap.parse_args()

    if args.download and not args.offline:
        hul_new, ver_new = fetch_hot_update_list()
        if hul_new:
            HUL_FILE = hul_new
            RES_VERSION = ver_new
            print(f'热更清单: {os.path.basename(HUL_FILE)} (resVersion={RES_VERSION})')

    hul = json.load(open(HUL_FILE, encoding='utf-8'))
    os.makedirs(DL_DIR, exist_ok=True)
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(DATA_EXCEL_DIR, exist_ok=True)

    excel_bundles = discover_bundles(hul)
    if args.table:
        excel_bundles = {k: v for k, v in excel_bundles.items() if k == args.table}
    print(f'excel 表: {len(excel_bundles)}')

    if args.download:
        need = {k: v for k, v in excel_bundles.items() if not os.path.exists(v) or os.path.getsize(v) < 1000}
        print(f'待下载: {len(need)}')
        for base, dat in need.items():
            ab = next(a for a in hul['abInfos'] if trans_name(a['name']) == os.path.basename(dat))
            dat2 = download(ab)
            if dat2:
                excel_bundles[base] = dat2
                print(f'  已下载 {base}')
            else:
                print(f'  下载失败 {base}')

    if args.decode:
        ok = fail = 0
        for base, dat in sorted(excel_bundles.items()):
            out = os.path.join(OUT_DIR, f'{base}.json')
            if os.path.exists(out) and os.path.getsize(out) > 100:
                continue  # 已解码
            try:
                dic, msg = decode(dat)
                if dic is None:
                    print(f'  跳过 {base}: {msg}')
                    continue
                json.dump(dic, open(out, 'w', encoding='utf-8'), ensure_ascii=False)
                ok += 1
                print(f'  解码 {base}: {os.path.getsize(out)//1024}KB')
            except Exception as e:
                fail += 1
                print(f'  解码失败 {base}: {str(e)[:60]}')
        print(f'解码完成: {ok} ok, {fail} fail')

    if args.convert:
        ok = fail = 0
        for f in sorted(os.listdir(OUT_DIR)):
            if not f.endswith('.json'):
                continue
            name = f[:-5]
            if args.table and name != args.table:
                continue
            out = os.path.join(DATA_EXCEL_DIR, f)
            locp = out  # 本地既有文件（枚举学习种子）；首次运行即当前快照
            try:
                convert_enums(os.path.join(OUT_DIR, f), locp if os.path.exists(locp) else None, out, name)
                ok += 1
                print(f'  转换 {name}: {os.path.getsize(out)//1024}KB')
            except Exception as e:
                fail += 1
                print(f'  转换失败 {name}: {str(e)[:60]}')
        print(f'转换完成: {ok} ok, {fail} fail')


if __name__ == '__main__':
    main()
