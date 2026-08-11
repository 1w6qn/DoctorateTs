# -*- coding: utf-8 -*-
"""
从官服热更清单下载并解码全部 excel 数据表（明日方舟）
链路：ark_assets.py 的下载 URL 转换 + Ark-Unpacker-5.x 的 lz4ak/FBO 解码
用法: python scripts/hotupdate-excel.py [--download] [--decode] [--table name]
"""
import sys, os, re, io, json, zipfile, subprocess, importlib, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "reference/Ark-Unpacker-5.x"))

from src.lz4ak.Block import decompress_lz4ak
from UnityPy.enums.BundleFile import CompressionFlags
from UnityPy.helpers import CompressionHelper
CompressionHelper.DECOMPRESSION_MAP[CompressionFlags.LZHAM] = decompress_lz4ak
CompressionHelper.DECOMPRESSION_MAP[CompressionFlags.LZMA] = decompress_lz4ak
import UnityPy
from src.DecodeTextAsset import FBOHandler

HU = "https://ak.hycdn.cn/assetbundle/official"
HUL_FILE = os.path.join(ROOT, "reference/hotupdate/hot_update_list_26-08-07-10-51-39.json")
DL_DIR = os.path.join(ROOT, "reference/hotupdate/downloads")
OUT_DIR = os.path.join(ROOT, "reference/hotupdate/excel_json")
RES_VERSION = "26-08-07-10-51-39_26e0fc"

def trans_name(path):
    """ark_assets.py 的 URL 文件名转换：扩展名→dat、/→_、#→__"""
    return re.sub(r'(?<=\.)((?!\.).)*$', 'dat', path).replace('/', '_').replace('#', '__')

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
    """解包 UnityFS bundle → 去 128 字节 RSA 头 → FlatBuffers 解码"""
    with zipfile.ZipFile(dat) as z:
        inner = z.read(z.namelist()[0])
    env = UnityPy.load(io.BytesIO(inner))
    for o in env.objects:
        if o.type.name == 'TextAsset':
            t = o.read()
            script = t.m_Script.encode('utf-8', 'surrogateescape')
            fbo = script[128:]
            base = re.sub(r'[0-9a-f]{6}$', '', t.m_Name)
            schema = importlib.import_module(f'src.fbs.CN.{base}')
            _patch_schema_init_collision(schema)
            root = getattr(schema, 'ROOT_TYPE', None)
            if root is None:
                return None, f'{base} 无 schema ROOT_TYPE'
            dic = FBOHandler(bytearray(fbo), root).to_json_dict()
            return dic, base
    return None, '无 TextAsset'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--download', action='store_true', help='下载 excel bundle')
    ap.add_argument('--decode', action='store_true', help='解码为 JSON')
    ap.add_argument('--table', default=None, help='仅处理指定表（如 character_table）')
    args = ap.parse_args()

    hul = json.load(open(HUL_FILE, encoding='utf-8'))
    os.makedirs(DL_DIR, exist_ok=True)
    os.makedirs(OUT_DIR, exist_ok=True)
    abInfos = hul['abInfos']

    # 定位 excel bundle：TextAsset 名 = {表名}{6位hash}
    excel_bundles = {}  # base -> dat
    for ab in abInfos:
        if not ab['name'].startswith('anon/'):
            continue
        dat = os.path.join(DL_DIR, trans_name(ab['name']))
        if not os.path.exists(dat):
            continue
        name = get_textasset_name(dat)
        if not name:
            continue
        base = re.sub(r'[0-9a-f]{6}$', '', name)
        if base and base != name:  # 带 hash 后缀的表数据
            excel_bundles[base] = dat

    if args.table:
        excel_bundles = {k: v for k, v in excel_bundles.items() if k == args.table}
    print(f'excel 表: {len(excel_bundles)}')

    if args.download:
        # 下载缺失的 bundle
        need = {k: v for k, v in excel_bundles.items() if not os.path.exists(v) or os.path.getsize(v) < 1000}
        print(f'待下载: {len(need)}')
        for base, dat in need.items():
            ab = next(a for a in abInfos if trans_name(a['name']) == os.path.basename(dat))
            dat2 = download(ab)
            if dat2:
                excel_bundles[base] = dat2
                print(f'  已下载 {base}')
            else:
                print(f'  下载失败 {base}')

    if args.decode:
        for base, dat in sorted(excel_bundles.items()):
            try:
                dic, _ = decode(dat)
                out = os.path.join(OUT_DIR, f'{base}.json')
                json.dump(dic, open(out, 'w', encoding='utf-8'), ensure_ascii=False)
                print(f'  解码 {base}: {os.path.getsize(out)//1024}KB')
            except Exception as e:
                print(f'  解码失败 {base}: {str(e)[:60]}')

if __name__ == '__main__':
    main()

def convert_enums(dec_path, loc_path, out_path, table):
    """枚举转换：解码 FBO(数值) → 本地格式(字符串)
    策略：本地 JSON 数据引导（对已有条目精确）+ FBS/cs 枚举兜底（对新条目）"""
    import importlib
    dec = json.load(open(dec_path, encoding='utf-8'))
    loc = json.load(open(loc_path, encoding='utf-8')) if os.path.exists(loc_path) else None

    def norm_key(k):
        k = k[0].lower()+k[1:] if k and k[0].isupper() else k
        return k[:-1] if k.endswith('_') else k
    def norm(d):
        if isinstance(d, dict): return {norm_key(k): norm(v) for k, v in d.items() if not k.endswith('AsNumpy')}
        if isinstance(d, list): return [norm(x) for x in d]
        return d
    def strip_idx(p): return re.sub(r'\[\d+\]', '', p)

    # FBS 枚举
    enum_maps = {}
    for f in os.listdir(os.path.join(ROOT, 'reference/Ark-Unpacker-5.x/src/fbs/CN')):
        if not f.endswith('.py') or f.startswith('__'): continue
        try: m = importlib.import_module(f'src.fbs.CN.{f[:-3]}')
        except: continue
        for n in dir(m):
            if n.startswith('enum__'):
                cls = getattr(m, n)
                vmap = {getattr(cls, a): a for a in dir(cls) if a.isupper() and isinstance(getattr(cls, a), int)}
                if vmap: enum_maps[f'{f[:-3]}.{n}'] = vmap
    # cs 枚举兜底
    cs_enums = {}
    cs_path = os.path.join(ROOT, 'reference/com.hypergryph.arknights_2.7.61.cs')
    if os.path.exists(cs_path):
        cs = open(cs_path, encoding='utf-8').read()
        for m in re.finditer(r'public enum (Torappu\.[A-Za-z0-9_.]+)\s*:[^\{]*\{([^}]*)\}', cs):
            vals = re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+)', m.group(2))
            cs_enums.setdefault(m.group(1).split('.')[-1], {}).update({int(v): k for k, v in vals})
    all_enums = list(enum_maps.values()) + list(cs_enums.values())

    dec = norm(dec)
    loc = norm(loc) if loc else None
    # 容器解包
    def unwrap(d, l=None):
        if isinstance(d, dict) and len(d) == 1 and l and isinstance(l, dict) and len(l) != 1:
            return next(iter(d.values())), l
        if isinstance(d, dict) and len(d) == 1 and not l:
            return next(iter(d.values())), None
        return d, l
    dec, loc = unwrap(dec, loc)

    # 1. 关联（本地数据引导）
    value_map = {}  # norm_path -> {value: name}
    if loc:
        def walk_pairs(d, l, path):
            if isinstance(d, dict) and isinstance(l, dict):
                for k in d.keys() & l.keys(): walk_pairs(d[k], l[k], f'{path}.{k}')
            elif isinstance(d, list) and isinstance(l, list):
                for i in range(min(len(d), len(l))): walk_pairs(d[i], l[i], f'{path}[{i}]')
            elif isinstance(d, int) and isinstance(l, str) and not isinstance(d, bool):
                value_map.setdefault(strip_idx(path), {})[d] = l
        for k in list(loc.keys())[:2000]:
            walk_pairs(dec.get(k, {}), loc[k], table)

    # 2. 转换（逐条目标对象转换，路径基准为 table 名）
    def convert(d, path=''):
        if isinstance(d, dict): return {k: convert(v, f'{path}.{k}') for k, v in d.items()}
        if isinstance(d, list): return [convert(x, f'{path}[{i}]') for i, x in enumerate(d)]
        if isinstance(d, int) and not isinstance(d, bool):
            ep = strip_idx(path)
            vm = value_map.get(ep, {})
            if d in vm: return vm[d]  # 本地引导（精确）
            for e in all_enums:  # 枚举兜底
                if e.get(d) is not None: return e[d]
        return d
    if isinstance(dec, dict):
        return {k: convert(v, table) for k, v in dec.items()}
    return convert(dec, table)
