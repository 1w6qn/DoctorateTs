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
