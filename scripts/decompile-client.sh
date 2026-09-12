#!/usr/bin/env bash
# =============================================================================
# Arknights 官服客户端反编译工作流
#
# 从本机安装的官服客户端静态反编译 C# 源码（全离线，无需运行游戏，不受 ACE 反作弊影响）：
#   1. Cpp2IL   静态分析 GameAssembly.dll + global-metadata.dat（metadata v29，Unity 2021.3）
#               -> 91 个 dummy DLL（含内嵌 IL 方法体）+ types/*/*_metadata.txt 逐类分析
#   2. ilspycmd 将 13 个游戏程序集反编译为完整 C# 项目
#               -> reference/arknights-<版本>-csharp/
#
# 用法：
#   pnpm run decompile                                     # 使用默认游戏路径
#   bash scripts/decompile-client.sh "E:\Games\...\Arknights Game"   # 指定路径
#   GAME_PATH="E:\Games\..." bash scripts/decompile-client.sh        # 或用环境变量
#   环境变量：CPP2IL_VERSION / ILSPY_VERSION 可换版本，DECOMPILE_WORKDIR 可换工作目录
#
# 依赖：bash(Git Bash), python, curl, unzip, dotnet(.NET 8+ runtime)
# 工具缓存在 tmp/decompile/tools/；重复运行会跳过已完成步骤（幂等）。
# =============================================================================

set -euo pipefail

# ---------- 配置 ----------
_raw_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 强制 Windows 绝对路径，避免后台 shell 下 POSIX 路径被 MSYS 二次转换为
# "D:/d/develop/..." 导致后续 python/工具找不到文件（曾导致签名生成步失败）
if command -v cygpath >/dev/null 2>&1; then
  REPO_ROOT="$(cygpath -w "$_raw_root")"
else
  REPO_ROOT="$_raw_root"
fi
GAME_PATH="${1:-${GAME_PATH:-E:\Games\Hypergryph Launcher\games\Arknights Game}}"
WORKDIR="${DECOMPILE_WORKDIR:-$REPO_ROOT/tmp/decompile}"
TOOLS="$WORKDIR/tools"
CPP2IL_VERSION="${CPP2IL_VERSION:-2022.0.7}"
ILSPY_VERSION="${ILSPY_VERSION:-11.0.0.9375}"
CPP2IL_OUT="$WORKDIR/cpp2il_out"
REFERENCE_ROOT="$REPO_ROOT/reference"

# 游戏程序集清单（ilspycmd 反编译对象；Hypergryph.NativeBridge 无类型，Cpp2IL 跳过）
GAME_ASSEMBLIES=(
  Assembly-CSharp.dll Assembly-CSharp-firstpass.dll
  Torappu.Common.dll Torappu.CETest.dll Torappu.UICommonEditor.dll Torappu.Sofdec.dll
  Hypergryph.EventLogSDK.dll Hypergryph.GameUpdate.dll Hypergryph.Log.dll
  Hypergryph.OneChannel.dll Hypergryph.Webview.dll
  torappu.CrashSight.Standalone.dll enum2int.dll
)

log()  { printf '\033[1;36m[decompile]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[decompile] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# POSIX 路径 -> Windows 路径（已是 Windows 风格则原样保留）
to_win() {
  case "$1" in
    [A-Za-z]:*|\\\\*) printf '%s' "$1" ;;
    *) command -v cygpath >/dev/null 2>&1 && cygpath -w "$1" || printf '%s' "$1" ;;
  esac
}

# ---------- 0. 前置校验 ----------
GAME_DATA="$GAME_PATH/Arknights_Data"
test -f "$GAME_PATH/GameAssembly.dll" || fail "未找到 $GAME_PATH/GameAssembly.dll，请检查游戏路径"
test -f "$GAME_DATA/il2cpp_data/Metadata/global-metadata.dat" || fail "未找到 IL2CPP 元数据 global-metadata.dat"
command -v python  >/dev/null || fail "需要 python"
command -v curl    >/dev/null || fail "需要 curl"
command -v unzip   >/dev/null || fail "需要 unzip"
command -v dotnet  >/dev/null || fail "需要 dotnet（.NET 8+ runtime）"
mkdir -p "$WORKDIR" "$TOOLS"

# ---------- 1. 识别游戏版本 / 元数据版本 / Unity 版本 ----------
GAME_VERSION="$(GAME_DATA="$GAME_DATA" python - <<'EOF'
import os, re
d = open(os.environ['GAME_DATA'] + '/globalgamemanagers', 'rb').read()
vers = {m.decode() for m in re.findall(rb'\d+\.\d+\.\d+', d) if not m.startswith(b'20')}
def k(s): return tuple(int(x) for x in s.split('.'))
print(sorted(vers, key=k)[-1] if vers else 'unknown')
EOF
)"
META_VERSION="$(GAME_DATA="$GAME_DATA" python - <<'EOF'
import os, struct
with open(os.environ['GAME_DATA'] + '/il2cpp_data/Metadata/global-metadata.dat', 'rb') as f:
    magic, ver = struct.unpack('<II', f.read(8))
assert magic == 0xFAB11BAF, 'global-metadata.dat 魔数不正确'
print(ver)
EOF
)"
UNITY_VERSION="$(GAME_DATA="$GAME_DATA" python - <<'EOF'
import os, re
d = open(os.environ['GAME_DATA'] + '/globalgamemanagers', 'rb').read()
m = re.search(rb'\d{4}\.\d+\.\d+[a-z0-9]*', d)
print(m.group().decode() if m else 'unknown')
EOF
)"
log "游戏版本 $GAME_VERSION | Unity $UNITY_VERSION | IL2CPP metadata v$META_VERSION"
if [ "$META_VERSION" -lt 28 ]; then
  fail "metadata v$META_VERSION 属旧版（经典 Il2CppDumper 即可处理）；本工作流面向 metadata v28+"
fi

# ---------- 2. 工具准备（缓存于 $TOOLS，缺失才下载） ----------
CPP2IL_BIN="$TOOLS/Cpp2IL.exe"
if [ ! -f "$CPP2IL_BIN" ]; then
  log "下载 Cpp2IL $CPP2IL_VERSION ..."
  curl -sL --max-time 600 -o "$CPP2IL_BIN" \
    "https://github.com/SamboyCoding/Cpp2IL/releases/download/$CPP2IL_VERSION/Cpp2IL-$CPP2IL_VERSION-Windows.exe" \
    || { rm -f "$CPP2IL_BIN"; fail "Cpp2IL 下载失败"; }
  [ "$(wc -c < "$CPP2IL_BIN")" -gt 10000000 ] || { rm -f "$CPP2IL_BIN"; fail "Cpp2IL 下载不完整"; }
else
  log "复用已缓存 Cpp2IL"
fi

ILSPYCMD_DLL="$(find "$TOOLS/ilspycmd" -name ilspycmd.dll -path '*/any/*' 2>/dev/null | head -1)"
if [ -z "$ILSPYCMD_DLL" ]; then
  log "下载 ilspycmd $ILSPY_VERSION ..."
  curl -sL --max-time 600 -o "$TOOLS/ilspycmd.nupkg" \
    "https://www.nuget.org/api/v2/package/ilspycmd/$ILSPY_VERSION" \
    || { rm -f "$TOOLS/ilspycmd.nupkg"; fail "ilspycmd 下载失败"; }
  mkdir -p "$TOOLS/ilspycmd" && unzip -o -q "$TOOLS/ilspycmd.nupkg" -d "$TOOLS/ilspycmd"
  ILSPYCMD_DLL="$(find "$TOOLS/ilspycmd" -name ilspycmd.dll -path '*/any/*' | head -1)"
  [ -n "$ILSPYCMD_DLL" ] || fail "ilspycmd 解包失败"
else
  log "复用已缓存 ilspycmd"
fi

# ---------- 3. Cpp2IL 静态分析（约 20-30 min，幂等：完成标记在日志） ----------
CPP2IL_LOG="$WORKDIR/cpp2il_run.log"
GAME_PATH_WIN="$(to_win "$GAME_PATH")"
CPP2IL_OUT_WIN="$(to_win "$CPP2IL_OUT")"
if [ -f "$CPP2IL_OUT/Assembly-CSharp.dll" ] && grep -q "Done." "$CPP2IL_LOG" 2>/dev/null; then
  log "Cpp2IL 分析已完成，跳过（重新分析请删除 $CPP2IL_OUT 与 $CPP2IL_LOG）"
else
  log "Cpp2IL 分析开始（Assembly-CSharp 约 3.6 万类型，约 20-30 min）..."
  "$CPP2IL_BIN" \
    --game-path "$GAME_PATH_WIN" \
    --experimental-enable-il-to-assembly-please \
    --throw-safety-out-the-window \
    --output-root "$CPP2IL_OUT_WIN" > "$CPP2IL_LOG" 2>&1 \
    || { tail -30 "$CPP2IL_LOG" >&2; fail "Cpp2IL 分析失败"; }
fi

# ---------- 4. ilspycmd 反编译为 C# 项目（幂等：目标目录已含 sln 则跳过） ----------
REF_DIR="$REFERENCE_ROOT/arknights-$GAME_VERSION-csharp"
if [ -f "$REF_DIR/csharp-src.sln" ]; then
  log "C# 项目已存在于 $REF_DIR，跳过反编译"
else
  log "ilspycmd 反编译为 C# 项目 -> $REF_DIR"
  mkdir -p "$REF_DIR"
  args=(-p -o "$REF_DIR")
  for dll in "${GAME_ASSEMBLIES[@]}"; do
    f="$CPP2IL_OUT/$dll"
    if [ -f "$f" ]; then args+=("$f"); else log "跳过缺失程序集: $dll"; fi
  done
  [ "${#args[@]}" -gt 3 ] || fail "Cpp2IL 输出中没有可用程序集"
  set +e
  dotnet "$ILSPYCMD_DLL" "${args[@]}" > "$WORKDIR/ilspy_project.log" 2>&1
  rc=$?
  set -e
  # 0=成功，70=个别方法体反编译失败（占位替换，属正常）
  [ "$rc" -eq 0 ] || [ "$rc" -eq 70 ] || { tail -20 "$WORKDIR/ilspy_project.log" >&2; fail "ilspycmd 反编译失败(exit=$rc)"; }
fi

# ---------- 5. 生成签名文件（供 generate-types.ts 消费，形如 com.hypergryph.arknights_<版本>.cs） ----------
SIG_FILE="$REFERENCE_ROOT/com.hypergryph.arknights_$GAME_VERSION.cs"
log "生成签名文件 -> $SIG_FILE"
python "$REPO_ROOT/scripts/dump-cs-signature.py" --in "$CPP2IL_OUT" --out "$SIG_FILE" \
  > "$WORKDIR/signature_gen.log" 2>&1 || { tail -20 "$WORKDIR/signature_gen.log" >&2; fail "签名文件生成失败"; }

# ---------- 5b. FBO schema 漂移检查（关键安全阀） ----------
# 客户端更新后 C# 字段序可能变化，而 .fbs schema 是按字段序推导 vtable slot 的
# （slot = 4 + 2×字段序）。字段一旦插入中部，其后所有字段 slot 全体位移 → 解码读到
# 错误字段（症状：向量长度变成天文数字、JSON.stringify 触发 V8 "Invalid string length"、OOM）。
# 此处以 --check 与新版签名逐字段比对，检出漂移即告警（不自动改写，避免误伤）。
log "FBO schema 漂移检查（cs2schema --check）..."
set +e
(cd "$REPO_ROOT" && pnpm exec tsx scripts/cs2schema.ts --check) > "$WORKDIR/schema_check.log" 2>&1
schema_rc=$?
set -e
if [ "$schema_rc" -eq 0 ]; then
  log "  schema 与新版签名一致 ✓"
else
  log "  ⚠ 检测到 schema 漂移！请先执行: pnpm run schema:check -- --diff 20 查看，"
  log "    确认无误后用 pnpm run schema:write 重写 scripts/vendor/fbs-schemas/*.json"
  log "    （详细日志: $WORKDIR/schema_check.log）"
  tail -20 "$WORKDIR/schema_check.log" 2>/dev/null >&2 || true
fi

# ---------- 6. 生成/刷新 README（仅当缺失） ----------
if [ ! -f "$REF_DIR/README.md" ]; then
  cat > "$REF_DIR/README.md" <<EOF
# Arknights $GAME_VERSION 客户端反编译源码（C# 项目）

由 \`scripts/decompile-client.sh\`（Cpp2IL + ilspycmd）从本机官服客户端静态反编译。
- Unity $UNITY_VERSION，IL2CPP metadata v$META_VERSION
- 含方法体（IL2CPP x86-64 重建，可读伪代码）；字段带偏移、方法带 Token/RVA/VA
- 类型/字段/接口/枚举完整还原；少量方法体为 ILSpy 占位（体内有错误说明）
- 项目不可编译，仅作协议/逻辑研究参考

复现：\`pnpm run decompile\`（详见 \`scripts/decompile-client.sh\` 头部注释与 \`reference/com.hypergryph.arknights_$GAME_VERSION.cs\` 对照）
EOF
fi

# ---------- 7. 验证 & 汇总 ----------
total="$(find "$REF_DIR" -name '*.cs' | wc -l)"
failed="$(grep -rl "ILSpy could not decompile" --include='*.cs' "$REF_DIR" 2>/dev/null | wc -l)"
rate="$(grep -oE 'Overall analysis success rate: [0-9]+% \([0-9]+\) of [0-9]+ methods' "$CPP2IL_LOG" | head -1)"
sig_cls="$(grep -cE '^public (abstract |static |sealed )?(class|struct) Torappu\.' "$SIG_FILE" 2>/dev/null || echo 0)"
sig_enum="$(grep -cE '^public enum Torappu\.' "$SIG_FILE" 2>/dev/null || echo 0)"
log "====== 完成 ======"
log "C# 源码:  $REF_DIR"
log "文件数:   $total 个 .cs（含失败方法体 $failed 个，占 $(python -c "print(f'{$failed/$total*100:.1f}' if $total else 'n/a')")%）"
[ -n "$rate" ] && log "分析方法: $rate"
log "签名文件: $SIG_FILE（Torappu 类/结构体 $sig_cls 个，枚举 $sig_enum 个；随后可 pnpm run generate:types 再生类型）"
log "分析文件: $CPP2IL_OUT/types/**/*_metadata.txt（$(find "$CPP2IL_OUT/types" -name '*_metadata.txt' 2>/dev/null | wc -l) 个）"
log "工具缓存: $TOOLS"
