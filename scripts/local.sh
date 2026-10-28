#!/usr/bin/env bash
# local.sh — 本地一键：导入证书 → 生成配置 → 拉取 v1/v2/both → 汇总
#
# 用法：
#   ./scripts/local.sh init --certs <客户端证书目录>    # 导入证书 + 写配置
#   ./scripts/local.sh run                              # 拉 v1 + v2 + both
#   ./scripts/local.sh run --source v1                  # 只拉一条
#   ./scripts/local.sh all --certs <目录>               # init + run
#   ./scripts/local.sh check                            # 只检查环境
#
# 凭据：优先读环境变量 APEX_EMAIL / APEX_PASSWORD，否则交互输入（不回显）。
# 目录：默认 ~/.apex-local/{certs,out,config}（在仓库之外，不会误提交）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${APEX_LOCAL_DIR:-$HOME/.apex-local}"
CERTS="$BASE/certs"
OUT="$BASE/out"
CONF="$BASE/config"

API_BASE="${API_BASE:-https://fbaxapi.apiv2.a047.com}"
SUB_BASE="${SUB_BASE:-https://fbaxsub.web.ak005.com}"
MIN_NODES="${MIN_NODES:-20}"

c_ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
c_warn() { printf '\033[33m%s\033[0m\n' "$*"; }
c_err()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }
die()    { c_err "错误：$*"; exit 1; }

usage() { sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

# ---------------------------------------------------------------- check
cmd_check() {
    command -v python3 >/dev/null || die "找不到 python3"
    python3 "$ROOT/scripts/_check_env.py" || die "环境检查未通过"
    c_ok "环境检查通过"
}

# ---------------------------------------------------------------- init
normalize_certs() { # normalize_certs <src_dir>
    local src=$1 n=0 purpose dst ext f
    # 1) 已经是 api.crt/api.key/sub.crt/sub.key
    for f in api.crt api.key sub.crt sub.key; do
        [ -f "$src/$f" ] || continue
        [ -f "$CERTS/$f" ] || { cp "$src/$f" "$CERTS/$f"; n=$((n + 1)); }
    done
    # 2) 客户端原始命名 profile5_<purpose>_client.<ext>.pem
    for purpose in api subscription; do
        [ "$purpose" = api ] && dst=api || dst=sub
        for ext in crt key; do
            f="$(ls "$src"/profile5_"$purpose"_client*."$ext".pem 2>/dev/null | head -1 || true)"
            [ -n "$f" ] || continue
            [ -f "$CERTS/$dst.$ext" ] || { cp "$f" "$CERTS/$dst.$ext"; n=$((n + 1)); }
        done
    done
    chmod 700 "$CERTS" 2>/dev/null || true
    chmod 600 "$CERTS"/*.key 2>/dev/null || true
    c_ok "导入 $n 个证书文件 → $CERTS"
}

cmd_init() {
    local src="${1:-}"
    mkdir -p "$CERTS" "$OUT"
    [ -z "$src" ] || { [ -d "$src" ] || die "证书目录不存在：$src"; normalize_certs "$src"; }

    [ -f "$CERTS/api.crt" ] || c_warn "缺 $CERTS/api.crt（v1 需要 api 证书）"
    [ -f "$CERTS/sub.crt" ] || c_warn "缺 $CERTS/sub.crt（v2 需要 subscription 证书）"

    local email="${APEX_EMAIL:-}" pass="${APEX_PASSWORD:-}"
    [ -n "$email" ] || { printf '账号邮箱: '; read -r email; }
    [ -n "$pass" ] || { printf '密码（不回显）: '; read -rs pass; echo; }
    [ -n "$email" ] && [ -n "$pass" ] || die "账号或密码为空"

    umask 077
    cat > "$CONF" <<EOF
API_BASE=$API_BASE
SUB_BASE=$SUB_BASE
APEX_EMAIL=$email
APEX_PASSWORD=$pass
CERT_DIR=$CERTS
MIN_NODES=$MIN_NODES
SOURCE=v2
EOF
    chmod 600 "$CONF"
    c_ok "配置已写入 $CONF（600）"
}

# ---------------------------------------------------------------- run
run_one() { # run_one <v1|v2|both>
    local src=$1
    mkdir -p "$OUT"
    printf '\n── %s ─────────────────────────────\n' "$src"
    python3 "$ROOT/src/apex_fetch.py" --config "$CONF" --source "$src" --out "$OUT/$src.yaml" \
        || c_warn "$src 失败（继续）"
}

cmd_run() {
    local source="${1:-all}"
    [ -f "$CONF" ] || die "没有配置文件，先跑：$0 init --certs <证书目录>"
    [ -f "$ROOT/src/apex_fetch.py" ] || die "找不到 src/apex_fetch.py"
    case "$source" in
        all)        for s in v2 v1 both; do run_one "$s"; done ;;
        v1|v2|both) run_one "$source" ;;
        *)          die "--source 只能是 v1 / v2 / both / all" ;;
    esac
    printf '\n── 汇总 ────────────────────────────\n'
    python3 "$ROOT/scripts/_summary.py" "$OUT"
}

# ---------------------------------------------------------------- main
cmd="${1:-}"; shift || true
src_arg=""; source_arg="all"
while [ $# -gt 0 ]; do
    case "$1" in
        --certs)  src_arg="${2:-}"; shift 2 ;;
        --source) source_arg="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        *) die "未知参数：$1" ;;
    esac
done

case "$cmd" in
    init)  cmd_check; cmd_init "$src_arg" ;;
    run)   cmd_run "$source_arg" ;;
    all)   cmd_check; cmd_init "$src_arg"; cmd_run all ;;
    check) cmd_check ;;
    ""|-h|--help) usage ;;
    *) die "未知命令：$cmd（可用：init / run / all / check）" ;;
esac
