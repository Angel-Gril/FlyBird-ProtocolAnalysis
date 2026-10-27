#!/usr/bin/env bash
# apex-fetch.sh — 飞鸟订阅纯协议抓取（无需官方客户端 / 无需 netns / 不用关 swap）
#
#   apex-fetch.sh run      抓取一次（systemd 调用）
#   apex-fetch.sh status   查看结果
#   apex-fetch.sh test     只验证账号/证书/解密，不落盘
#
# 配置：/etc/apex-fetch/config（600）
set -uo pipefail

CONF=${APEX_CONF:-/etc/apex-fetch/config}
[ -r "$CONF" ] || { echo "缺少配置文件 $CONF" >&2; exit 2; }
# shellcheck disable=SC1090
. "$CONF"

PYTHON=${PYTHON:-python3}
FETCHER=${FETCHER:-/opt/apex/apex_fetch.py}
OUT=${OUT:-/var/lib/apex-fetch/sub.yaml}
LOGDIR=${LOGDIR:-/var/log/apex-fetch}
HOOK_AFTER_PUBLISH=${HOOK_AFTER_PUBLISH:-}
MIN_NODES=${MIN_NODES:-20}
PRIVATE_CACHE_DIR=${PRIVATE_CACHE_DIR:-/var/lib/private-subscription/cache}
PUBLISH_PRIVATE_SUBSCRIPTION=${PUBLISH_PRIVATE_SUBSCRIPTION:-auto}

count_nodes() {
    python3 - "$1" <<'PY' 2>/dev/null || echo 0
import sys
try:
    import yaml
except ImportError:
    raise SystemExit(1)
d = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
print(len((d or {}).get("proxies") or []))
PY
}

publish_private_subscription() {
    [ "${PUBLISH_PRIVATE_SUBSCRIPTION:-auto}" = "1" ] || {
        [ "$PUBLISH_PRIVATE_SUBSCRIPTION" = "auto" ] && [ -d "$PRIVATE_CACHE_DIR" ] || return 0
    }
    [ -d "$PRIVATE_CACHE_DIR" ] || { log "Private Subscription 缓存目录不存在：$PRIVATE_CACHE_DIR"; return 0; }
    local target="$PRIVATE_CACHE_DIR/flybird.yaml" previous="$PRIVATE_CACHE_DIR/flybird.previous.yaml"
    local metadata="$PRIVATE_CACHE_DIR/flybird.json" tmp_yaml tmp_meta sha count updated changed
    tmp_yaml="$target.apex.tmp"; tmp_meta="$metadata.apex.tmp"
    sha=$(sha256sum "$OUT" | awk '{print $1}')
    count=$(count_nodes "$OUT")
    updated=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ); changed=true
    if [ -f "$target" ] && cmp -s "$OUT" "$target"; then
        changed=false
    elif [ -f "$target" ]; then
        install -o subsvc -g subsvc -m 0640 "$target" "$previous" 2>/dev/null || cp -f "$target" "$previous"
    fi
    install -o subsvc -g subsvc -m 0640 "$OUT" "$tmp_yaml" 2>/dev/null || install -m 0640 "$OUT" "$tmp_yaml"
    cat > "$tmp_meta" <<EOF
{
  "schemaVersion": 1,
  "provider": "flybird",
  "updatedAt": "$updated",
  "changed": $changed,
  "sha256": "$sha",
  "proxyCount": $count,
  "validatedHostCount": 0,
  "recoveredServerCount": 0,
  "delegatedHostCount": 0,
  "lastError": null,
  "source": "apex-pure-protocol"
}
EOF
    chown subsvc:subsvc "$tmp_meta" 2>/dev/null || true; chmod 0600 "$tmp_meta"
    mv -f "$tmp_yaml" "$target"; mv -f "$tmp_meta" "$metadata"
    log "已同步 Private Subscription：$target（$count 节点，changed=$changed）"
}

mkdir -p "$LOGDIR" "$(dirname "$OUT")"
TS=$(date +%Y%m%d-%H%M%S)
LOG=$LOGDIR/$TS.log
ln -sf "$LOG" "$LOGDIR/latest.log"

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG" >&2; }

do_run() {
    [ -x "$PYTHON" ] || command -v "$PYTHON" >/dev/null || { log "缺少 python3"; exit 2; }
    [ -f "$FETCHER" ] || { log "缺少 $FETCHER"; exit 2; }

    exec 9>"$LOGDIR/.lock"
    if ! flock -n 9; then
        log "已有实例在运行，退出"
        exit 0
    fi

    log "开始抓取"
    if "$PYTHON" "$FETCHER" --config "$CONF" --out "$OUT" 2>&1 | tee -a "$LOG"; then
        n=$(count_nodes "$OUT")
        log "完成：$OUT（$n 节点）"
        publish_private_subscription
        rc=0
        if [ -n "$HOOK_AFTER_PUBLISH" ]; then
            log "执行发布后钩子"
            sh -c "$HOOK_AFTER_PUBLISH" >>"$LOG" 2>&1 || log "钩子失败（不影响结果）"
        fi
    else
        log "抓取失败（详见上方日志）"
        rc=1
    fi
    exit $rc
}

do_test() {
    exec 9>"$LOGDIR/.lock"
    flock -n 9 || { echo "已有实例在运行"; exit 0; }
    "$PYTHON" "$FETCHER" --config "$CONF" --test 2>&1 | tee -a "$LOG"
}

do_status() {
    echo "配置文件: $CONF"
    echo "输出文件: $OUT"
    if [ -f "$OUT" ]; then
        echo "节点数  : $(count_nodes "$OUT")"
        echo "更新时间: $(date -r "$OUT" '+%F %T')"
        echo "大小    : $(stat -c%s "$OUT") B"
    else
        echo "节点数  : (无输出)"
    fi
    echo "最近日志: $(readlink -f "$LOGDIR/latest.log" 2>/dev/null)"
    [ -f "$LOGDIR/latest.log" ] && tail -6 "$LOGDIR/latest.log"
    echo "定时器  : $(systemctl is-active apex-fetch.timer 2>/dev/null)"
}

case "${1:-}" in
    run)    do_run ;;
    status) do_status ;;
    test)   do_test ;;
    *) echo "用法: $0 {run|status|test}" >&2; exit 2 ;;
esac
