#!/bin/sh
# docker-entrypoint.sh — 容器入口
#
# 环境变量：
#   APEX_EMAIL / APEX_PASSWORD   必填
#   CERT_DIR                     证书目录（默认 /certs，需 api.crt/api.key/sub.crt/sub.key）
#   OUT                          输出路径（默认 /output/sub.yaml）
#   INTERVAL                     循环间隔秒数（默认 21600 = 6h）
#   RETRY                        失败重试秒数（默认 300）
#   ONCE=1                       只跑一次就退出（适合 cron / k8s Job）
#   API_BASE / SUB_BASE          覆盖端点
#   MIN_NODES                    最少节点数（默认 20）
set -eu

: "${OUT:=/output/sub.yaml}"
: "${CERT_DIR:=/certs}"
: "${INTERVAL:=21600}"
: "${RETRY:=300}"
: "${ONCE:=0}"
: "${MIN_NODES:=20}"
: "${APEX_CONF:=/tmp/apex-fetch.conf}"

log() { printf '%s [apex] %s\n' "$(date '+%F %T')" "$*"; }

if [ -z "${APEX_EMAIL:-}" ] || [ -z "${APEX_PASSWORD:-}" ]; then
    log "错误：需要 APEX_EMAIL / APEX_PASSWORD"
    exit 2
fi

for f in api.crt api.key sub.crt sub.key; do
    [ -f "$CERT_DIR/$f" ] || { log "错误：缺少证书 $CERT_DIR/$f"; exit 2; }
done

mkdir -p "$(dirname "$OUT")"

# 由环境变量生成配置（apex_fetch.py 读取 KEY=VALUE）
{
    echo "APEX_EMAIL=\"$APEX_EMAIL\""
    echo "APEX_PASSWORD=\"$APEX_PASSWORD\""
    echo "API_BASE=\"${API_BASE:-https://fbaxapi.apiv2.a047.com}\""
    echo "SUB_BASE=\"${SUB_BASE:-https://fbaxsub.web.ak005.com}\""
    echo "CERT_DIR=\"$CERT_DIR\""
    echo "API_CERT=\"$CERT_DIR/api.crt\""
    echo "API_KEY=\"$CERT_DIR/api.key\""
    echo "SUB_CERT=\"$CERT_DIR/sub.crt\""
    echo "SUB_KEY=\"$CERT_DIR/sub.key\""
    echo "MIN_NODES=\"$MIN_NODES\""
} > "$APEX_CONF"
chmod 600 "$APEX_CONF"

run_once() {
    log "开始抓取 -> $OUT"
    if python3 /app/apex_fetch.py --config "$APEX_CONF" --out "$OUT"; then
        n=$(python3 - "$OUT" <<'PY' 2>/dev/null || echo 0
import sys
try:
    import yaml
    print(len((yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}).get("proxies") or []))
except Exception:
    print(0)
PY
)
        log "成功：$n 个节点"
        return 0
    else
        log "失败（$RETRY 秒后重试）"
        return 1
    fi
}

# 清理配置中的口令（进程退出或信号时）
trap 'rm -f "$APEX_CONF"' EXIT INT TERM

if [ "$ONCE" = "1" ]; then
    run_once
    exit $?
fi

log "常驻模式：间隔 ${INTERVAL}s"
while true; do
    run_once || sleep "$RETRY"
    sleep "$INTERVAL"
done
