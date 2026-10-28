#!/usr/bin/env bash
# install-apex-fetch.sh — 安装「飞鸟订阅纯协议抓取」服务
#
# 用法：
#   ./install-apex-fetch.sh <证书目录>            # 目录内含 api.crt/api.key/sub.crt/sub.key
#   APEX_EMAIL=a@b.c APEX_PASSWORD=xxx ./install-apex-fetch.sh <证书目录>
#
# 证书来源：本机已安装的飞鸟客户端目录里 profile5_{api,subscription}_client.{crt,key}.pem
#   （Windows: %LOCALAPPDATA%\...\certs\，macOS: ~/Library/.../certs/）
#   重命名成 api.crt/api.key/sub.crt/sub.key 即可。
#
# 安装内容：
#   /opt/apex/apex_fetch.py        纯协议抓取器
#   /opt/apex/apex-fetch.sh        服务入口
#   /etc/apex-fetch/certs/         客户端证书（600）
#   /etc/apex-fetch/config         账号与参数（600）
#   /etc/systemd/system/apex-fetch.{service,timer}
set -euo pipefail

SRC_DIR=$(cd "$(dirname "$0")" && pwd)
chmod +x "$SRC_DIR"/*.sh 2>/dev/null || true
CERT_SRC=${1:-}
[ -n "$CERT_SRC" ] && [ -d "$CERT_SRC" ] || { echo "用法: $0 <证书目录>"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "需要 root"; exit 2; }

for f in api.crt api.key sub.crt sub.key; do
    [ -f "$CERT_SRC/$f" ] || { echo "证书目录缺少 $f"; exit 2; }
done

echo "== 1. 安装脚本 =="
install -d -m 0755 /opt/apex
install -m 0755 "$SRC_DIR/apex_fetch.py" /opt/apex/apex_fetch.py
install -m 0755 "$SRC_DIR/apex-fetch.sh" /opt/apex/apex-fetch.sh
echo "   /opt/apex/apex_fetch.py, /opt/apex/apex-fetch.sh"

echo "== 2. 安装证书 =="
install -d -m 0700 /etc/apex-fetch /etc/apex-fetch/certs
for f in api.crt api.key sub.crt sub.key; do
    install -m 0600 "$CERT_SRC/$f" "/etc/apex-fetch/certs/$f"
done
echo "   /etc/apex-fetch/certs/（4 个文件，600）"

echo "== 3. 写配置 =="
if [ ! -f /etc/apex-fetch/config ]; then
    EMAIL=${APEX_EMAIL:-}
    PASS=${APEX_PASSWORD:-}
    [ -n "$EMAIL" ] || read -r -p "   账号邮箱: " EMAIL
    [ -n "$PASS" ] || { read -r -s -p "   密码: " PASS; echo; }
    cat > /etc/apex-fetch/config <<EOF
# Apex 纯协议抓取配置 —— 600，禁止外泄
APEX_EMAIL="$EMAIL"
APEX_PASSWORD="$PASS"

# 端点（一般无需改）
API_BASE=https://fbaxapi.apiv2.a047.com
SUB_BASE=https://fbaxsub.web.ak005.com

# 证书目录
CERT_DIR=/etc/apex-fetch/certs

# 抓取器与输出
FETCHER=/opt/apex/apex_fetch.py
OUT=/var/lib/apex-fetch/sub.yaml
LOGDIR=/var/log/apex-fetch

MIN_NODES=20

# 线路：v2=APXS 主线路（默认）/ v1=遗留明文线路 / both=合并
SOURCE=v2

# 发布后钩子，例如：
# HOOK_AFTER_PUBLISH="systemctl reload mihomo"
HOOK_AFTER_PUBLISH=""
EOF
    chmod 600 /etc/apex-fetch/config
    echo "   /etc/apex-fetch/config 已创建（600）"
else
    chmod 600 /etc/apex-fetch/config
    echo "   /etc/apex-fetch/config 已存在，保留"
fi

echo "== 4. 安装 systemd 单元 =="
install -m 0644 "$SRC_DIR/apex-fetch.service" /etc/systemd/system/apex-fetch.service
install -m 0644 "$SRC_DIR/apex-fetch.timer" /etc/systemd/system/apex-fetch.timer
systemctl daemon-reload
systemctl enable --now apex-fetch.timer >/dev/null
echo "   apex-fetch.timer: $(systemctl is-active apex-fetch.timer)"

echo "== 5. 连通性自检 =="
/opt/apex/apex-fetch.sh test || true

echo
echo "安装完成："
echo "  立即抓一次： systemctl start apex-fetch.service"
echo "  看结果：     /opt/apex/apex-fetch.sh status"
echo "  看日志：     journalctl -u apex-fetch -n 50 --no-pager"
