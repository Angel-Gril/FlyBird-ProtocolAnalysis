#!/usr/bin/env bash
# run.sh — 在独立 netns 内运行官方 OpenWrt 客户端并提取订阅明文（路线 B）
#
# 用法：
#   APEX_BIN=/opt/apex/mihomo \
#   APEX_EMAIL='you@example.com' APEX_PASSWORD='***' \
#   bash tools/netns/run.sh [输出文件]
#
# 说明：
#   - 该二进制会自行编排 nftables/ip rule（transparent 模式），必须 netns 隔离；
#   - 运行目录必须是 tmpfs，且系统不能有 swap（客户端会自检）；
#   - 退出时自动还原：netns / veth / iptables / tmpfs / swap。
set -u
NS=apex
VH=veth-ax0
VN=veth-ax1
HIP=10.210.0.1
NIP=10.210.0.2
NET=10.210.0.0/24
RUN=/tmp/apex-mihomo
BIN=${APEX_BIN:-/opt/apex/mihomo}
EMAIL=${APEX_EMAIL:?需要设置 APEX_EMAIL}
PASSWORD=${APEX_PASSWORD:?需要设置 APEX_PASSWORD}
OUT=${1:-/tmp/apex_sub.yaml}
EXTRACTOR=${EXTRACTOR:-$(dirname "$0")/../../src/extract_nodes.py}

SWAP_WAS_ON=0
ext=$(ip route show default | awk '{print $5; exit}')

cleanup() {
    local rc=$?
    ip netns exec $NS pkill -9 -x mihomo 2>/dev/null
    ip netns del $NS 2>/dev/null
    ip link del $VH 2>/dev/null
    for i in 1 2 3; do iptables -D FORWARD -s $NET -j ACCEPT 2>/dev/null || break; done
    for i in 1 2 3; do iptables -D FORWARD -d $NET -j ACCEPT 2>/dev/null || break; done
    iptables -t nat -D POSTROUTING -s $NET -o "$ext" -j MASQUERADE 2>/dev/null
    mountpoint -q $RUN && umount $RUN 2>/dev/null
    [ "$SWAP_WAS_ON" = 1 ] && swapon /swapfile 2>/dev/null
    echo "[cleanup] done (rc=$rc)"
    exit $rc
}
trap cleanup EXIT INT TERM

[ -x "$BIN" ] || { echo "找不到客户端 $BIN"; exit 2; }

echo "== swap =="
if swapon --show | grep -q .; then
    SWAP_WAS_ON=1
    swapoff -a || { echo "swapoff 失败"; exit 1; }
    echo "  已关闭"
fi

echo "== netns =="
ip netns del $NS 2>/dev/null
ip link del $VH 2>/dev/null
ip netns add $NS
ip netns exec $NS ip link set lo up
ip link add $VH type veth peer name $VN
ip link set $VN netns $NS
ip addr replace $HIP/24 dev $VH; ip link set $VH up
ip netns exec $NS ip addr replace $NIP/24 dev $VN
ip netns exec $NS ip link set $VN up
ip netns exec $NS ip route replace default via $HIP
sysctl -qw net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s $NET -o $ext -j MASQUERADE
iptables -I FORWARD 1 -s $NET -j ACCEPT
iptables -I FORWARD 1 -d $NET -j ACCEPT
mkdir -p /etc/netns/$NS
printf 'nameserver 223.5.5.5\nnameserver 1.1.1.1\n' > /etc/netns/$NS/resolv.conf

echo "== tmpfs =="
mountpoint -q $RUN || mount -t tmpfs -o size=256M,mode=700 tmpfs $RUN
chmod 700 $RUN; rm -rf $RUN/* 2>/dev/null

echo "== 启动客户端 =="
ip netns exec $NS "$BIN" -apex-openwrt -d $RUN > /tmp/apex_client.log 2>&1 &
sleep 6
PID=$(pgrep -f "$BIN -apex-openwrt" | head -1)
S=$RUN/control.sock
[ -S "$S" ] || { echo "控制口未出现"; cat /tmp/apex_client.log; exit 1; }
echo "  pid=$PID"

ctl() { local b=${2:-}; [ -n "$b" ] || b='{}'; curl -s --unix-socket "$S" -X POST "http://localhost/$1" \
        -H 'Content-Type: application/json' --data-binary "$b"; }

echo "== 登录 =="
ctl settings '{"transparent":false,"allow_lan":true}' >/dev/null
ctl login "$(python3 - "$EMAIL" "$PASSWORD" <<'PY'
import json,sys
print(json.dumps({"email":sys.argv[1],"password":sys.argv[2]}))
PY
)" > /tmp/apex_login.json
sleep 5

echo "== 提取（同时触发 start）=="
python3 "$EXTRACTOR" --pid "$PID" --seconds 25 --out "$OUT" &
EX=$!
sleep 1
ctl start '{}' >/dev/null
wait $EX
echo "== 结果 =="
grep -c '^  - flow:' "$OUT" 2>/dev/null || true
head -12 "$OUT" 2>/dev/null
