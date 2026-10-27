#!/usr/bin/env bash
# run.sh — 在 netns 内跑官方 OpenWrt 客户端，并挂 gdb 抓 OpenAPXS 入参与明文
#
# 用法：
#   APEX_BIN=/opt/apex/mihomo \
#   APEX_EMAIL='you@example.com' APEX_PASSWORD='***' \
#   bash tools/gdb/run.sh
#
# 前置：
#   - APEX_BIN 指向官方 OpenWrt 版 mihomo（-apex-openwrt 支持）
#   - geodata 已放在 /usr/share/apex-mihomo/geodata/
#   - 断点地址需与二进制版本匹配（见 hook.gdb 顶部注释）
set -u
NS=apex
VH=veth-ax0
VN=veth-ax1
HIP=10.210.0.1
NIP=10.210.0.2
NET=10.210.0.0/24
RUN=/tmp/apex-mihomo
DIR=/tmp/apexgdb
BIN=${APEX_BIN:-/opt/apex/mihomo}
HOOK=${HOOK:-$(dirname "$0")/hook.gdb}
EMAIL=${APEX_EMAIL:?需要设置 APEX_EMAIL}
PASSWORD=${APEX_PASSWORD:?需要设置 APEX_PASSWORD}

mkdir -p "$DIR"
ext=$(ip route show default | awk '{print $5; exit}')
[ -x "$BIN" ] || { echo "找不到客户端 $BIN"; exit 2; }
command -v gdb >/dev/null || { echo "需要 gdb"; exit 2; }

cleanup() {
    local rc=$?
    ip netns exec $NS pkill -9 -x mihomo 2>/dev/null
    pkill -9 -f "$DIR/[g]db_marker" 2>/dev/null
    ip netns del $NS 2>/dev/null
    ip link del $VH 2>/dev/null
    for i in 1 2 3; do iptables -D FORWARD -s $NET -j ACCEPT 2>/dev/null || break; done
    for i in 1 2 3; do iptables -D FORWARD -d $NET -j ACCEPT 2>/dev/null || break; done
    iptables -t nat -D POSTROUTING -s $NET -o "$ext" -j MASQUERADE 2>/dev/null
    mountpoint -q $RUN && umount $RUN 2>/dev/null
    echo "[cleanup] done (rc=$rc)"
    exit $rc
}
trap cleanup EXIT INT TERM

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

echo "== tmpfs（客户端强制要求）=="
mountpoint -q $RUN || mount -t tmpfs -o size=256M,mode=700 tmpfs $RUN
chmod 700 $RUN; rm -rf $RUN/* 2>/dev/null

echo "== 启动客户端 =="
ip netns exec $NS "$BIN" -apex-openwrt -d $RUN > $DIR/client.log 2>&1 &
sleep 6
PID=$(pgrep -f "$BIN -apex-openwrt" | head -1)
S=$RUN/control.sock
[ -n "$PID" ] || { echo "客户端未启动，见 $DIR/client.log"; cat $DIR/client.log; exit 1; }
[ -S "$S" ] || { echo "控制口未出现"; cat $DIR/client.log; exit 1; }
echo "pid=$PID"

echo "== 挂 gdb（$HOOK）=="
gdb -q -p "$PID" -x "$HOOK" > $DIR/gdb.log 2>&1 &
GDBPID=$!
sleep 3

echo "== 登录 + start =="
ctl() { local b=${2:-}; [ -n "$b" ] || b='{}'; curl -s --unix-socket "$S" -X POST "http://localhost/$1" \
        -H 'Content-Type: application/json' --data-binary "$b"; }
ctl settings '{"transparent":false}' >/dev/null
ctl login "$(python3 - "$EMAIL" "$PASSWORD" <<'PY'
import json,sys
print(json.dumps({"email":sys.argv[1],"password":sys.argv[2]}))
PY
)" >/dev/null
sleep 5
ctl start '{}' >/dev/null
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    sleep 2
    echo "  [$i] hits=$(grep -c '^### ' $DIR/gdb.log 2>/dev/null || echo 0)"
done

kill $GDBPID 2>/dev/null
echo "== 输出 =="
ls -l /tmp/apex_body.bin /tmp/apex_plain.bin 2>/dev/null
echo "  明文: head -1 /tmp/apex_plain.bin"
