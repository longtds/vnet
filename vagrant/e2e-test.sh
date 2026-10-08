#!/usr/bin/env bash
# vnet VM 集群端到端测试
#
# 拓扑: node1 --tcp--> node2(hub) <--quic-- node3
# 验证:
#   1. 直连:     node1 <-> node2 互 ping
#   2. 多跳中继: node1 <-> node3 互 ping (经 node2 中继)
#   3. QUIC 隧道: node3 与 node2 通过 quic:// 建连
#   4. 管理 API: 各节点 vnet-cli status 有 peer 与路由
set -uo pipefail
cd "$(dirname "$0")"

NET=demo
SECRET=e2e-secret
HUB=192.168.56.12   # node2
PASS=0
FAIL=0

say()  { echo -e "\033[1;36m== $* ==\033[0m"; }
ok()   { echo -e "\033[1;32m  PASS: $*\033[0m"; PASS=$((PASS+1)); }
bad()  { echo -e "\033[1;31m  FAIL: $*\033[0m"; FAIL=$((FAIL+1)); }

ssh_vm() { vagrant ssh "$1" -c "$2" 2>/dev/null; }

stop_all() {
  for n in node1 node2 node3; do
    ssh_vm $n "sudo pkill -x vnet || true"
  done
}

# pkill 后等待进程真正退出 (vnet 以 root 运行, pgrep 需 sudo)
wait_exit() {
  ssh_vm "$1" "for i in \$(seq 1 20); do sudo pgrep -x vnet >/dev/null || break; sleep 0.2; done"
}

start_vm() { # name vip peer_arg...
  local name=$1 vip=$2; shift 2
  ssh_vm $name "sudo bash -c 'nohup /usr/local/bin/vnet \
    -n $NET -s $SECRET -i $vip \
    -l tcp://0.0.0.0:11010 -l udp://0.0.0.0:11010 \
    -l kcp://0.0.0.0:11011 -l quic://0.0.0.0:11012 \
    -l ws://0.0.0.0:11013 \
    $* >/tmp/vnet.log 2>&1 &'"
}

say "0. 清理旧进程并刷新二进制"
stop_all
for n in node1 node2 node3; do
  ssh_vm $n "sudo cp -f /opt/vnet/vnet /opt/vnet/vnet-cli /usr/local/bin/"
done
sleep 2

say "1. 启动 hub (node2)"
start_vm node2 10.144.144.2
sleep 2

say "2. 启动 node1 (tcp:// 直连 hub)"
start_vm node1 10.144.144.1 -p tcp://$HUB:11010

say "3. 启动 node3 (quic:// 直连 hub)"
start_vm node3 10.144.144.3 -p quic://$HUB:11012
sleep 4

say "4. 对等连接状态"
for n in node1 node2 node3; do
  echo "--- $n ---"
  ssh_vm $n "vnet-cli status 2>&1 || tail -20 /tmp/vnet.log"
done
node2_peers=$(ssh_vm node2 "vnet-cli peer 2>/dev/null | grep -c 10.144.144 || true")
[ "$node2_peers" -ge 2 ] && ok "node2 已连接 node1+node3" || bad "node2 peers 不足 (=$node2_peers)"

say "5. 直连 ping (node1 <-> node2, tcp 隧道)"
ssh_vm node1 "ping -c3 -W2 10.144.144.2" >/dev/null && ok "node1 -> node2" || bad "node1 -> node2"
ssh_vm node2 "ping -c3 -W2 10.144.144.1" >/dev/null && ok "node2 -> node1" || bad "node2 -> node1"

say "6. 多跳中继 ping (node1 <-> node3, 经 node2)"
ssh_vm node1 "ping -c3 -W2 10.144.144.3" >/dev/null && ok "node1 -> node3" || bad "node1 -> node3"
ssh_vm node3 "ping -c3 -W2 10.144.144.1" >/dev/null && ok "node3 -> node1" || bad "node3 -> node1"

say "7. kcp/ws 隧道 (node1 换协议重连 hub)"
ssh_vm node1 "sudo pkill -x vnet || true"
wait_exit node1
start_vm node1 10.144.144.1 -p kcp://$HUB:11011
sleep 3
ssh_vm node1 "ping -c3 -W2 10.144.144.2" >/dev/null && ok "node1 -> node2 (kcp)" || {
  bad "node1 -> node2 (kcp)"
  echo "--- node1 诊断 ---"; ssh_vm node1 "sudo pgrep -ax vnet; ls -la /tmp/vnet.log; tail -15 /tmp/vnet.log"
  echo "--- node2 诊断 ---"; ssh_vm node2 "sudo pgrep -ax vnet; tail -6 /tmp/vnet.log"
}

ssh_vm node1 "sudo pkill -x vnet || true"
wait_exit node1
start_vm node1 10.144.144.1 -p ws://$HUB:11013
sleep 3
ssh_vm node1 "ping -c3 -W2 10.144.144.2" >/dev/null && ok "node1 -> node2 (ws)" || bad "node1 -> node2 (ws)"

say "结果: PASS=$PASS FAIL=$FAIL"
stop_all
[ $FAIL -eq 0 ]
