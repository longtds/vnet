#!/usr/bin/env bash
# vnet 性能测试: iperf3 对比物理网络基线与各隧道协议吞吐
#
# 拓扑: node1 --proto--> node2(hub) <--quic-- node3
# 用例:
#   0. 基线:   node1 -> node2 物理网络 (192.168.56.12)
#   1. 直连:   node1 -> node2 经 vnet (10.144.144.2), 协议 tcp/kcp/quic/ws
#   2. 多跳:   node1 -> node3 (10.144.144.3) 经 node2 中继
# 每组 5 秒, 单向; 直连 tcp 额外跑反向 (-R)
set -uo pipefail
cd "$(dirname "$0")"

NET=demo
SECRET=e2e-secret
HUB=192.168.56.12
T=5   # 每组测试秒数

ssh_vm() { vagrant ssh "$1" -c "$2" 2>/dev/null; }

start_vm() { # name vip peer_arg...
  local name=$1 vip=$2; shift 2
  ssh_vm $name "sudo bash -c 'nohup /usr/local/bin/vnet \
    -n $NET -s $SECRET -i $vip \
    -l tcp://0.0.0.0:11010 -l udp://0.0.0.0:11010 \
    -l kcp://0.0.0.0:11011 -l quic://0.0.0.0:11012 \
    -l ws://0.0.0.0:11013 \
    $* >/tmp/vnet.log 2>&1 &'"
}

iperf_run() { # client_vm target_ip [extra args...]
  local vm=$1 dst=$2; shift 2
  ssh_vm $vm "iperf3 -c $dst -t $T -f m $* 2>/dev/null" | \
    awk '/receiver/ {for(i=NF;i>0;i--) if($i ~ /^[0-9]+([.][0-9]+)?$/) {printf "%.0f", $i; exit}}'
}

# 清理
for n in node1 node2 node3; do ssh_vm $n "sudo pkill -x vnet || true; sudo pkill -x iperf3 || true"; done
sleep 1

echo "== 启动集群 (hub=node2, node3=quic) =="
start_vm node2 10.144.144.2
sleep 1
start_vm node1 10.144.144.1 -p tcp://$HUB:11010
start_vm node3 10.144.144.3 -p quic://$HUB:11012
sleep 4

# hub 上常驻 iperf3 server (物理 + 虚拟网段共用一个进程即可, iperf3 单连接串行)
ssh_vm node2 "nohup iperf3 -s >/dev/null 2>&1 &"
ssh_vm node3 "nohup iperf3 -s >/dev/null 2>&1 &"
sleep 1

printf "%-38s %10s\n" "用例" "Mbps"
printf "%-38s %10s\n" "------------------------------------" "-----"

r=$(iperf_run node1 $HUB);           printf "%-38s %10s\n" "0. 基线: 物理网络 node1->node2" "$r"
r=$(iperf_run node1 10.144.144.2);   printf "%-38s %10s\n" "1a. vnet 直连 tcp (node1->node2)" "$r"
r=$(iperf_run node1 10.144.144.2 -R);printf "%-38s %10s\n" "1a'. vnet 直连 tcp 反向 (-R)" "$r"

echo "== node1 切换 kcp:// =="
ssh_vm node1 "sudo pkill -x vnet"; sleep 1
start_vm node1 10.144.144.1 -p kcp://$HUB:11011
sleep 3
r=$(iperf_run node1 10.144.144.2);   printf "%-38s %10s\n" "1b. vnet 直连 kcp" "$r"

echo "== node1 切换 quic:// =="
ssh_vm node1 "sudo pkill -x vnet"; sleep 1
start_vm node1 10.144.144.1 -p quic://$HUB:11012
sleep 3
r=$(iperf_run node1 10.144.144.2);   printf "%-38s %10s\n" "1c. vnet 直连 quic" "$r"

echo "== node1 切换 ws:// =="
ssh_vm node1 "sudo pkill -x vnet"; sleep 1
start_vm node1 10.144.144.1 -p ws://$HUB:11013
sleep 3
r=$(iperf_run node1 10.144.144.2);   printf "%-38s %10s\n" "1d. vnet 直连 ws" "$r"

echo "== node1 恢复 tcp:// (多跳测试) =="
ssh_vm node1 "sudo pkill -x vnet"; sleep 1
start_vm node1 10.144.144.1 -p tcp://$HUB:11010
sleep 4
r=$(iperf_run node1 10.144.144.3);   printf "%-38s %10s\n" "2a. 多跳中继 node1->node3 (tcp入)" "$r"
r=$(iperf_run node1 10.144.144.3 -R);printf "%-38s %10s\n" "2a'. 多跳中继反向 (-R)" "$r"

# 清理
for n in node1 node2 node3; do ssh_vm $n "sudo pkill -x vnet || true; sudo pkill -x iperf3 || true"; done
echo "done"
