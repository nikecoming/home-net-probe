#!/usr/bin/env bash
# 把最近 N 個 pcap（預設全部）彙整成可貼給 Claude 的摘要：DNS 查詢、TLS SNI、目的 IP 排行、每分鐘位元組、重傳數。
cd ~/xiaoai/pcap || exit 1
FILES=$(ls -t xiaoai_*.pcap 2>/dev/null | head -${1:-48} | sort)
[ -z "$FILES" ] && { echo "沒有 pcap"; exit 1; }
SP="ip.src==192.168.2.5 || ip.src==192.168.2.6 || ip.src==192.168.2.20"
echo "=== 檔案 ==="; ls -la $FILES | awk '{print $6,$7,$8,$9,$5" bytes"}'
echo; echo "=== 小愛問了哪些 DNS（次數）==="
tshark -r <(mergecap -w - $FILES) -Y "dns.flags.response==0 && ($SP)" -T fields -e ip.src -e dns.qry.name 2>/dev/null | sort | uniq -c | sort -rn | head -40
echo; echo "=== DNS 答案（域名 → IP，次數）==="
tshark -r <(mergecap -w - $FILES) -Y "dns.flags.response==1 && dns.a && (ip.dst==192.168.2.5 || ip.dst==192.168.2.6 || ip.dst==192.168.2.20)" -T fields -e dns.qry.name -e dns.a 2>/dev/null | sort | uniq -c | sort -rn | head -40
echo; echo "=== TLS SNI（喇叭連去的主機名，次數）==="
tshark -r <(mergecap -w - $FILES) -Y "tls.handshake.type==1 && ($SP)" -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null | sort | uniq -c | sort -rn | head -40
echo; echo "=== 目的 IP（TCP，非區網，依封包數）==="
tshark -r <(mergecap -w - $FILES) -Y "tcp && ($SP) && !(ip.dst==192.168.2.0/24)" -T fields -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null | sort | uniq -c | sort -rn | head -30
echo; echo "=== 重傳／遺失（每個目的 IP）==="
tshark -r <(mergecap -w - $FILES) -Y "(tcp.analysis.retransmission || tcp.analysis.lost_segment) && (ip.addr==192.168.2.5 || ip.addr==192.168.2.6 || ip.addr==192.168.2.20)" -T fields -e ip.src -e ip.dst 2>/dev/null | sort | uniq -c | sort -rn | head -20
echo; echo "=== 每分鐘進到小愛的位元組（下載量；斷音時應該掉到接近 0）==="
tshark -r <(mergecap -w - $FILES) -Y "ip.dst==192.168.2.5 || ip.dst==192.168.2.6 || ip.dst==192.168.2.20" -T fields -e frame.time_epoch -e frame.len 2>/dev/null | awk '{m=strftime("%H:%M",int($1/60)*60); b[m]+=$2} END{for(k in b) printf "%s %8.1f KB\n",k,b[k]/1024}' | sort | tail -60
