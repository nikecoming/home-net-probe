#!/usr/bin/env bash
# 分析最近 N 個 pcap（預設 3），輸出貼到 paste.rs，印出網址。以 root 跑（curl ... | sudo bash）。
N="${1:-3}"
cd /opt/xiaoai/pcap 2>/dev/null || { echo "no pcap dir"; exit 1; }
FILES=$(ls -t xiaoai_*.pcap 2>/dev/null | head -"$N" | sort)
[ -z "$FILES" ] && { echo "no pcap files"; exit 1; }
M=/tmp/xiaoai_merged.pcap
mergecap -w "$M" $FILES 2>/dev/null
SP='ip.src==192.168.2.5 || ip.src==192.168.2.6 || ip.src==192.168.2.20'
ANY='ip.addr==192.168.2.5 || ip.addr==192.168.2.6 || ip.addr==192.168.2.20'
OUT=$( {
  echo "== 檔案 =="; ls -la $FILES | awk '{print $9, $5" B"}'
  echo; echo "== 小愛問了哪些 DNS（次數 / src / 域名）=="
  tshark -r "$M" -Y "dns.flags.response==0 && ($SP)" -T fields -e ip.src -e dns.qry.name 2>/dev/null | sort | uniq -c | sort -rn | head -40
  echo; echo "== DNS 答案（域名 → IP，次數）=="
  tshark -r "$M" -Y "dns.a" -T fields -e dns.qry.name -e dns.a 2>/dev/null | sort | uniq -c | sort -rn | head -40
  echo; echo "== TLS SNI（連去的主機名 / 目的IP / 次數）=="
  tshark -r "$M" -Y "tls.handshake.type==1 && ($SP)" -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null | sort | uniq -c | sort -rn | head -40
  echo; echo "== 目的 IP（TCP 非區網，依封包數）=="
  tshark -r "$M" -Y "tcp && ($SP) && !(ip.dst==192.168.2.0/24)" -T fields -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null | sort | uniq -c | sort -rn | head -30
  echo; echo "== ICMP 目標（小愛 ping 誰 / 次數）=="
  tshark -r "$M" -Y "icmp && ($SP)" -T fields -e ip.src -e ip.dst 2>/dev/null | sort | uniq -c | sort -rn | head -20
  echo; echo "== 重傳／遺失（每個目的 IP）=="
  tshark -r "$M" -Y "(tcp.analysis.retransmission || tcp.analysis.lost_segment) && ($ANY)" -T fields -e ip.src -e ip.dst 2>/dev/null | sort | uniq -c | sort -rn | head -20
  echo; echo "== 每分鐘進到小愛的位元組（下載量 KB）=="
  tshark -r "$M" -Y "ip.dst==192.168.2.5 || ip.dst==192.168.2.6 || ip.dst==192.168.2.20" -T fields -e frame.time_epoch -e frame.len 2>/dev/null | awk '{m=strftime("%H:%M",int($1/60)*60); b[m]+=$2} END{for(k in b) printf "%s %8.1f\n",k,b[k]/1024}' | sort
} 2>&1 )
rm -f "$M"
echo "$OUT" | curl -s --data-binary @- https://paste.rs/
echo
