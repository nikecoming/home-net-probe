#!/usr/bin/env bash
# 音訊流體檢：在「正在播、正在斷」的當下跑。
# 看三件事：①秒級下載波形 ②每一條音訊連線的重傳／被 RST／被 FIN ③斷掉那幾秒發生什麼事
# 用法：pi_audio.sh [檔數，預設 2]
set -u
N="${1:-2}"
cd /opt/xiaoai/pcap 2>/dev/null || { echo "no pcap"; exit 1; }
FILES=$(ls -t xiaoai_*.pcap 2>/dev/null | head -"$N" | sort)
[ -z "$FILES" ] && { echo "找不到 pcap"; exit 1; }
M=/tmp/audio.pcap; mergecap -w "$M" $FILES 2>/dev/null || { echo mergecap 失敗; exit 1; }
DP='ip.dst==192.168.2.5||ip.dst==192.168.2.6||ip.dst==192.168.2.20'
SP='ip.src==192.168.2.5||ip.src==192.168.2.6||ip.src==192.168.2.20'
ME="($SP||$DP)"

OUT=$(
echo "== 音訊流體檢 / $(date '+%F %T') / $(echo $FILES|wc -w) 檔 =="
echo
echo "== A. 每 5 秒下載 KB（波形；連續低就是斷）=="
tshark -r "$M" -Y "$DP" -T fields -e frame.time_epoch -e frame.len 2>/dev/null \
 | awk '{s=int($1/5)*5; b[s]+=$2} END{for(k in b) print k, b[k]}' | sort -n \
 | awk '{kb=$2/1024; bar=""; n=int(kb/20); for(i=0;i<n&&i<40;i++)bar=bar"#";
         printf "   %s %8.0f KB %s\n", strftime("%H:%M:%S",$1), kb, bar}'
echo
echo "== B. 大流量連線（音訊來源）：位元組 / 重傳 / RST / FIN =="
tshark -r "$M" -Y "tcp&&$ME" -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
   -e tcp.len -e tcp.flags.reset -e tcp.flags.fin -e tcp.analysis.retransmission 2>/dev/null \
 | awk -F'\t' '{
     if($1 ~ /^192\.168\.2\./){peer=$2; pp=$4} else {peer=$1; pp=$3}
     k=peer":"pp; by[k]+=$5; if($6=="1")rst[k]++; if($7=="1")fin[k]++; if($8!="")rt[k]++
   } END{for(k in by) if(by[k]>200000) printf "   %-24s %9.0f KB  重傳%4d  RST%3d  FIN%3d\n", k, by[k]/1024, rt[k]+0, rst[k]+0, fin[k]+0}' \
 | sort -k2 -rn
echo
echo "== C. 連線被重置（RST）的時刻——斷音的常見直接原因 =="
tshark -r "$M" -Y "tcp.flags.reset==1&&$ME" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport 2>/dev/null \
 | awk -F'\t' '{split($1,a," "); printf "   %s  %s:%s -> %s\n", a[4], $2, $4, $3}' | head -30
echo "   （空白＝沒有任何連線被重置）"
echo
echo "== D. 音訊來源主機名（TLS SNI／HTTP Host）=="
tshark -r "$M" -Y "http.request&&$SP" -T fields -e ip.dst -e http.host 2>/dev/null | sort | uniq -c | sort -rn | head -10 | sed 's/^/   /'
tshark -r "$M" -Y "tls.handshake.type==1&&$SP" -T fields -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null | sort | uniq -c | sort -rn | head -10 | sed 's/^/   /'
)
rm -f "$M"
echo "$OUT"
echo; echo "---- 上傳中 ----"
echo "$OUT" | curl -s --data-binary @- https://paste.rs/
echo
