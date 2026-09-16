#!/usr/bin/env bash
# 整晚「每分鐘進到三台小愛的下載量 KB」時序，找斷音時刻（波消失＝斷）。逐檔處理避免爆記憶體。root 跑。
N="${1:-40}"
cd /opt/xiaoai/pcap 2>/dev/null || { echo "no pcap dir"; exit 1; }
FILES=$(ls -t xiaoai_*.pcap 2>/dev/null | head -"$N" | sort)
[ -z "$FILES" ] && { echo "no pcap"; exit 1; }
OUT=$( {
  echo "== 每分鐘下載量 KB（進到 .5/.6/.20；順時每 3-4 分鐘一波 1500-2500，斷時該波消失或掉到數十）=="
  for f in $FILES; do
    tshark -r "$f" -Y "ip.dst==192.168.2.5 || ip.dst==192.168.2.6 || ip.dst==192.168.2.20" \
      -T fields -e frame.time_epoch -e frame.len 2>/dev/null
  done | awk '{m=strftime("%H:%M",int($1/60)*60); b[m]+=$2} END{for(k in b) printf "%s %8.1f\n",k,b[k]/1024}' | sort
} 2>&1 )
echo "$OUT" | curl -s --data-binary @- https://paste.rs/
echo
