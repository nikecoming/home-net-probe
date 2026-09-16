#!/usr/bin/env bash
# 秒級 stall 偵測：對最近 N 檔，逐秒統計「進到三台小愛的下載 KB」，找連續低於閾值的斷音事件。root 跑。
N="${1:-2}"; TH="${2:-30}"   # 閾值 30KB/s，連續 >=3 秒算一次 stall
cd /opt/xiaoai/pcap 2>/dev/null || { echo no pcap; exit 1; }
FILES=$(ls -t xiaoai_*.pcap 2>/dev/null | head -"$N" | sort)
M=/tmp/stall.pcap; mergecap -w "$M" $FILES 2>/dev/null
OUT=$( {
echo "== 秒級 stall 偵測（下載<${TH}KB/s 連續>=3秒＝一次斷）；也列各節點逐秒 =="
tshark -r "$M" -Y 'ip.dst==192.168.2.5 || ip.dst==192.168.2.6 || ip.dst==192.168.2.20' \
  -T fields -e frame.time_epoch -e frame.len 2>/dev/null \
| awk -v th="$TH" '
  {s=int($1); b[s]+=$2; if(s<mn||mn==0)mn=s; if(s>mx)mx=s}
  END{
    run=0; start=0; nev=0;
    for(t=mn;t<=mx;t++){
      kb=b[t]/1024;
      if(kb<th){ if(run==0)start=t; run++ }
      else { if(run>=3){nev++; printf "斷#%d  %s 起  持續 %d 秒\n", nev, strftime("%H:%M:%S",start), run} run=0 }
    }
    if(run>=3){nev++; printf "斷#%d  %s 起  持續 %d 秒\n", nev, strftime("%H:%M:%S",start), run}
    printf "\n總計 %d 次斷（涵蓋 %s ~ %s）\n", nev, strftime("%H:%M:%S",mn), strftime("%H:%M:%S",mx)
  }'
echo; echo "== 每 5 秒下載 KB（看波形；0 或極低＝斷）=="
tshark -r "$M" -Y 'ip.dst==192.168.2.5 || ip.dst==192.168.2.6 || ip.dst==192.168.2.20' \
  -T fields -e frame.time_epoch -e frame.len 2>/dev/null \
| awk '{s=int($1/5)*5; b[s]+=$2} END{for(k in b) print k,b[k]} ' | sort -n \
| awk 'NR==1{t0=$1} {printf "%s  %7.0f KB\n", strftime("%H:%M:%S",$1), $2/1024}'
} 2>&1 )
rm -f "$M"
echo "$OUT" | curl -s --data-binary @- https://paste.rs/
echo
