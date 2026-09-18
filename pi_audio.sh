#!/usr/bin/env bash
# 音訊流體檢：在「正在播、正在斷」的當下跑。
# 看三件事：①秒級下載波形 ②每一條音訊連線的重傳／被 RST／被 FIN ③斷掉那幾秒發生什麼事
# 用法：pi_audio.sh [檔數，預設 2]
# --- 儀器守衛：tshark 壞過濾器會靜默回 0，這裡讓它大聲失敗（2026-09-19 三審修）---
TSERR="$(mktemp -t tserr.XXXXXX)"
_ts_report() {
  # sudo tshark 每次都會印「Running as user root ...」，那不是錯誤；
  # 把它算進來的話每一份報告都會掛上假警報，警報就沒人看了（2026-09-19 負控實測）。
  grep -v -e 'Running as user' -e 'This could be dangerous' -e '^$' "$TSERR" > "$TSERR.real" 2>/dev/null
  if [ -s "$TSERR.real" ]; then
    echo
    echo "!!!!!!!! TSHARK 回報錯誤 —— 以上所有數字不可信 !!!!!!!!"
    sort -u "$TSERR.real" | head -5 | sed 's/^/  /'
    echo "!!!!!!!! （過濾器語法錯或欄位名不存在時會靜默回 0，不是「沒有資料」）"
  fi
  rm -f "$TSERR" "$TSERR.real"
}
trap _ts_report EXIT
set -u
N="${1:-2}"
cd /opt/xiaoai/pcap 2>/dev/null || { echo "no pcap"; exit 1; }
FILES=$(ls -t xiaoai_*.pcap 2>/dev/null | head -"$N" | sort)
[ -z "$FILES" ] && { echo "找不到 pcap"; exit 1; }
M=/tmp/audio.pcap; mergecap -w "$M" $FILES 2>>"$TSERR" || { echo mergecap 失敗; exit 1; }
DP='ip.dst==192.168.2.5||ip.dst==192.168.2.6||ip.dst==192.168.2.20'
SP='ip.src==192.168.2.5||ip.src==192.168.2.6||ip.src==192.168.2.20'
ME="($SP||$DP)"

OUT=$(
echo "== 音訊流體檢 / $(date '+%F %T') / $(echo $FILES|wc -w) 檔 =="
echo
echo "== A. 每 5 秒下載 KB（波形；連續低就是斷）=="
tshark -r "$M" -Y "$DP" -T fields -e frame.time_epoch -e frame.len 2>>"$TSERR" \
 | awk '{t=int($1/5)*5; b[t]+=$2; if(mn==0||t<mn)mn=t; if(t>mx)mx=t}
    END{if(mn==0)exit; for(t=mn;t<=mx;t+=5) print t, b[t]+0}' \
 | awk '{kb=$2/1024; bar=""; n=int(kb/20); for(i=0;i<n&&i<40;i++)bar=bar"#";
         printf "   %s %8.0f KB %s\n", strftime("%H:%M:%S",$1), kb, bar}'
echo
echo "== B. 大流量連線（音訊來源）：位元組 / 重傳 / RST / FIN =="
tshark -r "$M" -Y "tcp&&$ME" -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
   -e tcp.len -e tcp.flags.reset -e tcp.flags.fin -e tcp.analysis.retransmission 2>>"$TSERR" \
 | awk -F'\t' '{
     if($1 ~ /^192\.168\.2\./){peer=$2; pp=$4} else {peer=$1; pp=$3}
     k=peer":"pp; by[k]+=$5; if($6=="1")rst[k]++; if($7=="1")fin[k]++; if($8!="")rt[k]++
   } END{for(k in by) if(by[k]>200000) printf "   %-24s %9.0f KB  重傳%4d  RST%3d  FIN%3d\n", k, by[k]/1024, rt[k]+0, rst[k]+0, fin[k]+0}' \
 | sort -k2 -rn
echo
echo "== C. 連線被重置（RST）的時刻——斷音的常見直接原因 =="
tshark -r "$M" -Y "tcp.flags.reset==1&&$ME" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport 2>>"$TSERR" \
 | awk -F'\t' '{split($1,a," "); printf "   %s  %s:%s -> %s\n", a[4], $2, $4, $3}' | head -30
echo "   （空白＝沒有任何連線被重置）"
echo
echo "== D. 音訊來源主機名（TLS SNI／HTTP Host）=="
tshark -r "$M" -Y "http.request&&$SP" -T fields -e ip.dst -e http.host 2>>"$TSERR" | sort | uniq -c | sort -rn | head -10 | sed 's/^/   /'
tshark -r "$M" -Y "tls.handshake.type==1&&$SP" -T fields -e ip.dst -e tls.handshake.extensions_server_name 2>>"$TSERR" | sort | uniq -c | sort -rn | head -10 | sed 's/^/   /'
)
rm -f "$M"
echo "$OUT"
echo; echo "---- 上傳中 ----"
# --- 出貨：先落地再上傳；上傳失敗就把報告整份印出來，不讓資料消失（2026-09-19 三審修）---
RPT_DIR=/opt/xiaoai/reports; mkdir -p "$RPT_DIR" 2>/dev/null || RPT_DIR=/tmp
RPT="$RPT_DIR/pi_audio_$(date '+%Y%m%d_%H%M%S').txt"
printf '%s\n' "$OUT" > "$RPT" && echo "（本機留底：$RPT）"
URL="$(printf '%s\n' "$OUT" | curl -s --max-time 60 --data-binary @- https://paste.rs/)"
case "$URL" in
  http*) echo "$URL" ;;
  *) echo "!!!!!!!! paste.rs 上傳失敗（回應：${URL:-空}）—— 以下為報告全文 !!!!!!!!"
     printf '%s\n' "$OUT" ;;
esac
echo
