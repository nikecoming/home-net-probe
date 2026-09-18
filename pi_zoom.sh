#!/usr/bin/env bash
# 兩個問題：
#  1) 「隧道比直連差」是長期如此，還是只有 00:13 那一次爆發時如此？→ 逐檔分開算
#  2) 那次爆發長什麼樣？→ 挑 SYN 重傳最多的那一檔，逐分鐘 + 看誰連不上
# 用法：pi_zoom.sh [要看幾檔，預設 12]
# --- 儀器守衛：tshark 壞過濾器會靜默回 0，這裡讓它大聲失敗（2026-09-19 三審修）---
TSERR="$(mktemp -t tserr.XXXXXX)"
_ts_report() {
  if [ -s "$TSERR" ]; then
    echo
    echo "!!!!!!!! TSHARK 回報錯誤 —— 以上所有數字不可信 !!!!!!!!"
    sort -u "$TSERR" | head -5 | sed 's/^/  /'
    echo "!!!!!!!! （過濾器語法錯或欄位名不存在時會靜默回 0，不是「沒有資料」）"
  fi
  rm -f "$TSERR"
}
trap _ts_report EXIT
set -u
N="${1:-12}"
D=/opt/xiaoai/pcap
FILES=$(ls "$D"/*.pcap 2>/dev/null | tail -n "$N")
[ -z "$FILES" ] && { echo "找不到 pcap（$D）"; exit 1; }
SP='ip.src==192.168.2.5||ip.src==192.168.2.6||ip.src==192.168.2.20'
DP='ip.dst==192.168.2.5||ip.dst==192.168.2.6||ip.dst==192.168.2.20'
ME="($SP||$DP)"
CH="8.128.0.0/10 8.208.0.0/12 39.96.0.0/11 47.0.0.0/8 101.128.0.0/11 106.0.0.0/10 162.128.37.0/24 119.29.29.0/24 203.107.0.0/16 210.72.0.0/16 120.197.0.0/16"
F=""; for n in $CH; do F="$F||ip.addr==$n"; done; F="(${F#||})"
c(){ tshark -r "$1" -Y "$2" 2>>"$TSERR" | wc -l; }

BEST=""; BESTN=-1
OUT=$(
echo "== 逐檔：隧道 vs 直連 / 產生 $(date '+%F %T') =="
echo "   問題 1：隧道的高重傳是長期的，還是只在爆發那一檔？"
echo
printf "   %-13s %8s %7s %8s   %8s %7s %8s\n" 時段 隧道封包 隧道重傳 隧道率 直連封包 直連重傳 直連率
printf "   %s\n" "--------------------------------------------------------------------------"
for f in $FILES; do
  b=$(basename "$f" .pcap); t=$(echo "$b" | sed 's/^xiaoai_//; s/\(....\)\(..\)\(..\)_\(..\)\(..\)/\2\/\3 \4:\5/')
  tot=$(c "$f" "tcp&&$ME"); [ "$tot" -eq 0 ] && continue
  ct=$(c "$f" "tcp&&$F&&$ME");  cr=$(c "$f" "tcp.analysis.retransmission&&$F&&$ME")
  kt=$(c "$f" "tcp&&!$F&&$ME"); kr=$(c "$f" "tcp.analysis.retransmission&&!$F&&$ME")
  sr=$(c "$f" "tcp.analysis.retransmission&&tcp.flags.syn==1&&tcp.flags.ack==0&&$ME")
  [ "$sr" -gt "$BESTN" ] && { BESTN=$sr; BEST=$f; }
  awk -v t="$t" -v ct="$ct" -v cr="$cr" -v kt="$kt" -v kr="$kr" 'BEGIN{
    printf "   %-13s %8d %7d %7.2f%%   %8d %7d %7.2f%%\n",t,ct,cr,(ct?100*cr/ct:0),kt,kr,(kt?100*kr/kt:0)}'
done
echo
echo "== 放大 SYN 重傳最多的一檔：$(basename "${BEST:-無}") （$BESTN 次）=="
if [ -n "$BEST" ] && [ "$BESTN" -gt 0 ]; then
  echo
  echo "   -- 逐分鐘 SYN 嘗試 / 重傳 --"
  tshark -r "$BEST" -Y "tcp.flags.syn==1&&tcp.flags.ack==0&&$ME" -T fields \
     -e frame.time -e tcp.analysis.retransmission 2>>"$TSERR" \
   | awk -F'\t' '{split($1,a," "); split(a[4],b,":"); k=b[1]":"b[2]; n[k]++; if($2!="")r[k]++}
       END{for(k in n) printf "   %s  嘗試 %4d  重傳 %4d  %5.1f%%\n",k,n[k],r[k]+0,100*(r[k]+0)/n[k]}' | sort
  echo
  echo "   -- 誰連不上（目的 IP:埠）--"
  tshark -r "$BEST" -Y "tcp.analysis.retransmission&&tcp.flags.syn==1&&tcp.flags.ack==0&&$ME" \
     -T fields -e ip.dst -e tcp.dstport 2>>"$TSERR" | sort | uniq -c | sort -rn | head -14 | sed 's/^/   /'
  echo
  echo "   -- 該檔隧道 vs 直連 --"
  ct=$(c "$BEST" "tcp&&$F&&$ME"); cr=$(c "$BEST" "tcp.analysis.retransmission&&$F&&$ME")
  kt=$(c "$BEST" "tcp&&!$F&&$ME"); kr=$(c "$BEST" "tcp.analysis.retransmission&&!$F&&$ME")
  awk -v ct="$ct" -v cr="$cr" -v kt="$kt" -v kr="$kr" 'BEGIN{
    printf "   隧道 %d 封包 %d 重傳 %.2f%%   直連 %d 封包 %d 重傳 %.2f%%\n",ct,cr,(ct?100*cr/ct:0),kt,kr,(kt?100*kr/kt:0)}'
fi
)
echo "$OUT"
echo; echo "---- 上傳中 ----"
# --- 出貨：先落地再上傳；上傳失敗就把報告整份印出來，不讓資料消失（2026-09-19 三審修）---
RPT_DIR=/opt/xiaoai/reports; mkdir -p "$RPT_DIR" 2>/dev/null || RPT_DIR=/tmp
RPT="$RPT_DIR/pi_zoom_$(date '+%Y%m%d_%H%M%S').txt"
printf '%s\n' "$OUT" > "$RPT" && echo "（本機留底：$RPT）"
URL="$(printf '%s\n' "$OUT" | curl -s --max-time 60 --data-binary @- https://paste.rs/)"
case "$URL" in
  http*) echo "$URL" ;;
  *) echo "!!!!!!!! paste.rs 上傳失敗（回應：${URL:-空}）—— 以下為報告全文 !!!!!!!!"
     printf '%s\n' "$OUT" ;;
esac
echo
