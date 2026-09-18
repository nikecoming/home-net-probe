#!/usr/bin/env bash
# 逐檔（每檔 10 分鐘）算「建連失敗率」的時間序列。
# 目的：看 SYN 重試率是否在斷音時段升高、是否在 00:34 改設定後下降、以及有沒有慢慢爬回去。
# 用法：pi_trend.sh [要看幾個檔，預設 24 ≈ 4 小時]
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
N="${1:-24}"
D=/opt/xiaoai/pcap
FILES=$(ls "$D"/*.pcap 2>/dev/null | tail -n "$N")
[ -z "$FILES" ] && { echo "找不到 pcap（$D）"; exit 1; }
SP='ip.src==192.168.2.5||ip.src==192.168.2.6||ip.src==192.168.2.20'
DP='ip.dst==192.168.2.5||ip.dst==192.168.2.6||ip.dst==192.168.2.20'
ME="($SP||$DP)"

OUT=$(
echo "== 建連失敗率時間序列 / 產生 $(date '+%F %T') / $(echo $FILES|wc -w) 檔 =="
echo "   SYN重試% = 需要重送 SYN 的比例；高 = 連不上、指數退避 = 使用者在等"
echo "   下載KB = 該 10 分鐘進到三台小愛的位元組（判斷當時有沒有在播）"
echo
printf "   %-13s %7s %7s %8s %9s\n" 時段 連線數 需重試 比例 下載KB
printf "   %s\n" "----------------------------------------------------"
for f in $FILES; do
  b=$(basename "$f" .pcap); t=$(echo "$b" | sed 's/^xiaoai_//; s/\(....\)\(..\)\(..\)_\(..\)\(..\)/\2\/\3 \4:\5/')
  # 修：分母改「連線數」不是「SYN 封包數」——一條連線重試 3 次，封包算法會變成 75%
  s=$(tshark -r "$f" -Y "tcp.flags.syn==1&&tcp.flags.ack==0&&$ME" -T fields -e tcp.stream 2>>"$TSERR" | sort -u | wc -l)
  r=$(tshark -r "$f" -Y "tcp.analysis.retransmission&&tcp.flags.syn==1&&tcp.flags.ack==0&&$ME" -T fields -e tcp.stream 2>>"$TSERR" | sort -u | wc -l)
  kb=$(tshark -r "$f" -Y "$DP" -T fields -e frame.len 2>>"$TSERR" | awk '{s+=$1} END{printf "%.0f", s/1024}')
  awk -v t="$t" -v s="$s" -v r="$r" -v kb="${kb:-0}" 'BEGIN{
    if(s<10){ printf "   %-13s %7d %7d %8s %9s  (樣本太少，不給比例)
", t, s, r, "n/a", kb; exit }
    p=100*r/s; bar=""; n=int(p/2); for(i=0;i<n&&i<25;i++)bar=bar"#";
    printf "   %-13s %7d %7d %7.1f%% %9s  %s\n", t, s, r, p, kb, bar}'
done
echo
echo "   參考時間點：00:34 我寫入新路由（162.128.37/24、119.29.29/24 導教會，8.208/12 由停用改啟用）"
echo "   讀法：若重試率在 00:34 後才下降 => 改動有效；若之前就低或之後又爬回 => 改動不是原因"
)
echo "$OUT"
echo; echo "---- 上傳中 ----"
# --- 出貨：先落地再上傳；上傳失敗就把報告整份印出來，不讓資料消失（2026-09-19 三審修）---
RPT_DIR=/opt/xiaoai/reports; mkdir -p "$RPT_DIR" 2>/dev/null || RPT_DIR=/tmp
RPT="$RPT_DIR/pi_trend_$(date '+%Y%m%d_%H%M%S').txt"
printf '%s\n' "$OUT" > "$RPT" && echo "（本機留底：$RPT）"
URL="$(printf '%s\n' "$OUT" | curl -s --max-time 60 --data-binary @- https://paste.rs/)"
case "$URL" in
  http*) echo "$URL" ;;
  *) echo "!!!!!!!! paste.rs 上傳失敗（回應：${URL:-空}）—— 以下為報告全文 !!!!!!!!"
     printf '%s\n' "$OUT" ;;
esac
echo
