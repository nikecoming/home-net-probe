#!/usr/bin/env bash
# 整晚「每分鐘進到三台小愛的下載量 KB」時序，找斷音時刻（波消失＝斷）。逐檔處理避免爆記憶體。root 跑。
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
N="${1:-40}"
cd /opt/xiaoai/pcap 2>/dev/null || { echo "no pcap dir"; exit 1; }
FILES=$(ls -t xiaoai_*.pcap 2>/dev/null | head -"$N" | sort)
[ -z "$FILES" ] && { echo "no pcap"; exit 1; }
OUT=$( {
  echo "== 每分鐘下載量 KB（進到 .5/.6/.20；順時每 3-4 分鐘一波 1500-2500，斷時該波消失或掉到數十）=="
  for f in $FILES; do
    tshark -r "$f" -Y "ip.dst==192.168.2.5 || ip.dst==192.168.2.6 || ip.dst==192.168.2.20" \
      -T fields -e frame.time_epoch -e frame.len 2>>"$TSERR"
  done | awk '{t=int($1/60)*60; b[t]+=$2; if(mn==0||t<mn)mn=t; if(t>mx)mx=t}
   END{if(mn==0){print "  （此區間無任何封包）"; exit}
       for(t=mn;t<=mx;t+=60) printf "%s %8.1f%s\n", strftime("%m/%d %H:%M",t), b[t]/1024, (b[t]==0?"   <<< 歸零":"")}'
} 2>&1 )
# --- 出貨：先落地再上傳；上傳失敗就把報告整份印出來，不讓資料消失（2026-09-19 三審修）---
RPT_DIR=/opt/xiaoai/reports; mkdir -p "$RPT_DIR" 2>/dev/null || RPT_DIR=/tmp
RPT="$RPT_DIR/pi_timeline_$(date '+%Y%m%d_%H%M%S').txt"
printf '%s\n' "$OUT" > "$RPT" && echo "（本機留底：$RPT）"
URL="$(printf '%s\n' "$OUT" | curl -s --max-time 60 --data-binary @- https://paste.rs/)"
case "$URL" in
  http*) echo "$URL" ;;
  *) echo "!!!!!!!! paste.rs 上傳失敗（回應：${URL:-空}）—— 以下為報告全文 !!!!!!!!"
     printf '%s\n' "$OUT" ;;
esac
echo
