#!/usr/bin/env bash
# ⚠️ 2026-09-19 三審實測：本腳本對「已確認順暢」的時段報出 7 次斷／591 秒（全窗 601 秒）。
# 原因：音訊是爆發式下載（3-4 分鐘一波），其餘時間本來就接近 0，用「每秒 <30KB 連續 3 秒」掃必然滿版。
# 因此輸出一律改稱「低流量區間」，**不得當成斷音證據**；要判斷斷音請用 pi_audio.sh 的波形＋連線狀態。
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
N="${1:-2}"; TH="${2:-30}"   # 閾值 30KB/s，連續 >=3 秒算一次 stall
cd /opt/xiaoai/pcap 2>/dev/null || { echo no pcap; exit 1; }
FILES=$(ls -t xiaoai_*.pcap 2>/dev/null | head -"$N" | sort)
[ -z "$FILES" ] && { echo "!! 找不到 pcap，不下任何結論"; exit 1; }
M=/tmp/stall.pcap; mergecap -w "$M" $FILES 2>>"$TSERR"
OUT=$( {
echo "== 低流量區間（下載<${TH}KB/s 連續>=3秒）※ 正常的爆發式下載也會滿版，非斷音證據 =="
tshark -r "$M" -Y 'ip.dst==192.168.2.5 || ip.dst==192.168.2.6 || ip.dst==192.168.2.20' \
  -T fields -e frame.time_epoch -e frame.len 2>>"$TSERR" \
| awk -v th="$TH" '
  {s=int($1); b[s]+=$2; if(s<mn||mn==0)mn=s; if(s>mx)mx=s}
  END{
    run=0; start=0; nev=0;
    for(t=mn;t<=mx;t++){
      kb=b[t]/1024;
      if(kb<th){ if(run==0)start=t; run++ }
      else { if(run>=3){nev++; printf "低流量#%d  %s 起  持續 %d 秒\n", nev, strftime("%H:%M:%S",start), run} run=0 }
    }
    if(run>=3){nev++; printf "低流量#%d  %s 起  持續 %d 秒\n", nev, strftime("%H:%M:%S",start), run}
    printf "\n總計 %d 個低流量區間（涵蓋 %s ~ %s）※ 非斷音證據\n", nev, strftime("%H:%M:%S",mn), strftime("%H:%M:%S",mx)
  }'
echo; echo "== 每 5 秒下載 KB（看波形；0 或極低＝斷）=="
tshark -r "$M" -Y 'ip.dst==192.168.2.5 || ip.dst==192.168.2.6 || ip.dst==192.168.2.20' \
  -T fields -e frame.time_epoch -e frame.len 2>>"$TSERR" \
| awk '{s=int($1/5)*5; b[s]+=$2} END{for(k in b) print k,b[k]} ' | sort -n \
| awk 'NR==1{t0=$1} {printf "%s  %7.0f KB\n", strftime("%H:%M:%S",$1), $2/1024}'
} 2>&1 )
rm -f "$M"
# --- 出貨：先落地再上傳；上傳失敗就把報告整份印出來，不讓資料消失（2026-09-19 三審修）---
RPT_DIR=/opt/xiaoai/reports; mkdir -p "$RPT_DIR" 2>/dev/null || RPT_DIR=/tmp
RPT="$RPT_DIR/pi_stall_$(date '+%Y%m%d_%H%M%S').txt"
printf '%s\n' "$OUT" > "$RPT" && echo "（本機留底：$RPT）"
URL="$(printf '%s\n' "$OUT" | curl -s --max-time 60 --data-binary @- https://paste.rs/)"
case "$URL" in
  http*) echo "$URL" ;;
  *) echo "!!!!!!!! paste.rs 上傳失敗（回應：${URL:-空}）—— 以下為報告全文 !!!!!!!!"
     printf '%s\n' "$OUT" ;;
esac
echo
