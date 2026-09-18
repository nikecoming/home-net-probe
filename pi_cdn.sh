#!/usr/bin/env bash
# 用「真正的那個音訊 URL」去實測每個候選 CDN 節點的下載速度。
# DNS 對 isure6-qqmusic.a.bdydns.com 回了 6 個 IP，喇叭挑了最爛的那個。這支量出哪個最快。
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
D=/opt/xiaoai/pcap
M=/tmp/cdn.pcap
FILES=$(ls -t "$D"/*.pcap 2>/dev/null | head -3)
[ -z "$FILES" ] && { echo "找不到 pcap"; exit 1; }
sudo mergecap -w "$M" $FILES 2>>"$TSERR" || { echo mergecap 失敗; exit 1; }

# 從 pcap 撈最後一個對 111.20.254.35 的 HTTP GET（真實 URL，含 vkey）
read HOST URI <<<"$(sudo tshark -r "$M" -Y 'http.request && ip.dst==111.20.254.35' \
   -T fields -e http.host -e http.request.uri 2>>"$TSERR" | tail -1)"
rm -f "$M"
if [ -z "${URI:-}" ]; then
  echo "pcap 裡撈不到對 111.20.254.35 的 HTTP GET（可能剛好沒在播）。請在播放中再跑一次。"; exit 1
fi
echo "Host: $HOST"
echo "URI : ${URI:0:110}..."
echo

# DNS 對該域名回過的候選（含目前在用的那個當對照組）
CAND="111.20.254.35 180.76.76.118 182.61.200.72 180.101.49.224 111.45.3.163 110.242.68.26 180.76.5.78 180.76.5.228 103.235.46.223"

OUT=$(
echo "== CDN 候選節點實測（同一個真實音訊 URL，各抓 3 MB，上限 20 秒）=="
echo "   $(date '+%F %T')   Host: $HOST"
echo
printf "   %-18s %10s %8s %9s  %s\n" 節點IP 下載KB/s HTTP 取得KB 備註
printf "   %s\n" "---------------------------------------------------------------"
for ip in $CAND; do
  r=$(curl -s -o /dev/null --max-time 20 -r 0-3000000 \
        -H "Host: $HOST" -H "User-Agent: Mozilla/5.0" \
        -w '%{speed_download} %{http_code} %{size_download}' \
        "http://$ip$URI" 2>/dev/null)
  sp=$(echo "$r" | awk '{print $1+0}'); code=$(echo "$r" | awk '{print $2}'); sz=$(echo "$r" | awk '{print $3+0}')
  note=""
  [ "$ip" = "111.20.254.35" ] && note="<= 目前在用"
  [ -z "$code" ] && code="逾時/失敗"
  awk -v ip="$ip" -v sp="$sp" -v c="$code" -v sz="$sz" -v n="$note" 'BEGIN{
    bar=""; k=sp/1024; m=int(k/40); for(i=0;i<m&&i<20;i++)bar=bar"#";
    printf "   %-18s %10.1f %8s %9.0f  %s %s\n", ip, k, c, sz/1024, n, bar}'
done
echo
echo "   讀法：HTTP 200/206 且速度高 = 可用且快。404/403 = 該節點不認這個 URL（不能換）。"
echo "   目標：找到比 111.20.254.35 明顯快、且回 200/206 的節點。"
)
echo "$OUT"
echo; echo "---- 上傳中 ----"
# --- 出貨：先落地再上傳；上傳失敗就把報告整份印出來，不讓資料消失（2026-09-19 三審修）---
RPT_DIR=/opt/xiaoai/reports; mkdir -p "$RPT_DIR" 2>/dev/null || RPT_DIR=/tmp
RPT="$RPT_DIR/pi_cdn_$(date '+%Y%m%d_%H%M%S').txt"
printf '%s\n' "$OUT" > "$RPT" && echo "（本機留底：$RPT）"
URL="$(printf '%s\n' "$OUT" | curl -s --max-time 60 --data-binary @- https://paste.rs/)"
case "$URL" in
  http*) echo "$URL" ;;
  *) echo "!!!!!!!! paste.rs 上傳失敗（回應：${URL:-空}）—— 以下為報告全文 !!!!!!!!"
     printf '%s\n' "$OUT" ;;
esac
echo
