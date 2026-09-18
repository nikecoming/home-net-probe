#!/usr/bin/env bash
# 儀器可見度自檢：這台 Pi 從鏡像埠「到底看得到誰」。
#
# 為什麼需要這支（2026-09-18 一晚栽三次的共同形狀）：
#   我一直把「抓包裡沒有」讀成「沒有發生」。但鏡像有三層盲區，每一層都不會報錯：
#     1. 路由器有四顆交換晶片，鏡像只能在同一顆晶片內做；跨晶片的設定被靜默接受但無效。
#     2. 同一台 AP 底下的無線客戶端互相通訊，封包根本不上有線埠。
#     3. tcpdump 的抓取過濾器（目前只抓 .5/.6/.20）會把其他裝置全部濾掉。
#   所以「看不到」必須先證明是「不存在」還是「在盲區」——這支就是拿來畫盲區地圖的。
#
# 用法：bash pi_visibility.sh [秒數，預設 20]
SEC=${1:-20}
IFACE=$(ip -br link | awk '$1 ~ /^(eth|en)/ {print $1; exit}')
[ -z "$IFACE" ] && IFACE=eth0
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

OUT=$(
echo "== 鏡像可見度自檢 / $(date '+%F %T') / 介面 $IFACE / 取樣 ${SEC}s =="
echo
echo "本機位址："
ip -br addr show "$IFACE" | sed 's/^/   /'
echo
echo "抓取中（完全不設過濾器，只抓表頭）…"
# 🛑 這裡刻意不下任何過濾器：有過濾器就等於預先假設了「誰重要」，那正是盲區的來源
timeout "$SEC" sudo -n tcpdump -i "$IFACE" -nn -s 128 -U -w "$TMP/vis.pcap" 2>"$TMP/td.err"
rc=$?
if [ ! -s "$TMP/vis.pcap" ]; then
  echo "!!!!!!!! 沒抓到任何東西（tcpdump exit=$rc）—— 這份報告不能當成「網路很安靜」!!!!!!!!"
  sed 's/^/   /' "$TMP/td.err"
  exit 1
fi
TOT=$(tshark -r "$TMP/vis.pcap" 2>/dev/null | wc -l)
echo "   共 $TOT 個封包"
echo
echo "== A. 看得到的 IP（依封包數）—— 沒出現在這張表上的裝置，一律當成「盲區」不是「安靜」 =="
tshark -r "$TMP/vis.pcap" -T fields -e ip.src 2>/dev/null | grep -v '^$' | sort | uniq -c | sort -rn | head -40 | sed 's/^/   /'
echo
echo "== B. 看得到的 MAC（有些裝置只發廣播，A 表會漏）=="
tshark -r "$TMP/vis.pcap" -T fields -e eth.src 2>/dev/null | grep -v '^$' | sort | uniq -c | sort -rn | head -40 | sed 's/^/   /'
echo
echo "== C. 單播 vs 廣播／多播（只看得到廣播＝這個埠不在對方的鏡像範圍內）=="
B=$(tshark -r "$TMP/vis.pcap" -Y 'eth.dst[0] & 1' 2>/dev/null | wc -l)
U=$((TOT-B))
printf '   單播 %d（%d%%）／廣播·多播 %d（%d%%）\n' "$U" $((TOT?U*100/TOT:0)) "$B" $((TOT?B*100/TOT:0))
echo "   ※ 若某台裝置只在 B 表出現、A 表的封包數又極低，代表我們只收得到它的廣播，"
echo "     它的實際資料流在鏡像之外——對它做的任何流量統計都是假的。"
echo
echo "== D. 這台 Pi 自己知道的鄰居（ARP，含只在廣播裡出現過的）=="
ip neigh show | sed 's/^/   /'
echo
echo "== E. 交叉比對：ARP 裡有、但抓包看不到單播的 =="
for ip in $(ip neigh show | awk '{print $1}' | grep '^192\.168\.'); do
  c=$(tshark -r "$TMP/vis.pcap" -Y "ip.addr==$ip && !(eth.dst[0] & 1)" 2>/dev/null | wc -l)
  [ "$c" -eq 0 ] && printf '   %-16s 單播 0 個 → 盲區（或這 %ss 剛好沒講話）\n' "$ip" "$SEC"
done
echo
echo "== F. 目前 tcpdump 常駐抓包的過濾器（它自己也是一層盲區）=="
pgrep -af tcpdump | grep -v "$TMP" | sed 's/^/   /'
) 2>&1

RPT_DIR=/opt/xiaoai/reports; mkdir -p "$RPT_DIR" 2>/dev/null || RPT_DIR=/tmp
RPT="$RPT_DIR/pi_visibility_$(date '+%Y%m%d_%H%M%S').txt"
printf '%s\n' "$OUT" > "$RPT" && echo "（本機留底：$RPT）"
URL="$(printf '%s\n' "$OUT" | curl -s --max-time 60 --data-binary @- https://paste.rs/)"
case "$URL" in
  http*) echo "$URL" ;;
  *) echo "!!!!!!!! paste.rs 上傳失敗（回應：${URL:-空}）—— 以下為報告全文 !!!!!!!!"
     printf '%s\n' "$OUT" ;;
esac
