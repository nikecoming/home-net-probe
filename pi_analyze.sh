#!/usr/bin/env bash
# 分析最近 N 個 pcap（預設 3），輸出貼到 paste.rs，印出網址。以 root 跑（curl ... | sudo bash）。
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
N="${1:-3}"
cd /opt/xiaoai/pcap 2>/dev/null || { echo "no pcap dir"; exit 1; }
FILES=$(ls -t xiaoai_*.pcap 2>/dev/null | head -"$N" | sort)
[ -z "$FILES" ] && { echo "no pcap files"; exit 1; }
M=/tmp/xiaoai_merged.pcap
mergecap -w "$M" $FILES 2>>"$TSERR"
SP='ip.src==192.168.2.5 || ip.src==192.168.2.6 || ip.src==192.168.2.20'
ANY='ip.addr==192.168.2.5 || ip.addr==192.168.2.6 || ip.addr==192.168.2.20'
OUT=$( {
  echo "== 檔案 =="; ls -la $FILES | awk '{print $9, $5" B"}'
  echo; echo "== 小愛問了哪些 DNS（次數 / src / 域名）=="
  tshark -r "$M" -Y "dns.flags.response==0 && ($SP)" -T fields -e ip.src -e dns.qry.name 2>>"$TSERR" | sort | uniq -c | sort -rn | head -40
  echo; echo "== DNS 答案（域名 → IP，次數）=="
  tshark -r "$M" -Y "dns.a" -T fields -e dns.qry.name -e dns.a 2>>"$TSERR" | sort | uniq -c | sort -rn | head -40
  echo; echo "== TLS SNI（連去的主機名 / 目的IP / 次數）=="
  tshark -r "$M" -Y "tls.handshake.type==1 && ($SP)" -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>>"$TSERR" | sort | uniq -c | sort -rn | head -40
  echo; echo "== 目的 IP（TCP 非區網，依封包數）=="
  tshark -r "$M" -Y "tcp && ($SP) && !(ip.dst==192.168.2.0/24)" -T fields -e ip.src -e ip.dst -e tcp.dstport 2>>"$TSERR" | sort | uniq -c | sort -rn | head -30
  echo; echo "== ICMP 目標（小愛 ping 誰 / 次數）=="
  tshark -r "$M" -Y "icmp && ($SP)" -T fields -e ip.src -e ip.dst 2>>"$TSERR" | sort | uniq -c | sort -rn | head -20
  echo; echo "== 重傳／遺失（每個目的 IP）=="
  tshark -r "$M" -Y "(tcp.analysis.retransmission || tcp.analysis.lost_segment) && ($ANY)" -T fields -e ip.src -e ip.dst 2>>"$TSERR" | sort | uniq -c | sort -rn | head -20
  echo; echo "== 每分鐘進到小愛的位元組（下載量 KB）=="
  tshark -r "$M" -Y "ip.dst==192.168.2.5 || ip.dst==192.168.2.6 || ip.dst==192.168.2.20" -T fields -e frame.time_epoch -e frame.len 2>>"$TSERR" | awk '{t=int($1/60)*60; b[t]+=$2; if(mn==0||t<mn)mn=t; if(t>mx)mx=t}
   END{if(mn==0){print "  （此區間無任何封包）"; exit}
       for(t=mn;t<=mx;t+=60) printf "%s %8.1f%s\n", strftime("%m/%d %H:%M",t), b[t]/1024, (b[t]==0?"   <<< 歸零":"")}'
} 2>&1 )
rm -f "$M"
# --- 出貨：先落地再上傳；上傳失敗就把報告整份印出來，不讓資料消失（2026-09-19 三審修）---
RPT_DIR=/opt/xiaoai/reports; mkdir -p "$RPT_DIR" 2>/dev/null || RPT_DIR=/tmp
RPT="$RPT_DIR/pi_analyze_$(date '+%Y%m%d_%H%M%S').txt"
printf '%s\n' "$OUT" > "$RPT" && echo "（本機留底：$RPT）"
URL="$(printf '%s\n' "$OUT" | curl -s --max-time 60 --data-binary @- https://paste.rs/)"
case "$URL" in
  http*) echo "$URL" ;;
  *) echo "!!!!!!!! paste.rs 上傳失敗（回應：${URL:-空}）—— 以下為報告全文 !!!!!!!!"
     printf '%s\n' "$OUT" ;;
esac
echo
