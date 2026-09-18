#!/usr/bin/env bash
# 判別重傳是「路徑丟包」還是「隧道 MSS/MTU 問題」。
# 依封包大小分群：滿載大段重傳 = MTU/MSS 嫌疑；小段均勻重傳 = 單純丟包。
# 並把目的 IP 分成「走教會隧道」與「走凱擘直連」兩群比較。
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
M=/tmp/path_merged.pcap
FILES=$(ls -t "$D"/*.pcap 2>/dev/null | head -6)
[ -z "$FILES" ] && { echo "找不到 pcap（$D）"; exit 1; }
mergecap -w "$M" $FILES 2>>"$TSERR" || { echo mergecap 失敗; exit 1; }
SP='ip.src==192.168.2.5 || ip.src==192.168.2.6 || ip.src==192.168.2.20'
DP='ip.dst==192.168.2.5 || ip.dst==192.168.2.6 || ip.dst==192.168.2.20'

# 走教會隧道的網段（路由器 user_route，enable=on）
CHURCH='47.0.0.0/8 39.96.0.0/11 8.208.0.0/12 8.128.0.0/10 101.128.0.0/11 106.0.0.0/10 162.128.37.0/24 119.29.29.0/24 203.107.0.0/16 210.72.0.0/16 120.197.0.0/16'
FILT=""; for _n in $CHURCH; do FILT="$FILT||ip.addr==$_n"; done; FILT="(${FILT#||})"   # 修：paste -d 逐字元循環，'||' 只接出單一 |，是非法 dfilter

OUT=$(
echo "== 產生時間 $(date '+%F %T') / 檔案 $(echo $FILES | wc -w) 個 =="
echo
echo "== A. 重傳封包的大小分布（判 MTU/MSS）=="
echo "   滿載段(>=1300B)佔比高 => 隧道 MSS 沒夾緊；平均分布 => 單純丟包"
tshark -r "$M" -Y "tcp.analysis.retransmission && ($SP || $DP)" -T fields -e frame.len 2>>"$TSERR" \
 | awk '{n++; s+=$1; if($1>=1300)big++; else if($1>=600)mid++; else sml++}
        END{if(n==0){print "   （無重傳）";exit}
            printf "   重傳 %d 個，平均 %d B\n",n,s/n;
            printf "   >=1300B: %4d (%.1f%%)   600-1299B: %4d (%.1f%%)   <600B: %4d (%.1f%%)\n",
                   big,100*big/n, mid,100*mid/n, sml,100*sml/n}'
echo
echo "== B. 對照：全部封包的大小分布 =="
tshark -r "$M" -Y "tcp && ($SP || $DP)" -T fields -e frame.len 2>>"$TSERR" \
 | awk '{n++; if($1>=1300)big++; else if($1>=600)mid++; else sml++}
        END{if(n==0)exit; printf "   全部 %d 個  >=1300B: %.1f%%   600-1299B: %.1f%%   <600B: %.1f%%\n",
                   n,100*big/n,100*mid/n,100*sml/n}'
echo
echo "== C. 走教會隧道 vs 走凱擘直連（各自的重傳率）=="
CT=$(tshark -r "$M" -Y "tcp && ($FILT) && ($SP || $DP)" 2>>"$TSERR" | wc -l)
CR=$(tshark -r "$M" -Y "tcp.analysis.retransmission && ($FILT) && ($SP || $DP)" 2>>"$TSERR" | wc -l)
KT=$(tshark -r "$M" -Y "tcp && !($FILT) && ($SP || $DP)" 2>>"$TSERR" | wc -l)
KR=$(tshark -r "$M" -Y "tcp.analysis.retransmission && !($FILT) && ($SP || $DP)" 2>>"$TSERR" | wc -l)
awk -v ct="$CT" -v cr="$CR" -v kt="$KT" -v kr="$KR" 'BEGIN{
  printf "   走教會隧道 : %7d 封包  %5d 重傳  %5.2f%%\n", ct, cr, (ct?100*cr/ct:0);
  printf "   走凱擘直連 : %7d 封包  %5d 重傳  %5.2f%%\n", kt, kr, (kt?100*kr/kt:0);}'
echo
echo "== D. SYN 裡協商的 MSS（看隧道有沒有夾緊）=="
tshark -r "$M" -Y "tcp.flags.syn==1 && ($SP || $DP)" -T fields -e ip.src -e ip.dst -e tcp.options.mss_val 2>>"$TSERR" \
 | awk 'NF==3 && $3!=""{k=$3; c[k]++} END{for(m in c) printf "   MSS %-6s  %d 次\n", m, c[m]}' | sort -k2 -rn | head
echo
echo "== E. ICMP 需分割 / 不可達（PMTUD 訊號）=="
tshark -r "$M" -Y "icmp.type==3" -T fields -e ip.src -e icmp.code 2>>"$TSERR" | sort | uniq -c | sort -rn | head
[ -z "$(tshark -r "$M" -Y 'icmp.type==3' 2>>"$TSERR")" ] && echo "   （無，代表沒有 PMTUD 回饋）"
)
echo "$OUT"
echo
echo "---- 上傳中 ----"
# --- 出貨：先落地再上傳；上傳失敗就把報告整份印出來，不讓資料消失（2026-09-19 三審修）---
RPT_DIR=/opt/xiaoai/reports; mkdir -p "$RPT_DIR" 2>/dev/null || RPT_DIR=/tmp
RPT="$RPT_DIR/pi_path_$(date '+%Y%m%d_%H%M%S').txt"
printf '%s\n' "$OUT" > "$RPT" && echo "（本機留底：$RPT）"
URL="$(printf '%s\n' "$OUT" | curl -s --max-time 60 --data-binary @- https://paste.rs/)"
case "$URL" in
  http*) echo "$URL" ;;
  *) echo "!!!!!!!! paste.rs 上傳失敗（回應：${URL:-空}）—— 以下為報告全文 !!!!!!!!"
     printf '%s\n' "$OUT" ;;
esac
echo
