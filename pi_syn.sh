#!/usr/bin/env bash
# 追問：566 個重傳平均只有 222B，那重傳的是「哪一種」封包？
# 若大量是 SYN 重傳 → 連線建立失敗重試，指數退避 1s/2s/4s/8s 正好長成「按播放等 20 秒」。
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
M=/tmp/syn_merged.pcap
FILES=$(ls -t "$D"/*.pcap 2>/dev/null | head -6)
[ -z "$FILES" ] && { echo "找不到 pcap（$D）"; exit 1; }
sudo mergecap -w "$M" $FILES 2>>"$TSERR" || { echo mergecap 失敗; exit 1; }
SP='ip.src==192.168.2.5||ip.src==192.168.2.6||ip.src==192.168.2.20'
DP='ip.dst==192.168.2.5||ip.dst==192.168.2.6||ip.dst==192.168.2.20'
ME="($SP||$DP)"

# 走教會隧道的網段（修掉上一版 paste -d 只接單一 | 的 bug）
CH="8.128.0.0/10 8.208.0.0/12 39.96.0.0/11 47.0.0.0/8 101.128.0.0/11 106.0.0.0/10 162.128.37.0/24 119.29.29.0/24 203.107.0.0/16 210.72.0.0/16 120.197.0.0/16"
F=""; for n in $CH; do F="$F||ip.addr==$n"; done; F="(${F#||})"

q(){ sudo tshark -r "$M" -Y "$1" 2>>"$TSERR" | wc -l; }

OUT=$(
echo "== 產生 $(date '+%F %T') / $(echo $FILES | wc -w) 檔 =="
echo
echo "== A. 重傳的是哪一種封包 =="
R=$(q "tcp.analysis.retransmission&&$ME")
RS=$(q "tcp.analysis.retransmission&&tcp.flags.syn==1&&tcp.flags.ack==0&&$ME")
RA=$(q "tcp.analysis.retransmission&&tcp.flags.syn==1&&tcp.flags.ack==1&&$ME")
RD=$(q "tcp.analysis.retransmission&&tcp.len>0&&$ME")
RK=$(q "tcp.analysis.retransmission&&tcp.len==0&&tcp.flags.syn==0&&tcp.flags.fin==0&&$ME")
RF=$(q "tcp.analysis.retransmission&&tcp.flags.fin==1&&$ME")
awk -v r="$R" -v s="$RS" -v a="$RA" -v d="$RD" -v k="$RK" -v f="$RF" 'BEGIN{
 p=(r?100/r:0);
 printf "   總重傳          %5d\n",r;
 printf "   SYN（建連）     %5d  %5.1f%%   <= 高就是「連不上、退避重試」\n",s,s*p;
 printf "   SYN-ACK         %5d  %5.1f%%\n",a,a*p;
 printf "   有資料的段      %5d  %5.1f%%\n",d,d*p;
 printf "   純 ACK/保活     %5d  %5.1f%%\n",k,k*p;
 printf "   FIN             %5d  %5.1f%%\n",f,f*p;}'
echo
echo "== B. 有多少條連線「建立時就要重試 SYN」=="
TOT=$(sudo tshark -r "$M" -Y "tcp.flags.syn==1&&tcp.flags.ack==0&&$ME" -T fields -e tcp.stream 2>>"$TSERR"|sort -u|wc -l)
BAD=$(sudo tshark -r "$M" -Y "tcp.analysis.retransmission&&tcp.flags.syn==1&&tcp.flags.ack==0&&$ME" -T fields -e tcp.stream 2>>"$TSERR"|sort -u|wc -l)
awk -v t="$TOT" -v b="$BAD" 'BEGIN{printf "   嘗試建立 %d 條，其中 %d 條要重送 SYN（%.1f%%）\n",t,b,(t?100*b/t:0)}'
echo
echo "== C. SYN 重傳最多的目的地（誰連不上）=="
sudo tshark -r "$M" -Y "tcp.analysis.retransmission&&tcp.flags.syn==1&&tcp.flags.ack==0&&$ME" \
  -T fields -e ip.dst -e tcp.dstport 2>>"$TSERR" | sort | uniq -c | sort -rn | head -12 | sed 's/^/   /'
echo
echo "== D. 建連 RTT 分布（tcp.analysis.initial_rtt，秒）=="
sudo tshark -r "$M" -Y "tcp.analysis.initial_rtt&&$ME" -T fields -e tcp.analysis.initial_rtt 2>>"$TSERR"  | sort -n | awk '{n++; v[n]=$1+0; s+=v[n]; if(v[n]>1)slow++; if(v[n]>3)vslow++}
   END{if(!n){print "   （無資料）";exit}
     printf "   %d 條  中位數 %.3f  平均 %.3f  最大 %.3f
",n,v[int(n/2)+1],s/n,v[n];
     printf "   >1 秒 %d 條 (%.1f%%)   >3 秒 %d 條 (%.1f%%)  <= 這些就是使用者等的時間
",slow,100*slow/n,vslow,100*vslow/n}'
echo
echo "== E. 隧道 vs 直連（filter 已修）=="
CT=$(q "tcp&&$F&&$ME"); CR=$(q "tcp.analysis.retransmission&&$F&&$ME")
KT=$(q "tcp&&!$F&&$ME"); KR=$(q "tcp.analysis.retransmission&&!$F&&$ME")
awk -v ct="$CT" -v cr="$CR" -v kt="$KT" -v kr="$KR" 'BEGIN{
 printf "   走教會隧道 : %7d 封包 %5d 重傳 %6.2f%%\n",ct,cr,(ct?100*cr/ct:0);
 printf "   走凱擘直連 : %7d 封包 %5d 重傳 %6.2f%%\n",kt,kr,(kt?100*kr/kt:0)}'
)
echo "$OUT"
echo; echo "---- 上傳中 ----"
# --- 出貨：先落地再上傳；上傳失敗就把報告整份印出來，不讓資料消失（2026-09-19 三審修）---
RPT_DIR=/opt/xiaoai/reports; mkdir -p "$RPT_DIR" 2>/dev/null || RPT_DIR=/tmp
RPT="$RPT_DIR/pi_syn_$(date '+%Y%m%d_%H%M%S').txt"
printf '%s\n' "$OUT" > "$RPT" && echo "（本機留底：$RPT）"
URL="$(printf '%s\n' "$OUT" | curl -s --max-time 60 --data-binary @- https://paste.rs/)"
case "$URL" in
  http*) echo "$URL" ;;
  *) echo "!!!!!!!! paste.rs 上傳失敗（回應：${URL:-空}）—— 以下為報告全文 !!!!!!!!"
     printf '%s\n' "$OUT" ;;
esac
echo
