#!/usr/bin/env bash
# 把最近 N 個 pcap（預設全部）彙整成可貼給 Claude 的摘要：DNS 查詢、TLS SNI、目的 IP 排行、每分鐘位元組、重傳數。
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
cd ~/xiaoai/pcap || exit 1
FILES=$(ls -t xiaoai_*.pcap 2>/dev/null | head -${1:-48} | sort)
[ -z "$FILES" ] && { echo "沒有 pcap"; exit 1; }
SP="ip.src==192.168.2.5 || ip.src==192.168.2.6 || ip.src==192.168.2.20"
echo "=== 檔案 ==="; ls -la $FILES | awk '{print $6,$7,$8,$9,$5" bytes"}'
echo; echo "=== 小愛問了哪些 DNS（次數）==="
tshark -r <(mergecap -w - $FILES) -Y "dns.flags.response==0 && ($SP)" -T fields -e ip.src -e dns.qry.name 2>>"$TSERR" | sort | uniq -c | sort -rn | head -40
echo; echo "=== DNS 答案（域名 → IP，次數）==="
tshark -r <(mergecap -w - $FILES) -Y "dns.flags.response==1 && dns.a && (ip.dst==192.168.2.5 || ip.dst==192.168.2.6 || ip.dst==192.168.2.20)" -T fields -e dns.qry.name -e dns.a 2>>"$TSERR" | sort | uniq -c | sort -rn | head -40
echo; echo "=== TLS SNI（喇叭連去的主機名，次數）==="
tshark -r <(mergecap -w - $FILES) -Y "tls.handshake.type==1 && ($SP)" -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>>"$TSERR" | sort | uniq -c | sort -rn | head -40
echo; echo "=== 目的 IP（TCP，非區網，依封包數）==="
tshark -r <(mergecap -w - $FILES) -Y "tcp && ($SP) && !(ip.dst==192.168.2.0/24)" -T fields -e ip.src -e ip.dst -e tcp.dstport 2>>"$TSERR" | sort | uniq -c | sort -rn | head -30
echo; echo "=== 重傳／遺失（每個目的 IP）==="
tshark -r <(mergecap -w - $FILES) -Y "(tcp.analysis.retransmission || tcp.analysis.lost_segment) && (ip.addr==192.168.2.5 || ip.addr==192.168.2.6 || ip.addr==192.168.2.20)" -T fields -e ip.src -e ip.dst 2>>"$TSERR" | sort | uniq -c | sort -rn | head -20
echo; echo "=== 每分鐘進到小愛的位元組（下載量；斷音時應該掉到接近 0）==="
tshark -r <(mergecap -w - $FILES) -Y "ip.dst==192.168.2.5 || ip.dst==192.168.2.6 || ip.dst==192.168.2.20" -T fields -e frame.time_epoch -e frame.len 2>>"$TSERR" | awk '{t=int($1/60)*60; b[t]+=$2; if(mn==0||t<mn)mn=t; if(t>mx)mx=t}
   END{if(mn==0){print "  （此區間無任何封包）"; exit}
       if(mx-mn>3600) mn=mx-3600;
       for(t=mn;t<=mx;t+=60) printf "%s %8.1f KB%s\n", strftime("%m/%d %H:%M",t), b[t]/1024, (b[t]==0?"   <<< 歸零":"")}'
