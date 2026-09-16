#!/usr/bin/env bash
# 抓三台小愛（192.168.2.5/.6/.20）經鏡像埠送來的封包；每 10 分鐘切一檔，保留 48 檔（8 小時）。同時啟動家裡端境外監測。
IFACE="${IFACE:-$(ip -br link | awk '$1 ~ /^(eth|en)/ && $2=="UP"{print $1;exit}')}"
[ -z "$IFACE" ] && IFACE=eth0
cd ~/xiaoai
sudo pkill -f "tcpdump -i $IFACE" 2>/dev/null; sleep 1
nohup sudo tcpdump -i "$IFACE" -nn -s 0 -U -G 600 -W 48 -w "pcap/xiaoai_%Y%m%d_%H%M.pcap" \
  '(host 192.168.2.5 or host 192.168.2.6 or host 192.168.2.20) and not arp' > capture.log 2>&1 &
echo "tcpdump 已在 $IFACE 背景執行（pid $!）；檔案在 ~/xiaoai/pcap/"
pkill -f intl_watch.py 2>/dev/null
nohup python3 intl_watch.py home 48 > intl_watch.log 2>&1 &
echo "家裡端境外監測已啟動（_intl_watch_home.csv）"
sleep 3; ls -la pcap | tail -3
echo "提醒：鏡像埠要由路由器設定（Claude 從教會遠端設），設好前這裡只會看到廣播封包。"
