#!/usr/bin/env bash
# Raspberry Pi 安裝：tcpdump / tshark / python3；建立 ~/xiaoai 工作目錄。用法：curl -s https://nikecoming.github.io/home-net-probe/pi_setup.sh | bash
set -e
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpdump tshark python3 >/dev/null
sudo usermod -aG wireshark "$USER" 2>/dev/null || true
mkdir -p ~/xiaoai/pcap
cd ~/xiaoai
curl -fsSL https://nikecoming.github.io/home-net-probe/pi_capture.sh -o pi_capture.sh
curl -fsSL https://nikecoming.github.io/home-net-probe/pi_summary.sh -o pi_summary.sh
curl -fsSL https://nikecoming.github.io/home-net-probe/intl_watch.py -o intl_watch.py
chmod +x pi_capture.sh pi_summary.sh
echo "== 網卡與 IP =="; ip -br addr | grep -v '^lo'
echo "== 安裝完成。啟動抓包：  cd ~/xiaoai && ./pi_capture.sh   （背景跑，抓三台小愛）"
echo "==            摘要：      cd ~/xiaoai && ./pi_summary.sh   （印出可直接貼給 Claude 的文字）"
