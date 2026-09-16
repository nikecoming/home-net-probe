# home-net-probe

家用網路觀測工具（王家，2026-09）。兩部分：

## 1. 瀏覽器觀測台
https://nikecoming.github.io/home-net-probe/ — 家裡任何電腑的 Chrome 開著就量：每分鐘一輪路徑探針、每 5 秒一次秒級停頓探針、Cloudflare 吞吐；「斷了／順了」按鍵蓋時間戳；匯出 CSV。

## 2. Raspberry Pi 抓包（看喇叭到底連去哪）

### 燒卡（Raspberry Pi Imager）
1. 裝置：Raspberry Pi 3 ；系統：**Raspberry Pi OS Lite (64-bit)**（Bookworm）。
2. 「編輯設定」：主機名 `xiaoai-pi`；使用者 `pi` ＋ 自訂密碾；**服務 → 啟用 SSH（密碼登入）**；WiFi 可不設（用有線）。
3. 燒好插卡、接網線到**路由器本體的有線埠**（鏡像只能鏡到路由器自己的埠；插交換器抓不到）、上電。

### 2026-09-16 這張卡已由 Claude 預先設好（cloud-init，全自動）
- 帳號 `nikecoming`（Imager 設的密碼）、主機名 `WangHomePI`、SSH 已開、時區台北。
- **首次開機接上有線網路後**：自動安裝 tcpdump/tshark → 啟動 `xiaoai-capture.service`（抓三台小愛，`/opt/xiaoai/pcap/`，10 分鐘切檔）與 `xiaoai-intlwatch.service`（家裡端境外監測 `/opt/xiaoai/_intl_watch_home.csv`）。`~/xiaoai` 是 `/opt/xiaoai` 的連結。
- 首次開機會裝套件，請給它 5–10 分鐘；完成的記號：`cat ~/xiaoai/READY.txt`。
- 看摘要：`~/xiaoai/pi_summary.sh`（會用 sudo 讀 root 抓的 pcap）。
- 若 cloud-init 沒跑成，才用下面的手動安裝。

### 手動安裝與啟動（備援）
```bash
curl -fsSL https://nikecoming.github.io/home-net-probe/pi_setup.sh | bash
cd ~/xiaoai && ./pi_capture.sh          # 背景抓三台小愛（192.168.2.5/.6/.20），10 分鐘切檔
```
接著告訴 Claude「插好了」——由路由器端把其他 LAN 埠鏡像到 Pi 所在的埠。

### 看結果
```bash
cd ~/xiaoai && ./pi_summary.sh          # 全部檔
cd ~/xiaoai && ./pi_summary.sh 3        # 只看最近 3 檔（30 分鐘）
```
輸出：小愛問了哪些 DNS、拿到哪些 IP、TLS SNI（實際連去的主機名）、目的 IP 排行、重傳數、每分鐘下載量。把整段貼給 Claude。

### 停止
```bash
sudo pkill tcpdump; pkill -f intl_watch.py
```
