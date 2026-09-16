# 境外穩定度監測（可移植：Windows/Linux 皆可，純 TCP 連線計時，不用 ICMP）。
# 用法：python intl_watch.py <站點標籤> [小時]   例：python intl_watch.py church 24 ／ python intl_watch.py home 24
import socket, time, csv, os, sys, urllib.request
SITE = sys.argv[1] if len(sys.argv) > 1 else 'site'
HOURS = float(sys.argv[2]) if len(sys.argv) > 2 else 24
OUT = os.environ.get('INTL_WATCH_OUT', os.path.join(os.path.dirname(os.path.abspath(__file__)), f'_intl_watch_{SITE}.csv'))
TARGETS = [('cloudflare_1.1.1.1','1.1.1.1',443),('google_8.8.8.8','8.8.8.8',443),('hinet_dns_168.95.1.1_p53','168.95.1.1',53),
           ('us_aws_us-east','ec2.us-east-1.amazonaws.com',443),('jp_aws_tokyo','ec2.ap-northeast-1.amazonaws.com',443),
           ('hk_aws','ec2.ap-east-1.amazonaws.com',443),('qq_isure_43.152.14.111','43.152.14.111',443),('qq_ws_43.175.44.41','43.175.44.41',443),
           ('qq_isure_203.205.137.157','203.205.137.157',443),('xiaomi_mina_47.236.127.146','47.236.127.146',443)]
def tcp(host, port, timeout=5):
    t0 = time.time()
    try:
        ip = socket.gethostbyname(host); sk = socket.create_connection((ip, port), timeout=timeout); sk.close()
        return int((time.time() - t0) * 1000)
    except Exception as e: return f'FAIL:{type(e).__name__}'
def throughput_kbps(url='https://speed.cloudflare.com/__down?bytes=3000000', secs=8):
    t0 = time.time(); got = 0
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 intl_watch'})
        with urllib.request.urlopen(req, timeout=15) as r:
            while time.time() - t0 < secs:
                c = r.read(65536)
                if not c: break
                got += len(c)
        return int(got * 8 / 1000 / max(0.001, time.time() - t0))
    except Exception as e: return f'FAIL:{type(e).__name__}'
new = not os.path.exists(OUT)
with open(OUT, 'a', newline='', encoding='utf-8') as f:
    w = csv.writer(f)
    if new: w.writerow(['time','site'] + [t[0] for t in TARGETS] + ['cloudflare_kbps(hourly)'])
    end = time.time() + HOURS * 3600; n = 0
    while time.time() < end:
        t0 = time.time(); row = [time.strftime('%Y-%m-%d %H:%M:%S'), SITE] + [tcp(h, p) for _, h, p in TARGETS]
        row.append(throughput_kbps() if n % 60 == 0 else ''); w.writerow(row); f.flush(); n += 1
        time.sleep(max(0, 60 - (time.time() - t0)))
