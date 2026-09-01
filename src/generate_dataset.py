"""Generate 1-5 years of synthetic SOC history.

Set HISTORY_YEARS=1..5 (default 5). The generated timestamps end at the
current time so the dataset can be combined with the live simulator.
"""
import os, random, ipaddress
from datetime import datetime, timedelta

random.seed(42)
HISTORY_YEARS = max(1, min(5, int(os.getenv("HISTORY_YEARS", "5"))))
END = datetime.now().replace(microsecond=0)
START = END - timedelta(days=365 * HISTORY_YEARS)

EMPLOYEES = ["jsmith", "amartin", "rkumar", "lgarcia", "twong", "kpatel", "bwilliams", "nchen", "mrossi", "sohara", "dfoster", "hyamada", "cbrooks", "epena", "fmuller", "gsingh", "iivanov", "jkovacs", "kalvarez", "lweber"]
SERVICE_ACCOUNTS = ["svc_backup", "svc_deploy", "svc_monitor"]
ADMIN_ACCOUNTS = ["admin", "root"]
INTERNAL_IPS = [f"10.20.{random.randint(0,5)}.{i}" for i in range(10, 60)]
EMP_HOME_IP = {u: f"10.20.{random.randint(0,5)}.{random.randint(60,240)}" for u in EMPLOYEES}
HOSTS = ["auth-srv01", "web-srv01", "app-srv02", "db-srv01"]
WEB_PATHS = ["/", "/login", "/dashboard", "/api/v1/users", "/api/v1/orders", "/static/app.css", "/static/app.js", "/account/settings", "/checkout", "/api/v1/products", "/logout"]
SCAN_PATHS = ["/wp-login.php", "/.env", "/admin/config.php", "/phpmyadmin/", "/.git/config", "/server-status", "/api/v1/../../etc/passwd", "/xmlrpc.php", "/wp-admin/", "/config.json", "/backup.zip"]
UA_NORMAL = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15", "Mozilla/5.0 (X11; Linux x86_64) Chrome/123.0 Safari/537.36"]
UA_BOT = ["python-requests/2.31.0", "curl/8.4.0", "sqlmap/1.7.11", "Go-http-client/1.1"]
ATTACKER_IP_BRUTE, ATTACKER_IP_SPRAY, ATTACKER_IP_STUFF, ATTACKER_IP_SCAN = "185.220.101.47", "45.155.205.12", "193.106.31.98", "89.248.165.74"
PUBLIC_IP_POOL = [f"198.51.100.{i}" for i in range(10, 60)]
TRAVEL_IP_2 = "203.0.113.55"

auth_records, web_records = [], []
PID_COUNTER = 20000

def rand_public_ip():
    while True:
        ip = ipaddress.IPv4Address(random.randint(1, 2**32 - 1))
        if ip.is_global and not ip.is_multicast:
            return str(ip)

def auth_log(ts, host, user, src_ip, success, reason=None):
    global PID_COUNTER
    PID_COUNTER += 1
    msg = (f"Accepted password for {user} from {src_ip} port {random.randint(30000,60000)} ssh2" if success
           else f"Failed password for {'invalid user ' if reason == 'invalid_user' else ''}{user} from {src_ip} port {random.randint(30000,60000)} ssh2")
    auth_records.append((ts, f"{ts.strftime('%b %d %H:%M:%S')} {host} sshd[{PID_COUNTER}]: {msg}"))

def web_log(ts, src_ip, method, path, status, size, ua, user=None):
    user_field = user if user else "-"
    web_records.append((ts, f'{src_ip} - {user_field} [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'))

# Efficient historical background: one activity tick every hour.
cur = START.replace(minute=0, second=0)
while cur <= END:
    if 8 <= cur.hour <= 19:
        login_probability, web_count = 0.70, random.randint(3, 7)
    elif 20 <= cur.hour <= 23:
        login_probability, web_count = 0.25, random.randint(1, 4)
    else:
        login_probability, web_count = 0.02, random.randint(1, 2)
    if random.random() < login_probability:
        user = random.choice(EMPLOYEES); ip = EMP_HOME_IP[user]
        if random.random() < 0.04: auth_log(cur, random.choice(HOSTS), user, ip, False)
        auth_log(cur, random.choice(HOSTS), user, ip, True)
    if random.random() < 0.15:
        auth_log(cur, random.choice(HOSTS), random.choice(SERVICE_ACCOUNTS), "10.20.0.5", True)
    for _ in range(web_count):
        ip = random.choice(INTERNAL_IPS + PUBLIC_IP_POOL)
        path = random.choice(WEB_PATHS)
        status = 200 if random.random() > 0.05 else random.choice([301, 302, 404])
        web_log(cur, ip, "GET", path, status, random.randint(200, 15000), random.choice(UA_NORMAL))
    cur += timedelta(hours=1)

# Repeat controlled attack scenarios roughly once per month. This makes long-term
# trend charts meaningful while keeping the dataset explainable.
month_cursor = START.replace(day=5, hour=0, minute=0, second=0)
while month_cursor <= END:
    base = month_cursor
    # A: brute force
    t = base + timedelta(hours=3, minutes=10)
    for _ in range(60):
        auth_log(t, "auth-srv01", random.choice(["root", "admin"]), ATTACKER_IP_BRUTE, False)
        t += timedelta(seconds=random.randint(3, 9))
    auth_log(t, "auth-srv01", "admin", ATTACKER_IP_BRUTE, True)
    # B: password spray
    t = base + timedelta(hours=14, minutes=2)
    for user in random.sample(EMPLOYEES, 15) + ["admin", "svc_backup"]:
        for _ in range(random.randint(1, 2)):
            auth_log(t, "auth-srv01", user, ATTACKER_IP_SPRAY, False)
            t += timedelta(seconds=random.randint(20, 50))
    # C: credential stuffing
    t = base + timedelta(hours=22, minutes=40)
    for _ in range(150):
        web_log(t, ATTACKER_IP_STUFF, "POST", "/login", random.choice([401, 401, 401, 200]), random.randint(300, 900), random.choice(UA_BOT))
        t += timedelta(seconds=random.uniform(0.4, 1.5))
    # D: off-hours login
    auth_log(base + timedelta(hours=3, minutes=14), "auth-srv01", "hyamada", "77.91.124.10", True)
    # E: impossible travel
    travel = base + timedelta(hours=9)
    auth_log(travel, "auth-srv01", "kalvarez", EMP_HOME_IP["kalvarez"], True)
    auth_log(travel + timedelta(minutes=6), "auth-srv01", "kalvarez", TRAVEL_IP_2, True)
    # F: recon
    t = base + timedelta(hours=1, minutes=5)
    for path in SCAN_PATHS * 4:
        web_log(t, ATTACKER_IP_SCAN, "GET", path, random.choice([404, 404, 404, 403, 500]), random.randint(150, 500), random.choice(UA_BOT))
        t += timedelta(seconds=random.uniform(0.2, 0.8))
    month_cursor += timedelta(days=32)
    month_cursor = month_cursor.replace(day=5)

# Keep chronological order. Auth syslog lines do not contain a year, so we retain
# the true timestamp internally while sorting and let the parser reconstruct years
# from month rollovers.
auth_records.sort(key=lambda x: x[0])
web_records.sort(key=lambda x: x[0])
auth_lines = [line for _, line in auth_records]
web_lines = [line for _, line in web_records]
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.makedirs(os.path.join(BASE, "data", "raw_logs"), exist_ok=True)
with open(os.path.join(BASE, "data", "raw_logs", "auth.log"), "w") as f: f.write("\n".join(auth_lines)+"\n")
with open(os.path.join(BASE, "data", "raw_logs", "web_access.log"), "w") as f: f.write("\n".join(web_lines)+"\n")
print(f"Generated {HISTORY_YEARS} year(s): {START} -> {END}")
print(f"auth.log lines: {len(auth_lines)}")
print(f"web_access.log lines: {len(web_lines)}")
