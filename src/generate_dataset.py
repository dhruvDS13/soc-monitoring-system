"""
generate_dataset.py
--------------------
Generates a realistic, synthetic security log dataset for the SOC project:

1. data/raw_logs/auth.log        -> Linux-style SSH/PAM authentication log (syslog format)
2. data/raw_logs/web_access.log  -> Nginx/Apache "combined" access log format

The generator simulates ~5 days of normal traffic from a small company
(20 employees, a handful of service accounts, a public web app) and then
INJECTS several realistic attack scenarios so the detection engine has
something real to find:

  - Scenario A: SSH brute-force from a single external IP against 'root' and 'admin'
  - Scenario B: Password-spraying - one IP tries many different usernames with 1-2
                attempts each (low & slow, designed to dodge simple per-user thresholds)
  - Scenario C: Credential-stuffing on the web login endpoint (high-frequency POSTs)
  - Scenario D: Off-hours successful login from an internal user (compromised creds
                used at 03:14 local time)
  - Scenario E: A single "traveling" account logging in from two geographically
                distant IPs within minutes (impossible travel)
  - Scenario F: A web crawler/scanner hitting many different paths very fast
                (looks like recon / vuln scanning, mixed 404s)

This is NOT real data (no real hosts, people or IPs) - it exists purely so the
rest of the pipeline (parsing -> SQL -> detection -> dashboard) has believable
input to work on, the same way a junior analyst would work off a SIEM export.
"""

import random
from datetime import datetime, timedelta
import ipaddress

random.seed(42)

START = datetime(2025, 6, 1, 0, 0, 0)
DAYS = 6

EMPLOYEES = [
    "jsmith", "amartin", "rkumar", "lgarcia", "twong", "kpatel", "bwilliams",
    "nchen", "mrossi", "sohara", "dfoster", "hyamada", "cbrooks", "epena",
    "fmuller", "gsingh", "iivanov", "jkovacs", "kalvarez", "lweber",
]
SERVICE_ACCOUNTS = ["svc_backup", "svc_deploy", "svc_monitor"]
ADMIN_ACCOUNTS = ["admin", "root"]
ALL_VALID_USERS = EMPLOYEES + SERVICE_ACCOUNTS + ADMIN_ACCOUNTS

# Internal corporate IP pool (office + VPN)
INTERNAL_IPS = [f"10.20.{random.randint(0,5)}.{i}" for i in range(10, 60)]
EMP_HOME_IP = {u: f"10.20.{random.randint(0,5)}.{random.randint(60,240)}" for u in EMPLOYEES}

HOSTS = ["auth-srv01", "web-srv01", "app-srv02", "db-srv01"]

WEB_PATHS = [
    "/", "/login", "/dashboard", "/api/v1/users", "/api/v1/orders",
    "/static/app.css", "/static/app.js", "/account/settings", "/checkout",
    "/api/v1/products", "/logout",
]
SCAN_PATHS = [
    "/wp-login.php", "/.env", "/admin/config.php", "/phpmyadmin/",
    "/.git/config", "/server-status", "/api/v1/../../etc/passwd",
    "/xmlrpc.php", "/wp-admin/", "/config.json", "/backup.zip",
]

UA_NORMAL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0 Safari/537.36",
]
UA_BOT = ["python-requests/2.31.0", "curl/8.4.0", "sqlmap/1.7.11", "Go-http-client/1.1"]

def rand_public_ip():
    while True:
        ip = ipaddress.IPv4Address(random.randint(1, 2**32 - 1))
        if ip.is_global and not ip.is_multicast:
            return str(ip)

ATTACKER_IP_BRUTE = "185.220.101.47"      # Scenario A
ATTACKER_IP_SPRAY = "45.155.205.12"       # Scenario B
ATTACKER_IP_STUFF = "193.106.31.98"       # Scenario C
ATTACKER_IP_SCAN = "89.248.165.74"        # Scenario F
TRAVEL_IP_2 = "203.0.113.55"              # Scenario E (far away IP)

auth_lines = []
web_lines = []
PID_COUNTER = 20000


def auth_log(ts, host, user, src_ip, success, reason=None, pid=None):
    global PID_COUNTER
    if pid is None:
        PID_COUNTER += 1
        pid = PID_COUNTER
    ts_str = ts.strftime("%b %d %H:%M:%S")
    if success:
        msg = f"Accepted password for {user} from {src_ip} port {random.randint(30000,60000)} ssh2"
    else:
        if reason == "invalid_user":
            msg = f"Failed password for invalid user {user} from {src_ip} port {random.randint(30000,60000)} ssh2"
        else:
            msg = f"Failed password for {user} from {src_ip} port {random.randint(30000,60000)} ssh2"
    auth_lines.append(f"{ts_str} {host} sshd[{pid}]: {msg}")


def web_log(ts, src_ip, method, path, status, size, ua, user=None):
    ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    user_field = user if user else "-"
    web_lines.append(
        f'{src_ip} - {user_field} [{ts_str}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
    )


# ---------------------------------------------------------------------------
# 1. Normal background traffic over DAYS days
# ---------------------------------------------------------------------------
cur = START
while cur < START + timedelta(days=DAYS):
    # Business-hours-weighted login activity.
    # 08:00-19:00 -> normal office activity (most logins happen here)
    # 20:00-23:59 -> a little late-evening remote work, reduced volume
    # 00:00-07:59 -> essentially nobody logs in (small company, no night shift);
    #                only a tiny chance of a legitimate early-riser/late-worker login
    if 8 <= cur.hour <= 19:
        hour_weight = 3
        login_chance = 1.0
    elif 20 <= cur.hour <= 23:
        hour_weight = 1
        login_chance = 0.5
    else:  # 00:00 - 07:59, off-hours
        hour_weight = 1
        login_chance = 0.03

    for _ in range(hour_weight):
        if random.random() > login_chance:
            continue
        user = random.choice(EMPLOYEES)
        ip = EMP_HOME_IP[user]
        host = random.choice(HOSTS)
        # 96% success, occasional real typo failure then success
        if random.random() < 0.04:
            auth_log(cur, host, user, ip, success=False)
            cur += timedelta(seconds=random.randint(1, 5))
        auth_log(cur, host, user, ip, success=True)

    # occasional service account activity (scheduled jobs, low volume)
    if random.random() < 0.15:
        svc = random.choice(SERVICE_ACCOUNTS)
        auth_log(cur, random.choice(HOSTS), svc, "10.20.0.5", success=True)

    # normal web traffic
    for _ in range(random.randint(3, 10)):
        ip = random.choice(INTERNAL_IPS + [rand_public_ip() for _ in range(3)])
        path = random.choice(WEB_PATHS)
        status = 200 if random.random() > 0.05 else random.choice([301, 302, 404])
        web_log(cur, ip, "GET", path, status, random.randint(200, 15000), random.choice(UA_NORMAL))

    cur += timedelta(minutes=random.randint(2, 8))

# ---------------------------------------------------------------------------
# Scenario A: SSH brute force against root/admin from one external IP
# ---------------------------------------------------------------------------
bf_start = START + timedelta(days=2, hours=3, minutes=10)
t = bf_start
for i in range(60):
    target_user = random.choice(["root", "admin"])
    auth_log(t, "auth-srv01", target_user, ATTACKER_IP_BRUTE, success=False)
    t += timedelta(seconds=random.randint(3, 9))
# attacker finally guesses correctly (weak password on 'admin')
auth_log(t, "auth-srv01", "admin", ATTACKER_IP_BRUTE, success=True)

# ---------------------------------------------------------------------------
# Scenario B: Password spraying - one/two attempts across many usernames
# ---------------------------------------------------------------------------
spray_start = START + timedelta(days=3, hours=14, minutes=2)
t = spray_start
spray_targets = random.sample(EMPLOYEES, 15) + ["admin", "svc_backup"]
for user in spray_targets:
    for _ in range(random.randint(1, 2)):
        auth_log(t, "auth-srv01", user, ATTACKER_IP_SPRAY, success=False)
        t += timedelta(seconds=random.randint(20, 50))

# ---------------------------------------------------------------------------
# Scenario C: Credential stuffing against the web /login endpoint
# ---------------------------------------------------------------------------
stuff_start = START + timedelta(days=1, hours=22, minutes=40)
t = stuff_start
for i in range(150):
    web_log(t, ATTACKER_IP_STUFF, "POST", "/login", random.choice([401, 401, 401, 200]),
            random.randint(300, 900), random.choice(UA_BOT))
    t += timedelta(seconds=random.uniform(0.4, 1.5))

# ---------------------------------------------------------------------------
# Scenario D: Off-hours successful login (compromised credentials)
# ---------------------------------------------------------------------------
off_hours_ts = START + timedelta(days=4, hours=3, minutes=14)
auth_log(off_hours_ts, "auth-srv01", "hyamada", "77.91.124.10", success=True)

# ---------------------------------------------------------------------------
# Scenario E: Impossible travel - same user, two distant IPs within 6 minutes
# ---------------------------------------------------------------------------
travel_base = START + timedelta(days=4, hours=9, minutes=0)
auth_log(travel_base, "auth-srv01", "kalvarez", EMP_HOME_IP["kalvarez"], success=True)
auth_log(travel_base + timedelta(minutes=6), "auth-srv01", "kalvarez", TRAVEL_IP_2, success=True)

# ---------------------------------------------------------------------------
# Scenario F: Web scanner / recon sweep hitting many sensitive paths fast
# ---------------------------------------------------------------------------
scan_start = START + timedelta(days=5, hours=1, minutes=5)
t = scan_start
for path in SCAN_PATHS * 4:
    status = random.choice([404, 404, 404, 403, 500])
    web_log(t, ATTACKER_IP_SCAN, "GET", path, status, random.randint(150, 500), random.choice(UA_BOT))
    t += timedelta(seconds=random.uniform(0.2, 0.8))

# ---------------------------------------------------------------------------
# Sort and write out
# ---------------------------------------------------------------------------
def auth_sort_key(line):
    ts_part = line[:15]
    return datetime.strptime(f"2025 {ts_part}", "%Y %b %d %H:%M:%S")

auth_lines.sort(key=auth_sort_key)

with open("/home/claude/soc-project/data/raw_logs/auth.log", "w") as f:
    f.write("\n".join(auth_lines) + "\n")

# web lines: sort by embedded timestamp
def web_sort_key(line):
    ts_part = line.split("[")[1].split("]")[0]
    return datetime.strptime(ts_part, "%d/%b/%Y:%H:%M:%S %z")

web_lines.sort(key=web_sort_key)

with open("/home/claude/soc-project/data/raw_logs/web_access.log", "w") as f:
    f.write("\n".join(web_lines) + "\n")

print(f"auth.log lines: {len(auth_lines)}")
print(f"web_access.log lines: {len(web_lines)}")
