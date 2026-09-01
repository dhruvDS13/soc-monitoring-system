"""Near-real-time synthetic SOC event simulator.

This is for portfolio/demo use when production log access is unavailable.
It continuously appends realistic auth/web events to the existing database and
raw log files, then runs the detection engine against the recent 24 hours.

Run after building the historical dataset:
    python3 src/live_simulator.py
"""
import os
import random
import sqlite3
import subprocess
import time
from datetime import datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE, "soc.db")
AUTH_LOG = os.path.join(BASE, "data", "raw_logs", "auth.log")
WEB_LOG = os.path.join(BASE, "data", "raw_logs", "web_access.log")

EMPLOYEES = ["jsmith", "amartin", "rkumar", "lgarcia", "twong", "kpatel", "bwilliams", "nchen", "mrossi", "sohara", "dfoster", "hyamada", "cbrooks", "epena", "fmuller", "gsingh", "iivanov", "jkovacs", "kalvarez", "lweber"]
INTERNAL_IPS = [f"10.20.{random.randint(0,5)}.{random.randint(10,240)}" for _ in range(30)]
HOSTS = ["auth-srv01", "web-srv01", "app-srv02", "db-srv01"]
WEB_PATHS = ["/", "/login", "/dashboard", "/api/v1/users", "/api/v1/orders", "/static/app.js", "/account/settings", "/checkout"]
BOT_UA = "python-requests/2.31.0"
ATTACKER_IP = "185.220.101.47"
WEB_ATTACKER_IP = "193.106.31.98"
PID = random.randint(60000, 90000)


def add_auth(conn, ts, user, ip, success=False, host="auth-srv01"):
    global PID
    PID += 1
    result = "Accepted" if success else "Failed"
    line = f"{ts.strftime('%b %d %H:%M:%S')} {host} sshd[{PID}]: {result} password for {user} from {ip} port {random.randint(30000,60000)} ssh2"
    with open(AUTH_LOG, "a") as f:
        f.write(line + "\n")
    conn.execute("""INSERT INTO logs_normalized
        (source_type,event_timestamp,username,source_ip,destination_ip,destination_host,
         event_type,action,status,response_code,url_path,user_agent,raw_line)
        VALUES ('auth',?,?,?,?,?,?,?,?,?,?,?,?)""",
        (ts.strftime("%Y-%m-%d %H:%M:%S"), user, ip, None, host, "login", "authentication",
         "success" if success else "failure", "auth_success" if success else "auth_failure",
         None, None, line))


def add_web(conn, ts, ip, method="GET", path="/", status=200, user=None, ua="Mozilla/5.0"):
    user_field = user if user else "-"
    line = f'{ip} - {user_field} [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {random.randint(200,15000)} "-" "{ua}"'
    with open(WEB_LOG, "a") as f:
        f.write(line + "\n")
    conn.execute("""INSERT INTO logs_normalized
        (source_type,event_timestamp,username,source_ip,destination_ip,destination_host,
         event_type,action,status,response_code,url_path,user_agent,raw_line)
        VALUES ('web',?,?,?,?,?,?,?,?,?,?,?,?)""",
        (ts.strftime("%Y-%m-%d %H:%M:%S"), user, ip, None, "-", "http_request", method,
         "success" if str(status).startswith(("2", "3")) else "failure", str(status), path, ua, line))


def refresh_reputation(conn, ip):
    row = conn.execute("""SELECT COUNT(*), SUM(CASE WHEN status='failure' THEN 1 ELSE 0 END),
                                COUNT(DISTINCT username), MIN(event_timestamp), MAX(event_timestamp)
                         FROM logs_normalized WHERE source_ip=?""", (ip,)).fetchone()
    total, failed, users, first_seen, last_seen = row
    failed = failed or 0
    score = min(int((failed / total if total else 0) * 60) + min(users or 0, 10) * 3 + (0 if ip.startswith("10.20.") else 15), 100)
    label = "Malicious" if score >= 70 else "Suspicious" if score >= 45 else "Watch" if score >= 20 else "Benign"
    conn.execute("""INSERT INTO ip_reputation(source_ip,is_internal,first_seen,last_seen,total_events,failed_events,distinct_users,risk_score,risk_label)
                    VALUES(?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(source_ip) DO UPDATE SET is_internal=excluded.is_internal, first_seen=excluded.first_seen,
                    last_seen=excluded.last_seen,total_events=excluded.total_events,failed_events=excluded.failed_events,
                    distinct_users=excluded.distinct_users,risk_score=excluded.risk_score,risk_label=excluded.risk_label""",
                 (ip, int(ip.startswith("10.20.")), first_seen, last_seen, total, failed, users or 0, score, label))


def run_detection():
    script = os.path.join(BASE, "src", "detection_rules.py")
    subprocess.run(["python", script, "--recent-minutes", "1440", "--append"], cwd=BASE, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    if not os.path.exists(DB_PATH):
        raise SystemExit("soc.db not found. Run: python3 src/generate_dataset.py && python3 src/parse_logs.py && python3 src/detection_rules.py")
    print("LIVE simulator started. Press Ctrl+C to stop.")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.commit()
    last_burst = time.monotonic() - 35
    last_web_burst = time.monotonic() - 110
    try:
        while True:
            now = datetime.now().replace(microsecond=0)
            # Normal live activity
            user = random.choice(EMPLOYEES)
            ip = random.choice(INTERNAL_IPS)
            if random.random() < 0.12:
                add_auth(conn, now, user, ip, success=False)
                refresh_reputation(conn, ip)
            else:
                add_auth(conn, now, user, ip, success=True)
                refresh_reputation(conn, ip)
            add_web(conn, now, random.choice(INTERNAL_IPS), path=random.choice(WEB_PATHS), status=200)
            conn.commit()

            # Every ~45 seconds create a small brute-force burst.
            if time.monotonic() - last_burst >= 45:
                for _ in range(12):
                    ts = datetime.now().replace(microsecond=0)
                    add_auth(conn, ts, random.choice(["root", "admin"]), ATTACKER_IP, success=False)
                    time.sleep(0.35)
                refresh_reputation(conn, ATTACKER_IP)
                conn.commit()
                run_detection()
                print(f"[{datetime.now():%H:%M:%S}] simulated SSH brute-force burst")
                last_burst = time.monotonic()

            # Every ~2 minutes create a web credential-stuffing burst.
            if time.monotonic() - last_web_burst >= 120:
                for _ in range(22):
                    ts = datetime.now().replace(microsecond=0)
                    add_web(conn, ts, WEB_ATTACKER_IP, method="POST", path="/login", status=401, ua=BOT_UA)
                    time.sleep(0.20)
                refresh_reputation(conn, WEB_ATTACKER_IP)
                conn.commit()
                run_detection()
                print(f"[{datetime.now():%H:%M:%S}] simulated web credential-stuffing burst")
                last_web_burst = time.monotonic()

            # Refresh detections for normal events periodically too.
            if random.random() < 0.15:
                run_detection()
            time.sleep(3)
    except KeyboardInterrupt:
        print("\nLIVE simulator stopped.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
