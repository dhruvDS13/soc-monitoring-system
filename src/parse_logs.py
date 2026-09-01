"""
parse_logs.py
-------------
Parses raw SSH auth logs (syslog format) and web server access logs
(NCSA combined format), extracts structured fields, normalizes both
sources into one common schema, and loads them into the SQLite
database defined in sql/schema.sql.

Usage:
    python3 src/parse_logs.py
"""

import re
import sqlite3
import os
from datetime import datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUTH_LOG = os.path.join(BASE, "data", "raw_logs", "auth.log")
WEB_LOG = os.path.join(BASE, "data", "raw_logs", "web_access.log")
DB_PATH = os.path.join(BASE, "soc.db")
SCHEMA_PATH = os.path.join(BASE, "sql", "schema.sql")

YEAR_ASSUMED = 2025  # syslog auth.log lines have no year field

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Jun 01 00:00:00 web-srv01 sshd[20001]: Accepted password for kpatel from 10.20.5.218 port 42433 ssh2
AUTH_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<result>Accepted|Failed)\s+password\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)

# 10.20.2.59 - - [01/Jun/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 725 "-" "Mozilla/5.0 ..."
WEB_RE = re.compile(
    r'^(?P<ip>[\d.]+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[^"]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)


def parse_auth_log(path):
    rows = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = AUTH_RE.match(line)
            if not m:
                continue
            gd = m.groupdict()
            ts = datetime.strptime(
                f"{YEAR_ASSUMED} {gd['month']} {gd['day']} {gd['time']}", "%Y %b %d %H:%M:%S"
            )
            invalid_user = "invalid user" in line
            success = gd["result"] == "Accepted"
            rows.append({
                "source_type": "auth",
                "event_timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "username": gd["user"],
                "source_ip": gd["ip"],
                "destination_ip": None,
                "destination_host": gd["host"],
                "event_type": "login",
                "action": "authentication",
                "status": "success" if success else "failure",
                "response_code": "invalid_user" if (invalid_user and not success) else (
                    "auth_success" if success else "auth_failure"),
                "url_path": None,
                "user_agent": None,
                "raw_line": line,
            })
    return rows


def parse_web_log(path):
    rows = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = WEB_RE.match(line)
            if not m:
                continue
            gd = m.groupdict()
            ts = datetime.strptime(gd["ts"], "%d/%b/%Y:%H:%M:%S %z")
            status = gd["status"]
            success = status.startswith("2") or status.startswith("3")
            user = None if gd["user"] == "-" else gd["user"]
            rows.append({
                "source_type": "web",
                "event_timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "username": user,
                "source_ip": gd["ip"],
                "destination_ip": None,
                "destination_host": "-",
                "event_type": "http_request",
                "action": gd["method"],
                "status": "success" if success else "failure",
                "response_code": status,
                "url_path": gd["path"],
                "user_agent": gd["ua"],
                "raw_line": line,
            })
    return rows


def load_to_db(auth_rows, web_rows):
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())

    cols = ["source_type", "event_timestamp", "username", "source_ip", "destination_ip",
            "destination_host", "event_type", "action", "status", "response_code",
            "url_path", "user_agent", "raw_line"]
    placeholders = ",".join(["?"] * len(cols))
    sql = f"INSERT INTO logs_normalized ({','.join(cols)}) VALUES ({placeholders})"

    all_rows = auth_rows + web_rows
    values = [[r.get(c) for c in cols] for r in all_rows]
    conn.executemany(sql, values)
    conn.commit()

    # ---- Build ip_reputation heuristic enrichment table ----
    conn.execute("""
        INSERT INTO ip_reputation (source_ip, is_internal, first_seen, last_seen,
                                    total_events, failed_events, distinct_users,
                                    risk_score, risk_label)
        SELECT
            source_ip,
            CASE WHEN source_ip LIKE '10.20.%' THEN 1 ELSE 0 END AS is_internal,
            MIN(event_timestamp),
            MAX(event_timestamp),
            COUNT(*),
            SUM(CASE WHEN status='failure' THEN 1 ELSE 0 END),
            COUNT(DISTINCT username),
            0,
            'Benign'
        FROM logs_normalized
        GROUP BY source_ip
    """)
    conn.commit()

    # simple heuristic risk score: failure ratio + distinct users touched + external
    ips = conn.execute("SELECT source_ip, is_internal, total_events, failed_events, distinct_users FROM ip_reputation").fetchall()
    for ip, is_internal, total, failed, distinct_users in ips:
        fail_ratio = failed / total if total else 0
        score = 0
        score += int(fail_ratio * 60)
        score += min(distinct_users, 10) * 3
        score += 0 if is_internal else 15
        score = min(score, 100)
        if score >= 70:
            label = "Malicious"
        elif score >= 45:
            label = "Suspicious"
        elif score >= 20:
            label = "Watch"
        else:
            label = "Benign"
        conn.execute("UPDATE ip_reputation SET risk_score=?, risk_label=? WHERE source_ip=?",
                     (score, label, ip))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    auth_rows = parse_auth_log(AUTH_LOG)
    web_rows = parse_web_log(WEB_LOG)
    print(f"Parsed {len(auth_rows)} auth events, {len(web_rows)} web events")
    load_to_db(auth_rows, web_rows)
    print(f"Loaded into {DB_PATH}")
