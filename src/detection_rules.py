"""
detection_rules.py
-------------------
Rule-based threat detection engine for the SOC project.

Reads the normalized events from logs_normalized (populated by parse_logs.py),
applies a set of hand-written detection rules that mirror common junior-SOC
playbook checks, and writes structured alerts (with severity + recommended
investigation step) into the `alerts` table.

Each rule is intentionally simple and explainable -- this is meant to be a
transparent, tunable rule-based system (the kind an analyst can audit line
by line), not a black-box ML model. Thresholds are declared as constants up
top so they're easy to tune against your own environment.

Usage:
    python3 src/detection_rules.py
"""

import os
import sqlite3
import pandas as pd

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE, "soc.db")

# ---------------------------------------------------------------------------
# Tunable thresholds
# ---------------------------------------------------------------------------
BRUTE_FORCE_WINDOW_MIN = 10
BRUTE_FORCE_MIN_FAILS = 5

SPRAY_WINDOW_MIN = 30
SPRAY_MIN_DISTINCT_USERS = 5
SPRAY_MAX_ATTEMPTS_PER_USER = 2

WEB_CRED_STUFF_WINDOW_MIN = 15
WEB_CRED_STUFF_MIN_FAILS = 20

MULTI_ACCOUNT_WINDOW_HOURS = 24
MULTI_ACCOUNT_MIN_USERS = 3

OFF_HOURS_START = 0    # 00:00
OFF_HOURS_END = 5       # 05:00 (exclusive)
# Known automated/service accounts are expected to run at any hour (cron jobs,
# scheduled backups, monitoring agents) - excluding them from the off-hours
# rule is a standard SOC tuning step to cut down false positives.
OFF_HOURS_ALLOWLIST_USERS = {"svc_backup", "svc_deploy", "svc_monitor"}

IMPOSSIBLE_TRAVEL_WINDOW_MIN = 30

HIGH_FREQ_WINDOW_MIN = 5
HIGH_FREQ_MIN_REQUESTS = 50

RECON_WINDOW_MIN = 10
RECON_MIN_DISTINCT_PATHS = 8
RECON_MIN_ERROR_RATIO = 0.6

FAILED_LOGIN_USER_WINDOW_MIN = 15
FAILED_LOGIN_USER_MIN = 5

alerts_buffer = []


def add_alert(detected_at, rule_name, severity, source_ip, affected_user, affected_system,
              event_count, window_start, window_end, reason, action, evidence_ids):
    alerts_buffer.append({
        "detected_at": detected_at,
        "rule_name": rule_name,
        "severity": severity,
        "source_ip": source_ip,
        "affected_user": affected_user,
        "affected_system": affected_system,
        "event_count": event_count,
        "window_start": window_start,
        "window_end": window_end,
        "detection_reason": reason,
        "recommended_action": action,
        "evidence_event_ids": ",".join(str(i) for i in evidence_ids) if evidence_ids else None,
    })


def load_events(conn):
    df = pd.read_sql_query("SELECT * FROM logs_normalized", conn, parse_dates=["event_timestamp"])
    return df


# ---------------------------------------------------------------------------
# Rule 1: SSH Brute Force -- many failed logins from one IP in a short window
# ---------------------------------------------------------------------------
def rule_brute_force(df):
    auth = df[(df.source_type == "auth") & (df.status == "failure")].sort_values("event_timestamp")
    for ip, grp in auth.groupby("source_ip"):
        grp = grp.reset_index(drop=True)
        times = grp["event_timestamp"].tolist()
        i = 0
        n = len(times)
        while i < n:
            j = i
            while j < n and (times[j] - times[i]).total_seconds() <= BRUTE_FORCE_WINDOW_MIN * 60:
                j += 1
            count = j - i
            if count >= BRUTE_FORCE_MIN_FAILS:
                window = grp.iloc[i:j]
                users = sorted(window["username"].unique())
                if count >= 30:
                    sev = "Critical"
                elif count >= 15:
                    sev = "High"
                else:
                    sev = "Medium"
                add_alert(
                    detected_at=window["event_timestamp"].max().strftime("%d-%m-%Y %H:%M:%S"),
                    rule_name="BRUTE_FORCE_SSH",
                    severity=sev,
                    source_ip=ip,
                    affected_user=",".join(users[:5]) + ("..." if len(users) > 5 else ""),
                    affected_system=",".join(window["destination_host"].dropna().unique()),
                    event_count=count,
                    window_start=window["event_timestamp"].min().strftime("%d-%m-%Y %H:%M:%S"),
                    window_end=window["event_timestamp"].max().strftime("%d-%m-%Y %H:%M:%S"),
                    reason=(f"{count} failed SSH login attempts from {ip} within "
                            f"{BRUTE_FORCE_WINDOW_MIN} minutes, targeting {len(users)} "
                            f"account(s): {', '.join(users[:5])}."),
                    action=("Block/rate-limit source IP at firewall, force password reset for "
                            "targeted accounts, verify no subsequent successful login from this IP, "
                            "check for lateral movement if credentials were valid."),
                    evidence_ids=window["event_id"].tolist(),
                )
                i = j  # jump past this window
            else:
                i += 1


# ---------------------------------------------------------------------------
# Rule 2: Password spraying -- one IP, many usernames, few attempts each
# ---------------------------------------------------------------------------
def rule_password_spray(df):
    auth = df[(df.source_type == "auth") & (df.status == "failure")].sort_values("event_timestamp")
    for ip, grp in auth.groupby("source_ip"):
        grp = grp.reset_index(drop=True)
        times = grp["event_timestamp"].tolist()
        i, n = 0, len(grp)
        while i < n:
            j = i
            while j < n and (times[j] - times[i]).total_seconds() <= SPRAY_WINDOW_MIN * 60:
                j += 1
            window = grp.iloc[i:j]
            user_counts = window["username"].value_counts()
            distinct_users = len(user_counts)
            max_attempts = user_counts.max() if distinct_users else 0
            if distinct_users >= SPRAY_MIN_DISTINCT_USERS and max_attempts <= SPRAY_MAX_ATTEMPTS_PER_USER:
                sev = "Critical" if distinct_users >= 15 else ("High" if distinct_users >= 8 else "Medium")
                add_alert(
                    detected_at=window["event_timestamp"].max().strftime("%d-%m-%Y %H:%M:%S"),
                    rule_name="PASSWORD_SPRAYING",
                    severity=sev,
                    source_ip=ip,
                    affected_user=",".join(sorted(user_counts.index)[:8]) + ("..." if distinct_users > 8 else ""),
                    affected_system=",".join(window["destination_host"].dropna().unique()),
                    event_count=len(window),
                    window_start=window["event_timestamp"].min().strftime("%d-%m-%Y %H:%M:%S"),
                    window_end=window["event_timestamp"].max().strftime("%d-%m-%Y %H:%M:%S"),
                    reason=(f"{ip} attempted logins against {distinct_users} distinct usernames "
                            f"within {SPRAY_WINDOW_MIN} minutes with only {max_attempts} attempt(s) "
                            "per account - classic low-and-slow password spray pattern."),
                    action=("Force password reset + MFA enrollment check for all targeted accounts, "
                            "block source IP, review for any accepted logins from same IP/subnet."),
                    evidence_ids=window["event_id"].tolist(),
                )
                i = j
            else:
                i += 1


# ---------------------------------------------------------------------------
# Rule 3: Web credential stuffing -- high volume POST /login failures
# ---------------------------------------------------------------------------
def rule_web_credential_stuffing(df):
    web = df[(df.source_type == "web") & (df.url_path == "/login") & (df.status == "failure")]
    web = web.sort_values("event_timestamp")
    for ip, grp in web.groupby("source_ip"):
        grp = grp.reset_index(drop=True)
        times = grp["event_timestamp"].tolist()
        i, n = 0, len(grp)
        while i < n:
            j = i
            while j < n and (times[j] - times[i]).total_seconds() <= WEB_CRED_STUFF_WINDOW_MIN * 60:
                j += 1
            count = j - i
            if count >= WEB_CRED_STUFF_MIN_FAILS:
                window = grp.iloc[i:j]
                sev = "Critical" if count >= 100 else "High"
                add_alert(
                    detected_at=window["event_timestamp"].max().strftime("%d-%m-%Y %H:%M:%S"),
                    rule_name="WEB_CREDENTIAL_STUFFING",
                    severity=sev,
                    source_ip=ip,
                    affected_user=None,
                    affected_system="web-srv01 (/login)",
                    event_count=count,
                    window_start=window["event_timestamp"].min().strftime("%d-%m-%Y %H:%M:%S"),
                    window_end=window["event_timestamp"].max().strftime("%d-%m-%Y %H:%M:%S"),
                    reason=(f"{count} failed POST /login attempts from {ip} within "
                            f"{WEB_CRED_STUFF_WINDOW_MIN} minutes at a rate consistent with "
                            "automated credential-stuffing tooling."),
                    action=("Enable CAPTCHA/WAF rate-limiting on /login, block IP, review "
                            "logs for any 200/302 (successful) response from this IP, notify "
                            "affected users to reset passwords if any account was compromised."),
                    evidence_ids=window["event_id"].tolist(),
                )
                i = j
            else:
                i += 1


# ---------------------------------------------------------------------------
# Rule 4: Multiple accounts accessed from same source IP
# ---------------------------------------------------------------------------
def rule_multi_account_same_ip(df):
    auth = df[(df.source_type == "auth")].sort_values("event_timestamp")
    for ip, grp in auth.groupby("source_ip"):
        grp = grp.reset_index(drop=True)
        start = grp["event_timestamp"].min()
        end = grp["event_timestamp"].max()
        span_hours = (end - start).total_seconds() / 3600
        distinct_users = grp["username"].nunique()
        if distinct_users >= MULTI_ACCOUNT_MIN_USERS and span_hours <= MULTI_ACCOUNT_WINDOW_HOURS:
            is_internal = ip.startswith("10.20.")
            sev = "Low" if is_internal else ("High" if distinct_users >= 8 else "Medium")
            add_alert(
                detected_at=end.strftime("%d-%m-%Y %H:%M:%S"),
                rule_name="MULTIPLE_ACCOUNTS_SAME_IP",
                severity=sev,
                source_ip=ip,
                affected_user=",".join(sorted(grp["username"].dropna().unique())[:8]),
                affected_system=",".join(grp["destination_host"].dropna().unique()),
                event_count=len(grp),
                window_start=start.strftime("%d-%m-%Y %H:%M:%S"),
                window_end=end.strftime("%d-%m-%Y %H:%M:%S"),
                reason=(f"{distinct_users} distinct usernames authenticated from {ip} within "
                        f"{span_hours:.1f} hours ({'internal' if is_internal else 'EXTERNAL'} IP) - "
                        "possible shared/jump host, or credential compromise if unexpected."),
                action=("Confirm whether this IP is an approved shared host (VPN gateway, jump box). "
                        "If not expected, treat as potential credential compromise: reset passwords, "
                        "review each account's recent activity."),
                evidence_ids=grp["event_id"].tolist(),
            )


# ---------------------------------------------------------------------------
# Rule 5: Unusual/off-hours successful login
# ---------------------------------------------------------------------------
def rule_off_hours_login(df):
    auth = df[(df.source_type == "auth") & (df.status == "success") &
              (~df.username.isin(OFF_HOURS_ALLOWLIST_USERS))]
    off = auth[(auth["event_timestamp"].dt.hour >= OFF_HOURS_START) &
               (auth["event_timestamp"].dt.hour < OFF_HOURS_END)]
    for _, row in off.iterrows():
        is_internal_ip = str(row["source_ip"]).startswith("10.20.")
        severity = "Medium" if is_internal_ip else "High"
        add_alert(
            detected_at=row["event_timestamp"].strftime("%d-%m-%Y %H:%M:%S"),
            rule_name="OFF_HOURS_LOGIN",
            severity=severity,
            source_ip=row["source_ip"],
            affected_user=row["username"],
            affected_system=row["destination_host"],
            event_count=1,
            window_start=row["event_timestamp"].strftime("%d-%m-%Y %H:%M:%S"),
            window_end=row["event_timestamp"].strftime("%d-%m-%Y %H:%M:%S"),
            reason=(f"Successful login for '{row['username']}' at "
                    f"{row['event_timestamp'].strftime('%H:%M')} local time, outside normal "
                    f"business hours ({OFF_HOURS_START:02d}:00-{OFF_HOURS_END:02d}:00 is treated "
                    "as anomalous for this org)."),
            action=("Verify with the account owner whether this login was expected (e.g. "
                    "on-call work, travel). If not confirmed, treat as suspected account "
                    "compromise and force password reset + session revocation."),
            evidence_ids=[row["event_id"]],
        )


# ---------------------------------------------------------------------------
# Rule 6: Impossible travel -- same user, two different IPs, short window
# ---------------------------------------------------------------------------
def rule_impossible_travel(df):
    auth = df[(df.source_type == "auth") & (df.status == "success")].sort_values("event_timestamp")
    for user, grp in auth.groupby("username"):
        grp = grp.reset_index(drop=True)
        for k in range(1, len(grp)):
            prev, cur = grp.iloc[k - 1], grp.iloc[k]
            gap_min = (cur["event_timestamp"] - prev["event_timestamp"]).total_seconds() / 60
            if prev["source_ip"] != cur["source_ip"] and gap_min <= IMPOSSIBLE_TRAVEL_WINDOW_MIN:
                add_alert(
                    detected_at=cur["event_timestamp"].strftime("%d-%m-%Y %H:%M:%S"),
                    rule_name="IMPOSSIBLE_TRAVEL",
                    severity="High",
                    source_ip=f"{prev['source_ip']} -> {cur['source_ip']}",
                    affected_user=user,
                    affected_system=cur["destination_host"],
                    event_count=2,
                    window_start=prev["event_timestamp"].strftime("%d-%m-%Y %H:%M:%S"),
                    window_end=cur["event_timestamp"].strftime("%d-%m-%Y %H:%M:%S"),
                    reason=(f"User '{user}' logged in successfully from {prev['source_ip']} then "
                            f"from a different IP {cur['source_ip']} only {gap_min:.1f} minutes "
                            "later - not physically plausible unless VPN/NAT explains it."),
                    action=("Contact the user to confirm both sessions. If unconfirmed, force "
                            "logout of all sessions, reset credentials, and enable/verify MFA."),
                    evidence_ids=[prev["event_id"], cur["event_id"]],
                )


# ---------------------------------------------------------------------------
# Rule 7: High-frequency requests (possible DoS / scraping / automation)
# ---------------------------------------------------------------------------
def rule_high_frequency_requests(df):
    web = df[df.source_type == "web"].sort_values("event_timestamp")
    for ip, grp in web.groupby("source_ip"):
        grp = grp.reset_index(drop=True)
        times = grp["event_timestamp"].tolist()
        i, n = 0, len(grp)
        while i < n:
            j = i
            while j < n and (times[j] - times[i]).total_seconds() <= HIGH_FREQ_WINDOW_MIN * 60:
                j += 1
            count = j - i
            if count >= HIGH_FREQ_MIN_REQUESTS:
                window = grp.iloc[i:j]
                sev = "Critical" if count >= 200 else ("High" if count >= 100 else "Medium")
                add_alert(
                    detected_at=window["event_timestamp"].max().strftime("%d-%m-%Y %H:%M:%S"),
                    rule_name="HIGH_FREQUENCY_REQUESTS",
                    severity=sev,
                    source_ip=ip,
                    affected_user=None,
                    affected_system="web-srv01",
                    event_count=count,
                    window_start=window["event_timestamp"].min().strftime("%d-%m-%Y %H:%M:%S"),
                    window_end=window["event_timestamp"].max().strftime("%d-%m-%Y %H:%M:%S"),
                    reason=(f"{count} HTTP requests from {ip} within {HIGH_FREQ_WINDOW_MIN} minutes "
                            "- rate far exceeds normal human browsing, consistent with a bot, "
                            "scraper, or denial-of-service attempt."),
                    action=("Apply rate-limiting/WAF rule for this IP, inspect targeted endpoints "
                            "for data exfiltration or DoS impact, consider temporary IP block."),
                    evidence_ids=window["event_id"].tolist(),
                )
                i = j
            else:
                i += 1


# ---------------------------------------------------------------------------
# Rule 8: Suspicious IP recon / scanning behaviour
# ---------------------------------------------------------------------------
def rule_recon_scanning(df):
    web = df[df.source_type == "web"].sort_values("event_timestamp")
    for ip, grp in web.groupby("source_ip"):
        grp = grp.reset_index(drop=True)
        times = grp["event_timestamp"].tolist()
        i, n = 0, len(grp)
        while i < n:
            j = i
            while j < n and (times[j] - times[i]).total_seconds() <= RECON_WINDOW_MIN * 60:
                j += 1
            window = grp.iloc[i:j]
            distinct_paths = window["url_path"].nunique()
            error_ratio = (window["response_code"].astype(str).str[0].isin(["4", "5"])).mean()
            if distinct_paths >= RECON_MIN_DISTINCT_PATHS and error_ratio >= RECON_MIN_ERROR_RATIO:
                sev = "High" if distinct_paths >= 15 else "Medium"
                add_alert(
                    detected_at=window["event_timestamp"].max().strftime("%d-%m-%Y %H:%M:%S"),
                    rule_name="RECON_SCANNING",
                    severity=sev,
                    source_ip=ip,
                    affected_user=None,
                    affected_system="web-srv01",
                    event_count=len(window),
                    window_start=window["event_timestamp"].min().strftime("%d-%m-%Y %H:%M:%S"),
                    window_end=window["event_timestamp"].max().strftime("%d-%m-%Y %H:%M:%S"),
                    reason=(f"{ip} requested {distinct_paths} distinct URL paths within "
                            f"{RECON_WINDOW_MIN} minutes with a {error_ratio:.0%} error rate "
                            "(4xx/5xx) - consistent with vulnerability scanning/path enumeration "
                            "(e.g. probing for .env, wp-login.php, admin panels)."),
                    action=("Block source IP at WAF/firewall, review targeted paths for any "
                            "that returned 200 (may indicate a real exposure), check for follow-up "
                            "exploitation attempts from same IP/subnet."),
                    evidence_ids=window["event_id"].tolist(),
                )
                i = j
            else:
                i += 1


# ---------------------------------------------------------------------------
# Rule 9: Repeated failed logins for a single user (any source)
# ---------------------------------------------------------------------------
def rule_repeated_failed_login_user(df):
    auth = df[(df.source_type == "auth") & (df.status == "failure") & df.username.notna()]
    auth = auth.sort_values("event_timestamp")
    for user, grp in auth.groupby("username"):
        grp = grp.reset_index(drop=True)
        times = grp["event_timestamp"].tolist()
        i, n = 0, len(grp)
        while i < n:
            j = i
            while j < n and (times[j] - times[i]).total_seconds() <= FAILED_LOGIN_USER_WINDOW_MIN * 60:
                j += 1
            count = j - i
            if count >= FAILED_LOGIN_USER_MIN:
                window = grp.iloc[i:j]
                ips = window["source_ip"].unique()
                # Skip if this is already better explained by brute force from single IP
                # (still log it, but at Medium since brute-force rule already covers the IP angle)
                sev = "High" if len(ips) > 1 else "Medium"
                add_alert(
                    detected_at=window["event_timestamp"].max().strftime("%d-%m-%Y %H:%M:%S"),
                    rule_name="REPEATED_FAILED_LOGIN_USER",
                    severity=sev,
                    source_ip=",".join(ips[:3]),
                    affected_user=user,
                    affected_system=",".join(window["destination_host"].dropna().unique()),
                    event_count=count,
                    window_start=window["event_timestamp"].min().strftime("%d-%m-%Y %H:%M:%S"),
                    window_end=window["event_timestamp"].max().strftime("%d-%m-%Y %H:%M:%S"),
                    reason=(f"Account '{user}' had {count} failed login attempts within "
                            f"{FAILED_LOGIN_USER_WINDOW_MIN} minutes from {len(ips)} source IP(s)."),
                    action=("Check if account is locked out per policy, confirm with user whether "
                            "they mistyped their password repeatedly, otherwise treat as targeted "
                            "attack on this account."),
                    evidence_ids=window["event_id"].tolist(),
                )
                i = j
            else:
                i += 1


def run_all_rules(conn):
    df = load_events(conn)
    rule_brute_force(df)
    rule_password_spray(df)
    rule_web_credential_stuffing(df)
    rule_multi_account_same_ip(df)
    rule_off_hours_login(df)
    rule_impossible_travel(df)
    rule_high_frequency_requests(df)
    rule_recon_scanning(df)
    rule_repeated_failed_login_user(df)


def save_alerts(conn):
    conn.execute("DELETE FROM alerts")
    cols = ["detected_at", "rule_name", "severity", "source_ip", "affected_user",
            "affected_system", "event_count", "window_start", "window_end",
            "detection_reason", "recommended_action", "evidence_event_ids"]
    placeholders = ",".join(["?"] * len(cols))
    sql = f"INSERT INTO alerts ({','.join(cols)}) VALUES ({placeholders})"
    values = [[a.get(c) for c in cols] for a in alerts_buffer]
    conn.executemany(sql, values)
    conn.commit()


if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH)
    run_all_rules(conn)
    save_alerts(conn)
    print(f"Generated {len(alerts_buffer)} alerts")
    sev_counts = pd.Series([a["severity"] for a in alerts_buffer]).value_counts()
    print(sev_counts)
    conn.close()
