# SOC Security Log Monitoring & Threat Detection
# pip install -r requirements.txt
# ./run_pipeline.sh
# streamlit run dashboard/app.py
An end-to-end, portfolio-ready SOC (Security Operations Center) project that
takes raw authentication and web server logs, normalizes them into a SQL
database, runs a rule-based detection engine over them, and surfaces the
results in an interactive analyst dashboard — the same workflow a junior SOC
analyst follows day to day: **collect → parse → detect → triage → report.**

**Stack:** Python (log parsing + detection engine) · SQLite/SQL (storage &
analysis queries) · Streamlit + Plotly (dashboard)

---

## 1. Project Goals

- Ingest realistic, unstructured security logs (SSH auth logs + web access logs)
- Parse and normalize them into a single structured schema
- Store the structured data in a proper SQL database
- Detect suspicious activity using **explainable, rule-based logic** (not a
  black box) — the same kind of logic a SOC analyst would codify from a
  detection playbook
- Assign **severity** (Low / Medium / High / Critical) to every alert
- Generate alerts with a **timestamp, source IP, affected user/system,
  detection reason, severity, and recommended investigation step** — i.e.
  something an analyst could act on directly
- Visualize everything in an interactive SOC dashboard

---

## 2. Architecture

```
                 ┌─────────────────────────┐
                 │   Raw Logs (synthetic)   │
                 │  auth.log / web_access.log│
                 └────────────┬─────────────┘
                              │  src/generate_dataset.py
                              ▼
                 ┌─────────────────────────┐
                 │   src/parse_logs.py      │
                 │  regex parsing + field    │
                 │  extraction + normalize   │
                 └────────────┬─────────────┘
                              ▼
                 ┌─────────────────────────┐
                 │   soc.db (SQLite)        │
                 │  logs_normalized          │
                 │  ip_reputation             │
                 │  alerts                     │
                 └────────────┬─────────────┘
                              │  src/detection_rules.py
                              ▼
                 ┌─────────────────────────┐
                 │  Rule-based detection      │
                 │  engine (9 rules) → alerts  │
                 │  table with severity        │
                 └────────────┬─────────────┘
                              ▼
                 ┌─────────────────────────┐
                 │  dashboard/app.py           │
                 │  Streamlit + Plotly SOC      │
                 │  dashboard (KPIs, charts,     │
                 │  alert table, drill-down)      │
                 └─────────────────────────┘
```

### Project layout

```
soc-project/
├── README.md
├── requirements.txt
├── run_pipeline.sh              # one-shot: generate -> parse -> detect
├── soc.db                       # SQLite database (generated)
├── data/
│   └── raw_logs/
│       ├── auth.log             # synthetic SSH/syslog auth log
│       └── web_access.log       # synthetic NCSA combined web access log
├── src/
│   ├── generate_dataset.py      # builds the synthetic dataset (+ injected attacks)
│   ├── parse_logs.py            # regex parsing, normalization, DB load
│   └── detection_rules.py       # 9 rule-based detections -> alerts table
├── sql/
│   ├── schema.sql                # table definitions
│   └── detection_queries.sql     # standalone SQL versions of the analysis
└── dashboard/
    └── app.py                    # Streamlit SOC dashboard
```

---

## 3. The Dataset

Real SOC log dumps (e.g. from Kaggle's "cybersecurity attacks" sets or a lab's
Splunk/ELK export) are either too small, not annotated with ground truth, or
carry licensing/PII concerns for a public portfolio repo. Instead, this
project **generates a realistic synthetic dataset** (`src/generate_dataset.py`)
that mimics two industry-standard log formats byte-for-byte:

- **`auth.log`** — Linux `sshd`/syslog authentication log format:
  ```
  Jun 03 03:10:12 auth-srv01 sshd[21044]: Failed password for root from 185.220.101.47 port 51322 ssh2
  ```
- **`web_access.log`** — NCSA "combined" web server log format (Apache/Nginx):
  ```
  193.106.31.98 - - [02/Jun/2025:22:41:03 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.31.0"
  ```

It simulates **6 days** of a small company (20 employees, 3 service accounts,
2 admin accounts, 4 hosts, a public web app) with realistic business-hours
login weighting, and then **injects 6 labeled attack scenarios** so the
detection engine has real signal to find — exactly like how detection
engineers test rules against known-bad test cases before deploying them:

| # | Scenario | Simulates |
|---|----------|-----------|
| A | SSH brute force from one external IP against `root`/`admin` | Classic credential brute-forcing |
| B | Password spraying — 1–2 attempts across 17 different usernames | Low-and-slow spray designed to dodge per-user thresholds |
| C | Credential stuffing against `/login` (150 rapid POSTs) | Automated login-bot / breached-credential replay |
| D | Successful login at 03:14 from an unfamiliar external IP | Compromised-credential usage off-hours |
| E | Same user logging in from two distant IPs 6 minutes apart | "Impossible travel" |
| F | Scanner hitting `/wp-login.php`, `/.env`, `/phpmyadmin/`, etc. | Recon / vulnerability scanning |

Because the ground truth is known, you can verify the detection engine finds
exactly these six cases (it does — see [§7 Sample Alerts](#7-sample-alerts-output)).

> To point this project at **real** logs instead: drop your own `auth.log`
> and `web_access.log`-formatted files into `data/raw_logs/` (or adjust the
> regexes in `src/parse_logs.py` to match your actual log format — e.g.
> Windows Event Logs, Cisco ASA, CloudTrail) and run the pipeline unchanged.

---

## 4. Parsing & Normalization

`src/parse_logs.py` uses regular expressions to extract fields from each raw
log line and maps both sources into **one common schema** (see
`sql/schema.sql`, table `logs_normalized`):

| Field | Description |
|---|---|
| `event_id` | Auto-increment primary key |
| `source_type` | `auth` or `web` |
| `event_timestamp` | Normalized ISO-8601 timestamp |
| `username` | Extracted username (NULL for anonymous web hits) |
| `source_ip` | Client/attacker IP |
| `destination_host` | Server that received the event |
| `event_type` | `login` / `http_request` |
| `action` | `authentication`, `GET`, `POST`, ... |
| `status` | `success` / `failure` |
| `response_code` | SSH auth result or HTTP status code |
| `url_path`, `user_agent` | Web-log-specific fields |
| `raw_line` | Original untouched log line (kept as evidence for drill-down) |

This is the same "parse once, detect many" pattern used in real SIEMs
(Splunk CIM, Elastic ECS): once logs are normalized, every downstream
detection rule can be source-agnostic.

An `ip_reputation` table is also built during load — a lightweight heuristic
scoring model (failure ratio, distinct users touched, internal vs. external)
that labels every IP `Benign` / `Watch` / `Suspicious` / `Malicious`. In a
production SOC this table would instead be populated from a real threat-intel
feed (AbuseIPDB, OTX, VirusTotal, etc.).

---

## 5. Detection Methodology

Detection logic lives in `src/detection_rules.py` (Python/pandas, using
sliding time-windows) with the equivalent logic also written as **plain SQL**
in `sql/detection_queries.sql` for transparency/portability. Nine rules are
implemented:

| Rule | Logic | Base Severity |
|---|---|---|
| `BRUTE_FORCE_SSH` | ≥5 failed SSH logins from one IP within 10 min | Medium→Critical by volume |
| `PASSWORD_SPRAYING` | One IP fails logins against ≥5 distinct usernames within 30 min, ≤2 attempts/user | Medium→Critical by user count |
| `WEB_CREDENTIAL_STUFFING` | ≥20 failed `POST /login` from one IP within 15 min | High/Critical |
| `MULTIPLE_ACCOUNTS_SAME_IP` | ≥3 distinct usernames authenticate from one IP within 24h | Low (internal) / Medium–High (external) |
| `OFF_HOURS_LOGIN` | Successful login between 00:00–05:00, excluding known service accounts | Medium (internal IP) / High (external IP) |
| `IMPOSSIBLE_TRAVEL` | Same user, two different source IPs, successful logins <30 min apart | High |
| `HIGH_FREQUENCY_REQUESTS` | ≥50 web requests from one IP within 5 min | Medium→Critical by volume |
| `RECON_SCANNING` | ≥8 distinct URL paths from one IP within 10 min, ≥60% 4xx/5xx | Medium/High |
| `REPEATED_FAILED_LOGIN_USER` | ≥5 failed logins for one username within 15 min (any source) | Medium/High |

**Severity model:** each rule maps its own volume/spread metric to Low →
Medium → High → Critical using fixed thresholds declared at the top of
`detection_rules.py`, so they're easy to tune to your environment (a bigger
org with more legitimate off-hours or shared-IP traffic would raise these
thresholds; a high-security environment would lower them).

**Noise reduction (a real analyst tuning step):** service/automation
accounts (`svc_backup`, `svc_deploy`, `svc_monitor`) are excluded from the
off-hours rule since scheduled jobs are *expected* to run at any hour — this
is exactly the kind of allowlisting a SOC analyst adds after the first
detection run floods them with expected-but-flagged automation noise.

Every alert stores a `evidence_event_ids` field (comma-separated
`event_id`s) that links straight back to the raw log lines that triggered
it — the dashboard's drill-down view uses this for one-click evidence
review, mirroring how an analyst pivots from an alert to raw logs in a SIEM.

---

## 6. SQL Layer

- **`sql/schema.sql`** — three tables: `logs_normalized` (the parsed events),
  `alerts` (detection output), `ip_reputation` (enrichment). Indexed on
  timestamp, source IP, username, and status for fast filtering.
- **`sql/detection_queries.sql`** — 12 standalone queries covering the KPIs
  and detections used by the dashboard (failed-login counts, brute-force
  candidates, multi-account IPs, off-hours logins, high-frequency requesters,
  top targeted accounts, alerts by severity, attack trend by day, etc.) —
  runnable directly with `sqlite3 soc.db < sql/detection_queries.sql`, useful
  for ad-hoc analyst investigation outside the dashboard.

---

## 7. Sample Alerts (Output)

Real output from a run of the included synthetic dataset:

```
BRUTE_FORCE_SSH        | Critical | 185.220.101.47             | 60 failed SSH login attempts from 185.220.101.47
                          within 10 minutes, targeting 2 account(s): admin, root.
PASSWORD_SPRAYING       | Critical | 45.155.205.12              | 45.155.205.12 attempted logins against 17 distinct
                          usernames within 30 minutes with only 2 attempt(s) per account.
WEB_CREDENTIAL_STUFFING | Critical | 193.106.31.98              | 108 failed POST /login attempts from 193.106.31.98
                          within 15 minutes at a rate consistent with automated tooling.
BRUTE_FORCE_SSH         | High     | 45.155.205.12              | 19 failed SSH login attempts, targeting 13 accounts.
MULTIPLE_ACCOUNTS_SAME_IP| High    | 45.155.205.12              | 17 distinct usernames authenticated from this
                          EXTERNAL IP within 0.2 hours.
OFF_HOURS_LOGIN         | High     | 185.220.101.47             | Successful login for 'admin' at 03:15 local time,
                          outside normal business hours.
OFF_HOURS_LOGIN         | High     | 77.91.124.10               | Successful login for 'hyamada' at 03:14 local time
                          from an unfamiliar external IP.
IMPOSSIBLE_TRAVEL       | High     | 10.20.5.225 -> 203.0.113.55| User 'kalvarez' logged in from two different IPs
                          6 minutes apart.
RECON_SCANNING          | Medium   | 89.248.165.74              | Requested 11 distinct paths within 10 minutes,
                          ~93% error rate (probing /.env, /wp-login.php, /phpmyadmin/, etc.).
```

Every alert row in the database additionally carries: `detected_at`,
`window_start`/`window_end`, `event_count`, `affected_system`, and a full
`recommended_action` string (see `alerts` table).

---

## 8. Investigation Process (How an Analyst Would Use This)

1. **Triage by severity** — start with the Critical/High alerts on the
   dashboard (top-left severity chart + the sorted incidents table).
2. **Read the detection reason** — each alert explains *why* it fired in
   plain language (e.g. "60 failed SSH attempts from X within 10 minutes").
3. **Pivot to evidence** — use the dashboard's drill-down selector to view
   the exact raw log lines (`raw_line`) that produced the alert.
4. **Check IP reputation** — cross-reference the source IP against the
   `ip_reputation` table/chart to see its overall behavior (is this a
   one-off or a repeat offender?).
5. **Follow the recommended action** — every alert includes a concrete next
   step (block IP, force password reset, verify with account owner, enable
   MFA, etc.) instead of just a bare notification.
6. **Close the loop** — the `alerts.status` column (`Open` /
   `Investigating` / `Closed` / `False Positive`) is designed to be updated
   by an analyst as they work the queue (not automated in this project, but
   the schema supports it — a natural next feature).

---

## 9. Running the Project

```bash
pip install -r requirements.txt

# 1. Generate the dataset, parse/normalize it, and run detections (one command)
./run_pipeline.sh
# ...or step by step:
python3 src/generate_dataset.py
python3 src/parse_logs.py
python3 src/detection_rules.py

# 2. Launch the dashboard
streamlit run dashboard/app.py
```

The dashboard opens at `http://localhost:8501` with:
- **KPIs**: total events, failed logins, suspicious/malicious IPs, total & critical alerts
- **Alerts by severity** (bar chart) and **attack trend over time** (stacked bar by day)
- **Top targeted accounts** and **top suspicious source IPs**
- **Recent security incidents** table (filterable by date/severity/rule, CSV export)
- **Alert investigation drill-down** — pick an alert, see its raw evidence log lines

*(A Power BI version can be built directly on top of `soc.db`/`alerts` via
Power BI's SQLite/ODBC connector using the same KPIs and the queries in
`sql/detection_queries.sql` as the basis for each visual, if you prefer
Power BI over Streamlit.)*

---

## 10. Limitations

- **Synthetic data**: while formatted identically to real logs, volumes,
  timing, and attacker behavior are simplified compared to production
  traffic; real environments have far more noise and edge cases.
- **Rule-based only**: thresholds are static and can be evaded by
  attackers who deliberately stay under them (e.g. spacing attempts wider
  than the detection window) — no ML/anomaly-detection or UEBA baseline is
  included.
- **No enrichment feeds**: `ip_reputation` is a local heuristic, not backed
  by a real threat-intel API (GeoIP, ASN, known-bad-IP lists).
- **Single-node SQLite**: fine for a portfolio project; a production SOC
  would use a proper SIEM/data lake (Splunk, Elastic, Snowflake) for
  ingest volume and long-term retention.
- **No automated response**: alerts are generated but not auto-remediated
  (no SOAR integration, no automatic IP blocking).
- **Batch, not streaming**: the pipeline processes a static log file; a
  production system would ingest continuously (e.g. via Kafka/Filebeat).

---

## 11. Security Recommendations (General, Based on Findings)

- Enforce **account lockout / rate limiting** after N failed logins per
  account and per source IP (mitigates brute force & spraying).
- Require **MFA** for all admin and remotely-accessible accounts —
  especially `root`/`admin`, which are the most targeted usernames in this
  dataset, as in real attacks.
- Put a **WAF with rate limiting** in front of login endpoints to blunt
  credential-stuffing bots.
- **Disable or tightly restrict `root` SSH login**; use named accounts +
  sudo instead, so brute force has no single high-value target.
- Maintain an **allowlist of expected off-hours automation** (service
  accounts, scheduled jobs) so real off-hours anomalies stand out instead
  of being buried in expected noise.
- Feed source IPs through a **real threat-intel/reputation feed** rather
  than local heuristics alone.
- Alert on **impossible travel** and **multi-account single-IP** patterns
  as part of standard identity-protection monitoring (this is exactly what
  Azure AD/Okta "risky sign-in" detections do).
- Regularly **review and tune detection thresholds** against your own
  traffic to keep the false-positive rate manageable — a detection nobody
  trusts because it's noisy is a detection that gets ignored.

---

## 12. Possible Extensions

- Add a `alerts.status` workflow UI in the dashboard (mark alerts
  Investigating/Closed/False Positive, add analyst notes).
- Swap the heuristic `ip_reputation` for a real threat-intel API call.
- Add a simple anomaly-detection model (e.g. isolation forest on
  per-IP/per-user request-rate features) alongside the rule engine.
- Stream logs in near-real-time instead of batch (watch the log file,
  append new events to `logs_normalized`, re-run detection incrementally).
- Port the dashboard to Power BI using the same `soc.db` and SQL queries.
#   s o c - m o n i t o r i n g - s y s t e m  
 