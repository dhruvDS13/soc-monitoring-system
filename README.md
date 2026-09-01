# SOC Security Log Monitoring & Threat Detection 
> **🚀 Live Demo:** [Open SOC Monitoring Dashboard](https://soc-monitoring-system-nttkgcafub4mkazq3e6ejr.streamlit.app/)

An end-to-end, portfolio-ready Security Operations Center (SOC) project that ingests authentication and web server logs, normalizes them into SQLite, applies explainable rule-based threat detection, enriches source IPs with a lightweight reputation score, and presents the results in an interactive Streamlit dashboard.

The portfolio version supports **1–5 years of synthetic historical security events** plus an optional **near-real-time synthetic event simulator** for demonstrations when an authorized production log source is unavailable.

> **Important:** This is a portfolio/demo project. The data is synthetic and live mode simulates security events. It is not connected to a production security environment.

## 1. Project Goals

- Ingest realistic SSH authentication and web access logs.
- Parse and normalize different log formats into one common schema.
- Store normalized events, alerts, and IP reputation data in SQLite.
- Detect suspicious activity using **explainable rule-based detection**.
- Assign **Low / Medium / High / Critical** severity.
- Preserve evidence linking alerts back to raw events.
- Provide SOC-style KPIs, charts, incident tables, and investigation drill-down.
- Demonstrate near-real-time monitoring using synthetic events.
- Keep the architecture ready for replacement of the simulator with an authorized real log source.

## 2. Architecture

```text
Historical Synthetic Logs
        │
        ▼
generate_dataset.py
        │
        ▼
parse_logs.py
(Parse + Normalize + Load)
        │
        ▼
      soc.db
        │
        ├── logs_normalized
        ├── ip_reputation
        └── alerts
        │
        ▼
detection_rules.py
(9 Rule-Based Detections)
        │
        ▼
     Security Alerts
        │
        ▼
dashboard/app.py
(Streamlit + Plotly)
```

### Near-Real-Time Demo

```text
live_simulator.py
      │
      ├── Normal auth events
      ├── Normal web requests
      ├── SSH brute-force bursts
      └── Web credential-stuffing bursts
                │
                ▼
              soc.db
                │
                ▼
        Detection Engine
                │
                ▼
             Alerts
                │
                ▼
           Dashboard
```

## 3. Project Structure

```text
SOC-Security-Log-Monitoring/
│
├── README.md
├── requirements.txt
├── run_pipeline.sh
├── soc.db
│
├── data/
│   └── raw_logs/
│       ├── auth.log
│       └── web_access.log
│
├── src/
│   ├── generate_dataset.py
│   ├── parse_logs.py
│   ├── detection_rules.py
│   └── live_simulator.py
│
├── sql/
│   ├── schema.sql
│   └── detection_queries.sql
│
└── dashboard/
    └── app.py
```

## 4. Technology Stack

| Component | Technology |
|---|---|
| Programming | Python |
| Data Processing | Pandas |
| Database | SQLite / SQL |
| Dashboard | Streamlit |
| Visualization | Plotly |
| Log Parsing | Python Regex |
| Detection | Rule-based sliding-window logic |
| Live Demo | Python synthetic event simulator |

## 5. Dataset

The project uses synthetic security data because public production SOC logs may contain privacy, licensing, or sensitive security information.

Two log formats are simulated:

**SSH authentication log**

```text
Jun 03 03:10:12 auth-srv01 sshd[21044]: Failed password for root from 185.220.101.47 port 51322 ssh2
```

**Web access log**

```text
193.106.31.98 - - [02/Jun/2025:22:41:03 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.31.0"
```

The historical generator supports **1–5 years** of data through `HISTORY_YEARS`.

```text
HISTORY_YEARS=1
HISTORY_YEARS=3
HISTORY_YEARS=5
```

Controlled scenarios include SSH brute force, password spraying, credential stuffing, off-hours login, impossible travel, and reconnaissance scanning.

## 6. Parsing & Normalization

`src/parse_logs.py` converts different raw log formats into a common normalized schema.

Important fields include:

| Field | Purpose |
|---|---|
| `event_id` | Unique event identifier |
| `source_type` | `auth` or `web` |
| `event_timestamp` | Normalized timestamp |
| `username` | User associated with event |
| `source_ip` | Source/client IP |
| `destination_host` | Destination server |
| `event_type` | Login or HTTP request |
| `action` | Authentication method or HTTP method |
| `status` | Success/failure |
| `response_code` | Authentication result or HTTP status |
| `url_path` | Requested web path |
| `user_agent` | Web client information |
| `raw_line` | Original log evidence |

The project follows a **parse once, detect many** approach so downstream rules operate on a common structure.

## 7. IP Reputation

The `ip_reputation` table uses a lightweight heuristic based on:

- Failed-event ratio
- Distinct usernames
- Internal vs. external source IP
- Overall event volume

IPs are labelled:

```text
Benign
Watch
Suspicious
Malicious
```

A production implementation could replace this heuristic with an authorized threat-intelligence source.

## 8. Detection Rules

`src/detection_rules.py` implements nine explainable rules:

| Rule | Logic | Base Severity |
|---|---|---|
| `BRUTE_FORCE_SSH` | ≥5 failed SSH logins from one IP within 10 min | Medium → Critical |
| `PASSWORD_SPRAYING` | One IP targets ≥5 usernames within 30 min | Medium → Critical |
| `WEB_CREDENTIAL_STUFFING` | ≥20 failed POST `/login` within 15 min | High / Critical |
| `MULTIPLE_ACCOUNTS_SAME_IP` | ≥3 distinct usernames from one IP within 24h | Low → High |
| `OFF_HOURS_LOGIN` | Successful login between 00:00–05:00 | Medium / High |
| `IMPOSSIBLE_TRAVEL` | Same user from different IPs <30 min apart | High |
| `HIGH_FREQUENCY_REQUESTS` | ≥50 web requests from one IP within 5 min | Medium → Critical |
| `RECON_SCANNING` | ≥8 distinct paths with ≥60% 4xx/5xx | Medium / High |
| `REPEATED_FAILED_LOGIN_USER` | ≥5 failed logins for one username within 15 min | Medium / High |

Each alert includes a reason, severity, affected entities, event count, and evidence event IDs.

## 9. Investigation Workflow

```text
Triage by severity
        ↓
Read detection reason
        ↓
Pivot to raw evidence
        ↓
Review source IP behavior
        ↓
Follow recommended action
        ↓
Close / investigate / classify
```

The dashboard supports alert filtering, CSV export, and drill-down to the raw log lines behind an alert.

## 10. SQL Layer

`sql/schema.sql` defines the main database tables and indexes:

```text
logs_normalized
alerts
ip_reputation
```

`sql/detection_queries.sql` contains standalone SQL investigation and KPI queries.

Example:

```bash
sqlite3 soc.db < sql/detection_queries.sql
```

## 11. Running the Project

Install dependencies:

```bash
pip install -r requirements.txt
```

Generate historical data:

```bash
python src/generate_dataset.py
```

Parse and normalize:

```bash
python src/parse_logs.py
```

Run detections:

```bash
python src/detection_rules.py
```

Or run the pipeline:

```bash
./run_pipeline.sh
```

Start the dashboard:

```bash
streamlit run dashboard/app.py
```

The dashboard opens at:

```text
http://localhost:8501
```

## 12. Near-Real-Time Demo Mode

Run:

```bash
python src/live_simulator.py
```

The simulator appends synthetic authentication and web events to the same SQLite database, periodically creates controlled attack bursts, and runs detection against recent events.

The dashboard refreshes periodically so new database activity becomes visible.

```text
New Event
   ↓
SQLite
   ↓
Detection Rules
   ↓
No suspicious pattern ──→ No Alert
   │
   └── Suspicious pattern
            ↓
          Alert
            ↓
       Dashboard
```

> **This is simulated near-real-time data, not production streaming.**

## 13. Dashboard Features

- Total Events
- Failed Logins
- Suspicious/Malicious IPs
- Total Alerts
- Critical Alerts
- Alerts by Severity
- Attack Trend Over Time
- Top Targeted Accounts
- Top Suspicious Source IPs
- Recent Security Incidents
- Date/severity/rule filtering
- CSV alert export
- Alert investigation drill-down
- Raw evidence log lines
- Detection reason
- Recommended action

## 14. Real Log Integration

The current project uses synthetic data. To connect it to an **authorized** real environment, replace the synthetic generator with an ingestion/log-collection layer.

```text
Company Systems
      │
      ├── Windows Servers
      ├── Linux Servers
      ├── Web Servers
      ├── Firewalls
      └── Applications
              │
              ▼
     Authorized Log Collector
              │
              ▼
       Ingestion / Parsing
              │
              ▼
       logs_normalized
              │
              ▼
       Detection Engine
              │
              ▼
            Alerts
              │
              ▼
       SOC / SIEM Dashboard
```

The parser can be adapted to authorized formats such as Windows Event Logs, CloudTrail, firewall logs, or other enterprise telemetry.

For production scale, SQLite would normally be replaced by a centralized SIEM, data lake, or scalable database.

## 15. Limitations

- Synthetic data, not production telemetry.
- Rule-based detection rather than ML/UEBA.
- Static thresholds require environment-specific tuning.
- Local IP reputation heuristic instead of a production threat-intelligence feed.
- SQLite is suitable for portfolio scale, not high-volume production SOC storage.
- No automated SOAR response or automatic IP blocking.
- Near-real-time mode is simulated rather than production streaming.

## 16. Future Improvements

- Analyst alert status workflow.
- Analyst notes and case management.
- Real threat-intelligence enrichment.
- Anomaly detection and UEBA baselines.
- Incremental event processing.
- Kafka/Filebeat or another production ingestion mechanism.
- Elastic/Splunk SIEM integration.
- SOAR integration.
- PostgreSQL or another scalable database.
- Containerized and cloud deployment.

## 17. Security Recommendations Demonstrated

- Enforce account lockout and rate limiting.
- Require MFA for administrative and remotely accessible accounts.
- Protect login endpoints with WAF/rate limiting.
- Restrict direct root SSH access.
- Maintain allowlists for expected automation.
- Use real threat-intelligence feeds for IP enrichment.
- Monitor impossible-travel and multi-account authentication patterns.
- Tune detection thresholds to reduce false positives.

## 18. Disclaimer

This repository is intended for **education, portfolio demonstration, and authorized testing only**.

The generated attack events are synthetic. No real organization's logs, credentials, systems, or security infrastructure are accessed by this project.

For real-world deployment, integrate only with systems and telemetry for which you have explicit authorization.
