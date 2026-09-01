-- ============================================================
-- SOC Security Log Monitoring - Database Schema (SQLite/ANSI SQL)
-- ============================================================

DROP TABLE IF EXISTS logs_normalized;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS ip_reputation;

-- Single normalized "events" table that both log sources feed into.
-- This is the star of the pipeline: every raw auth/web line gets
-- mapped into this common schema so detection SQL doesn't need to
-- care which source produced the event.
CREATE TABLE logs_normalized (
    event_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type     TEXT NOT NULL,          -- 'auth' | 'web'
    event_timestamp TEXT NOT NULL,          -- ISO-8601 'YYYY-MM-DD HH:MM:SS'
    username        TEXT,                   -- NULL for anonymous web hits
    source_ip       TEXT NOT NULL,
    destination_ip  TEXT,                   -- host/server that received the event
    destination_host TEXT,                  -- hostname (auth logs) or '-' (web)
    event_type      TEXT NOT NULL,          -- 'login', 'http_request'
    action          TEXT,                   -- 'authentication', 'GET', 'POST', ...
    status          TEXT NOT NULL,          -- 'success' | 'failure'
    response_code   TEXT,                   -- ssh2/PAM code or HTTP status code
    url_path        TEXT,                   -- web only
    user_agent      TEXT,                   -- web only
    raw_line        TEXT NOT NULL           -- original unmodified log line, for evidence
);

CREATE INDEX idx_logs_ts       ON logs_normalized(event_timestamp);
CREATE INDEX idx_logs_srcip    ON logs_normalized(source_ip);
CREATE INDEX idx_logs_user     ON logs_normalized(username);
CREATE INDEX idx_logs_status   ON logs_normalized(status);
CREATE INDEX idx_logs_type     ON logs_normalized(event_type);

-- Alerts produced by the detection engine (src/detection_rules.py)
CREATE TABLE alerts (
    alert_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at        TEXT NOT NULL,        -- when the rule fired (ISO ts of triggering event)
    rule_name          TEXT NOT NULL,        -- e.g. 'BRUTE_FORCE_SSH'
    severity           TEXT NOT NULL,        -- Low | Medium | High | Critical
    source_ip          TEXT,
    affected_user       TEXT,
    affected_system     TEXT,
    event_count         INTEGER,             -- number of events that triggered the rule
    window_start         TEXT,
    window_end           TEXT,
    detection_reason      TEXT NOT NULL,
    recommended_action     TEXT NOT NULL,
    evidence_event_ids     TEXT,              -- comma-separated event_id list for drill-down
    status               TEXT DEFAULT 'Open'   -- Open | Investigating | Closed | False Positive
);

CREATE INDEX idx_alerts_sev ON alerts(severity);
CREATE INDEX idx_alerts_ts  ON alerts(detected_at);
CREATE INDEX idx_alerts_ip  ON alerts(source_ip);

-- Lightweight IP reputation / enrichment table, populated heuristically
-- (in a real SOC this would be fed by threat-intel feeds e.g. AbuseIPDB, OTX)
CREATE TABLE ip_reputation (
    source_ip     TEXT PRIMARY KEY,
    is_internal   INTEGER,          -- 1/0
    first_seen    TEXT,
    last_seen     TEXT,
    total_events  INTEGER,
    failed_events INTEGER,
    distinct_users INTEGER,
    risk_score    INTEGER,          -- 0-100 heuristic score
    risk_label    TEXT              -- Benign | Watch | Suspicious | Malicious
);
