-- ============================================================
-- SOC Security Log Monitoring - Reference SQL Analysis Queries
-- ============================================================
-- These queries demonstrate the SQL-based analysis side of the project.
-- The production detection engine (src/detection_rules.py) implements the
-- same logic in Python/pandas so it can do sliding-time-window grouping,
-- but every rule below can be expressed (and validated) directly in SQL.
-- Run against soc.db, e.g.:  sqlite3 soc.db < sql/detection_queries.sql

-- ------------------------------------------------------------
-- 1. Total events processed, by source
-- ------------------------------------------------------------
SELECT source_type, COUNT(*) AS total_events
FROM logs_normalized
GROUP BY source_type;

-- ------------------------------------------------------------
-- 2. Failed logins by day
-- ------------------------------------------------------------
SELECT DATE(event_timestamp) AS day, COUNT(*) AS failed_logins
FROM logs_normalized
WHERE source_type = 'auth' AND status = 'failure'
GROUP BY day
ORDER BY day;

-- ------------------------------------------------------------
-- 3. Repeated failed logins per user (>=5 failures, any window)
--    Quick non-windowed version - see detection_rules.py for the
--    true 15-minute sliding-window implementation.
-- ------------------------------------------------------------
SELECT username, COUNT(*) AS failed_attempts
FROM logs_normalized
WHERE source_type = 'auth' AND status = 'failure'
GROUP BY username
HAVING COUNT(*) >= 5
ORDER BY failed_attempts DESC;

-- ------------------------------------------------------------
-- 4. Brute-force candidate IPs: many failed SSH attempts, few successes
-- ------------------------------------------------------------
SELECT
    source_ip,
    SUM(CASE WHEN status = 'failure' THEN 1 ELSE 0 END) AS failed_attempts,
    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS successful_attempts,
    COUNT(DISTINCT username) AS distinct_usernames_tried,
    MIN(event_timestamp) AS first_seen,
    MAX(event_timestamp) AS last_seen
FROM logs_normalized
WHERE source_type = 'auth'
GROUP BY source_ip
HAVING failed_attempts >= 5
ORDER BY failed_attempts DESC;

-- ------------------------------------------------------------
-- 5. Multiple distinct accounts accessed from the same source IP
-- ------------------------------------------------------------
SELECT
    source_ip,
    COUNT(DISTINCT username) AS distinct_accounts,
    GROUP_CONCAT(DISTINCT username) AS accounts,
    MIN(event_timestamp) AS first_seen,
    MAX(event_timestamp) AS last_seen
FROM logs_normalized
WHERE source_type = 'auth'
GROUP BY source_ip
HAVING distinct_accounts >= 3
ORDER BY distinct_accounts DESC;

-- ------------------------------------------------------------
-- 6. Unusual login times (successful logins between 00:00-05:00)
-- ------------------------------------------------------------
SELECT event_timestamp, username, source_ip, destination_host
FROM logs_normalized
WHERE source_type = 'auth'
  AND status = 'success'
  AND CAST(strftime('%H', event_timestamp) AS INTEGER) BETWEEN 0 AND 4
ORDER BY event_timestamp;

-- ------------------------------------------------------------
-- 7. High-frequency requesters (possible bots/scanners/DoS)
--    Requests per source IP per 5-minute bucket
-- ------------------------------------------------------------
SELECT
    source_ip,
    strftime('%Y-%m-%d %H:', event_timestamp) ||
        (CAST(strftime('%M', event_timestamp) AS INTEGER) / 5) * 5 AS five_min_bucket,
    COUNT(*) AS requests_in_bucket
FROM logs_normalized
WHERE source_type = 'web'
GROUP BY source_ip, five_min_bucket
HAVING requests_in_bucket >= 50
ORDER BY requests_in_bucket DESC;

-- ------------------------------------------------------------
-- 8. Suspicious IP behaviour: high failure ratio & many distinct users
--    (mirrors the ip_reputation heuristic scoring)
-- ------------------------------------------------------------
SELECT source_ip, is_internal, total_events, failed_events, distinct_users,
       risk_score, risk_label
FROM ip_reputation
WHERE risk_label IN ('Suspicious', 'Malicious')
ORDER BY risk_score DESC;

-- ------------------------------------------------------------
-- 9. Top targeted accounts (most failed login attempts against them)
-- ------------------------------------------------------------
SELECT username, COUNT(*) AS failed_attempts
FROM logs_normalized
WHERE source_type = 'auth' AND status = 'failure'
GROUP BY username
ORDER BY failed_attempts DESC
LIMIT 10;

-- ------------------------------------------------------------
-- 10. Alerts by severity (dashboard KPI source)
-- ------------------------------------------------------------
SELECT severity, COUNT(*) AS alert_count
FROM alerts
GROUP BY severity
ORDER BY CASE severity
    WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END;

-- ------------------------------------------------------------
-- 11. Recent security incidents (latest 20 alerts, most severe first)
-- ------------------------------------------------------------
SELECT detected_at, rule_name, severity, source_ip, affected_user,
       event_count, detection_reason
FROM alerts
ORDER BY
    CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END,
    detected_at DESC
LIMIT 20;

-- ------------------------------------------------------------
-- 12. Attack trend over time: alerts per day
-- ------------------------------------------------------------
SELECT DATE(detected_at) AS day, severity, COUNT(*) AS alerts
FROM alerts
GROUP BY day, severity
ORDER BY day;
