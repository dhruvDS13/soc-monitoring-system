"""
SOC Security Log Monitoring & Threat Detection Dashboard
----------------------------------------------------------
Interactive Streamlit dashboard reading from soc.db (SQLite).

Run with:
    streamlit run dashboard/app.py

If soc.db doesn't exist yet, run the pipeline first:
    python3 src/generate_dataset.py
    python3 src/parse_logs.py
    python3 src/detection_rules.py
"""
import os
import sqlite3
import subprocess
import sys

import pandas as pd
import streamlit as st
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE, "soc.db")

st.set_page_config(page_title="SOC Threat Monitoring Dashboard", layout="wide", page_icon="🛡️")

SEVERITY_COLORS = {
    "Critical": "#B00020",
    "High": "#E8590C",
    "Medium": "#F1B400",
    "Low": "#2F9E44",
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


@st.cache_data(ttl=2)
def load_data():
    conn = sqlite3.connect(DB_PATH)
    logs = pd.read_sql_query("SELECT * FROM logs_normalized", conn, parse_dates=["event_timestamp"])
    alerts = pd.read_sql_query("SELECT * FROM alerts", conn, parse_dates=["detected_at", "window_start", "window_end"])
    ip_rep = pd.read_sql_query("SELECT * FROM ip_reputation", conn)
    conn.close()
    return logs, alerts, ip_rep
# ---------------------------------------------------------------------------
# Live simulator control
# ---------------------------------------------------------------------------
SIMULATOR_SCRIPT = os.path.join(BASE, "src", "live_simulator.py")


def start_live_simulator():
    """Start the live simulator once for this Streamlit session."""
    if not os.path.exists(SIMULATOR_SCRIPT):
        return None

    if "simulator_process" not in st.session_state:
        try:
            process = subprocess.Popen(
                [sys.executable, SIMULATOR_SCRIPT],
                cwd=BASE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            st.session_state.simulator_process = process
        except Exception:
            st.session_state.simulator_process = None

    return st.session_state.get("simulator_process")


def stop_live_simulator():
    """Stop the simulator when Live Mode is disabled."""
    process = st.session_state.get("simulator_process")

    if process is not None and process.poll() is None:
        process.terminate()

    st.session_state.simulator_process = None

if not os.path.exists(DB_PATH):
    st.error(
        "soc.db not found. Run the pipeline first:\n\n"
        "```\npython3 src/generate_dataset.py\npython3 src/parse_logs.py\n"
        "python3 src/detection_rules.py\n```"
    )
    st.stop()

logs, alerts, ip_rep = load_data()

# ---------------------------------------------------------------------------
# Sidebar filters
# ---------------------------------------------------------------------------
#st.sidebar.title("🛡️ SOC Dashboard Filters")
#live_mode = st.sidebar.toggle("🟢 Live Mode", value=True)
#if live_mode:
#    st_autorefresh(interval=5000, key="soc_live_refresh")
#    st.sidebar.caption("Refreshing every 5 seconds")


live_mode = st.sidebar.toggle("🟢 Live Mode", value=True)

if live_mode:
    simulator = start_live_simulator()

    st_autorefresh(
        interval=5000,
        key="soc_live_refresh"
    )

    st.sidebar.success("Live simulator running")
    st.sidebar.caption("New events are being generated automatically.")
else:
    stop_live_simulator()
    st.sidebar.info("Live Mode is OFF")    
    
    
    
    
min_d, max_d = logs["event_timestamp"].min().date(), logs["event_timestamp"].max().date()
date_range = st.sidebar.date_input("Date range", (min_d, max_d), min_value=min_d, max_value=max_d, format="DD/MM/YYYY")
sev_filter = st.sidebar.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
rule_filter = st.sidebar.multiselect(
    "Detection rule", sorted(alerts["rule_name"].unique()), default=sorted(alerts["rule_name"].unique())
)
st.sidebar.markdown("---")
st.sidebar.caption("Dataset: 1–5 years historical synthetic security events + optional near-real-time simulator.\n\nLive data is simulated because this portfolio project has no production log source.")

if isinstance(date_range, tuple) and len(date_range) == 2:
    start_d, end_d = date_range
else:
    start_d, end_d = min_d, max_d

logs_f = logs[(logs["event_timestamp"].dt.date >= start_d) & (logs["event_timestamp"].dt.date <= end_d)]
alerts_f = alerts[
    (alerts["detected_at"].dt.date >= start_d) & (alerts["detected_at"].dt.date <= end_d) &
    (alerts["severity"].isin(sev_filter)) & (alerts["rule_name"].isin(rule_filter))
]

# ---------------------------------------------------------------------------
# Header + KPIs
# ---------------------------------------------------------------------------
st.title("🛡️ SOC Security Log Monitoring & Threat Detection")
st.caption("Rule-based detection over authentication + web server logs, junior-analyst workflow")

total_events = len(logs_f)
failed_logins = len(logs_f[(logs_f.source_type == "auth") & (logs_f.status == "failure")])
suspicious_ips = ip_rep[ip_rep.risk_label.isin(["Suspicious", "Malicious"])].shape[0]
critical_alerts = len(alerts_f[alerts_f.severity == "Critical"])
total_alerts = len(alerts_f)

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Total Events", f"{total_events:,}")
k2.metric("Failed Logins", f"{failed_logins:,}")
k3.metric("Suspicious/Malicious IPs", f"{suspicious_ips:,}")
k4.metric("Total Alerts", f"{total_alerts:,}")
k5.metric("Critical Alerts", f"{critical_alerts:,}", delta=None,
          delta_color="inverse")

st.markdown("---")

# ---------------------------------------------------------------------------
# Row 1: Alerts by severity + Attack trend over time
# ---------------------------------------------------------------------------
c1, c2 = st.columns([1, 2])

with c1:
    st.subheader("Alerts by Severity")
    sev_counts = alerts_f["severity"].value_counts().reindex(SEVERITY_ORDER).fillna(0).reset_index()
    sev_counts.columns = ["severity", "count"]
    fig = px.bar(sev_counts, x="severity", y="count", color="severity",
                 color_discrete_map=SEVERITY_COLORS, category_orders={"severity": SEVERITY_ORDER})
    fig.update_layout(showlegend=False, height=350)
    st.plotly_chart(fig, use_container_width=True)

with c2:
    st.subheader("Attack Trend Over Time")
    trend = alerts_f.copy()
    range_days = (end_d - start_d).days
    trend["period"] = trend["detected_at"].dt.to_period("D").dt.start_time if range_days <= 90 else trend["detected_at"].dt.to_period("M").dt.start_time
    trend_counts = trend.groupby(["period", "severity"]).size().reset_index(name="count")
    fig2 = px.bar(trend_counts, x="period", y="count", color="severity",
                  color_discrete_map=SEVERITY_COLORS, category_orders={"severity": SEVERITY_ORDER},
                  barmode="stack")
    fig2.update_layout(height=350)
    st.plotly_chart(fig2, use_container_width=True)

# ---------------------------------------------------------------------------
# Row 2: Top targeted accounts + Top suspicious IPs
# ---------------------------------------------------------------------------
c3, c4 = st.columns(2)

with c3:
    st.subheader("Top Targeted Accounts (Failed Logins)")
    fail_users = (
        logs_f[(logs_f.source_type == "auth") & (logs_f.status == "failure")]
        .groupby("username").size().reset_index(name="failed_attempts")
        .sort_values("failed_attempts", ascending=False).head(10)
    )
    if not fail_users.empty:
        fig3 = px.bar(fail_users, x="failed_attempts", y="username", orientation="h",
                      color="failed_attempts", color_continuous_scale="Reds")
        fig3.update_layout(height=380, yaxis={"categoryorder": "total ascending"}, coloraxis_showscale=False)
        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("No failed logins in selected range.")

with c4:
    st.subheader("Top Suspicious Source IPs")
    top_ips = ip_rep.sort_values("risk_score", ascending=False).head(10)
    fig4 = px.bar(top_ips, x="risk_score", y="source_ip", orientation="h",
                  color="risk_label",
                  color_discrete_map={"Malicious": "#B00020", "Suspicious": "#E8590C",
                                       "Watch": "#F1B400", "Benign": "#2F9E44"})
    fig4.update_layout(height=380, yaxis={"categoryorder": "total ascending"})
    st.plotly_chart(fig4, use_container_width=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# Row 3: Recent Security Incidents (alert table)
# ---------------------------------------------------------------------------
st.subheader("🚨 Recent Security Incidents")

display_cols = ["detected_at", "rule_name", "severity", "source_ip", "affected_user",
                 "affected_system", "event_count", "detection_reason", "recommended_action"]
alerts_display = alerts_f.sort_values(
    by="severity", key=lambda s: s.map({v: i for i, v in enumerate(SEVERITY_ORDER)})
).sort_values("detected_at", ascending=False)[display_cols]


def highlight_severity(row):
    color = SEVERITY_COLORS.get(row["severity"], "#FFFFFF")
    return [f"background-color: {color}20" if c == "severity" else "" for c in row.index]


st.dataframe(
    alerts_display.style.apply(highlight_severity, axis=1),
    use_container_width=True,
    height=450,
)

st.download_button(
    "⬇ Download alerts as CSV",
    alerts_display.to_csv(index=False).encode("utf-8"),
    file_name="soc_alerts_export.csv",
    mime="text/csv",
)

st.markdown("---")

# ---------------------------------------------------------------------------
# Row 4: Alert investigation drill-down
# ---------------------------------------------------------------------------
st.subheader("🔍 Alert Investigation Drill-Down")
if not alerts_f.empty:
    alert_options = alerts_f.sort_values("detected_at", ascending=False)
    selected_id = st.selectbox(
        "Select an alert to inspect its raw evidence log lines",
        alert_options["alert_id"],
        format_func=lambda i: (
            f"#{i} - {alert_options.loc[alert_options.alert_id == i, 'rule_name'].values[0]} "
            f"({alert_options.loc[alert_options.alert_id == i, 'severity'].values[0]})"
        ),
    )
    sel = alerts[alerts.alert_id == selected_id].iloc[0]
    st.markdown(f"**Rule:** {sel['rule_name']}  |  **Severity:** {sel['severity']}  |  "
                f"**Source IP:** {sel['source_ip']}  |  **Affected user:** {sel['affected_user']}")
    st.markdown(f"**Detection reason:** {sel['detection_reason']}")
    st.markdown(f"**Recommended action:** {sel['recommended_action']}")
    if sel["evidence_event_ids"]:
        ids = [int(x) for x in str(sel["evidence_event_ids"]).split(",") if x][:50]
        evidence = logs[logs.event_id.isin(ids)][["event_timestamp", "raw_line"]].sort_values("event_timestamp")
        st.code("\n".join(evidence["raw_line"].tolist()), language="text")
else:
    st.info("No alerts match the current filters.")

st.markdown("---")
st.caption("⚠️ Portfolio mode: historical data is synthetic and Live Mode uses a local event simulator. Replace the simulator with an authorized production log source when available.")
