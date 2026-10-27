import re
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "soc_incidents.db"
SAMPLE_PATH = APP_DIR / "data" / "sample_logs.csv"

REQUIRED_COLUMNS = ["timestamp", "event_type", "username", "src_ip", "host", "details"]

st.set_page_config(page_title="AI SOC Threat Triage", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.stApp { background: #07111f; color: #e8f4ff; }
h1, h2, h3 { color: #55dff5 !important; }
[data-testid="stMetric"] {
  background: #0d2033; border: 1px solid #17415b;
  padding: 14px; border-radius: 10px;
}
div[data-testid="stDataFrame"] { border: 1px solid #17415b; }
</style>
""", unsafe_allow_html=True)

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incident_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                event_type TEXT NOT NULL,
                username TEXT,
                src_ip TEXT,
                host TEXT,
                details TEXT,
                rationale TEXT
            )
        """)

def load_events(uploaded_file):
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
    else:
        df = pd.read_csv(SAMPLE_PATH)

    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError("CSV is missing required columns: " + ", ".join(missing))

    df = df[REQUIRED_COLUMNS].copy()
    for col in REQUIRED_COLUMNS:
        df[col] = df[col].fillna("").astype(str).str.strip()

    # Validate timestamps and retain the original string for display.
    parsed = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    if parsed.isna().any():
        bad_rows = (parsed.isna()).sum()
        raise ValueError(f"{bad_rows} timestamp value(s) could not be parsed. Use ISO timestamps such as 2026-10-18T10:32:14Z.")
    df["_parsed_time"] = parsed
    return df.sort_values("_parsed_time").reset_index(drop=True)

def analyze_events(df):
    results = []
    # Correlate failed then successful logins for the same username and source IP.
    failed_keys = set()
    for _, row in df.iterrows():
        event = row["event_type"].lower()
        details = row["details"].lower()
        user = row["username"]
        ip = row["src_ip"]
        key = (user, ip)

        if "failed login" in event or "login failed" in event:
            failed_keys.add(key)

        severity = "Low"
        rationale = "No configured high-risk rule matched."

        if "powershell" in event or "encoded command" in details or "encoded powershell" in details:
            severity = "Critical"
            rationale = "PowerShell or encoded-command indicator requires analyst review."
        elif "data exfiltration" in event or "exfiltration" in details:
            severity = "Critical"
            rationale = "Possible data-exfiltration indicator requires investigation."
        elif "successful login" in event or "login success" in event:
            if key in failed_keys:
                severity = "High"
                rationale = "Successful login follows a failed login for the same username and source IP in this dataset."
            else:
                severity = "Low"
                rationale = "Successful login without a matching earlier failed login in this dataset."
        elif "suspicious domain" in event or "malicious domain" in details:
            severity = "High"
            rationale = "Domain-related event is marked suspicious in the supplied log."
        elif "network scan" in event or "port scan" in event:
            severity = "Medium"
            rationale = "Network scanning can be reconnaissance; verify whether it was authorized."
        elif "failed login" in event or "login failed" in event:
            severity = "Medium"
            rationale = "Failed authentication may indicate a mistake or attempted account access."

        results.append({
            **row.to_dict(),
            "severity": severity,
            "rationale": rationale,
        })

    out = pd.DataFrame(results)
    return out.drop(columns=["_parsed_time"], errors="ignore")

def extract_iocs(df):
    text = " ".join(df["src_ip"].astype(str).tolist() + df["details"].astype(str).tolist())
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))
    # Basic domain extraction; intentionally not a threat verdict.
    domains = sorted(set(re.findall(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b",
        text
    )))
    hashes = sorted(set(re.findall(r"\b[a-fA-F0-9]{32,64}\b", text)))
    return ips, domains, hashes

def save_incidents(df):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = [
        (now, r["severity"], r["event_type"], r["username"], r["src_ip"],
         r["host"], r["details"], r["rationale"])
        for _, r in df.iterrows()
    ]
    with sqlite3.connect(DB_PATH) as conn:
        conn.executemany("""
            INSERT INTO incident_history
            (created_at, severity, event_type, username, src_ip, host, details, rationale)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)

def read_history():
    with sqlite3.connect(DB_PATH) as conn:
        return pd.read_sql_query(
            "SELECT id, created_at, severity, event_type, username, src_ip, host, details, rationale "
            "FROM incident_history ORDER BY id DESC LIMIT 500", conn
        )

init_db()
st.title("🛡️ AI-Powered SOC Threat Triage")
st.caption("Final-year project prototype | Log analysis · Rule-based detection · IOC extraction · Incident history")

with st.sidebar:
    st.header("Investigation Controls")
    uploaded = st.file_uploader("Upload security logs (CSV)", type=["csv"])
    st.caption("Required columns: " + ", ".join(REQUIRED_COLUMNS))
    severity_filter = st.multiselect(
        "Filter by severity",
        ["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"],
    )
    st.divider()
    st.info("Demo mode uses sample logs unless you upload your own authorized lab logs.")

try:
    raw_df = load_events(uploaded)
    analyzed = analyze_events(raw_df)
except Exception as exc:
    st.error(f"Could not load or analyze logs: {exc}")
    st.stop()

filtered = analyzed[analyzed["severity"].isin(severity_filter)].copy()
counts = analyzed["severity"].value_counts()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analyzed", len(analyzed))
c2.metric("Critical", int((analyzed["severity"] == "Critical").sum()))
c3.metric("High", int((analyzed["severity"] == "High").sum()))
c4.metric("Medium", int((analyzed["severity"] == "Medium").sum()))

tab1, tab2, tab3, tab4 = st.tabs(["Dashboard", "Investigate", "IOC Extraction", "Incident History"])

with tab1:
    left, right = st.columns([3, 2])
    with left:
        st.subheader("Event Timeline")
        st.dataframe(
            filtered[["timestamp", "event_type", "username", "src_ip", "host", "severity", "rationale"]],
            use_container_width=True, hide_index=True
        )
    with right:
        st.subheader("Severity Distribution")
        chart_data = counts.reindex(["Critical", "High", "Medium", "Low"], fill_value=0)
        st.bar_chart(chart_data)
        st.subheader("Detection Notes")
        st.write("These are rule-based findings. They are not proof that an attack occurred.")
        st.write("Review the event context and correlate with trusted endpoint, identity, and network records.")

with tab2:
    st.subheader("Incident Investigation")
    if filtered.empty:
        st.warning("No events match the selected severity filters.")
    else:
        options = filtered.index.tolist()
        selected = st.selectbox(
            "Choose an event",
            options,
            format_func=lambda i: f'{filtered.loc[i, "timestamp"]} | {filtered.loc[i, "event_type"]} | {filtered.loc[i, "severity"]}'
        )
        row = filtered.loc[selected]
        a, b = st.columns(2)
        with a:
            st.write("**Event:**", row["event_type"])
            st.write("**Severity:**", row["severity"])
            st.write("**Username:**", row["username"] or "Not provided")
            st.write("**Source IP:**", row["src_ip"] or "Not provided")
        with b:
            st.write("**Host:**", row["host"] or "Not provided")
            st.write("**Timestamp:**", row["timestamp"])
            st.write("**Details:**", row["details"] or "Not provided")
        st.info("**Detection rationale:** " + row["rationale"])
        if st.button("Save displayed events to incident history"):
            save_incidents(filtered)
            st.success(f"Saved {len(filtered)} event record(s) to local SQLite history.")

with tab3:
    st.subheader("Indicators of Compromise (IOC) Extraction")
    ips, domains, hashes = extract_iocs(raw_df)
    x, y, z = st.columns(3)
    x.metric("IP-like values", len(ips))
    y.metric("Domain-like values", len(domains))
    z.metric("Hash-like values", len(hashes))
    st.caption("Pattern matching extracts candidate indicators; it does not validate reputation or maliciousness.")
    st.write("**IP addresses**")
    st.code("\n".join(ips) if ips else "No IP-like values found.")
    st.write("**Domains**")
    st.code("\n".join(domains) if domains else "No domain-like values found.")
    st.write("**Hashes**")
    st.code("\n".join(hashes) if hashes else "No hash-like values found.")

with tab4:
    st.subheader("Saved Incident History")
    history = read_history()
    if history.empty:
        st.info("No history saved yet. Open Investigate and click the save button.")
    else:
        st.dataframe(history, use_container_width=True, hide_index=True)
        st.download_button(
            "Download history as CSV",
            data=history.to_csv(index=False).encode("utf-8"),
            file_name="soc_incident_history.csv",
            mime="text/csv",
        )

st.divider()
st.subheader("Export current analysis")
st.download_button(
    "Download analyzed events (CSV)",
    data=analyzed.to_csv(index=False).encode("utf-8"),
    file_name="soc_analyzed_events.csv",
    mime="text/csv",
)
st.caption("Prototype limitation: no live SIEM connection, trained ML classifier, RAG pipeline, or automatic response is enabled in this starter.")
