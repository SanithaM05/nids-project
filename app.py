import streamlit as st
import pandas as pd
import plotly.express as px
import time
from collections import Counter

st.set_page_config(layout="wide")

st.title("🚨 Real-Time Network Intrusion Detection System")

# ------------------ READ ALERTS ------------------
alerts = []
try:
    with open("alerts.log", "r") as f:
        alerts = f.readlines()
except:
    pass

# ------------------ TOP METRICS ------------------
total_alerts = len(alerts)
unique_ips = set()

for alert in alerts:
    parts = alert.split()
    if len(parts) > 3:
        unique_ips.add(parts[-1])

col1, col2, col3 = st.columns(3)

col1.metric("Total Alerts", total_alerts)
col2.metric("Suspicious IPs", len(unique_ips))
col3.metric("System Status", "🟢 Running")

# ------------------ ALERTS SECTION ------------------
st.subheader("🚨 Live Alerts")

if alerts:
    for alert in alerts[-10:]:
        st.error(alert.strip())
else:
    st.success("No threats detected")

# ------------------ ATTACK TYPE ANALYSIS ------------------
st.subheader("📊 Attack Distribution")

attack_types = []
for alert in alerts:
    if "DDoS" in alert:
        attack_types.append("DDoS")
    elif "Port Scan" in alert:
        attack_types.append("Port Scan")
    elif "ML Attack" in alert:
        attack_types.append("ML Attack")

if attack_types:
    count = Counter(attack_types)
    df = pd.DataFrame({
        "Attack": list(count.keys()),
        "Count": list(count.values())
    })

    fig = px.bar(df, x="Attack", y="Count", color="Attack")
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No attack data yet")

# ------------------ SUSPICIOUS IP TABLE ------------------
st.subheader("🌐 Suspicious IPs")

ip_counter = Counter()
for alert in alerts:
    parts = alert.split()
    if len(parts) > 3:
        ip_counter[parts[-1]] += 1

if ip_counter:
    df_ip = pd.DataFrame({
        "IP": list(ip_counter.keys()),
        "Frequency": list(ip_counter.values())
    })

    st.dataframe(df_ip)
else:
    st.info("No suspicious IPs yet")

# ------------------ LIVE TRAFFIC GRAPH ------------------
st.subheader("📈 Alert Activity Over Time")

times = list(range(len(alerts)))
counts = list(range(1, len(alerts)+1))

if alerts:
    df_graph = pd.DataFrame({
        "Time": times,
        "Alerts": counts
    })

    fig2 = px.line(df_graph, x="Time", y="Alerts")
    st.plotly_chart(fig2, use_container_width=True)

# ------------------ AUTO REFRESH ------------------
time.sleep(3)
st.rerun()