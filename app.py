import streamlit as st
import pandas as pd
import random
import time
import plotly.express as px

st.set_page_config(layout="wide")

st.title("🚨 NIDS with DevOps Dashboard")

# -------------------------------
# TOP METRICS
# -------------------------------
col1, col2, col3 = st.columns(3)

col1.metric("Detection Accuracy", "98.7%")
col2.metric("Active Models", "1 Running")
col3.metric("System Status", "🟢 Operational")

# -------------------------------
# TRAFFIC GRAPH
# -------------------------------
st.subheader("📈 Traffic Volume Over Time")

data = pd.DataFrame({
    "time": list(range(50)),
    "traffic": [random.randint(10, 200) for _ in range(50)]
})

fig = px.line(data, x="time", y="traffic")
st.plotly_chart(fig, use_container_width=True)

# -------------------------------
# ATTACK DISTRIBUTION
# -------------------------------
st.subheader("📊 Attack Types Distribution")

attack_data = pd.DataFrame({
    "type": ["DoS", "Probe", "R2L", "U2R"],
    "count": [random.randint(10,100) for _ in range(4)]
})

fig2 = px.bar(attack_data, x="type", y="count", color="type")
st.plotly_chart(fig2, use_container_width=True)

# -------------------------------
# ALERTS SECTION
# -------------------------------
st.subheader("🚨 Active Alerts")

alerts = []
try:
    with open("alerts.log", "r") as f:
        alerts = f.readlines()
except:
    pass

if alerts:
    for alert in alerts[-5:]:
        st.error(alert)
else:
    st.success("No threats detected")

# -------------------------------
# SUSPICIOUS IP TABLE
# -------------------------------
st.subheader("🌐 Suspicious IPs")

ip_data = pd.DataFrame({
    "IP": ["192.168.1.100","192.168.1.102","192.168.1.105"],
    "Attack Type": ["DoS","Probe","Port Scan"],
    "Frequency": [10, 7, 5]
})

st.dataframe(ip_data)

# -------------------------------
# FEATURE TABLE (SIMULATION)
# -------------------------------
st.subheader("🔍 Feature Extraction")

feature_data = pd.DataFrame({
    "Source IP": ["192.168.1.100","192.168.1.102"],
    "Packet Size": [120, 300],
    "Prediction": ["Normal","Attack"]
})

st.dataframe(feature_data)