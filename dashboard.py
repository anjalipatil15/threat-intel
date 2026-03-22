import streamlit as st
import pandas as pd
import re
from collections import Counter

st.set_page_config(page_title="Honeypot Threat Dashboard", layout="wide")

st.markdown("""
### Project Overview

This dashboard visualizes real-time cyber attack data collected from an SSH honeypot deployed on a cloud server.

The system captures:
- Unauthorized login attempts
- Credential brute-force attacks
- Commands executed by attackers

All data is parsed and analyzed to generate actionable threat intelligence.
""")

logfile = "cowrie.log"

ips = Counter()
passwords = Counter()
commands = Counter()

with open(logfile, "r", errors="ignore") as f:
    for line in f:
        ip_match = re.search(r"New connection: ([0-9\.]+)", line)
        if ip_match:
            ips[ip_match.group(1)] += 1

        login_match = re.search(r"login attempt \[b?'?(\w+)'?/b?'?(\w+)'?\]", line)
        if login_match:
            passwords[login_match.group(2)] += 1

        cmd_match = re.search(r"CMD: (.+)", line)
        if cmd_match:
            commands[cmd_match.group(1)] += 1

# Title
st.title("🚨 Cyber Threat Intelligence Dashboard")

# Metrics
col1, col2, col3 = st.columns(3)

col1.metric("Unique Attackers", len(ips))
col2.metric("Passwords Tried", sum(passwords.values()))
col3.metric("Commands Executed", sum(commands.values()))

# Layout
col1, col2 = st.columns(2)

with col1:
    st.subheader("Top Attacking IPs")
    ip_df = pd.DataFrame(ips.items(), columns=["IP", "Attempts"])
    st.bar_chart(ip_df.set_index("IP"))

with col2:
    st.subheader("Top Passwords")
    pass_df = pd.DataFrame(passwords.items(), columns=["Password", "Count"])
    st.bar_chart(pass_df.set_index("Password"))

st.subheader("Commands Executed")
cmd_df = pd.DataFrame(commands.items(), columns=["Command", "Count"])
st.bar_chart(cmd_df.set_index("Command"))
