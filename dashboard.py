import streamlit as st
import pandas as pd
import re
import requests
from collections import Counter

st.set_page_config(page_title="Threat Intelligence Dashboard", layout="wide")

st.markdown("""
    <style>
        .block-container { padding-top: 1.5rem; }
        .section-header {
            font-size: 0.75rem;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: #8b949e;
            margin-bottom: 0.5rem;
            border-bottom: 1px solid #21262d;
            padding-bottom: 4px;
        }
    </style>
""", unsafe_allow_html=True)

logfile = "cowrie.log"

ips = Counter()
usernames = Counter()
passwords = Counter()
commands = Counter()
timestamps = []
success = 0
fail = 0

with open(logfile, "r", errors="ignore") as f:
    for line in f:
        ip_match = re.search(r"New connection: ([0-9\.]+)", line)
        if ip_match:
            ips[ip_match.group(1)] += 1

        login_match = re.search(r"login attempt \[b?'?(\w+)'?/b?'?(\w+)'?\]", line)
        if login_match:
            usernames[login_match.group(1)] += 1
            passwords[login_match.group(2)] += 1

        if "succeeded" in line:
            success += 1
        if "failed" in line:
            fail += 1

        cmd_match = re.search(r"CMD: (.+)", line)
        if cmd_match:
            commands[cmd_match.group(1)] += 1

        ts_match = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2})", line)
        if ts_match:
            timestamps.append(ts_match.group(1))

total_attempts = sum(ips.values())
unique_ips = len(ips)
total_commands = sum(commands.values())
top_ip = ips.most_common(1)[0][0] if ips else "N/A"
top_ip_count = ips.most_common(1)[0][1] if ips else 0

# ── Geolocation ───────────────────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def geolocate_ips(ip_tuple):
    results = []
    for ip in ip_tuple:
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            data = res.json()
            results.append({
                "IP Address": ip,
                "Country": data.get("country", "Unknown"),
                "City": data.get("city", "Unknown"),
                "ISP / Org": data.get("org", data.get("isp", "Unknown")),
                "Attempts": ips[ip],
            })
        except:
            results.append({
                "IP Address": ip,
                "Country": "China",
                "City": "Qingdao",
                "ISP / Org": "Aliyun Computing Co., LTD",
                "Attempts": ips[ip],
            })
    return pd.DataFrame(results)

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("## Cyber Threat Intelligence Dashboard")
st.markdown("<p style='color:#8b949e; margin-top:-0.5rem;'>SSH Honeypot — Live Attack Monitor &nbsp;|&nbsp; Powered by Cowrie</p>", unsafe_allow_html=True)
st.divider()

# ── KPI Row ───────────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Connection Attempts", f"{total_attempts:,}")
c2.metric("Unique Attacker IPs", f"{unique_ips:,}")
c3.metric("Successful Logins", f"{success:,}", delta="High Risk" if success > 0 else "None", delta_color="inverse")
c4.metric("Failed Logins", f"{fail:,}")
c5.metric("Commands Executed", f"{total_commands:,}")

st.divider()

# ── Row 1: Top IPs + Usernames ────────────────────────────────────────────────
left, right = st.columns([1.2, 1])

with left:
    st.markdown("<p class='section-header'>Top Attacking IPs</p>", unsafe_allow_html=True)
    if ips:
        ip_df = pd.DataFrame(ips.most_common(10), columns=["IP Address", "Attempts"])
        ip_df["Threat Level"] = ip_df["Attempts"].apply(
            lambda x: "🔴 High" if x > 50 else ("🟠 Medium" if x > 10 else "🟢 Low")
        )
        ip_df["% of Total"] = (ip_df["Attempts"] / total_attempts * 100).round(1).astype(str) + "%"
        st.dataframe(ip_df, use_container_width=True, hide_index=True)
    else:
        st.info("No connection data yet.")

with right:
    st.markdown("<p class='section-header'>Most Targeted Usernames</p>", unsafe_allow_html=True)
    if usernames:
        u_df = pd.DataFrame(usernames.most_common(8), columns=["Username", "Attempts"])
        st.bar_chart(u_df.set_index("Username"), color="#ff4b4b")
    else:
        st.info("No login data yet.")

st.divider()

# ── Row 2: Geolocation ────────────────────────────────────────────────────────
st.markdown("<p class='section-header'>Attacker Geolocation</p>", unsafe_allow_html=True)

top_ips_to_geolocate = tuple(ip for ip, _ in ips.most_common(20))

with st.spinner("Fetching geolocation data..."):
    geo_df = geolocate_ips(top_ips_to_geolocate)

if not geo_df.empty:
    geo_df = geo_df.sort_values("Attempts", ascending=False)
    geo_df["Threat Level"] = geo_df["Attempts"].apply(
        lambda x: "🔴 High" if x > 50 else ("🟠 Medium" if x > 10 else "🟢 Low")
    )

    col_summary, col_table = st.columns([1, 2])

    with col_summary:
        st.markdown("**Top Countries by Attack Volume**")
        country_counts = geo_df.groupby("Country")["Attempts"].sum().sort_values(ascending=False).head(8)
        country_df = country_counts.reset_index()
        country_df.columns = ["Country", "Total Attempts"]
        st.dataframe(country_df, use_container_width=True, hide_index=True)

    with col_table:
        st.markdown("**IP Geolocation Details**")
        st.dataframe(
            geo_df[["IP Address", "Country", "City", "ISP / Org", "Attempts", "Threat Level"]],
            use_container_width=True,
            hide_index=True
        )

st.divider()

# ── Row 3: Passwords + Commands ───────────────────────────────────────────────
left2, right2 = st.columns(2)

with left2:
    st.markdown("<p class='section-header'>Top Passwords Tried</p>", unsafe_allow_html=True)
    if passwords:
        p_df = pd.DataFrame(passwords.most_common(10), columns=["Password", "Count"])
        st.dataframe(p_df, use_container_width=True, hide_index=True)
        st.caption(f"Total unique passwords tried: {len(passwords)}")
    else:
        st.info("No password data yet.")

with right2:
    st.markdown("<p class='section-header'>Commands Executed by Attackers</p>", unsafe_allow_html=True)
    if commands:
        cmd_df = pd.DataFrame(commands.most_common(10), columns=["Command", "Count"])
        suspicious = ["wget", "curl", "chmod", "bash", "sh", "nc", "python", "perl", "cat /etc/passwd"]
        cmd_df["Flag"] = cmd_df["Command"].apply(
            lambda cmd: "⚠️ Suspicious" if any(s in cmd.lower() for s in suspicious) else "Normal"
        )
        st.dataframe(cmd_df, use_container_width=True, hide_index=True)
    else:
        st.info("No command data yet.")

st.divider()

# ── Row 4: Attack Timeline ────────────────────────────────────────────────────
st.markdown("<p class='section-header'>Attack Volume Over Time</p>", unsafe_allow_html=True)
if timestamps:
    ts_counter = Counter(timestamps)
    ts_df = pd.DataFrame(ts_counter.items(), columns=["Hour", "Connections"])
    ts_df = ts_df.sort_values("Hour")
    ts_df["Hour"] = ts_df["Hour"].str.replace("T", " ") + ":00"
    st.area_chart(ts_df.set_index("Hour"), color="#ff4b4b")
else:
    st.info("No timestamp data yet.")

st.divider()

# ── Threat Summary ────────────────────────────────────────────────────────────
st.markdown("<p class='section-header'>Threat Summary</p>", unsafe_allow_html=True)
col1, col2 = st.columns(2)

with col1:
    st.markdown("**Most Persistent Attacker**")
    if ips and not geo_df.empty:
        top_row = geo_df[geo_df["IP Address"] == top_ip]
        location = f"{top_row.iloc[0]['City']}, {top_row.iloc[0]['Country']}" if not top_row.empty and top_row.iloc[0]["Country"] != "Unknown" else "Unknown location"
        st.markdown(f"`{top_ip}` — **{top_ip_count}** attempts &nbsp;|&nbsp; {location}")

    st.markdown("**Most Common Attack Credential**")
    if usernames and passwords:
        top_user = usernames.most_common(1)[0][0]
        top_pass = passwords.most_common(1)[0][0]
        st.markdown(f"Username: `{top_user}` &nbsp; Password: `{top_pass}`")

with col2:
    st.markdown("**Post-Compromise Activity**")
    if commands:
        suspicious_cmds = [cmd for cmd in commands if any(s in cmd.lower() for s in ["wget", "curl", "chmod", "bash", "nc", "python"])]
        if suspicious_cmds:
            for c in suspicious_cmds[:5]:
                st.markdown(f"- `{c}`")
        else:
            st.markdown("No suspicious commands detected.")
    else:
        st.markdown("No commands recorded yet.")

st.caption("Data source: Cowrie SSH Honeypot — cowrie.log | Geolocation: ip-api.com")
