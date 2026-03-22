# Honeypot-Based Cyber Threat Intelligence (CTI) System

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Deployment: AWS](https://img.shields.io/badge/Deployment-AWS_EC2-orange.svg)](https://aws.amazon.com/)

## 📌 Overview
This project implements a cloud-deployed **Cyber Threat Intelligence pipeline** using an SSH honeypot to capture, monitor, and analyze real-world attacker behavior. 

By simulating a vulnerable server, the system attracts malicious actors, collects interaction logs, and processes telemetry data to generate actionable intelligence—including IP patterns, brute-force credentials, and post-compromise command analysis.

---

## 🎯 Objectives
* **Capture** real-time attack traffic in a secure, isolated environment.
* **Analyze** TTPs (Tactics, Techniques, and Procedures) used by automated bots and human actors.
* **Extract** actionable indicators of compromise (IoCs) from raw logs.
* **Visualize** security trends via an interactive, data-driven dashboard.

---

## ⚙️ Key Features
* **🍯 Cowrie SSH Honeypot:** High-interaction shell simulation to deceive attackers.
* **🌍 Global Telemetry:** Tracking attacker source IPs and session durations.
* **🔐 Brute-Force Analytics:** Logging and deduplicating username/password combinations.
* **💻 Command Tracking:** Recording every keystroke and command executed by the attacker.
* **📊 Dynamic Dashboard:** Real-time visualization using Streamlit.
* **🧠 Logic-Driven Parsing:** Automated Python scripts to transform JSON logs into structured insights.

---

## 🧱 System Architecture



1.  **Attackers (Internet):** Initiate brute-force or SSH connection attempts.
2.  **AWS EC2 Instance:** Hosts the Cowrie honeypot container/service.
3.  **Log Storage:** Raw JSON logs are stored locally (e.g., `cowrie.json`).
4.  **Processing Layer:** Python scripts (`parser.py`) clean and structure the data.
5.  **Intelligence Layer:** Data is aggregated into Pandas DataFrames for trend analysis.
6.  **Presentation Layer:** Streamlit renders a dashboard for the security analyst.

---

## 🛠️ Technologies Used
* **Language:** Python 3.x
* **Honeypot:** Cowrie (SSH/Telnet)
* **Infrastructure:** AWS EC2
* **Data Science:** Pandas, NumPy
* **Visualization:** Streamlit, Plotly
* **Testing:** Hydra (for local attack simulation)

---

## 🚀 Setup & Execution

### 1️⃣ Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/honeypot-threat-intel.git](https://github.com/YOUR_USERNAME/honeypot-threat-intel.git)
cd honeypot-threat-intel
```

### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 3️⃣ Prepare Data
Ensure your Cowrie logs (`cowrie.json`) are placed in the `/logs` directory, then run the parser:
```bash
python parser.py
```

### 4️⃣ Launch the Dashboard
```bash
streamlit run dashboard.py
```

---

## 📊 Dashboard Capabilities
The interactive UI provides a "Security Operations Center" (SOC) view of the following:
* **Top 10 Attacking IPs:** Identifying persistent threats.
* **Credential Heatmap:** Most targeted usernames (e.g., `root`, `admin`) and common passwords.
* **Command Audit:** A chronological feed of commands like `wget`, `curl`, and `chmod`.
* **Attack Velocity:** Time-series charts showing peak attack hours.

---

## 📈 Sample Threat Insights
> [!IMPORTANT]
> Initial observations from the deployment revealed:
> * **Reconnaissance:** Frequent use of `whoami` and `uname -a` immediately after login.
> * **Payloads:** Attempts to download shell scripts via `wget` from remote mirrors.
> * **Botnets:** Automated "spray and pray" patterns originating from known malicious subnets.

---

## 🔮 Future Enhancements
* **MITRE ATT&CK Mapping:** Automatically tag captured commands with ATT&CK IDs.
* **Geographic Heatmap:** Integrate IP geolocation APIs for 3D globe visualizations.
* **Automated Response:** Integration with AWS Security Groups to auto-block high-frequency IPs.
* **Discord/Slack Alerts:** Real-time notifications for successful "logins."

---

## 🧠 Learning Outcomes
* Deployed and hardened cloud infrastructure for security research.
* Mastered log transformation (ETL) from unstructured JSON to structured intelligence.
* Gained deep insight into how automated botnets navigate Linux environments.
* Developed a full-stack security application using Python.

