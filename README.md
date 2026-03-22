```markdown
# 🚨 Honeypot-Based Cyber Threat Intelligence System

## 📌 Overview

This project implements a cloud-deployed cyber threat intelligence pipeline using an SSH honeypot to capture, monitor, and analyze real-world attacker behavior.

The system simulates a vulnerable server environment to attract malicious activity, collects detailed interaction logs, and processes telemetry data to generate actionable threat intelligence such as attacker IP patterns, credential brute-force attempts, and executed command analysis.

---

## 🎯 Objectives

- Capture real attack traffic in a controlled environment  
- Analyze attacker techniques and behavior patterns  
- Extract meaningful threat intelligence from raw honeypot logs  
- Visualize attack insights through an interactive dashboard  

---

## ⚙️ Key Features

- 🍯 Deployment of SSH honeypot to capture live attack attempts  
- 🌍 Logging of real attacker IP addresses and session activity  
- 🔐 Detection and analysis of username/password brute-force attempts  
- 💻 Command execution tracking and behavioral analysis  
- 📊 Interactive dashboard for real-time threat visualization  
- 🧠 Insight generation from structured log parsing  

---

## 🧱 System Architecture

```

Internet Attackers
↓
Cloud VM (SSH Honeypot – Cowrie)
↓
Log Collection & Storage
↓
Python Log Parser & Data Processing
↓
Threat Intelligence Generation
↓
Streamlit Dashboard Visualization

```

---

## 🛠️ Technologies Used

- Python  
- Cowrie SSH Honeypot  
- Streamlit  
- AWS EC2  
- Hydra (Attack Simulation Tool)  
- Pandas / Data Processing Libraries  

---

## 📊 Dashboard Capabilities

- Top attacking IP addresses  
- Most targeted usernames  
- Most common password attempts  
- Commands executed by attackers  
- Attack frequency trends  
- Real-time monitoring of honeypot activity  

---

## 🚀 Setup & Execution

### 1️⃣ Clone the Repository

```

git clone [https://github.com/YOUR_USERNAME/honeypot-threat-intel.git](https://github.com/YOUR_USERNAME/honeypot-threat-intel.git)
cd honeypot-threat-intel

```

### 2️⃣ Install Dependencies

```

pip install -r requirements.txt

```

### 3️⃣ Run Log Parser

```

python parser.py

```

### 4️⃣ Launch Dashboard

```

streamlit run dashboard.py

```

---

## 📈 Sample Threat Insights

- Attackers frequently attempt login using the `root` and `admin` accounts  
- Common passwords observed include `123456`, `password`, and `admin`  
- Commands such as `whoami`, `ls`, and `pwd` indicate reconnaissance behavior  
- Automated brute-force patterns detected from repeated IP sessions  

---

## 🔮 Future Enhancements

- Real-time log ingestion pipeline  
- MITRE ATT&CK technique mapping  
- Automated IP blocking / firewall integration  
- Geographic attack heatmap visualization  
- Alerting system for high-severity attack patterns  

---

## 🧠 Learning Outcomes

- Practical exposure to honeypot deployment and attacker interaction analysis  
- Experience in log parsing, data engineering, and threat intelligence extraction  
- Cloud infrastructure deployment and monitoring  
- Building security dashboards for cyber defense use cases  

---


