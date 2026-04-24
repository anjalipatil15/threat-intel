# Honeypot-Based Cyber Threat Intelligence (CTI) System

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Deployment: AWS](https://img.shields.io/badge/Deployment-AWS_EC2-orange.svg)](https://aws.amazon.com/)

A threat intelligence pipeline built on **Cowrie** (SSH honeypot) deployed on **AWS EC2** via **Kali Linux**, designed to capture and analyze real attacker behavior — not just generate alerts.

---

## What This Does

Most detection tools tell you an attack happened. This project focuses on what attackers do *after* they get in.

The honeypot emulates a vulnerable SSH endpoint and logs everything: credential stuffing patterns, command sequences, and post-login reconnaissance activity. A Python analysis layer structures the raw session data, and surfaces it through a Streamlit dashboard.

---

## Architecture

```
Kali Linux (Attacker Simulation + Deployment)
        │
        ▼
AWS EC2 Instance
└── Cowrie SSH Honeypot
        │
        ▼
Session Logs (JSON)
        │
        ▼
Python Parsing & Enrichment Layer
        │
        ▼
Streamlit Dashboard
```

---

## Stack

| Component | Tool |
|---|---|
| Honeypot | Cowrie |
| Cloud | AWS EC2 |
| Environment | Kali Linux |
| Analysis | Python |
| Framework Mapping | MITRE ATT&CK |
| Dashboard | Streamlit |

---

## Features

- **SSH honeypot** emulating a vulnerable endpoint to capture live attacker interactions
- **Session-level parsing** — extracts IP behavior, credential pairs, command sequences, and session duration
- **Credential analysis** — identifies reuse patterns across unrelated source IPs
- **Post-login command tracking** — logs what attackers run after gaining access
- **Streamlit dashboard** — visualizes attacker patterns, top credentials attempted, and session timelines

---

## Setup

### Prerequisites

- Kali Linux (or any Debian-based system)
- AWS account with EC2 access
- Python 3.9+

### 1. Deploy Cowrie on EC2

```bash
# On your EC2 instance
sudo apt update && sudo apt install -y git python3-virtualenv

git clone https://github.com/cowrie/cowrie
cd cowrie
virtualenv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt

cp etc/cowrie.cfg.dist etc/cowrie.cfg
bin/cowrie start
```

> Make sure port 22 on the EC2 security group is open to inbound traffic. Move your real SSH to a different port first.

### 2. Clone This Repository

```bash
git clone https://github.com/yourusername/honeypot-threat-intel.git
cd honeypot-threat-intel
pip install -r requirements.txt
```

### 3. Point the Parser at Your Cowrie Logs

```bash
# Default Cowrie log path
cp /path/to/cowrie/var/log/cowrie/cowrie.json* data/

python parse_sessions.py --input data/ --output output/sessions.csv
```

### 4. Run the Dashboard

```bash
streamlit run dashboard.py
```

---

## Project Structure

```
honeypot-threat-intel/
├── clean_log.py
├── parser.py       # Log parser and enrichment
├── dashboard.py            # Streamlit dashboard
├── requirements.txt
└── README.md
```

---

## Key Observations

- Credential stuffing is highly consistent — the same username/password pairs appear across unrelated source IPs, suggesting shared wordlists
- Recon commands (e.g., `uname -a`, `whoami`, `cat /etc/passwd`) execute within seconds of a successful login
- Attacker sessions follow recognizable patterns that map cleanly to ATT&CK tactics, making behavioral classification reliable

---

## Requirements

```
cowrie
streamlit
pandas
matplotlib
requests
```

---

## Disclaimer
Deploy honeypots responsibly — only on infrastructure you own, in isolated environments, and in compliance with your cloud provider's terms of service.
