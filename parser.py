import re
from collections import Counter

import requests

logfile = "cowrie.log"

ips = Counter()
usernames = Counter()
passwords = Counter()
commands = Counter()
success = 0
fail = 0

with open(logfile, "r", errors="ignore") as f:
    for line in f:
        
        # IP extraction
        ip_match = re.search(r"New connection: ([0-9\.]+)", line)
        if ip_match:
            ips[ip_match.group(1)] += 1

        # login attempts
        login_match = re.search(r"login attempt \[b?'?(\w+)'?/b?'?(\w+)'?\]", line)
        if login_match:
            usernames[login_match.group(1)] += 1
            passwords[login_match.group(2)] += 1

        # success/fail
        if "succeeded" in line:
            success += 1
        if "failed" in line:
            fail += 1

        # commands
        cmd_match = re.search(r"CMD: (.+)", line)
        if cmd_match:
            commands[cmd_match.group(1)] += 1

print("\n=== Top Attacking IPs ===")
for ip, count in ips.most_common(5):
    print(ip, "→", count)

print("\n=== Usernames ===")
for u, count in usernames.most_common(5):
    print(u, "→", count)

print("\n=== Passwords ===")
for p, count in passwords.most_common(5):
    print(p, "→", count)

print("\n=== Commands ===")
for c, count in commands.most_common(5):
    print(c, "→", count)

print("\n=== Login Stats ===")
print("Success:", success)
print("Failed:", fail)

def get_country(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}")
        data = res.json()
        return data.get("country", "Unknown")
    except:
        return "Unknown"

print("\n=== IP Geolocation ===")
for ip in ips:
    print(ip, "→", get_country(ip))
