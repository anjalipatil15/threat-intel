import re

INPUT_FILE = "cowrie.log"
OUTPUT_FILE = "cowrie_readable_report.txt"

log_entries = []

with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        # Extract timestamp
        time_match = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line)
        timestamp = time_match.group() if time_match else ""

        # Extract IP
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        ip = ip_match.group() if ip_match else ""

        # Extract username/password
        user_match = re.search(r'login attempt \[(.*?)\/(.*?)\]', line)
        username = user_match.group(1) if user_match else ""
        password = user_match.group(2) if user_match else ""

        # Extract command
        cmd_match = re.search(r'Command found: (.*)', line)
        command = cmd_match.group(1).strip() if cmd_match else ""

        # Decide event type
        if "login attempt" in line:
            event = "LOGIN ATTEMPT"
        elif "Command found" in line:
            event = "COMMAND EXECUTED"
        elif "New connection" in line:
            event = "NEW CONNECTION"
        elif "Connection lost" in line:
            event = "SESSION CLOSED"
        else:
            event = ""

        if event:
            log_entries.append({
                "time": timestamp,
                "ip": ip,
                "event": event,
                "username": username,
                "password": password,
                "command": command
            })


with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write("Honeypot Attack Activity Report\n")
    f.write("=" * 70 + "\n\n")

    for i, entry in enumerate(log_entries, start=1):
        f.write(f"Event #{i}\n")
        f.write("-" * 40 + "\n")
        f.write(f"Time      : {entry['time']}\n")
        f.write(f"Attacker  : {entry['ip']}\n")
        f.write(f"Event     : {entry['event']}\n")

        if entry['username']:
            f.write(f"Username  : {entry['username']}\n")
            f.write(f"Password  : {entry['password']}\n")

        if entry['command']:
            f.write(f"Command   : {entry['command']}\n")

        f.write("\n")

print("Clean readable report generated → cowrie_report.txt")
