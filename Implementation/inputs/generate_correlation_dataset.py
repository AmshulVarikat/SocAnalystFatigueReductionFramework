import os
import json
from datetime import datetime, timedelta

output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Correlation_Test_Data")
os.makedirs(output_dir, exist_ok=True)

# Generate assets.json
assets = {
    "10.10.10.11": {"criticality": "high", "owner": "HR", "device_type": "workstation"},
    "10.10.10.15": {"criticality": "low", "owner": "Sales", "device_type": "workstation"},
    "10.10.10.100": {"criticality": "critical", "owner": "IT", "device_type": "server"}
}
with open(os.path.join(output_dir, "assets.json"), "w") as f:
    json.dump(assets, f, indent=2)

# Generate threat_intel.json
threat_intel = {
    "malicious_ips": ["192.168.1.50"],
    "malicious_hashes": ["9E590F2F936B4982CA6E7C77A6A38DF1"]
}
with open(os.path.join(output_dir, "threat_intel.json"), "w") as f:
    json.dump(threat_intel, f, indent=2)

# Generate extracted_alerts.json
alerts = []
base_time = datetime(2026, 8, 1, 8, 0, 0)

# Generate background noise
for i in range(50):
    alert_time = base_time + timedelta(minutes=i*2)
    host_num = (i % 5) + 1
    alert = {
        "timestamp": alert_time.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": {
            "level": 2,
            "description": "Generic noisy event",
            "id": "1002",
            "mitre": {
                "id": ["T1059"],
                "tactic": ["Execution"],
                "technique": ["T1059"]
            }
        },
        "agent": {
            "id": f"00{host_num}",
            "name": f"NOISY-PC-0{host_num}",
            "ip": f"10.10.20.{host_num}"
        }
    }
    alerts.append(alert)

# Inject the attack (Needle)
attack_stages = [
    {"rule_id": "90001", "desc": "Phishing Link Clicked", "tactic": "Initial Access"},
    {"rule_id": "90002", "desc": "Suspicious Powershell", "tactic": "Execution"},
    {"rule_id": "90003", "desc": "Service Installed", "tactic": "Privilege Escalation"},
    {"rule_id": "90004", "desc": "LSASS Memory Dump", "tactic": "Credential Access"}, # Forces Requires Investigation
    {"rule_id": "90005", "desc": "Remote Desktop Connection", "tactic": "Lateral Movement"}
]

for i, stage in enumerate(attack_stages):
    # Insert them at minute 15, 25, 35, 45, 55
    alert_time = base_time + timedelta(minutes=15 + i*10)
    alert = {
        "timestamp": alert_time.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": {
            "level": 8 + i, # Increasing severity
            "description": stage["desc"],
            "id": stage["rule_id"],
            "mitre": {
                "tactic": [stage["tactic"]]
            }
        },
        "agent": {
            "id": "011",
            "name": "HR-PC-01",
            "ip": "10.10.10.11"
        }
    }
    alerts.append(alert)

# Sort by timestamp
alerts.sort(key=lambda x: x["timestamp"])

with open(os.path.join(output_dir, "extracted_alerts.json"), "w") as f:
    for a in alerts:
        f.write(json.dumps(a) + "\n")

print(f"Dataset generated at {output_dir}")
