# Test Data Alerts Details

This document contains the specific details of all the alerts generated in the test data files under `Implementation/inputs/Test_Data`.

## File 1: `benign_low_severity.json` (Benign / Low-Severity Alerts Mix)

*Objective: Triggers the high-frequency noise dampener ($M_{freq} = 0.5$ for rules with low severity), the early-stage phase multiplier ($M_{mitre} = 0.9$), and default fallbacks.*

* **Alert Type 1: High-Volume Firewall Noise Spam**
  * **Wazuh Rule ID:** `4100` (Firewall dropped packet)
  * **MITRE Tactic:** `""` (None — tests default fallback)
  * **Testing Instruction:** This specific Rule ID is repeated 26 times within a 60-minute window to trigger the `alert_count_per_hr > 20` threshold.

* **Alert Type 2: Host Network Asset Discovery Scan**
  * **Wazuh Rule ID:** `516` (System network configuration discovery)
  * **MITRE Tactic:** `"Discovery"` (Triggers Early Phase)

* **Alert Type 3: Local Domain User Account Reconnaissance**
  * **Wazuh Rule ID:** `92200` (Active Directory account enumeration)
  * **MITRE Tactic:** `"Reconnaissance"` (Triggers Early Phase)

* **Alert Type 4: Routine System Time Synchronization Log**
  * **Wazuh Rule ID:** `2901` (NTP time synchronization status)
  * **MITRE Tactic:** `""` (None)

---

## File 2: `mid_severity.json` (Mid-Severity Alerts Mix)

*Objective: Triggers standard MITRE phase multipliers ($M_{mitre} = 1.0$), baseline mid-tier severities, and validates that higher-severity spam completely escapes the noise dampener.*

* **Alert Type 1: Inbound Connection from Suspicious External Node**
  * **Wazuh Rule ID:** `5710` (SSHD attempt to establish connection)
  * **MITRE Tactic:** `"Initial Access"` (Triggers Standard Phase)

* **Alert Type 2: Local Windows Firewall Security Bypass**
  * **Wazuh Rule ID:** `60112` (Firewall configuration or rule modification)
  * **MITRE Tactic:** `"Defense Evasion"` (Triggers Standard Phase)

* **Alert Type 3: External Command and Control Beaconing Triage**
  * **Wazuh Rule ID:** `91540` (Dynamic DNS request anomaly detected)
  * **MITRE Tactic:** `"Command and Control"` (Triggers Standard Phase)

* **Alert Type 4: Repeated Failed Password Guessing Attempt**
  * **Wazuh Rule ID:** `5716` (SSHD authentication failed)
  * **MITRE Tactic:** `"Initial Access"`
  * **Testing Instruction:** This Rule ID is repeated 31 times. Because its severity floor is set $\ge 5$, it tests if the engine correctly bypasses the frequency dampener.

---

## File 3: `high_severity.json` (High-Severity Alerts Mix)

*Objective: Triggers the highest tier phase multipliers ($M_{mitre} = 1.2$), compounding unmanaged network asset impacts, and hits the upper limit score capping logic (`min(100.0, score)`).*

* **Alert Type 1: Memory LSASS Credential Harvesting**
  * **Wazuh Rule ID:** `82103` (Sysmon Mimikatz process access)
  * **MITRE Tactic:** `"Credential Access"` (Triggers Critical Phase)

* **Alert Type 2: Domain Controller Process Hijacking**
  * **Wazuh Rule ID:** `92651` (Malicious DLL injection detected)
  * **MITRE Tactic:** `"Privilege Escalation"` (Triggers Critical Phase)

* **Alert Type 3: Mass Encrypted File Disruption (Ransomware Deployment)**
  * **Wazuh Rule ID:** `92800` (High volume rapid file modification)
  * **MITRE Tactic:** `"Impact"` (Triggers Critical Phase)

* **Alert Type 4: Corporate Data Extraction Vault Drop**
  * **Wazuh Rule ID:** `20050` (Abnormal outbound data exfiltration volume)
  * **MITRE Tactic:** `"Exfiltration"` (Triggers Critical Phase)

* **Alert Type 5: Remote PowerShell Script Task Scheduler Injection**
  * **Wazuh Rule ID:** `92260` (Persistence modification via WinRM)
  * **MITRE Tactic:** `"Persistence"` (Triggers Critical Phase)
