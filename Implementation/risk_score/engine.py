# risk_score_engine.py

# ==========================================
# CONFIGURATION VARIABLES: MULTIPLIERS & BASE
# ==========================================

# Base Score Max Values
MAX_WAZUH_SEVERITY = 15.0
MAX_ASSET_CRITICALITY = 10.0

# 1. Threat Intel Multipliers (M_intel)
M_INTEL_MALICIOUS = 1.5
M_INTEL_SUSPICIOUS = 1.2
M_INTEL_UNKNOWN = 1.0
M_INTEL_BENIGN = 0.2

# 2. Unmanaged Asset Multipliers (M_asset)
M_ASSET_UNMANAGED_HIGH_SEV = 1.5  # is_unmanaged == True AND Severity >= 8
M_ASSET_UNMANAGED_LOW_SEV = 1.1   # is_unmanaged == True AND Severity < 8
M_ASSET_MANAGED = 1.0             # is_unmanaged == False

# 3. MITRE Tactic Multipliers (M_mitre)
# Critical Phase: Execution, Persistence, PrivEsc, Credential Access, Lateral Movement, Exfiltration, Impact
M_MITRE_CRITICAL = 1.2
# Standard Phase: Initial Access, Defense Evasion, C2
M_MITRE_STANDARD = 1.0
# Early Phase: Recon, Resource Dev, Discovery, Collection
M_MITRE_EARLY = 0.9

# 4. Frequency / Noise Dampener (M_freq)
M_FREQ_HIGH_NOISE = 0.5  # Alert Count > 20/hr AND Severity < 5
M_FREQ_STANDARD = 1.0


# MITRE Tactic Mappings
MITRE_PHASES = {
    "Critical": [
        "Execution", "Persistence", "Privilege Escalation", "PrivEsc",
        "Credential Access", "Lateral Movement", "Exfiltration", "Impact"
    ],
    "Standard": [
        "Initial Access", "Defense Evasion", "Command and Control", "C2"
    ],
    "Early": [
        "Reconnaissance", "Recon", "Resource Development", "Discovery", "Collection"
    ]
}

def get_mitre_multiplier(tactic: str) -> float:
    if not tactic:
        return M_MITRE_STANDARD
        
    tactic_normalized = tactic.lower().replace('_', ' ').replace('-', ' ')
    
    for phase, tactics in MITRE_PHASES.items():
        for t in tactics:
            t_normalized = t.lower().replace('_', ' ').replace('-', ' ')
            if t_normalized in tactic_normalized:
                if phase == "Critical":
                    return M_MITRE_CRITICAL
                elif phase == "Standard":
                    return M_MITRE_STANDARD
                elif phase == "Early":
                    return M_MITRE_EARLY
                    
    return M_MITRE_STANDARD


def calculate_risk_score(
    wazuh_severity: int,
    asset_criticality: int,
    threat_intel_status: str,
    is_unmanaged: bool,
    mitre_tactic: str,
    alert_count_per_hr: int
) -> float:
    """
    Calculates the risk score for an alert based on severity, criticality, and contextual multipliers.
    
    Args:
        wazuh_severity (int): The severity score from Wazuh (typically 0-15).
        asset_criticality (int): The criticality of the asset (typically 0-10).
        threat_intel_status (str): The threat intel status ('Malicious', 'Suspicious', 'Unknown', 'Known Benign').
        is_unmanaged (bool): True if the asset is unmanaged, False otherwise.
        mitre_tactic (str): The MITRE ATT&CK tactic associated with the alert.
        alert_count_per_hr (int): The number of alerts seen for this entity/type in the last hour.
        
    Returns:
        float: The final calculated risk score.
    """
    
    # Step A: The Base Score (Range: 0 - 100)
    # We calculate the baseline technical and business impact using a weighted average. 
    # Since Wazuh severity is out of 15 and Criticality is out of 10, we normalize them to 50 points each.
    
    # Ensure values are within expected bounds
    wazuh_severity = max(0, min(wazuh_severity, MAX_WAZUH_SEVERITY))
    asset_criticality = max(0, min(asset_criticality, MAX_ASSET_CRITICALITY))
    
    base_score = ((wazuh_severity / MAX_WAZUH_SEVERITY) * 50) + ((asset_criticality / MAX_ASSET_CRITICALITY) * 50)
    
    # Step B: The Contextual Multipliers
    
    # 1. Threat Intel Multiplier (M_intel)
    ti_status_lower = threat_intel_status.lower() if threat_intel_status else "unknown"
    if ti_status_lower == "malicious":
        m_intel = M_INTEL_MALICIOUS
    elif ti_status_lower == "suspicious":
        m_intel = M_INTEL_SUSPICIOUS
    elif "benign" in ti_status_lower:
        m_intel = M_INTEL_BENIGN
    else:
        m_intel = M_INTEL_UNKNOWN
        
    # 2. Unmanaged Asset Multiplier (M_asset)
    if is_unmanaged:
        if wazuh_severity >= 8:
            m_asset = M_ASSET_UNMANAGED_HIGH_SEV
        else:
            m_asset = M_ASSET_UNMANAGED_LOW_SEV
    else:
        m_asset = M_ASSET_MANAGED
        
    # 3. MITRE Tactic Multiplier (M_mitre)
    m_mitre = get_mitre_multiplier(mitre_tactic)
    
    # 4. Frequency / Noise Dampener (M_freq)
    if alert_count_per_hr > 20 and wazuh_severity < 5:
        m_freq = M_FREQ_HIGH_NOISE
    else:
        m_freq = M_FREQ_STANDARD
        
    # Final Risk Score = Base Score * M_intel * M_asset * M_mitre * M_freq
    final_risk_score = base_score * m_intel * m_asset * m_mitre * m_freq
    
    return round(min(100.0, final_risk_score), 2)
