from datetime import datetime, timedelta
from typing import Any, Dict
from .engine import calculate_risk_score

class FrequencyTracker:
    """
    A lightweight, in-memory state tracker to calculate alert frequency.
    Maintains a sliding time window to identify noisy, spamming alerts.
    """
    def __init__(self, time_window_minutes=60):
        self.time_window = timedelta(minutes=time_window_minutes)
        # Dictionary to store timestamps. 
        # Format: {"rule_id_source_ip": [datetime_obj1, datetime_obj2, ...]}
        self._history = {}

    def get_frequency(self, alert: Any) -> int:
        """
        Records the alert and returns the total count of similar alerts within the time window.
        """
        # 1. Create a unique identifier for the specific behavior
        rule_id = getattr(alert, 'rule_id', getattr(alert, 'rule_level', 'unknown_rule'))
        if not rule_id:
            rule_id = "unknown_rule"
            
        src_ip = getattr(alert, 'src_ip', None)
        if not src_ip:
            # Fallback to agent ID if src_ip is missing to still get a meaningful grouping
            src_ip = getattr(alert, 'agent_id', 'unknown_ip')
            
        event_key = f"{rule_id}_{src_ip}"

        # Get current time from the alert, or fallback to system time
        try:
            timestamp_str = getattr(alert, 'event_time', getattr(alert, 'timestamp_original', ''))
            if timestamp_str:
                # Basic normalization for standard ISO 8601 parsing
                current_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                current_time = datetime.now()
        except (ValueError, TypeError, AttributeError):
            current_time = datetime.now()

        # Initialize the list if this is a new event type
        if event_key not in self._history:
            self._history[event_key] = []

        # 2. Append the current alert's timestamp
        self._history[event_key].append(current_time)

        # 3. Purge timestamps older than the sliding window
        cutoff_time = current_time - self.time_window
        self._history[event_key] = [
            t for t in self._history[event_key] if t > cutoff_time
        ]

        # 4. Return the calculated count
        return len(self._history[event_key])


class AlertRiskScorer:
    """
    Phase 8: Risk Scoring.
    Calculates the final risk score based on enriched alert data.
    """
    def __init__(self):
        # Initializes the tracker for stateful alert frequency tracking
        self.freq_tracker = FrequencyTracker(time_window_minutes=60)

    def score(self, alert: Any) -> Dict[str, Any]:
        """Calculates risk score and wraps it with the alert."""
        
        # 1. Extract Wazuh Severity (Explicit type-casting)
        severity_str = getattr(alert, 'severity', getattr(alert, 'rule_level', '0'))
        try:
            wazuh_severity = float(severity_str)
        except (ValueError, TypeError):
            wazuh_severity = 0.0
            
        # 2. Extract Asset Context
        asset_context = getattr(alert, 'asset_context', {})
        asset_criticality = asset_context.get('criticality', 1) if isinstance(asset_context, dict) else 1
        is_unmanaged = asset_context.get('is_unmanaged', True) if isinstance(asset_context, dict) else True
        
        # 3. Extract Threat Intel (Safeguard against missing/empty dicts)
        threat_intel = getattr(alert, 'threat_intel', {})
        if isinstance(threat_intel, dict):
            threat_intel_status = threat_intel.get('highest_reputation', 'unknown')
        else:
            threat_intel_status = 'unknown'
            
        if not threat_intel_status:
            threat_intel_status = 'unknown'
        
        # 4. Extract MITRE Tactic
        mitre_tactic = getattr(alert, 'mitre_tactic', '')
        
        # 5. Alert frequency (Stateful tracking)
        alert_count_per_hr = self.freq_tracker.get_frequency(alert)
        
        risk_score = calculate_risk_score(
            wazuh_severity=wazuh_severity,
            asset_criticality=asset_criticality,
            threat_intel_status=threat_intel_status,
            is_unmanaged=is_unmanaged,
            mitre_tactic=mitre_tactic,
            alert_count_per_hr=alert_count_per_hr
        )
        
        return {
            "alert": alert,
            "risk_score": risk_score
        }
