from typing import Dict, Any


def detect(raw_alert: Dict[str, Any], meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Heuristic detector that returns a source_info dict.

    Current heuristic: if alert has both 'rule' and 'agent' keys, assume 'wazuh'.
    Returns: {'source': '<name>', 'meta': {...}}
    """
    meta = meta or {}

    # Conservative detection for Wazuh: presence of 'rule' dict and 'agent' dict
    if isinstance(raw_alert, dict):
        if 'rule' in raw_alert and 'agent' in raw_alert:
            return {'source': 'wazuh', 'meta': meta}

    return {'source': 'unknown', 'meta': meta}
