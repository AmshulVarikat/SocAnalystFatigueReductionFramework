# Implementation/enrichment/alert_enricher.py
from typing import Any, Optional, Dict
from .asset_repository import AssetRepository
from .threat_intel_repository import ThreatIntelRepository

class AlertEnricher:
    """
    Phase 7: Alert Enrichment Module.
    Attaches Asset Context and Threat Intelligence to Normalized Alerts.
    """
    def __init__(self, asset_repo: AssetRepository, local_threat_repo: Optional[ThreatIntelRepository] = None):
        self.asset_repo = asset_repo
        self.local_threat_repo = local_threat_repo
        # NEW: The Local Memory Cache
        self._ioc_cache: Dict[str, dict] = {}

    def enrich(self, alert: Any) -> Any:
        """Enriches a single NormalizedAlert with context in-place."""
        # Ensure enrichment dict exists
        if not hasattr(alert, "enrichment"):
            alert.enrichment = {}
            
        self._enrich_asset_context(alert)
        self._enrich_threat_intel(alert)
        return alert

    def _enrich_asset_context(self, alert: Any):
        """Looks up the asset by hostname/agent_name and attaches context."""
        target_host = alert.hostname or alert.agent_name
        asset_info = self.asset_repo.get_asset(target_host)
        
        if asset_info:
            alert.asset_context = {
                "asset_id": asset_info.get("asset_id"),
                "asset_type": asset_info.get("asset_type"),
                "criticality": asset_info.get("criticality", 1),
                "department": asset_info.get("department"),
                "owner": asset_info.get("owner"),
                "business_function": asset_info.get("business_function"),
                "is_unmanaged": False
            }
        else:
            alert.asset_context = {
                "asset_id": target_host or "Unknown",
                "asset_type": "Unknown",
                "criticality": 1, 
                "department": "Unknown",
                "owner": "Unknown",
                "business_function": "Unknown",
                "is_unmanaged": True
            }

    def _enrich_threat_intel(self, alert: Any):
        alert.threat_intel = {"matched_indicators": [], "highest_reputation": "unknown", "max_confidence": 0}

        if not self.local_threat_repo:
            return

        observables = set()
        if hasattr(alert, 'ips'): observables.update(alert.ips)
        if hasattr(alert, 'domains'): observables.update(alert.domains)
        if hasattr(alert, 'hashes'): observables.update(alert.hashes)

        matched_intel = []

        # Check Local Cache / Local DB first
        for obs in observables:
            if not obs: continue
            
            if obs in self._ioc_cache:
                matched_intel.append(self._ioc_cache[obs])
            else:
                # Try local DB
                intel = self.local_threat_repo.lookup_ioc(obs)
                
                if intel:
                    self._ioc_cache[obs] = intel
                    matched_intel.append(intel)

        # Calculate the scores
        rep_weights = {"malicious": 3, "suspicious": 2, "unknown": 1, "known_benign": 0, "safe": 0}
        highest_reputation = "unknown"
        max_confidence = 0

        for intel in matched_intel:
            alert.enrichment[intel['indicator']] = intel
            rep = intel.get("reputation", "unknown").lower()
            conf = intel.get("confidence_score", 0)

            if rep_weights.get(rep, 1) > rep_weights.get(highest_reputation, 1):
                highest_reputation = rep
                max_confidence = conf
            elif rep == highest_reputation and conf > max_confidence:
                max_confidence = conf

        alert.threat_intel["matched_indicators"] = matched_intel
        alert.threat_intel["highest_reputation"] = highest_reputation
        alert.threat_intel["max_confidence"] = max_confidence
