# Implementation/enrichment/alert_enricher.py
from typing import Any, Optional
from .asset_repository import AssetRepository
from .threat_intel_repository import ThreatIntelRepository

class AlertEnricher:
    """
    Phase 7: Alert Enrichment Module.
    Attaches Asset Context and Threat Intelligence to Normalized Alerts.
    """
    def __init__(self, asset_repo: AssetRepository, threat_intel_repo: Optional[ThreatIntelRepository] = None):
        self.asset_repo = asset_repo
        self.threat_intel_repo = threat_intel_repo

    def enrich(self, alert: Any) -> Any:
        """Enriches a single NormalizedAlert with context in-place."""
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
        """
        Scans alert observables against the Threat Intel repository.
        Calculates the highest reputation/confidence watermark for the alert.
        """
        # 1. Establish a safe baseline. Phase 8 will rely on these keys existing.
        alert.threat_intel = {
            "matched_indicators": [],
            "highest_reputation": "unknown",
            "max_confidence": 0
        }

        # 2. If no repo is provided, or it failed to load data, we just return the baseline
        if not self.threat_intel_repo:
            return

        # Collect all observables safely
        observables = set()
        if hasattr(alert, 'ips'): observables.update(alert.ips)
        if hasattr(alert, 'domains'): observables.update(alert.domains)
        if hasattr(alert, 'hashes'): observables.update(alert.hashes)

        matched_intel = []
        highest_reputation = "unknown"
        max_confidence = 0

        # Simple weighting to determine the "worst" indicator in the alert
        rep_weights = {"malicious": 3, "suspicious": 2, "unknown": 1, "known_benign": 0}

        # 3. Check every observable against the database
        for obs in observables:
            if not obs: continue
            
            intel = self.threat_intel_repo.lookup_ioc(obs)
            if intel:
                matched_intel.append(intel)
                rep = intel.get("reputation", "unknown").lower()
                conf = intel.get("confidence_score", 0)

                # Determine if this is the highest threat seen so far in this alert
                if rep_weights.get(rep, 1) > rep_weights.get(highest_reputation, 1):
                    highest_reputation = rep
                    max_confidence = conf
                elif rep == highest_reputation and conf > max_confidence:
                    max_confidence = conf

        # 4. Attach findings to the alert
        if matched_intel:
            alert.threat_intel["matched_indicators"] = matched_intel
            alert.threat_intel["highest_reputation"] = highest_reputation
            alert.threat_intel["max_confidence"] = max_confidence
