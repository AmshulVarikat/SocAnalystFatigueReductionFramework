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
        
        # Load MITRE ATT&CK Data
        self.mitre_data = None
        try:
            import os
            from mitreattack.stix20 import MitreAttackData
            # Use path relative to this file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            mitre_json_path = os.path.join(current_dir, "enterprise-attack.json")
            if os.path.exists(mitre_json_path):
                self.mitre_data = MitreAttackData(mitre_json_path)
            else:
                print(f"[!] Warning: MITRE ATT&CK json not found at {mitre_json_path}")
        except Exception as e:
            print(f"[!] Warning: Could not load MitreAttackData: {e}")

    def enrich(self, alert: Any) -> Any:
        """Enriches a single NormalizedAlert with context in-place."""
        # Ensure enrichment dict exists
        if not hasattr(alert, "enrichment"):
            alert.enrichment = {}
            
        self._enrich_asset_context(alert)
        self._enrich_threat_intel(alert)
        self._enrich_mitre_tactic(alert)
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

    def _enrich_mitre_tactic(self, alert: Any):
        """Enriches the alert with MITRE ATT&CK tactic information based on the technique ID."""
        if not self.mitre_data:
            return
            
        technique_id = getattr(alert, "mitre_technique_id", None)
        if not technique_id:
            return
            
        # Extract base technique ID in case it includes a subtechnique (e.g., T1059.001)
        # Often tactics apply to the parent technique in STIX. But let's try direct first.
        obj = self.mitre_data.get_object_by_attack_id(technique_id, "attack-pattern")
        
        # If not found directly, try parent technique if it's a subtechnique
        if not obj and "." in technique_id:
            parent_id = technique_id.split(".")[0]
            obj = self.mitre_data.get_object_by_attack_id(parent_id, "attack-pattern")
            
        if obj:
            if not getattr(alert, "mitre_technique_name", None):
                alert.mitre_technique_name = obj.name
                
            tactics = self.mitre_data.get_tactics_by_technique(obj.id)
            if tactics:
                # Typically can be multiple tactics, we'll comma-separate their names
                tactic_names = [t.name for t in tactics if hasattr(t, "name")]
                if tactic_names:
                    alert.mitre_tactic = ", ".join(tactic_names)
