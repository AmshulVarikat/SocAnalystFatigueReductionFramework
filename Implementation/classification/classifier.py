import json
import os
from typing import Any, Dict

class AlertClassifier:
    """
    Phase 9: Alert Classification Module.
    Buckets alerts into four categories using a rule-based approach based on
    risk scores and specific contextual overrides.
    """
    def __init__(self, rules_path: str = None):
        self.rules_path = rules_path
        
        # Hardcoded safe defaults
        self.numeric_thresholds = {
            "Critical Incident": 80,
            "Requires Investigation": 40
        }
        self.absolute_overrides_threat_intel = set()
        self.absolute_overrides_mitre_tactics = set()
        self.known_noisy_rules = {
            "5716", # Example: SSH insecure connection
            "1002", # Example: Unknown problem somewhere in the system
        }
        self.approved_scanners = {
            "192.168.1.100", # Example: internal Nessus scanner
            "10.0.0.50",     # Example: Qualys scanner
        }
        
        self._load_rules()

    def _load_rules(self):
        if not self.rules_path:
            return
            
        try:
            with open(self.rules_path, 'r', encoding='utf-8') as f:
                rules = json.load(f)
                
            self.numeric_thresholds = rules.get("numeric_thresholds", self.numeric_thresholds)
            
            overrides = rules.get("absolute_overrides", {})
            self.absolute_overrides_threat_intel = set(overrides.get("threat_intel", []))
            self.absolute_overrides_mitre_tactics = set(overrides.get("mitre_tactics", []))
            
            self.known_noisy_rules = set(rules.get("false_positive_indicators", []))
            self.approved_scanners = set(rules.get("benign_indicators", []))
            
        except Exception as e:
            print(f"[!] Warning: Failed to load classification rules from {self.rules_path}. Using safe defaults. Error: {e}")

    def classify_alert(self, enriched_alert: Any, risk_score: float) -> str:
        """
        Classifies an enriched alert based on context and calculated risk score.
        """
        # Extract needed context securely whether it's a dict or an object
        if isinstance(enriched_alert, dict):
            rule_id = str(enriched_alert.get('rule_id', ''))
            threat_intel = enriched_alert.get('threat_intel', {}).get('highest_reputation', '').lower()
            source_ip = enriched_alert.get('src_ip', '')
            asset_context = enriched_alert.get('asset_context', {})
            asset_criticality = asset_context.get('criticality', 1)
            mitre_tactic = enriched_alert.get('mitre_tactic', '').lower()
        else:
            rule_id = str(getattr(enriched_alert, 'rule_id', getattr(enriched_alert, 'rule_level', '')))
            threat_intel_obj = getattr(enriched_alert, 'threat_intel', {})
            threat_intel = threat_intel_obj.get('highest_reputation', '').lower() if isinstance(threat_intel_obj, dict) else ''
            source_ip = getattr(enriched_alert, 'src_ip', '')
            asset_context_obj = getattr(enriched_alert, 'asset_context', {})
            asset_criticality = asset_context_obj.get('criticality', 1) if isinstance(asset_context_obj, dict) else 1
            mitre_tactic = getattr(enriched_alert, 'mitre_tactic', '').lower()

        # 1. Critical Overrides (Evaluate First)
        if threat_intel in self.absolute_overrides_threat_intel:
            return "Critical Incident"
            
        if asset_criticality == 10 and any(t in mitre_tactic for t in self.absolute_overrides_mitre_tactics):
            return "Critical Incident"
            
        # 2. Known Benign Overrides (e.g., Approved Scanners)
        if source_ip in self.approved_scanners:
            return "Likely Benign"
            
        # 3. Known False Positive Overrides
        investigation_threshold = self.numeric_thresholds.get("Requires Investigation", 40)
        if rule_id in self.known_noisy_rules and risk_score < investigation_threshold:
            return "Likely False Positive"

        # Explicit promotion for critical rules that might be undervalued by risk score
        if rule_id in ["92029", "92213", "92037", "60122"]:
            return "Requires Investigation"

        # 4. Fallback to Risk Score Thresholds
        critical_threshold = self.numeric_thresholds.get("Critical Incident", 80)
        
        if risk_score >= critical_threshold:
            return "Critical Incident"
        elif risk_score >= investigation_threshold:
            return "Requires Investigation"
        else:
            # Default for low-scoring, non-noisy events
            return "Likely Benign"

    def process(self, scored_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes the output from the Risk Scorer, runs classification,
        and adds the category to the result.
        """
        alert = scored_output.get("alert")
        risk_score = scored_output.get("risk_score", 0.0)
        
        category = self.classify_alert(alert, risk_score)
        
        # Add the classification category to the payload
        scored_output["classification"] = category
        return scored_output
