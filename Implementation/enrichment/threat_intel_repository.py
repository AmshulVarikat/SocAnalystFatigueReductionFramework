import json
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
 

class ThreatIntelRepository(ABC):
    """Abstract interface for Threat Intelligence data access."""
    
    @abstractmethod
    def lookup_ioc(self, indicator: str, indicator_type: Any = None) -> Optional[Dict[str, Any]]:
        """Retrieve threat intelligence for a specific indicator (IP, Hash, Domain)."""
        pass


class JsonThreatIntelRepository(ThreatIntelRepository):
    """
    JSON-backed implementation of the ThreatIntelRepository.
    Designed to fail gracefully if the IOC database does not exist yet.
    """
    def __init__(self, json_path: str):
        self.json_path = json_path
        self._intel: Dict[str, Dict[str, Any]] = {}
        self._load_database(json_path)

    def _load_database(self, json_path: str):
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                raw_intel = json.load(f)
                for entry in raw_intel:
                    indicator = entry.get("indicator")
                    if indicator:
                        # Store in lowercase for case-insensitive matching (important for hashes/domains)
                        self._intel[indicator.lower()] = entry
        except FileNotFoundError:
            # THIS FULFILLS YOUR REQUIREMENT: Report and continue
            print(f"[!] Notice: IOC database not found at '{json_path}'. Continuing without Threat Intel enrichment.")

    def lookup_ioc(self, indicator: str, indicator_type: Any = None) -> Optional[Dict[str, Any]]:
        if not indicator:
            return None
        return self._intel.get(indicator.lower())

    def add_ioc(self, intel_data: Dict[str, Any]):
        indicator = intel_data.get("indicator")
        if indicator:
            self._intel[indicator.lower()] = intel_data
            self._save_database()

    def _save_database(self):
        try:
            with open(self.json_path, 'w', encoding='utf-8') as f:
                json.dump(list(self._intel.values()), f, indent=2)
        except Exception as e:
            print(f"[!] Notice: Failed to save IOC database to '{self.json_path}': {e}")


class CompositeThreatIntelRepository(ThreatIntelRepository):
    """
    Composite repository that queries multiple threat intelligence repositories.
    """
    def __init__(self, repositories: List[ThreatIntelRepository]):
        self.repositories = repositories

    def lookup_ioc(self, indicator: str, indicator_type: Any = None) -> Optional[Dict[str, Any]]:
        results = []
        for repo in self.repositories:
            res = repo.lookup_ioc(indicator, indicator_type)
            if res:
                results.append(res)
        
        if not results:
            return None
            
        if len(results) == 1:
            return results[0]
            
        # Combine multiple results
        combined = {
            "indicator": indicator,
            "sources": [r.get("source", "Unknown") for r in results],
            "details": results
        }
        
        # Calculate max confidence and highest reputation among the results
        max_conf = 0
        rep_weights = {"malicious": 3, "suspicious": 2, "unknown": 1, "known_benign": 0, "safe": 0}
        highest_rep = "unknown"
        
        for r in results:
            conf = r.get("confidence_score", 0)
            if conf > max_conf:
                max_conf = conf
                
            rep = r.get("reputation", "unknown").lower()
            if rep_weights.get(rep, 1) > rep_weights.get(highest_rep, 1):
                highest_rep = rep
                
        combined["confidence_score"] = max_conf
        combined["reputation"] = highest_rep
        
        return combined
