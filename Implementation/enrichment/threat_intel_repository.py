# Implementation/enrichment/threat_intel_repository.py
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
 

class ThreatIntelRepository(ABC):
    """Abstract interface for Threat Intelligence data access."""
    
    @abstractmethod
    def lookup_ioc(self, indicator: str) -> Optional[Dict[str, Any]]:
        """Retrieve threat intelligence for a specific indicator (IP, Hash, Domain)."""
        pass


class JsonThreatIntelRepository(ThreatIntelRepository):
    """
    JSON-backed implementation of the ThreatIntelRepository.
    Designed to fail gracefully if the IOC database does not exist yet.
    """
    def __init__(self, json_path: str):
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

    def lookup_ioc(self, indicator: str) -> Optional[Dict[str, Any]]:
        if not indicator:
            return None
        return self._intel.get(indicator.lower())
