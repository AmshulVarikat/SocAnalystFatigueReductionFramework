import asyncio
from typing import Dict, Any, Optional
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from .threat_intel_repository import ThreatIntelRepository

class AlienVaultRepository(ThreatIntelRepository):
    def __init__(self, api_key: str):
        self.otx = OTXv2(api_key)

    def lookup_ioc(self, indicator: str, indicator_type: Any = None) -> Optional[Dict[str, Any]]:
        """Queries OTX and normalizes the response."""
        if not indicator_type:
            # Fallback if indicator_type is not provided
            # A more advanced implementation might try to guess the type, but we'll rely on the enricher
            return None
            
        try:
            # Synchronous call to OTX
            response = self.otx.get_indicator_details_full(indicator_type, indicator)
            
            # Extract Pulses (Threat Campaigns)
            pulse_count = response.get('general', {}).get('pulse_info', {}).get('count', 0)
            
            # Map OTX Pulses to your internal 0-100 score
            confidence_score = self._calculate_score(pulse_count)
            reputation = self._determine_reputation(confidence_score)

            return {
                "indicator": indicator,
                "pulse_count": pulse_count,
                "confidence_score": confidence_score,
                "reputation": reputation,
                "source": "AlienVault OTX"
            }
        except Exception as e:
            # Handle API timeouts or invalid IOCs gracefully
            return {
                "indicator": indicator,
                "error": str(e), 
                "confidence_score": 0, 
                "reputation": "Unknown",
                "source": "AlienVault OTX"
            }

    async def alookup_ioc(self, indicator: str, indicator_type: Any = None):
        """Asynchronously queries OTX by delegating the blocking call to a thread."""
        if not indicator_type:
            return None
            
        try:
            # asyncio.to_thread runs the blocking otx SDK call in a background thread
            # and crucially, WAITS for it to return before proceeding.
            response = await asyncio.to_thread(
                self.otx.get_indicator_details_full, indicator_type, indicator
            )
            
            pulse_count = response.get('general', {}).get('pulse_info', {}).get('count', 0)
            confidence_score = self._calculate_score(pulse_count)
            reputation = self._determine_reputation(confidence_score)

            return {
                "indicator": indicator,
                "pulse_count": pulse_count,
                "confidence_score": confidence_score,
                "reputation": reputation,
                "source": "AlienVault OTX"
            }
        except Exception as e:
            return {"indicator": indicator, "error": str(e), "confidence_score": 0, "reputation": "Unknown", "source": "AlienVault OTX"}

    def _calculate_score(self, pulse_count: int) -> int:
        if pulse_count == 0: return 0
        if pulse_count <= 2: return 50
        if pulse_count <= 5: return 80
        return 100

    def _determine_reputation(self, score: int) -> str:
        if score == 0: return "Safe"
        if score < 75: return "Suspicious"
        return "Malicious"
