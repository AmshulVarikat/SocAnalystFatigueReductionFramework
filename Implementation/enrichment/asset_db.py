# Implementation/enrichment/asset_db.py
import json
from typing import Dict, Any, Optional

class AssetDatabase:
    def __init__(self, json_path: str):
        self.assets: Dict[str, Dict[str, Any]] = {}
        self._load_database(json_path)

    def _load_database(self, json_path: str):
        """Loads the asset JSON list into a lookup dictionary keyed by asset_id."""
        with open(json_path, 'r', encoding='utf-8') as f:
            raw_assets = json.load(f)
            for asset in raw_assets:
                # Key the database by asset_id (e.g., 'DC01')
                asset_id = asset.get("asset_id")
                if asset_id:
                    self.assets[asset_id.upper()] = asset

    def get_asset(self, hostname: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves asset metadata based on hostname.
        Returns None if the asset is not found.
        """
        if not hostname:
            return None
        return self.assets.get(hostname.upper())

    def get_criticality(self, hostname: str, default: int = 1) -> int:
        """Helper to fetch just the criticality score, defaulting to 1 for unknown assets."""
        asset = self.get_asset(hostname)
        if asset and 'criticality' in asset:
            return asset['criticality']
        return default
