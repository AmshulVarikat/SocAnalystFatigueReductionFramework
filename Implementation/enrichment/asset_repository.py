# Implementation/enrichment/asset_repository.py
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class AssetRepository(ABC):
    """
    Abstract interface for asset data access. 
    Other modules MUST use this interface rather than database-specific classes.
    """
    @abstractmethod
    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full asset metadata by asset ID or hostname."""
        pass

    @abstractmethod
    def get_criticality(self, asset_id: str, default: int = 1) -> int:
        """Retrieve just the criticality score of an asset."""
        pass


class JsonAssetRepository(AssetRepository):
    """
    JSON-backed implementation of the AssetRepository.
    Loads the basic simulation asset inventory from a local file.
    """
    def __init__(self, json_path: str):
        self._assets: Dict[str, Dict[str, Any]] = {}
        self._load_database(json_path)

    def _load_database(self, json_path: str):
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                raw_assets = json.load(f)
                for asset in raw_assets:
                    asset_id = asset.get("asset_id")
                    if asset_id:
                        # Store keys in uppercase for case-insensitive lookups
                        self._assets[asset_id.upper()] = asset
        except FileNotFoundError:
            print(f"Warning: Asset database not found at {json_path}")

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        if not asset_id:
            return None
        return self._assets.get(asset_id.upper())

    def get_criticality(self, asset_id: str, default: int = 1) -> int:
        asset = self.get_asset(asset_id)
        if asset and 'criticality' in asset:
            return asset['criticality']
        return default