from typing import Callable, Dict, Any, Union

from ..normalized_alert import NormalizedAlert

REGISTRY: Dict[str, Callable[[Dict[str, Any]], NormalizedAlert]] = {}


def register_adapter(name: str):
    """Decorator to register an adapter normalization function under a source name.

    Usage:
        @register_adapter('wazuh')
        def normalize_wazuh(raw):
            ...
    """

    def decorator(func: Callable[[Dict[str, Any]], NormalizedAlert]):
        REGISTRY[name.lower()] = func
        return func

    return decorator


class BaseAdapter:
    @staticmethod
    def normalize(raw_alert: Dict[str, Any], source_info: Union[str, Dict[str, Any]]) -> NormalizedAlert:
        """Dispatch raw alert to the registered adapter based on source_info.

        `source_info` may be a string (source name) or a dict containing at least a 'source' key.
        """
        source = ''
        if isinstance(source_info, dict):
            source = source_info.get('source', '') or ''
        else:
            source = source_info or ''

        key = source.lower()
        adapter = REGISTRY.get(key)
        if adapter is None:
            raise ValueError(f"No adapter registered for source '{source}'")

        normalized = adapter(raw_alert)
        # Ensure metadata is set
        try:
            normalized.source = source
            normalized.raw_alert = raw_alert
        except Exception:
            # If adapter returned something unexpected, raise
            raise

        return normalized
