"""Adapters package for Normalisation.

Import adapter modules here so they can register with the BaseAdapter registry on import.
"""

from . import base_adapter  # noqa: F401

# Import adapters to ensure registration
from . import wazuh_adapter  # noqa: F401

__all__ = ["base_adapter", "wazuh_adapter"]
