# Normalisation

This package implements the canonical `NormalizedAlert` dataclass and adapters to convert raw alerts into that canonical form.

Usage
-----
Dispatch a raw alert via the `BaseAdapter`:

```python
from Implementation.Normalisation.adapters.base_adapter import BaseAdapter

na = BaseAdapter.normalize(raw_alert, {'source': 'wazuh', 'meta': {}})
print(na.to_dict())
```

Adapters
--------
- `wazuh`: currently implemented in `adapters/wazuh_adapter.py`.

Adding adapters
--------------
Create a normalization function and register it with `@register_adapter('source_name')` decorator from `adapters.base_adapter`.
