from Implementation.Normalisation.adapters.base_adapter import BaseAdapter


def test_base_adapter_dispatch():
    raw = {'rule': {'id': 1}, 'agent': {'name': 'a1'}}
    na = BaseAdapter.normalize(raw, {'source': 'wazuh'})
    assert na.source == 'wazuh'
    assert na.rule_id == '1'
