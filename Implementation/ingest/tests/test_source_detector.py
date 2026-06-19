from Implementation.ingest.source_detector import detect


def test_detect_wazuh():
    raw = {'rule': {'id': 1}, 'agent': {'name': 'a1'}}
    res = detect(raw, {'replay_time': 't'})
    assert isinstance(res, dict)
    assert res['source'] == 'wazuh'


def test_detect_unknown():
    raw = {'some': 'value'}
    res = detect(raw, {})
    assert res['source'] == 'unknown'
