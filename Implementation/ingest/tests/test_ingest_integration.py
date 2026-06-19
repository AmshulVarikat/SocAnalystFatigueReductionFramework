from Implementation.ingest.ingest import ingest_from_replay


def test_ingest_integration_one():
    gen = ingest_from_replay('Validation-001')
    na = next(gen)
    # should be a NormalizedAlert-like object with source set
    assert hasattr(na, 'to_dict')
    assert hasattr(na, 'source')
    assert na.source in ('wazuh', 'unknown')
