from __future__ import annotations

from typing import Callable, Dict, Any, Iterator
from pathlib import Path

from ReplayEngine.loader import JsonLoader
from ReplayEngine.engine import ReplayEngine
from ReplayEngine.modes import ReplayMode, ReplayOutputFormat

from Implementation.Normalisation.adapters.base_adapter import BaseAdapter
from Implementation.ingest import source_detector as default_detector
from Implementation.Normalisation.normalized_alert import NormalizedAlert


def ingest_from_replay(
    dataset_path: str | Path,
    replay_options: Dict[str, Any] | None = None,
    detector: Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]] | None = None,
) -> Iterator[NormalizedAlert]:
    """Load a dataset and yield NormalizedAlert objects by dispatching to adapters.

    Args:
        dataset_path: path to dataset directory (e.g., 'Validation-001')
        replay_options: dict with optional keys: mode, output_format, acceleration_factor
        detector: optional callable(raw_alert, meta) -> {'source': name, 'meta': {...}}
    """
    replay_options = replay_options or {}
    mode = replay_options.get('mode', ReplayMode.SEQUENTIAL)
    output_format = replay_options.get('output_format', ReplayOutputFormat.RAW)
    acceleration_factor = replay_options.get('acceleration_factor', 1.0)

    loader = JsonLoader(dataset_path)
    dataset = loader.load()

    engine = ReplayEngine(dataset, mode=mode, output_format=output_format, acceleration_factor=acceleration_factor)

    detector = detector or default_detector.detect

    for envelope in engine.replay():
        raw_alert = envelope.get('alert')
        meta = {'replay_time': envelope.get('replay_time'), 'dataset': envelope.get('source_dataset')}

        source_info = detector(raw_alert, meta)

        # Enforce dict-shaped source_info
        if not isinstance(source_info, dict):
            source_info = {'source': str(source_info), 'meta': meta}

        normalized = BaseAdapter.normalize(raw_alert, source_info)

        # attach ingest metadata
        try:
            if meta.get('replay_time'):
                normalized.ingest_id = f"{meta.get('dataset') or 'dataset'}:{meta.get('replay_time')}"
                normalized.normalized_timestamp = meta.get('replay_time')
        except Exception:
            pass

        yield normalized


def run_and_write(dataset_path: str | Path, out_path: str | Path | None = None):
    """Convenience runner: stream normalized alerts to stdout or a file (newline JSON)."""
    import json
    from sys import stdout

    out_file = None
    if out_path:
        out_file = open(out_path, 'w', encoding='utf-8')

    try:
        for na in ingest_from_replay(dataset_path):
            line = json.dumps(na.to_dict(), default=str)
            if out_file:
                out_file.write(line + "\n")
            else:
                stdout.write(line + "\n")
    finally:
        if out_file:
            out_file.close()
