# Replay Engine Details

This file documents the replay engine as implemented so far. It is the reference for how the current code works, how to run it, and what you would edit manually when extending it.

## Purpose

The replay engine is the Phase 6 entry point in the processing pipeline. Its job is to read the validation dataset and emit alerts in the order required by the framework so later stages can consume them.

Current scope:

- Sequential, time-preserved, and accelerated replay modes
- Streaming behavior
- Validation-001 dataset support
- Raw alert passthrough for downstream ingestion
- Optional test output with ground-truth context

Not yet implemented:

- Time-preserved replay
- Accelerated replay
- Enrichment
- Risk scoring
- Classification
- Grouping
- Prioritization

## Folder Layout

The replay engine lives in its own top-level folder:

- `ReplayEngine/__init__.py`
- `ReplayEngine/engine.py`
- `ReplayEngine/loader.py`
- `ReplayEngine/models.py`
- `ReplayEngine/modes.py`
- `ReplayEngine/queue.py`
- `ReplayEngine/README.md`
- `ReplayEngine/details.md`

## Data Inputs

The current implementation reads from the Validation-001 dataset folder.

Primary input:

- `Validation-001/extracted_alerts.json`

Context inputs:

- `Validation-001/GroundTruth/ground_truth.json`
- `Validation-001/GroundTruth/execution_log.json`

The loader is intentionally tolerant of the current workspace files because the validation files are not shaped exactly as their names suggest:

- `extracted_alerts.json` is the alert list and is the primary replay source.
- `execution_log.json` currently contains an array of per-technique records.
- `ground_truth.json` currently contains scenario metadata.

The loader preserves both raw context payloads so the replay layer does not lose information even if the validation files are swapped or repurposed later.

## Current Data Model

### `Alert`

Defined in `ReplayEngine/models.py`.

The normalized alert object currently includes:

- `alert_id`
- `timestamp`
- `rule_id`
- `severity`
- `host`
- `mitre`
- `description`
- `alert_level`
- `firedtimes`
- `agent_id`
- `agent_ip`
- `manager_name`
- `decoder_name`
- `location`
- `mitre_tactics`
- `mitre_techniques`
- `raw_rule`
- `raw_agent`
- `raw_manager`
- `raw_decoder`
- `raw_data`
- `raw_alert`

The `raw_*` fields are kept so later stages can inspect the original source event without needing to reload the JSON.

### `ReplayEnvelope`

Defined in `ReplayEngine/models.py`.

The current engine output is a plain dictionary. For raw mode it contains:

- `alert`
- `replay_time`

For test mode it also includes:

- `source_dataset`
- `ground_truth`

`ReplayEnvelope` remains available as a model type, but the replay output is now shaped directly by the engine.

### `ValidationContext`

Defined in `ReplayEngine/models.py`.

It stores:

- `start_time`
- `end_time`
- `asset`
- `scenario_id`
- `attack_count`
- `ground_truth_records`
- `execution_log_records`
- `ground_truth_meta`

This is context only. It does not affect sequential replay order.

## Loader Behavior

The loader is implemented in `ReplayEngine/loader.py` as `JsonLoader`.

What it does:

1. Reads `Validation-001/extracted_alerts.json`.
2. Normalizes each alert into an `Alert` dataclass.
3. Reads the `GroundTruth` files.
4. Builds a `ValidationDataset` object with the dataset name, alerts, and context.

Important parsing details:

- JSON files are opened with `utf-8-sig` to handle BOM-prefixed files.
- Alert timestamps are normalized with `datetime.fromisoformat` after translating `Z` to `+00:00`.
- Alert timestamps that end in `+0530` are normalized to `+05:30` before parsing.
- If `id` is missing from an alert, the loader falls back to the 1-based array index as the alert identifier.
- Numeric fields like `severity` and `firedtimes` are converted to integers when possible.

Current loader assumptions:

- `extracted_alerts.json` must be an array.
- Alert records should contain `timestamp`, `rule`, `agent`, `decoder`, `data`, and `location` fields when available.
- Missing nested fields are tolerated and default to empty values.

## Replay Engine Behavior

The replay engine is implemented in `ReplayEngine/engine.py` as `ReplayEngine`.

Sequential replay works like this:

1. Iterate through the normalized alerts in the order they appear in `extracted_alerts.json`.
2. Put each alert into the queue using `queue.put(alert)`.
3. Immediately remove it using `queue.get()`.
4. Wrap it into the output envelope.
5. Yield the envelope to the caller.

This means the current sequential implementation is a pass-through layer that preserves dataset order exactly.

Replay metadata:

- `replay_time` is set to the current UTC time at emission.
- `source_dataset` is included in test output and set to the dataset folder name, which is currently `Validation-001`.

The engine supports `SEQUENTIAL`, `TIME_PRESERVED`, and `ACCELERATED` replay modes.

## Queue Behavior

`ReplayEngine/queue.py` provides `AlertQueue`.

Available operations:

- `put(alert)`
- `get()`
- `empty()`
- `size()`

This is a thin wrapper around `collections.deque` and exists so the replay engine has an explicit queue abstraction.

## Replay Mode

`ReplayEngine/modes.py` defines `ReplayMode`.

Current values:

- `SEQUENTIAL`
- `TIME_PRESERVED`
- `ACCELERATED`

The enum is intentionally small so later work can add `TIME_PRESERVED` and other modes without changing the public API shape.

## Environment Setup

The workspace already uses a Python virtual environment.

Detected environment:

- Python: `3.13.5`
- Interpreter path: `.venv/bin/python`

Recommended setup from the project root:

```bash
python -m venv .venv
source .venv/bin/activate
python --version
```

If the environment already exists, you only need to activate it.

## Usage

The replay engine is currently a library-style module. A simple usage pattern is:

```python
from pathlib import Path
import sys

root = Path("/Users/amshul/Work/SOC_Internship/Project/Code_Implementation")
sys.path.insert(0, str(root))

from ReplayEngine import JsonLoader, ReplayEngine, ReplayMode, ReplayOutputFormat

loader = JsonLoader(root / "Validation-001")
dataset = loader.load()

engine = ReplayEngine(dataset, ReplayMode.SEQUENTIAL, ReplayOutputFormat.RAW)
for item in engine.replay():
    print(item)
```

Expected replay envelope shape in raw mode:

```json
{
  "alert": {
    "timestamp": "2026-06-11T15:10:48.735+0530",
    "rule": {},
    "agent": {},
    "manager": {},
    "decoder": {},
    "data": {},
    "location": "..."
  },
  "replay_time": "2026-06-12T00:00:00+00:00"
}
```

Expected replay envelope shape in test mode:

```json
{
  "alert": {},
  "replay_time": "2026-06-12T00:00:00+00:00",
  "source_dataset": "Validation-001",
  "ground_truth": {
    "start_time": "2026-06-11T15:10:16.7032926+05:30",
    "end_time": "2026-06-11T15:13:34.7558413+05:30",
    "asset": "DC01",
    "scenario_id": "Validation-001",
    "attack_count": 5,
    "ground_truth_records": [],
    "execution_log_records": [],
    "ground_truth_meta": {}
  }
}
```

### Add time-preserved replay

- File: `ReplayEngine/engine.py`
- File: `ReplayEngine/modes.py`

`TIME_PRESERVED` and `ACCELERATED` are now part of `ReplayMode`. The engine branches by mode and can preserve the original alert timing or compress it by an acceleration factor.

### Change alert normalization

- File: `ReplayEngine/loader.py`
- File: `ReplayEngine/models.py`

If the dataset changes shape, update `_normalize_alert` to map the new fields into `Alert`.

### Change replay metadata

- File: `ReplayEngine/engine.py`

If downstream ingestion needs more wrapper fields, extend `_build_envelope`.

### Change dataset location

- File: `ReplayEngine/loader.py`

If the replay source moves, update `JsonLoader.load()` or pass a different root path when constructing the loader.

### Change queue semantics

- File: `ReplayEngine/queue.py`

If you want batching, filtering, prioritization, or deduplication in the replay layer, this is the boundary to change.

## Validation Notes

The current implementation was checked against the Validation-001 files and confirmed to:

- Parse the dataset successfully
- Preserve alert order
- Emit exactly one envelope per alert
- Leave the queue empty after replay completes

## Known Limitations

- Sequential, time-preserved, and accelerated replay modes are implemented.
- The replay engine is not yet integrated with enrichment or scoring.
- The loader currently tolerates inconsistent validation file shapes instead of enforcing a strict schema.
- `replay_time` is source time in `TIME_PRESERVED` mode and emission time in the other modes.

## Future Extension Points

- Add time-preserved replay.
- Add accelerated replay.
- Add replay statistics and counters.
- Add stricter schema validation for alerts and context files.
- Add a CLI entry point if you want the replay engine to run directly from the terminal.