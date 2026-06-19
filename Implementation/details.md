# Implementation: Overall Design & Details

NOTE: None of the classes or modules in this implementation are intended to interact directly with one another. A single `Orchestrator` (not yet implemented) should be the only component that knows about and coordinates all others. The orchestrator is responsible for wiring the ReplayEngine, Ingest, Normalisation, and any downstream consumers.

This document describes the input, output, and behavior of the components implemented so far, how they fit together, and where to extend the system.

Contents
--------
- Components overview
- Data flow (inputs/outputs) for each phase
- Public APIs and important functions/classes
- How to run the provided tests and utilities
- Extension points and recommendations
- Assumptions and decisions made

Components overview
-------------------

1) ReplayEngine (existing package: `ReplayEngine/`)
   - Purpose: Replay recorded alert datasets (for testing and simulation).
   - Key files:
     - `ReplayEngine/loader.py` — `JsonLoader` reads `Validation-001/extracted_alerts.json` and ground-truth files, returns a `ValidationDataset` (contains a list of `ReplayEngine.models.Alert` dataclass instances and a `ValidationContext`).
     - `ReplayEngine/engine.py` — `ReplayEngine` accepts a `ValidationDataset` and yields replay envelopes via `replay()` according to a `ReplayMode` and `ReplayOutputFormat`.
     - `ReplayEngine/models.py` — dataclasses: `Alert`, `ReplayEnvelope`, `ValidationContext` describing internal alert representations.

2) Normalisation (new package: `Implementation/Normalisation/`)
   - Purpose: Convert raw alerts from different sources into a single canonical model `NormalizedAlert`.
   - Key files:
     - `normalized_alert.py` — `NormalizedAlert` dataclass (canonical schema). Fields are grouped by type (metadata, identifiers, timestamps, host/agent, network, process/file/user, rule/detection, MITRE, observables, enrichment, misc). All scalar fields default to empty strings and collection fields to empty lists/dicts.
     - `adapters/base_adapter.py` — `BaseAdapter` dispatcher and `register_adapter` decorator. Adapters register themselves with `@register_adapter('<source>')` and must implement a function that accepts the raw alert dict and returns a `NormalizedAlert`.
     - `adapters/wazuh_adapter.py` — a Wazuh adapter that maps common Wazuh fields (rule, agent, timestamp, severity, ips, tags) into `NormalizedAlert`.
     - `adapters/__init__.py` — imports adapters so they are registered on package import.

3) Ingest (new package: `Implementation/ingest/`)
   - Purpose: Pull alerts from `ReplayEngine`, detect the alert source, and dispatch the raw alert to `BaseAdapter` for normalization.
   - Key files:
     - `ingest/ingest.py` — `ingest_from_replay(dataset_path, replay_options=None, detector=None)` yields `NormalizedAlert` objects by iterating `ReplayEngine.replay()` and calling the configured detector followed by `BaseAdapter.normalize`.
     - `ingest/source_detector.py` — a small, pluggable heuristic-based source detector. Default heuristic: if a raw alert has both `rule` and `agent` keys, classify it as `wazuh`; otherwise return `unknown`.
     - `ingest/run_and_write` — convenience function to stream normalized alerts to stdout or an output file as newline-delimited JSON.

4) Tests and lightweight runners
   - For environments that don't have `pytest` installed, simple test runners are provided under `Implementation/Normalisation/tests/run_tests.py` and `Implementation/ingest/tests/run_tests.py` which import and execute test functions named `test_*`.
   - Unit tests exist for the Wazuh adapter, BaseAdapter dispatch, source detector, and a small ingest integration test that runs a single alert through the full path.

Data flow (per-phase inputs/outputs)
-----------------------------------

1) Replay / Loading
   - Input: Dataset directory (example: `Validation-001/`) containing `extracted_alerts.json` and `GroundTruth/` files.
   - Operation: `JsonLoader(dataset_root).load()` parses the files and builds a `ValidationDataset` with `Alert` dataclass instances.
   - Output: `ValidationDataset` used to construct `ReplayEngine`.

2) ReplayEngine.replay()
   - Input: `ValidationDataset`, `ReplayMode`, and `ReplayOutputFormat`.
   - Operation: yields a Python `dict` envelope for each alert. When `output_format` is `RAW` the envelope shape is:

       {
         "alert": <raw_alert_dict>,
         "replay_time": "<ISO8601 timestamp>"
       }

     When `output_format` is `TEST` the envelope also includes `source_dataset` and `ground_truth` context.

   - Output: iterator of envelope dicts.

3) Ingest
   - Input: replay envelopes from `ReplayEngine.replay()`.
   - Operation:
     - Extract `raw_alert = envelope['alert']` and a small `meta` dict (`replay_time`, `source_dataset`).
     - Call the provided `detector(raw_alert, meta)` which should return `{'source': '<name>', 'meta': {...}}`. The default detector uses a small heuristic to detect Wazuh alerts.
     - Call `BaseAdapter.normalize(raw_alert, source_info)` where `source_info` is the dict returned by the detector. `BaseAdapter` finds the registered adapter and calls it.
     - Attach minimal ingest metadata (e.g., `ingest_id`, `normalized_timestamp`) onto the returned `NormalizedAlert`.
   - Output: `NormalizedAlert` instances (Python dataclass objects). The caller can serialize them with the `to_dict()` helper.

4) Normalisation
   - Input: raw alert `dict` and `source_info`.
   - Operation: Adapter function maps source-specific fields to canonical `NormalizedAlert` fields. Missing canonical fields are left empty (per requirement). Adapters must not enrich or persist; only normalize.
   - Output: `NormalizedAlert` instance with `raw_alert` preserved for traceability.

Public APIs and entry points
----------------------------

- `ReplayEngine.loader.JsonLoader(dataset_root).load() -> ValidationDataset`
- `ReplayEngine.engine.ReplayEngine(dataset, mode, output_format).replay() -> Iterator[dict]` (envelope dicts)
- `Implementation.ingest.ingest.ingest_from_replay(dataset_path, replay_options=None, detector=None) -> Iterator[NormalizedAlert]`
- `Implementation.Normalisation.adapters.base_adapter.BaseAdapter.normalize(raw_alert, source_info) -> NormalizedAlert`
- `Implementation.Normalisation.adapters.register_adapter(name)` decorator for adapters
- `Implementation.Normalisation.normalized_alert.NormalizedAlert.to_dict()` for JSON-serializable output

How to run the provided tests and utilities
-----------------------------------------

1. Run Normalisation tests (lightweight runner):

```bash
cd /path/to/Code_Implementation
python3 Implementation/Normalisation/tests/run_tests.py
```

2. Run Ingest tests (lightweight runner):

```bash
python3 Implementation/ingest/tests/run_tests.py
```

3. Run a smoke ingestion and print the first normalized alert (example):

```bash
python3 - <<'PY'
from Implementation.ingest.ingest import ingest_from_replay
it = ingest_from_replay('Validation-001')
na = next(it)
print(na.to_dict())
PY
```

Extension points and recommendations
-----------------------------------

- Orchestrator: implement a top-level `Orchestrator` class (for example `Implementation/orchestrator.py`) that is the single component aware of all parts. The orchestrator should:
  - Load dataset(s) via `JsonLoader`.
  - Create `ReplayEngine` with configured modes.
  - Create and configure the ingest pipeline and any downstream sinks (queues, DBs, further enrichment).
  - Manage lifecycle: start/stop, metrics, error handling, and graceful shutdown.

- More robust source detection: add a registry of detectors and allow ordering; allow detectors to return a confidence score. The `ingest` module already accepts a custom detector callable.

- Additional adapters: add adapters for other sources (Suricata, Zeek, Carbon Black, etc.) by registering functions with `@register_adapter('<name>')`. Keep adapter implementations pure (no side effects).

- Tests: expand adapter tests using real samples from `Validation-001/extracted_alerts.json` to ensure mappings are correct and handle corner cases.

- Error handling: adapters currently assume certain shapes; consider adding safe extraction helpers and returning warnings or partial-normalized objects for downstream handling.

Assumptions and decisions made so far
------------------------------------

- All canonical scalar fields default to empty strings and collections to empty lists/dicts per the original request.
- Adapters are responsible only for normalization (no enrichment or persistence).
- `BaseAdapter` uses an explicit registry and adapters are imported in `adapters/__init__.py` so they register on package import. Dynamic discovery (entry-points) can be added later.
- `ingest` uses a default, conservative `source_detector` that only recognizes Wazuh if `rule` and `agent` keys are present.

Questions / next decisions you may want to make
---------------------------------------------

1. Implement the `Orchestrator` and define its responsibilities (CLI, config, metrics). I can implement a first-pass orchestrator that wires a replay → ingest → consumer pipeline.
2. Decide whether missing canonical fields should ever be `None` for semantic clarity rather than empty string. Currently all scalars are empty strings by design.
3. Confirm how ingest metadata should be represented long-term (fields `ingest_id` and `normalized_timestamp` are currently used for a minimal traceability mapping).

Contact
-------
This file is part of an ongoing implementation. If you want the orchestrator or further adapters/tests implemented now, tell me which part to implement next.
