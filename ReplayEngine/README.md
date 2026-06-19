# Replay Engine

Standalone replay layer for Validation-001.

## Scope

- Sequential, time-preserved, and accelerated replay modes
- Raw Wazuh alert passthrough for downstream ingestion
- Optional test output with ground-truth context
- Dataset loading from `Validation-001`
- Replay output for downstream ingestion

## Output Shape

Each replayed item is emitted as either raw mode or test mode.

```json
{
  "alert": {},
  "replay_time": "2026-06-12T00:00:00+00:00"
}
```

Test mode adds `source_dataset` and `ground_truth`.

In `TIME_PRESERVED` mode, `replay_time` reflects the source alert timestamp. In the other modes, it remains the replay emission time.