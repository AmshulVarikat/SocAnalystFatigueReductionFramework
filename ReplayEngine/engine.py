from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Iterator

from .loader import ValidationDataset
from .modes import ReplayMode, ReplayOutputFormat
from .models import Alert


class ReplayEngine:
    def __init__(
        self,
        dataset: ValidationDataset | None = None,
        mode: ReplayMode = ReplayMode.SEQUENTIAL,
        output_format: ReplayOutputFormat = ReplayOutputFormat.RAW,
        acceleration_factor: float = 1.0,
        live_filepath: str | None = "/var/ossec/logs/alerts/alerts.json",
    ) -> None:
        self.dataset = dataset
        self.mode = mode
        self.output_format = output_format
        self.acceleration_factor = acceleration_factor
        self.live_filepath = live_filepath

        if self.acceleration_factor <= 0:
            raise ValueError("acceleration_factor must be greater than zero")

    def replay(self) -> Iterator[dict]:
        if self.mode is ReplayMode.LIVE:
            yield from self._replay_live()
            return
            
        if self.dataset is None:
            raise ValueError("Dataset cannot be None for non-LIVE modes.")

        if self.mode is ReplayMode.SEQUENTIAL:
            yield from self._replay_sequential()
            return

        if self.mode is ReplayMode.TIME_PRESERVED:
            yield from self._replay_time_preserved()
            return

        if self.mode is ReplayMode.ACCELERATED:
            yield from self._replay_accelerated()
            return

        raise NotImplementedError(f"Unsupported replay mode: {self.mode}")

    def _replay_live(self) -> Iterator[dict]:
        import json
        import os

        if not self.live_filepath or not os.path.exists(self.live_filepath):
            raise FileNotFoundError(f"Live alerts file not found: {self.live_filepath}")

        with open(self.live_filepath, 'r', encoding='utf-8') as f:
            # Seek to the end of the file for live 'tail -f' behavior
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    alert_data = json.loads(line)
                    replay_time = datetime.now(timezone.utc)
                    if self.output_format is ReplayOutputFormat.RAW:
                        yield {
                            "alert": alert_data,
                            "replay_time": replay_time.isoformat(),
                            "source_dataset": "live"
                        }
                    else:
                        raise NotImplementedError("Only RAW output format is supported in LIVE mode.")
                except json.JSONDecodeError:
                    pass

    def _replay_sequential(self) -> Iterator[dict]:
        for alert in self.dataset.alerts:
            yield self._build_output(alert)

    def _replay_time_preserved(self) -> Iterator[dict]:
        previous_timestamp: datetime | None = None

        for alert in self.dataset.alerts:
            if previous_timestamp is not None:
                delay = (alert.timestamp - previous_timestamp).total_seconds()
                if delay > 0:
                    time.sleep(delay)
            previous_timestamp = alert.timestamp
            yield self._build_output(alert, replay_time=alert.timestamp)

    def _replay_accelerated(self) -> Iterator[dict]:
        previous_timestamp: datetime | None = None

        for alert in self.dataset.alerts:
            if previous_timestamp is not None:
                delay = (alert.timestamp - previous_timestamp).total_seconds() / self.acceleration_factor
                if delay > 0:
                    time.sleep(delay)
            previous_timestamp = alert.timestamp
            yield self._build_output(alert)

    def _build_output(self, alert: Alert, replay_time: datetime | None = None) -> dict:
        replay_time = replay_time or datetime.now(timezone.utc)
        if self.output_format is ReplayOutputFormat.TEST:
            return {
                "alert": alert.raw_alert,
                "replay_time": replay_time.isoformat(),
                "source_dataset": self.dataset.dataset_name,
                "ground_truth": self._build_ground_truth_context(),
            }

        if self.output_format is ReplayOutputFormat.RAW:
            return {
                "alert": alert.raw_alert,
                "replay_time": replay_time.isoformat(),
            }

        raise NotImplementedError(f"Unsupported replay output format: {self.output_format}")

    def _build_ground_truth_context(self) -> dict:
        context = self.dataset.context
        return {
            "start_time": context.start_time.isoformat() if context.start_time else None,
            "end_time": context.end_time.isoformat() if context.end_time else None,
            "asset": context.asset,
            "scenario_id": context.scenario_id,
            "attack_count": context.attack_count,
            "ground_truth_records": context.ground_truth_records,
            "execution_log_records": context.execution_log_records,
            "ground_truth_meta": context.ground_truth_meta,
        }