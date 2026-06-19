from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Alert, ValidationContext


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def _parse_alert_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    if normalized.endswith("+0530"):
        normalized = normalized[:-5] + "+05:30"
    return datetime.fromisoformat(normalized)


@dataclass(slots=True)
class ValidationDataset:
    dataset_name: str
    alerts: List[Alert]
    context: ValidationContext


class JsonLoader:
    def __init__(self, dataset_root: str | Path) -> None:
        self.dataset_root = Path(dataset_root)

    def load(self) -> ValidationDataset:
        alerts = self._load_alerts(self.dataset_root / "extracted_alerts.json")
        context = self._load_context(self.dataset_root / "GroundTruth")
        return ValidationDataset(
            dataset_name=self.dataset_root.name,
            alerts=alerts,
            context=context,
        )

    def _load_alerts(self, alerts_path: Path) -> List[Alert]:
        with alerts_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

        if not isinstance(payload, list):
            raise ValueError("extracted_alerts.json must contain an array of alerts")

        alerts: List[Alert] = []
        for index, item in enumerate(payload, start=1):
            alerts.append(self._normalize_alert(item, index))
        return alerts

    def _load_context(self, ground_truth_dir: Path) -> ValidationContext:
        execution_log_payload = self._load_json(ground_truth_dir / "execution_log.json")
        ground_truth_payload = self._load_json(ground_truth_dir / "ground_truth.json")

        execution_log_records = self._as_list(execution_log_payload)
        ground_truth_records = self._as_list(ground_truth_payload)
        ground_truth_meta = self._as_dict(ground_truth_payload)
        if not ground_truth_meta:
            ground_truth_meta = self._as_dict(execution_log_payload)

        timing_source = ground_truth_meta or self._first_record(execution_log_records) or self._first_record(ground_truth_records)

        return ValidationContext(
            start_time=_parse_datetime(timing_source.get("StartTime")) if timing_source else None,
            end_time=_parse_datetime(timing_source.get("EndTime")) if timing_source else None,
            asset=timing_source.get("Asset") if timing_source else None,
            scenario_id=timing_source.get("ScenarioID") if timing_source else None,
            attack_count=timing_source.get("AttackCount") if timing_source else None,
            ground_truth_records=ground_truth_records,
            execution_log_records=execution_log_records,
            ground_truth_meta=ground_truth_meta,
        )

    def _load_json(self, path: Path) -> Any:
        with path.open("r", encoding="utf-8-sig") as handle:
            return json.load(handle)

    def _as_list(self, payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, list):
            return payload
        return []

    def _as_dict(self, payload: Any) -> Dict[str, Any]:
        if isinstance(payload, dict):
            return payload
        return {}

    def _first_record(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        return records[0] if records else {}

    def _normalize_alert(self, item: Dict[str, Any], index: int) -> Alert:
        rule = item.get("rule", {})
        agent = item.get("agent", {})
        manager = item.get("manager", {})
        decoder = item.get("decoder", {})
        data = item.get("data", {})

        mitre = rule.get("mitre", {})
        alert_id = item.get("id") or str(index)
        timestamp = _parse_alert_timestamp(item["timestamp"])
        severity = int(rule.get("level", 0) or 0)

        return Alert(
            alert_id=str(alert_id),
            timestamp=timestamp,
            rule_id=str(rule.get("id", "")),
            severity=severity,
            host=str(agent.get("name", "")),
            mitre=list(mitre.get("id", []) or []),
            description=str(rule.get("description", "")),
            alert_level=severity,
            firedtimes=self._optional_int(rule.get("firedtimes")),
            agent_id=str(agent.get("id", "")) or None,
            agent_ip=str(agent.get("ip", "")) or None,
            manager_name=str(manager.get("name", "")) or None,
            decoder_name=str(decoder.get("name", "")) or None,
            location=str(item.get("location", "")) or None,
            mitre_tactics=list(mitre.get("tactic", []) or []),
            mitre_techniques=list(mitre.get("technique", []) or []),
            raw_rule=rule,
            raw_agent=agent,
            raw_manager=manager,
            raw_decoder=decoder,
            raw_data=data,
            raw_alert=item,
        )

    def _optional_int(self, value: Any) -> Optional[int]:
        if value is None or value == "":
            return None
        return int(value)