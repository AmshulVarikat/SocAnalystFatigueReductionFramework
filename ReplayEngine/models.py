from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass(slots=True)
class Alert:
    alert_id: str
    timestamp: datetime
    rule_id: str
    severity: int
    host: str
    mitre: List[str]
    description: str
    alert_level: Optional[int] = None
    firedtimes: Optional[int] = None
    agent_id: Optional[str] = None
    agent_ip: Optional[str] = None
    manager_name: Optional[str] = None
    decoder_name: Optional[str] = None
    location: Optional[str] = None
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    raw_rule: Dict[str, Any] = field(default_factory=dict)
    raw_agent: Dict[str, Any] = field(default_factory=dict)
    raw_manager: Dict[str, Any] = field(default_factory=dict)
    raw_decoder: Dict[str, Any] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    raw_alert: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ReplayEnvelope:
    alert: Alert
    replay_time: datetime
    source_dataset: str


@dataclass(slots=True)
class ValidationContext:
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    asset: Optional[str]
    scenario_id: Optional[str]
    attack_count: Optional[int]
    ground_truth_records: List[Dict[str, Any]]
    execution_log_records: List[Dict[str, Any]]
    ground_truth_meta: Dict[str, Any] = field(default_factory=dict)