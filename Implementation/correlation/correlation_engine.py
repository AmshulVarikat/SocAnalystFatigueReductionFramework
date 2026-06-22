import json
import uuid
from typing import Dict, Any, Callable, Optional, List
from datetime import datetime, timedelta

class Investigation:
    def __init__(self, investigation_id: str, rule: Dict[str, Any], anchor_alert: Dict[str, Any]):
        self.investigation_id = investigation_id
        self.rule = rule
        self.alerts: List[int] = []
        storage_id = anchor_alert.get('_storage_id')
        if storage_id is not None:
            self.alerts.append(storage_id)
            
        self.last_alert_time: datetime = self._parse_time(anchor_alert)
        self.match_values: Dict[str, Any] = self._extract_match_values(anchor_alert, rule.get('match_criteria', []))
        self.status = "OPEN"
        self.current_priority: float = 0.0
        self.max_risk_score: float = anchor_alert.get("risk_score", 0.0)
        self.total_alerts_count: int = 1

    def _get_field(self, obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    def _parse_time(self, alert: Dict[str, Any]) -> datetime:
        alert_inner = self._get_field(alert, "alert", {})
        ts_str = self._get_field(alert, "timestamp") or self._get_field(alert_inner, "timestamp") or self._get_field(alert_inner, "event_time") or self._get_field(alert_inner, "normalized_timestamp") or datetime.utcnow().isoformat()
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return datetime.utcnow()

    def _extract_match_values(self, alert: Dict[str, Any], match_criteria: List[str]) -> Dict[str, Any]:
        values = {}
        alert_data = self._get_field(alert, "alert", alert)
        for criterion in match_criteria:
            val = self._get_field(alert_data, criterion)
            if val is None:
                val = self._get_field(alert, criterion)
            values[criterion] = val
        return values
        
    def matches(self, alert: Dict[str, Any]) -> bool:
        alert_data = self._get_field(alert, "alert", alert)
        for criterion, expected_value in self.match_values.items():
            val = self._get_field(alert_data, criterion)
            if val is None:
                val = self._get_field(alert, criterion)
            if val != expected_value:
                return False
        return True


class CorrelationEngine:
    def __init__(self, db_repository, tick_interval: int = 10, rules_path: str = None, on_investigation_event: Optional[Callable] = None):
        self.db_repository = db_repository
        self.tick_interval = tick_interval
        self.rules_path = rules_path
        self.on_investigation_event = on_investigation_event
        
        self.active_investigations: Dict[str, Investigation] = {}
        self.alert_counter: int = 0
        self.engine_clock: datetime = datetime.min
        self.rules: List[Dict[str, Any]] = []
        
        self._load_rules()

    def _load_rules(self):
        if not self.rules_path:
            return
        try:
            with open(self.rules_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.rules = data.get("rules", [])
        except Exception as e:
            print(f"[!] CorrelationEngine failed to load rules from {self.rules_path}: {e}")

    def process_alert(self, alert: Dict[str, Any]):
        self._update_clock(alert)
        
        matched_active = self._evaluate_active_investigations(alert)
        
        if not matched_active:
            self._evaluate_new_triggers(alert)
            
        self._tick()

    def _get_field(self, obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    def _update_clock(self, alert: Dict[str, Any]):
        alert_inner = self._get_field(alert, "alert", {})
        ts_str = self._get_field(alert, "timestamp") or self._get_field(alert_inner, "timestamp") or self._get_field(alert_inner, "event_time") or self._get_field(alert_inner, "normalized_timestamp")
        if ts_str:
            try:
                alert_time = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
                if alert_time > self.engine_clock:
                    self.engine_clock = alert_time
            except ValueError:
                pass

    def _evaluate_active_investigations(self, alert: Dict[str, Any]) -> bool:
        matched = False
        alert_id = self._get_field(alert, "_storage_id")
        if alert_id is None:
            return False
            
        alert_inner = self._get_field(alert, "alert", {})
        alert_time_str = self._get_field(alert, "timestamp") or self._get_field(alert_inner, "timestamp") or self._get_field(alert_inner, "event_time") or self._get_field(alert_inner, "normalized_timestamp")
        try:
            alert_time = datetime.fromisoformat(alert_time_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, TypeError):
            alert_time = self.engine_clock

        for inv_id, inv in self.active_investigations.items():
            if inv.matches(alert):
                timeout_mins = inv.rule.get("rolling_timeout_minutes", 30)
                if alert_time <= inv.last_alert_time + timedelta(minutes=timeout_mins):
                    # Match
                    inv.alerts.append(alert_id)
                    inv.total_alerts_count += 1
                    alert_risk_score = alert.get("risk_score", 0.0)
                    inv.max_risk_score = max(inv.max_risk_score, alert_risk_score)
                    
                    inv.last_alert_time = max(inv.last_alert_time, alert_time)
                    self.db_repository.add_alert_to_investigation(inv_id, alert_id)
                    
                    self._recalculate_priority(inv_id)
                    self.db_repository.update_investigation_priority(inv_id, inv.current_priority)
                    
                    matched = True
                    
                    if self.on_investigation_event:
                        self.on_investigation_event({
                            "event": "INVESTIGATION_UPDATED",
                            "investigation_id": inv_id,
                            "alert_id": alert_id,
                            "current_priority": inv.current_priority
                        })
        return matched

    def _recalculate_priority(self, investigation_id: str):
        inv = self.active_investigations.get(investigation_id)
        if not inv:
            return
            
        p_max = inv.max_risk_score
        n = inv.total_alerts_count
        
        p_total = min(100.0, p_max + (n - 1) * 2.0)
        inv.current_priority = p_total

    def _evaluate_new_triggers(self, alert: Dict[str, Any]):
        alert_data = self._get_field(alert, "alert", alert)
        for rule in self.rules:
            anchor = rule.get("anchor", {})
            match = True
            for k, v in anchor.items():
                val = self._get_field(alert_data, k)
                if val is None:
                    val = self._get_field(alert, k)
                if str(val) != str(v):
                    match = False
                    break
            
            if match:
                self._spawn_investigation(alert, rule)
                break

    def _spawn_investigation(self, alert: Dict[str, Any], rule: Dict[str, Any]):
        alert_id = self._get_field(alert, "_storage_id")
        if alert_id is None:
            return
            
        inv_id = str(uuid.uuid4())
        inv = Investigation(inv_id, rule, alert)
        
        created_at = inv.last_alert_time
        
        self.db_repository.create_investigation(inv_id, "OPEN", created_at, rule.get("rule_name", "Unknown"))
        self.db_repository.add_alert_to_investigation(inv_id, alert_id)
        
        # Context extraction
        hist_window = rule.get("historical_window_minutes", 60)
        start_time = created_at - timedelta(minutes=hist_window)
        
        filters = inv.match_values
        historical_alerts = self.db_repository.search_alerts(filters, start_time=start_time, end_time=created_at)
        
        inv.total_alerts_count = 1 + len(historical_alerts)
        if historical_alerts:
            hist_max_risk = max([a.get("risk_score", 0.0) for a in historical_alerts])
            inv.max_risk_score = max(inv.max_risk_score, hist_max_risk)
        
        self.active_investigations[inv_id] = inv
        
        self._recalculate_priority(inv_id)
        self.db_repository.update_investigation_priority(inv_id, inv.current_priority)
        
        if self.on_investigation_event:
            self.on_investigation_event({
                "event": "INVESTIGATION_OPENED",
                "investigation_id": inv_id,
                "rule_name": rule.get("rule_name"),
                "anchor_alert_id": alert_id,
                "historical_alerts_count": len(historical_alerts),
                "current_priority": inv.current_priority
            })

    def _tick(self):
        self.alert_counter += 1
        if self.alert_counter >= self.tick_interval:
            self._evaluate_timeouts()
            self.alert_counter = 0

    def _evaluate_timeouts(self):
        to_close = []
        for inv_id, inv in self.active_investigations.items():
            timeout_mins = inv.rule.get("rolling_timeout_minutes", 30)
            if self.engine_clock > inv.last_alert_time + timedelta(minutes=timeout_mins):
                to_close.append(inv_id)
                
        for inv_id in to_close:
            inv = self.active_investigations.pop(inv_id)
            inv.status = "CLOSED"
            self.db_repository.update_investigation_status(inv_id, "CLOSED", self.engine_clock)
            
            if self.on_investigation_event:
                self.on_investigation_event({
                    "event": "INVESTIGATION_CLOSED",
                    "investigation_id": inv_id,
                    "closed_at": self.engine_clock.isoformat()
                })
