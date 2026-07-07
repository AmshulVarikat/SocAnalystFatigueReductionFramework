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
        self.match_values: Dict[str, set] = self._extract_match_values(anchor_alert, rule)
        
        # NEW: Track dynamic progression fields (e.g., evolving MITRE tactics)
        self.observed_progression: Dict[str, set] = {}
        self._initialize_progression(anchor_alert)

        self.status = "OPEN"
        self.current_priority: float = 0.0
        self.max_risk_score: float = anchor_alert.get("risk_score", 0.0)
        self.total_alerts_count: int = 1

    def _initialize_progression(self, alert: Dict[str, Any]):
        progression_keys = self.rule.get('track_progression', [])
        alert_data = self._get_field(alert, "alert", alert)
        
        for key in progression_keys:
            self.observed_progression[key] = set()
            val = self._get_field(alert_data, key) or self._get_field(alert, key)
            if val:
                # Handle both string values and lists (if an alert has multiple tactics)
                if isinstance(val, list):
                    self.observed_progression[key].update(val)
                else:
                    self.observed_progression[key].add(val)

    def update_progression(self, alert: Dict[str, Any]):
        progression_keys = self.rule.get('track_progression', [])
        alert_data = self._get_field(alert, "alert", alert)
        
        for key in progression_keys:
            val = self._get_field(alert_data, key) or self._get_field(alert, key)
            if val:
                if isinstance(val, list):
                    self.observed_progression[key].update(val)
                else:
                    self.observed_progression[key].add(val)

    def update_pivot_entities(self, alert: Dict[str, Any]):
        pivot_fields = self.rule.get('pivot_fields', [])
        alert_data = self._get_field(alert, "alert", alert)
        
        for field in pivot_fields:
            val = self._get_field(alert_data, field)
            if val is None:
                val = self._get_field(alert, field)
            if val is not None:
                if field not in self.match_values:
                    self.match_values[field] = set()
                if isinstance(val, list):
                    self.match_values[field].update(val)
                else:
                    self.match_values[field].add(val)

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

    def _extract_match_values(self, alert: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, set]:
        values = {}
        fields = rule.get('match_criteria', []) + rule.get('pivot_fields', [])
        alert_data = self._get_field(alert, "alert", alert)
        for field in set(fields):
            values[field] = set()
            val = self._get_field(alert_data, field)
            if val is None:
                val = self._get_field(alert, field)
            if val is not None:
                if isinstance(val, list):
                    values[field].update(val)
                else:
                    values[field].add(val)
        return values
        
    def matches(self, alert: Dict[str, Any]) -> bool:
        alert_data = self._get_field(alert, "alert", alert)
        
        pivot_fields = self.rule.get('pivot_fields', [])
        if pivot_fields:
            # Graph-based pivot logic
            for field in pivot_fields:
                val = self._get_field(alert_data, field)
                if val is None:
                    val = self._get_field(alert, field)
                if val is not None:
                    vals = set(val) if isinstance(val, list) else {val}
                    vals = {v for v in vals if v and str(v).strip()}
                    expected = {v for v in self.match_values.get(field, set()) if v and str(v).strip()}
                    if vals and expected.intersection(vals):
                        return True
            return False # If there are pivot fields, we must intersect with at least one
        
        else:
            # Linear logic
            for criterion in self.rule.get('match_criteria', []):
                expected_values = self.match_values.get(criterion, set())
                val = self._get_field(alert_data, criterion)
                if val is None:
                    val = self._get_field(alert, criterion)
                
                vals = set(val) if isinstance(val, list) else {val} if val is not None else set()
                # Prevent empty string black holes
                vals = {v for v in vals if v and str(v).strip()}
                
                if not vals or not expected_values.intersection(vals):
                    return False
                    
            progression_keys = self.rule.get('track_progression', [])
            if progression_keys:
                has_progression_data = False
                for key in progression_keys:
                    if self._get_field(alert_data, key) or self._get_field(alert, key):
                        has_progression_data = True
                        break
                if not has_progression_data:
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
        
        # Density config
        self.density_window_seconds: int = 60
        self.density_threshold: int = 15
        self.velocity_tracker: Dict[str, List[datetime]] = {}
        
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
        
        if matched_active:
            self._tick()
            return
            
        density_matched = self._evaluate_temporal_density(alert)
        if density_matched:
            # Spawn a synthetic investigation
            alert_data = self._get_field(alert, "alert", alert)
            hostname = self._get_field(alert_data, "hostname") or self._get_field(alert, "hostname")
            
            synthetic_rule = {
                "rule_name": "High-Density Anomalous Activity",
                "match_criteria": ["hostname"] if hostname else ["src_ip"],
                "rolling_timeout_minutes": 60,
                "historical_window_minutes": 60
            }
            # force spawn with this rule
            self._spawn_investigation(alert, synthetic_rule, forced_priority=85.0)
        else:
            self._evaluate_new_triggers(alert)
            
        self._tick()

    def _evaluate_temporal_density(self, alert: Dict[str, Any]) -> bool:
        classification = alert.get("classification", "")
        if classification in ["Likely Benign", "Likely False Positive"]:
            return False

        alert_data = self._get_field(alert, "alert", alert)
        entity_key = self._get_field(alert_data, "hostname") or self._get_field(alert, "hostname")
        if not entity_key:
            entity_key = self._get_field(alert_data, "src_ip") or self._get_field(alert, "src_ip")
            
        if not entity_key:
            return False
            
        ts_val = self._get_field(alert, "timestamp") or self._get_field(alert_data, "timestamp") or self._get_field(alert_data, "event_time") or self._get_field(alert_data, "normalized_timestamp")
        
        alert_time = None
        if ts_val:
            if isinstance(ts_val, datetime):
                alert_time = ts_val.replace(tzinfo=None)
            elif isinstance(ts_val, str):
                try:
                    alert_time = datetime.fromisoformat(ts_val.replace("Z", "+00:00")).replace(tzinfo=None)
                except ValueError:
                    try:
                        alert_time = datetime.strptime(ts_val, "%b %d, %Y @ %H:%M:%S.%f").replace(tzinfo=None)
                    except ValueError:
                        try:
                            alert_time = datetime.strptime(ts_val, "%b %d, %Y @ %H:%M:%S").replace(tzinfo=None)
                        except ValueError:
                            pass
        if alert_time is None:
            alert_time = self.engine_clock
            
        if entity_key not in self.velocity_tracker:
            self.velocity_tracker[entity_key] = []
            
        self.velocity_tracker[entity_key].append(alert_time)
        
        if self.engine_clock == datetime.min:
            cutoff_time = datetime.min
        else:
            cutoff_time = self.engine_clock - timedelta(seconds=self.density_window_seconds)
            
        self.velocity_tracker[entity_key] = [t for t in self.velocity_tracker[entity_key] if t >= cutoff_time]
        
        if len(self.velocity_tracker[entity_key]) >= self.density_threshold:
            return True
            
        return False

    def _get_field(self, obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    def _update_clock(self, alert: Dict[str, Any]):
        alert_inner = self._get_field(alert, "alert", {})
        ts_val = self._get_field(alert, "timestamp") or self._get_field(alert_inner, "timestamp") or self._get_field(alert_inner, "event_time") or self._get_field(alert_inner, "normalized_timestamp")
        if ts_val:
            alert_time = None
            if isinstance(ts_val, datetime):
                alert_time = ts_val.replace(tzinfo=None)
            elif isinstance(ts_val, str):
                try:
                    alert_time = datetime.fromisoformat(ts_val.replace("Z", "+00:00")).replace(tzinfo=None)
                except ValueError:
                    try:
                        alert_time = datetime.strptime(ts_val, "%b %d, %Y @ %H:%M:%S.%f").replace(tzinfo=None)
                    except ValueError:
                        try:
                            alert_time = datetime.strptime(ts_val, "%b %d, %Y @ %H:%M:%S").replace(tzinfo=None)
                        except ValueError:
                            pass
            
            if alert_time and alert_time > self.engine_clock:
                self.engine_clock = alert_time

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
                    
                    # NEW: Update the progression state (add new MITRE tactics)
                    inv.update_progression(alert)
                    
                    # NEW: Update pivot entities
                    inv.update_pivot_entities(alert)
                    
                    self.db_repository.add_alert_to_investigation(inv_id, alert_id)
                    
                    self._recalculate_priority(inv_id)
                    self.db_repository.update_investigation_priority(inv_id, inv.current_priority)
                    
                    matched = True
                    
                    if self.on_investigation_event:
                        # Convert sets to lists for JSON serialization in the event
                        serializable_progression = {k: list(v) for k, v in inv.observed_progression.items()}
                        serializable_match_values = {k: list(v) if isinstance(v, set) else v for k, v in inv.match_values.items()}
                        self.on_investigation_event({
                            "event": "INVESTIGATION_UPDATED",
                            "investigation_id": inv_id,
                            "alert_id": alert_id,
                            "current_priority": inv.current_priority,
                            "match_criteria": serializable_match_values,
                            "observed_progression": serializable_progression
                        })
        return matched

    def _recalculate_priority(self, investigation_id: str):
        import math
        inv = self.active_investigations.get(investigation_id)
        if not inv:
            return
            
        p_max = inv.max_risk_score
        n = inv.total_alerts_count
        
        # Calculate unique phases hit if tracking MITRE tactics
        unique_phases = len(inv.observed_progression.get('mitre_tactic', set()))
        
        # Base calculation: Use logarithmic scaling to prevent instant maxing out
        # E.g., log2(32 alerts) = 5. 5 * 3.0 = 15 points added to max risk score
        alert_volume_boost = (math.log2(n) * 3.0) if n > 0 else 0
        p_total = p_max + alert_volume_boost
        
        # Cap the score at 90 unless there's an active attack pattern
        max_base_score = 90.0
        
        if unique_phases <= 1:
            inv.current_priority = min(max_base_score, p_total)
            return
            
        # Progression Multiplier: Active attack pattern detected!
        # This is where we allow it to reach 100.
        progression_boost = math.log2(unique_phases) * 15.0
        p_total += progression_boost
        
        inv.current_priority = min(100.0, p_total)

    def _evaluate_new_triggers(self, alert: Dict[str, Any]):
        classification = alert.get("classification", "")

        alert_data = self._get_field(alert, "alert", alert)
        for rule in self.rules:
            anchor = rule.get("anchor", {})
            
            # If the alert is benign/FP, ONLY evaluate rules that explicitly look for it
            if classification in ["Likely Benign", "Likely False Positive"]:
                if anchor.get("classification") not in ["Likely Benign", "Likely False Positive"]:
                    continue
            
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

    def _spawn_investigation(self, alert: Dict[str, Any], rule: Dict[str, Any], forced_priority: float = None):
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
        if forced_priority is not None:
            inv.current_priority = forced_priority
            
        self.db_repository.update_investigation_priority(inv_id, inv.current_priority)
        
        if self.on_investigation_event:
            serializable_progression = {k: list(v) for k, v in inv.observed_progression.items()}
            serializable_match_values = {k: list(v) if isinstance(v, set) else v for k, v in inv.match_values.items()}
            self.on_investigation_event({
                "event": "INVESTIGATION_OPENED",
                "investigation_id": inv_id,
                "rule_name": rule.get("rule_name"),
                "anchor_alert_id": alert_id,
                "historical_alerts_count": len(historical_alerts),
                "current_priority": inv.current_priority,
                "match_criteria": serializable_match_values,
                "observed_progression": serializable_progression
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
                serializable_match_values = {k: list(v) if isinstance(v, set) else v for k, v in inv.match_values.items()}
                self.on_investigation_event({
                    "event": "INVESTIGATION_CLOSED",
                    "investigation_id": inv_id,
                    "closed_at": self.engine_clock.isoformat(),
                    "match_criteria": serializable_match_values
                })
