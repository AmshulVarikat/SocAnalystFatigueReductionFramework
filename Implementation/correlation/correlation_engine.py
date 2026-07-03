import json
import uuid
from typing import Dict, Any, Callable, Optional, List
from datetime import datetime, timedelta
import networkx as nx

class Investigation:
    def __init__(self, investigation_id: str, rules: List[Dict[str, Any]], anchor_alert: Dict[str, Any]):
        self.investigation_id = investigation_id
        self.rules = rules
        self.alerts: List[int] = []
        
        storage_id = anchor_alert.get('_storage_id')
        if storage_id is not None:
            self.alerts.append(storage_id)
            
        self.last_alert_time: datetime = self._parse_time(anchor_alert)
        self.match_values: Dict[str, set] = {}
        
        self.observed_progression: Dict[str, set] = {}
        self.status = "OPEN"
        self.current_priority: float = 0.0
        self.max_risk_score: float = anchor_alert.get("risk_score", 0.0)
        self.total_alerts_count: int = 1

        self.graph = nx.Graph()
        anchor_nodes = self._extract_graph_nodes(anchor_alert)
        self.anchor_nodes = set(anchor_nodes)
        
        self.edge_weights = {
            ('hash', 'session'): 1.0,
            ('session', 'hash'): 1.0,
            ('session', 'ip'): 0.8,
            ('ip', 'session'): 0.8,
            ('host', 'ip'): 0.4,
            ('ip', 'host'): 0.4,
            ('user', 'ip'): 0.5,
            ('ip', 'user'): 0.5,
        }
        
        self.technique_history: List[tuple] = []
        self.fired_rules = set()
        self.next_expected = set()
        self.rule_fire_times = {} 
        
        self.update_graph(anchor_nodes)
        self._add_technique(anchor_alert, self.last_alert_time)
        self.evaluate_behavioral_rules(self.last_alert_time)

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

    def _extract_graph_nodes(self, alert: Dict[str, Any]) -> List[tuple]:
        alert_data = self._get_field(alert, "alert", alert)
        nodes = []
        
        ip = self._get_field(alert_data, "src_ip") or self._get_field(alert, "src_ip")
        if ip:
            nodes.append(('ip', ip))
            
        hash_val = self._get_field(alert_data, "file_hash") or self._get_field(alert, "file_hash")
        if hash_val:
            nodes.append(('hash', hash_val))
            
        user = self._get_field(alert_data, "user_name") or self._get_field(alert, "user_name")
        host = self._get_field(alert_data, "hostname") or self._get_field(alert, "hostname")
        
        if user and host:
            nodes.append(('session', f"{user}@{host}"))
        else:
            if user:
                nodes.append(('user', user))
            if host:
                nodes.append(('host', host))
                
        return nodes

    def update_graph(self, nodes: List[tuple]):
        self.graph.add_nodes_from(nodes)
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                n1 = nodes[i]
                n2 = nodes[j]
                weight = self.edge_weights.get((n1[0], n2[0]), 0.5)
                self.graph.add_edge(n1, n2, weight=weight)

    def _add_technique(self, alert: Dict[str, Any], alert_time: datetime):
        alert_data = self._get_field(alert, "alert", alert)
        techs = self._get_field(alert_data, "mitre_technique_id") or self._get_field(alert_data, "mitre_technique")
        if techs:
            if not isinstance(techs, list):
                techs = [techs]
            for t in techs:
                self.technique_history.append((alert_time, t))
                if 'mitre_technique' not in self.observed_progression:
                    self.observed_progression['mitre_technique'] = set()
                self.observed_progression['mitre_technique'].add(t)

    def evaluate_behavioral_rules(self, current_time: datetime):
        new_fires = True
        while new_fires:
            new_fires = False
            for rule in self.rules:
                rname = rule.get("rule_name")
                if not rname or rname in self.fired_rules:
                    continue
                
                window = rule.get("window_seconds", 3600)
                cutoff = current_time - timedelta(seconds=window)
                
                conditions = rule.get("conditions", [])
                if conditions:
                    seen_techs = set()
                    for t_time, tech in self.technique_history:
                        if t_time >= cutoff and tech in conditions:
                            seen_techs.add(tech)
                    
                    min_matches = rule.get("minimum_matches", 1)
                    if len(seen_techs) >= min_matches:
                        self.fired_rules.add(rname)
                        self.rule_fire_times[rname] = current_time
                        self.current_priority += rule.get("investigation_score", 10)
                        self.current_priority = min(100.0, self.current_priority)
                        if "next_expected" in rule:
                            self.next_expected.update(rule["next_expected"])
                        new_fires = True
                
                depends_on = rule.get("depends_on", [])
                if depends_on:
                    all_met = True
                    for dep in depends_on:
                        if dep not in self.fired_rules:
                            all_met = False
                            break
                        if self.rule_fire_times[dep] < cutoff:
                            all_met = False
                            break
                            
                    if all_met:
                        self.fired_rules.add(rname)
                        self.rule_fire_times[rname] = current_time
                        if rule.get("priority") == "Critical":
                            self.current_priority = max(self.current_priority, 90.0)
                        elif rule.get("priority") == "High":
                            self.current_priority = max(self.current_priority, 70.0)
                        
                        self.current_priority += rule.get("investigation_score", 20)
                        self.current_priority = min(100.0, self.current_priority)
                        if "next_expected" in rule:
                            self.next_expected.update(rule["next_expected"])
                        new_fires = True

    def update_pivot_entities(self, alert: Dict[str, Any]):
        self.update_graph(self._extract_graph_nodes(alert))

    def matches(self, alert: Dict[str, Any]) -> bool:
        alert_nodes = self._extract_graph_nodes(alert)
        if not alert_nodes:
            return False
            
        existing_nodes = [n for n in alert_nodes if n in self.graph]
        if not existing_nodes:
            return False
            
        max_hops = 3
        min_confidence = 0.2
        
        for inc_node in existing_nodes:
            for anchor in self.anchor_nodes:
                if nx.has_path(self.graph, inc_node, anchor):
                    path = nx.shortest_path(self.graph, inc_node, anchor)
                    path_len = len(path) - 1
                    if path_len <= max_hops:
                        conf = 1.0
                        for i in range(len(path) - 1):
                            edge_data = self.graph.get_edge_data(path[i], path[i+1])
                            conf *= edge_data.get('weight', 0.5)
                        if conf >= min_confidence:
                            return True
        return False

class CorrelationEngine:
    def __init__(self, tick_interval: int = 10, rules_path: str = None, on_investigation_event: Optional[Callable] = None):
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
            # Spawn a synthetic investigation (using rules=[] for it)
            self._spawn_investigation(alert, rules=[], forced_priority=85.0)
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
                timeout_mins = 120
                if alert_time <= inv.last_alert_time + timedelta(minutes=timeout_mins):
                    # Match
                    inv.alerts.append(alert_id)
                    inv.total_alerts_count += 1
                    alert_risk_score = alert.get("risk_score", 0.0)
                    inv.max_risk_score = max(inv.max_risk_score, alert_risk_score)
                    
                    inv.last_alert_time = max(inv.last_alert_time, alert_time)
                    
                    inv.update_pivot_entities(alert)
                    inv._add_technique(alert, alert_time)
                    inv.evaluate_behavioral_rules(alert_time)
                    
                    matched = True
                    
                    if self.on_investigation_event:
                        serializable_progression = {k: list(v) for k, v in inv.observed_progression.items()}
                        serializable_match_values = {k: list(v) if isinstance(v, set) else v for k, v in inv.match_values.items()}
                        event_payload = {
                            "event": "INVESTIGATION_UPDATED",
                            "investigation_id": inv_id,
                            "alert_id": alert_id,
                            "current_priority": inv.current_priority,
                            "match_criteria": serializable_match_values,
                            "observed_progression": serializable_progression,
                            "graph": nx.node_link_data(inv.graph),
                            "fired_rules": list(inv.fired_rules),
                            "next_expected": list(inv.next_expected)
                        }
                        self.on_investigation_event(event_payload)
        return matched

    def _evaluate_new_triggers(self, alert: Dict[str, Any]):
        classification = alert.get("classification", "")
        if classification in ["Likely Benign", "Likely False Positive"]:
            return

        alert_data = self._get_field(alert, "alert", alert)
        
        techs = self._get_field(alert_data, "mitre_technique_id") or self._get_field(alert_data, "mitre_technique")
        if not techs:
            return
        if not isinstance(techs, list):
            techs = [techs]
        
        trigger_techs = set()
        for r in self.rules:
            trigger_techs.update(r.get("conditions", []))
            
        for t in techs:
            if t in trigger_techs:
                self._spawn_investigation(alert, self.rules)
                break

    def _spawn_investigation(self, alert: Dict[str, Any], rules: List[Dict[str, Any]], forced_priority: float = None):
        alert_id = self._get_field(alert, "_storage_id")
        if alert_id is None:
            return
            
        inv_id = str(uuid.uuid4())
        
        inv = Investigation(inv_id, rules, alert)
        
        created_at = inv.last_alert_time
        rule_name = "Behavioral Graph"
        
        # Simulating historical alert lookup with an empty list for in-memory only mode
        historical_alerts = []
        
        inv.total_alerts_count = 1 + len(historical_alerts)
        if historical_alerts:
            hist_max_risk = max([a.get("risk_score", 0.0) for a in historical_alerts])
            inv.max_risk_score = max(inv.max_risk_score, hist_max_risk)
        
        self.active_investigations[inv_id] = inv
            
        if forced_priority is not None:
            inv.current_priority = forced_priority
            
        if self.on_investigation_event:
            serializable_progression = {k: list(v) for k, v in inv.observed_progression.items()}
            serializable_match_values = {k: list(v) if isinstance(v, set) else v for k, v in inv.match_values.items()}
            event_payload = {
                "event": "INVESTIGATION_OPENED",
                "investigation_id": inv_id,
                "rule_name": rule_name,
                "anchor_alert_id": alert_id,
                "historical_alerts_count": len(historical_alerts),
                "current_priority": inv.current_priority,
                "match_criteria": serializable_match_values,
                "observed_progression": serializable_progression,
                "graph": nx.node_link_data(inv.graph),
                "fired_rules": list(inv.fired_rules),
                "next_expected": list(inv.next_expected)
            }
            self.on_investigation_event(event_payload)

    def _tick(self):
        self.alert_counter += 1
        if self.alert_counter >= self.tick_interval:
            self._evaluate_timeouts()
            self.alert_counter = 0

    def _evaluate_timeouts(self):
        to_close = []
        for inv_id, inv in self.active_investigations.items():
            timeout_mins = 120
                
            if self.engine_clock > inv.last_alert_time + timedelta(minutes=timeout_mins):
                to_close.append(inv_id)
                
        for inv_id in to_close:
            inv = self.active_investigations.pop(inv_id)
            
            # Determine new status based on priority
            new_status = "AWAITING_REVIEW" if inv.current_priority > 50.0 else "CLOSED"
            inv.status = new_status
            
            if self.on_investigation_event:
                serializable_match_values = {k: list(v) if isinstance(v, set) else v for k, v in inv.match_values.items()}
                event_payload = {
                    "event": "INVESTIGATION_CLOSED",
                    "investigation_id": inv_id,
                    "new_status": new_status,
                    "closed_at": self.engine_clock.isoformat(),
                    "match_criteria": serializable_match_values,
                    "graph": nx.node_link_data(inv.graph),
                    "fired_rules": list(inv.fired_rules),
                    "next_expected": list(inv.next_expected)
                }
                self.on_investigation_event(event_payload)
