# # import pytest
# from datetime import datetime, timedelta
# import json
# import os
# import uuid
# from typing import Dict, Any, List

# from Implementation.correlation.correlation_engine import CorrelationEngine, Investigation

# # Mock Database Repository
# class MockAlertStorageRepository:
#     def __init__(self):
#         self.investigations = {}
#         self.investigation_mappings = []
#         self.historical_alerts = []

#     def create_investigation(self, investigation_id: str, status: str, created_at: datetime, rule_name: str) -> None:
#         self.investigations[investigation_id] = {
#             "status": status,
#             "created_at": created_at,
#             "rule_name": rule_name
#         }

#     def update_investigation_status(self, investigation_id: str, status: str, closed_at: datetime) -> None:
#         if investigation_id in self.investigations:
#             self.investigations[investigation_id]["status"] = status
#             self.investigations[investigation_id]["closed_at"] = closed_at

#     def add_alert_to_investigation(self, investigation_id: str, alert_id: int) -> None:
#         self.investigation_mappings.append((investigation_id, alert_id))

#     def search_alerts(self, filters: Dict[str, Any], start_time: datetime = None, end_time: datetime = None) -> List[Dict[str, Any]]:
#         return self.historical_alerts

# @pytest.fixture
# def mock_db():
#     return MockAlertStorageRepository()

# @pytest.fixture
# def temp_rules_file(tmp_path):
#     rules = {
#         "rules": [
#             {
#                 "rule_name": "Test Rule",
#                 "anchor": {
#                     "rule_id": "100"
#                 },
#                 "match_criteria": ["hostname"],
#                 "rolling_timeout_minutes": 5,
#                 "historical_window_minutes": 60
#             }
#         ]
#     }
#     rules_file = tmp_path / "rules.json"
#     rules_file.write_text(json.dumps(rules))
#     return str(rules_file)

# def test_engine_initialization(mock_db, temp_rules_file):
#     engine = CorrelationEngine(db_repository=mock_db, tick_interval=2, rules_path=temp_rules_file)
#     assert len(engine.rules) == 1
#     assert engine.rules[0]["rule_name"] == "Test Rule"

# def test_investigation_spawning(mock_db, temp_rules_file):
#     events = []
#     def callback(event):
#         events.append(event)
        
#     engine = CorrelationEngine(db_repository=mock_db, tick_interval=5, rules_path=temp_rules_file, on_investigation_event=callback)
    
#     alert = {
#         "_storage_id": 1,
#         "timestamp": datetime.utcnow().isoformat() + "Z",
#         "alert": {
#             "rule_id": "100",
#             "hostname": "server-1"
#         }
#     }
    
#     engine.process_alert(alert)
    
#     assert len(engine.active_investigations) == 1
#     assert len(mock_db.investigations) == 1
#     assert len(mock_db.investigation_mappings) == 1
    
#     assert len(events) == 1
#     assert events[0]["event"] == "INVESTIGATION_OPENED"

# def test_investigation_matching_and_timeout(mock_db, temp_rules_file):
#     events = []
#     def callback(event):
#         events.append(event)
        
#     # tick_interval = 2 means it will check timeouts every 2 alerts
#     engine = CorrelationEngine(db_repository=mock_db, tick_interval=2, rules_path=temp_rules_file, on_investigation_event=callback)
    
#     now = datetime.utcnow()
    
#     # 1. Spawn investigation
#     alert1 = {
#         "_storage_id": 1,
#         "timestamp": now.isoformat() + "Z",
#         "alert": {"rule_id": "100", "hostname": "server-1"}
#     }
#     engine.process_alert(alert1)
#     assert len(engine.active_investigations) == 1
    
#     # 2. Match investigation (within timeout)
#     alert2 = {
#         "_storage_id": 2,
#         "timestamp": (now + timedelta(minutes=2)).isoformat() + "Z",
#         "alert": {"rule_id": "999", "hostname": "server-1"}
#     }
#     engine.process_alert(alert2)
    
#     # Two alerts processed, tick interval reached -> evaluates timeout
#     # But last alert is within 5 minutes, so it stays open
#     assert len(engine.active_investigations) == 1
    
#     # Check events: [OPENED, UPDATED]
#     assert len(events) == 2
#     assert events[1]["event"] == "INVESTIGATION_UPDATED"
    
#     # 3. Timeout investigation (after 6 minutes)
#     alert3 = {
#         "_storage_id": 3,
#         "timestamp": (now + timedelta(minutes=9)).isoformat() + "Z",
#         "alert": {"rule_id": "888", "hostname": "server-2"} # Different host, shouldn't match
#     }
#     # Doesn't match, doesn't spawn (rule_id != 100)
#     # Clock moves forward, but we need another alert to trigger tick
#     engine.process_alert(alert3)
    
#     alert4 = {
#         "_storage_id": 4,
#         "timestamp": (now + timedelta(minutes=10)).isoformat() + "Z",
#         "alert": {"rule_id": "888", "hostname": "server-3"}
#     }
#     engine.process_alert(alert4) # Triggers tick (counter = 2)
    
#     # Investigation for server-1 should now be closed
#     assert len(engine.active_investigations) == 0
#     assert len(events) == 3
#     assert events[2]["event"] == "INVESTIGATION_CLOSED"
