import sqlite3
import json
import os
from typing import Dict, Any, List
from datetime import datetime, timedelta

from .alert_storage_repository import AlertStorageRepository

class SqliteAlertStorage(AlertStorageRepository):
    """
    SQLite implementation of the Alert Storage layer.
    Uses a hybrid relational-document schema.
    """
    def __init__(self, db_path: str):
        self.db_path = db_path
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        
        self._initialize_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a new SQLite connection with WAL enabled."""
        conn = sqlite3.connect(self.db_path)
        # Enable Write-Ahead Logging for concurrent reads/writes
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _initialize_db(self):
        """Creates the schema and necessary indexes if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Create Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS processed_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    rule_id TEXT,
                    hostname TEXT,
                    username TEXT,
                    src_ip TEXT,
                    dest_ip TEXT,
                    process_name TEXT,
                    file_hash TEXT,
                    wazuh_level INTEGER,
                    mitre_tactic TEXT,
                    risk_score REAL,
                    classification TEXT,
                    full_alert_payload TEXT,
                    enrichment_data TEXT
                )
            ''')
            
            # Create Indexes
            indexes = [
                "timestamp",
                "rule_id",
                "hostname",
                "username",
                "src_ip",
                "dest_ip",
                "process_name",
                "file_hash",
                "wazuh_level",
                "mitre_tactic"
            ]
            
            for field in indexes:
                index_name = f"idx_alerts_{field}"
                cursor.execute(f"CREATE INDEX IF NOT EXISTS {index_name} ON processed_alerts({field})")
                
            # Update schema for existing databases (processed_alerts)
            cursor.execute("PRAGMA table_info(processed_alerts)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'enrichment_data' not in columns:
                cursor.execute("ALTER TABLE processed_alerts ADD COLUMN enrichment_data TEXT DEFAULT '{}'")
                
            # Create Investigations Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS investigations (
                    investigation_id TEXT PRIMARY KEY,
                    status TEXT,
                    created_at TEXT,
                    closed_at TEXT,
                    rule_name TEXT,
                    current_priority REAL,
                    alerts_count INTEGER DEFAULT 1,
                    match_values TEXT DEFAULT '{}',
                    observed_progression TEXT DEFAULT '{}'
                )
            ''')
            
            # Update schema for existing databases
            cursor.execute("PRAGMA table_info(investigations)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'current_priority' not in columns:
                cursor.execute("ALTER TABLE investigations ADD COLUMN current_priority REAL DEFAULT 0.0")
            if 'alerts_count' not in columns:
                cursor.execute("ALTER TABLE investigations ADD COLUMN alerts_count INTEGER DEFAULT 1")
            if 'match_values' not in columns:
                cursor.execute("ALTER TABLE investigations ADD COLUMN match_values TEXT DEFAULT '{}'")
            if 'observed_progression' not in columns:
                cursor.execute("ALTER TABLE investigations ADD COLUMN observed_progression TEXT DEFAULT '{}'")
            
            # Create Investigation Mapping Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS investigation_mapping (
                    mapping_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT,
                    alert_id INTEGER,
                    FOREIGN KEY(investigation_id) REFERENCES investigations(investigation_id),
                    FOREIGN KEY(alert_id) REFERENCES processed_alerts(id)
                )
            ''')
            
            # Index for mappings
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_mapping_inv_id ON investigation_mapping(investigation_id)")
                
            conn.commit()

    def _extract_fields(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts the indexed fields from the raw payload structure."""
        alert = alert_payload.get("alert")
        
        # Determine how to extract from the alert (dict vs object)
        is_dict = isinstance(alert, dict)
        
        def get_val(key, default=''):
            if is_dict:
                return alert.get(key, default)
            return getattr(alert, key, default)

        # Handle potential lists for hashes and tactics
        file_hashes = get_val('file_hashes', [])
        file_hash = file_hashes[0] if isinstance(file_hashes, list) and file_hashes else get_val('file_hash', '')
        
        # Timestamp: prefer event_time, fallback to normalized_timestamp or current time
        timestamp_str = get_val('event_time') or get_val('normalized_timestamp') or datetime.utcnow().isoformat()
        
        # Make sure wazuh level handles missing or non-integer nicely
        wazuh_level = get_val('rule_level', 0)
        try:
            wazuh_level = int(wazuh_level)
        except (ValueError, TypeError):
            wazuh_level = 0
            
        return {
            "timestamp": timestamp_str,
            "rule_id": str(get_val('rule_id', '')),
            "hostname": get_val('hostname', ''),
            "username": get_val('user_name', ''), # Notice 'user_name' in NormalizedAlert
            "src_ip": get_val('src_ip', ''),
            "dest_ip": get_val('dst_ip', ''),
            "process_name": get_val('process_name', ''),
            "file_hash": file_hash,
            "wazuh_level": wazuh_level,
            "mitre_tactic": get_val('mitre_tactic', ''),
            "risk_score": float(alert_payload.get("risk_score", 0.0)),
            "classification": alert_payload.get("classification", "")
        }

    def save_alert(self, alert_payload: Dict[str, Any]) -> int:
        """Saves a fully processed alert to the SQLite database and returns the generated ID."""
        fields = self._extract_fields(alert_payload)
        
        # Serialize the alert payload
        # Some components might not be natively serializable, so we use default=str
        payload_json = json.dumps(alert_payload, default=str)
        
        # Extract enrichment
        alert_obj = alert_payload.get("alert", alert_payload)
        enrichment_dict = {}
        if isinstance(alert_obj, dict):
            enrichment_dict = alert_obj.get("enrichment", {})
        elif hasattr(alert_obj, "enrichment"):
            enrichment_dict = getattr(alert_obj, "enrichment")
        
        enrichment_json = json.dumps(enrichment_dict, default=str)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO processed_alerts (
                    timestamp, rule_id, hostname, username, src_ip, dest_ip, 
                    process_name, file_hash, wazuh_level, mitre_tactic, 
                    risk_score, classification, full_alert_payload, enrichment_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                fields["timestamp"], fields["rule_id"], fields["hostname"], fields["username"],
                fields["src_ip"], fields["dest_ip"], fields["process_name"], fields["file_hash"],
                fields["wazuh_level"], fields["mitre_tactic"], fields["risk_score"], 
                fields["classification"], payload_json, enrichment_json
            ))
            inserted_id = cursor.lastrowid
            conn.commit()
            return inserted_id

    def get_alerts_for_grouping(self, hostname: str, rule_id: str, start_time: datetime, window_minutes: int) -> List[Dict[str, Any]]:
        """Queries for alerts matching criteria within a time window."""
        end_time = start_time + timedelta(minutes=window_minutes)
        
        start_iso = start_time.isoformat()
        end_iso = end_time.isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT full_alert_payload FROM processed_alerts 
                WHERE hostname = ? AND rule_id = ? 
                AND timestamp >= ? AND timestamp <= ?
            ''', (hostname, rule_id, start_iso, end_iso))
            
            rows = cursor.fetchall()
            return [json.loads(row[0]) for row in rows]

    def get_unprocessed_critical_alerts(self) -> List[Dict[str, Any]]:
        """Retrieves alerts with classification 'Critical Incident'."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT full_alert_payload FROM processed_alerts 
                WHERE classification = 'Critical Incident'
                ORDER BY timestamp ASC
            ''')
            
            rows = cursor.fetchall()
            return [json.loads(row[0]) for row in rows]

    def search_alerts(self, filters: Dict[str, Any], start_time: datetime = None, end_time: datetime = None) -> List[Dict[str, Any]]:
        """Dynamically queries the database based on arbitrary filter criteria."""
        query_parts = []
        params = []
        
        for key, value in filters.items():
            # Basic validation to ensure key is a valid column name to prevent SQL injection
            # Though in this internal context it's less critical, it's good practice.
            valid_columns = {
                "timestamp", "rule_id", "hostname", "username", "src_ip", "dest_ip",
                "process_name", "file_hash", "wazuh_level", "mitre_tactic", 
                "risk_score", "classification"
            }
            if key in valid_columns:
                if isinstance(value, (list, set, tuple)):
                    if not value:
                        continue
                    placeholders = ','.join(['?'] * len(value))
                    query_parts.append(f"{key} IN ({placeholders})")
                    params.extend(value)
                else:
                    query_parts.append(f"{key} = ?")
                    params.append(value)
            
        if start_time:
            query_parts.append("timestamp >= ?")
            params.append(start_time.isoformat())
            
        if end_time:
            query_parts.append("timestamp <= ?")
            params.append(end_time.isoformat())
            
        where_clause = " AND ".join(query_parts)
        if where_clause:
            query = f"SELECT full_alert_payload FROM processed_alerts WHERE {where_clause}"
        else:
            query = "SELECT full_alert_payload FROM processed_alerts"
            
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [json.loads(row[0]) for row in rows]

    def create_investigation(self, investigation_id: str, status: str, created_at: datetime, rule_name: str, current_priority: float = 0.0) -> None:
        """Creates a new investigation record."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO investigations (investigation_id, status, created_at, rule_name, current_priority)
                VALUES (?, ?, ?, ?, ?)
            ''', (investigation_id, status, created_at.isoformat(), rule_name, current_priority))
            conn.commit()

    def update_investigation_priority(self, investigation_id: str, current_priority: float) -> None:
        """Updates the priority of an existing investigation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE investigations 
                SET current_priority = ?
                WHERE investigation_id = ?
            ''', (current_priority, investigation_id))
            conn.commit()

    def update_investigation_context(self, investigation_id: str, alerts_count: int, match_values: str, observed_progression: str) -> None:
        """Updates the grouping context of an investigation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE investigations 
                SET alerts_count = ?, match_values = ?, observed_progression = ?
                WHERE investigation_id = ?
            ''', (alerts_count, match_values, observed_progression, investigation_id))
            conn.commit()

    def update_investigation_status(self, investigation_id: str, status: str, closed_at: datetime) -> None:
        """Updates the status and closure time of an existing investigation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE investigations 
                SET status = ?, closed_at = ?
                WHERE investigation_id = ?
            ''', (status, closed_at.isoformat(), investigation_id))
            conn.commit()

    def add_alert_to_investigation(self, investigation_id: str, alert_id: int) -> None:
        """Links a processed alert to an active investigation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO investigation_mapping (investigation_id, alert_id)
                VALUES (?, ?)
            ''', (investigation_id, alert_id))
            conn.commit()
