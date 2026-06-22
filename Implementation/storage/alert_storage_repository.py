from abc import ABC, abstractmethod
from typing import Dict, Any, List
from datetime import datetime

class AlertStorageRepository(ABC):
    """
    Abstract Base Class defining the contract for Alert Storage Layer.
    """
    
    @abstractmethod
    def save_alert(self, alert_payload: Dict[str, Any]) -> int:
        """
        Takes the fully processed alert from Phase 9, extracts the indexed fields,
        serializes the full object to JSON, and commits it to the database.
        
        Args:
            alert_payload: The final dictionary payload output by the classification stage.
            
        Returns:
            The generated unique ID of the saved alert.
        """
        pass

    @abstractmethod
    def create_investigation(self, investigation_id: str, status: str, created_at: datetime, rule_name: str) -> None:
        """
        Creates a new investigation record.
        """
        pass

    @abstractmethod
    def update_investigation_status(self, investigation_id: str, status: str, closed_at: datetime) -> None:
        """
        Updates the status and closure time of an existing investigation.
        """
        pass

    @abstractmethod
    def add_alert_to_investigation(self, investigation_id: str, alert_id: int) -> None:
        """
        Links a processed alert to an active investigation.
        """
        pass

    @abstractmethod
    def get_alerts_for_grouping(self, hostname: str, rule_id: str, start_time: datetime, window_minutes: int) -> List[Dict[str, Any]]:
        """
        Retrieves all alerts matching the specified host and rule that occurred 
        within `window_minutes` of the `start_time`.
        
        Args:
            hostname: The target host.
            rule_id: The specific rule ID.
            start_time: The start of the time window.
            window_minutes: The duration of the time window in minutes.
            
        Returns:
            A list of alert payloads (dictionaries).
        """
        pass

    @abstractmethod
    def get_unprocessed_critical_alerts(self) -> List[Dict[str, Any]]:
        """
        A utility query used by the Grouping Engine to find starting points.
        Returns the highest-risk alerts (e.g., Critical Incidents).
        
        Returns:
            A list of alert payloads (dictionaries).
        """
        pass

    @abstractmethod
    def search_alerts(self, filters: Dict[str, Any], start_time: datetime = None, end_time: datetime = None) -> List[Dict[str, Any]]:
        """
        Dynamically searches for alerts matching any combination of the provided filters.
        
        Args:
            filters: A dictionary of column names and exact values to match 
                     (e.g., {'rule_id': '1002', 'src_ip': '192.168.1.10'}).
            start_time: Optional start time to restrict the query.
            end_time: Optional end time to restrict the query.
            
        Returns:
            A list of alert payloads (dictionaries).
        """
        pass
