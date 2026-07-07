import os
import sys
import json
import threading
import queue
import httpx
from datetime import datetime
from dataclasses import asdict

# ==========================================
# CONFIGURATION: Hardcoded Paths
# ==========================================
import os
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATASET_ALERTS_PATH = os.path.join(PROJECT_ROOT, "Implementation/inputs/Dataset3")
DATASET_GROUND_TRUTH_PATH = os.path.join(PROJECT_ROOT, "Implementation/inputs/Dataset1/GroundTruth/ground_truth.json")

# Enrichment Databases
ASSET_DB_PATH = os.path.join(PROJECT_ROOT, "Implementation/inputs/Dataset3/assets.json")
THREAT_INTEL_DB_PATH = os.path.join(PROJECT_ROOT, "Implementation/inputs/Validation-001/threat_intel_dataset2.json")

# Output configuration
MAX_TERMINAL_OUTPUTS = 3
CLASSIFICATION_RULES_PATH = os.path.join(PROJECT_ROOT, "Implementation/classification/rules.json")

# Phase 6: Replay
from ReplayEngine.loader import JsonLoader
from ReplayEngine.engine import ReplayEngine
from ReplayEngine.modes import ReplayMode

from Implementation.ingest import source_detector as default_detector
from Implementation.Normalisation.adapters.base_adapter import BaseAdapter

class Ingest:
    def process(self, envelope):
        raw_alert = envelope.get('alert')
        meta = {'replay_time': envelope.get('replay_time'), 'dataset': envelope.get('source_dataset')}
        source_info = default_detector.detect(raw_alert, meta)
        if not isinstance(source_info, dict):
            source_info = {'source': str(source_info), 'meta': meta}
        normalized = BaseAdapter.normalize(raw_alert, source_info)
        return normalized

# Phase 7: Enrichment
from Implementation.enrichment.asset_repository import JsonAssetRepository
from Implementation.enrichment.threat_intel_repository import JsonThreatIntelRepository, CompositeThreatIntelRepository
from Implementation.enrichment.alert_enricher import AlertEnricher

# Phase 8: Risk Scoring
from Implementation.risk_score.scorer import AlertRiskScorer

# Phase 9: Classification
from Implementation.classification.classifier import AlertClassifier

# Phase 10: Storage
from Implementation.storage.sqlite_alert_storage import SqliteAlertStorage

# Phase 11: Correlation
from Implementation.correlation.correlation_engine import CorrelationEngine


class DashboardPublisher:
    """Asynchronously sends HTTP payloads to the FastAPI dashboard endpoint."""
    def __init__(self, endpoint_url="http://localhost:8000/api/internal/event_ingest"):
        self.endpoint_url = endpoint_url
        self.queue = queue.Queue()
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()

    def _worker(self):
        with httpx.Client() as client:
            while True:
                event = self.queue.get()
                try:
                    # We can wrap the event in a standard WebSocket payload format
                    # e.g., if event is already an investigation dict, we format it.
                    # Based on correlation engine, it usually sends something with 'event' and 'data'.
                    payload = {
                        "type": event.get("event", "INVESTIGATION_UPDATED"),
                        "payload": event.get("data", event)
                    }
                    client.post(self.endpoint_url, json=payload)
                except Exception as e:
                    pass
                finally:
                    self.queue.task_done()

    def publish(self, event_data: dict):
        self.queue.put(event_data)


class Orchestrator:
    """
    Central Controller for the SOC Alert Prioritization Framework.
    Wires together Replay, Ingest, Normalization, and Enrichment streams.
    """
    def __init__(self, use_dashboard: bool = False):
        print(f"[*] Initializing Orchestrator Pipeline...")
        self.use_dashboard = use_dashboard
        if self.use_dashboard:
            print("[*] Dashboard Publisher Enabled")
            self.publisher = DashboardPublisher()
        else:
            self.publisher = None
        
        # 1. Initialize Enrichment Repositories
        self.asset_repo = JsonAssetRepository(ASSET_DB_PATH)
        json_threat_repo = JsonThreatIntelRepository(THREAT_INTEL_DB_PATH)
        
        self.threat_repo = CompositeThreatIntelRepository([json_threat_repo])
        
        # 2. Initialize Pipeline Modules
        self.enricher = AlertEnricher(
            asset_repo=self.asset_repo, 
            local_threat_repo=json_threat_repo
        )
        self.ingest_pipeline = Ingest() 
        self.risk_scorer = AlertRiskScorer()
        self.classifier = AlertClassifier(rules_path=CLASSIFICATION_RULES_PATH)
        self.storage = SqliteAlertStorage(os.path.join(PROJECT_ROOT, "Implementation/storage/alerts.db"))
        self.correlator = CorrelationEngine(
            db_repository=self.storage, 
            tick_interval=10, 
            rules_path=os.path.join(PROJECT_ROOT, "Implementation/correlation/rules.json"),
            on_investigation_event=self._handle_investigation_event
        )

        # Setup Logging
        self.output_file = None

    def _setup_stage_logging(self, stage_name: str):
        if self.output_file and not self.output_file.closed:
            self.output_file.close()
            
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        stage_dir = os.path.join(project_root, "outputs", stage_name)
        os.makedirs(stage_dir, exist_ok=True)
        
        log_filename = f"{stage_name}_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        log_path = os.path.join(stage_dir, log_filename)
        
        self.output_file = open(log_path, 'w', encoding='utf-8')
        print(f"[*] Output for {stage_name} will be logged to: {log_path}")

    def __del__(self):
        if hasattr(self, 'output_file') and self.output_file and not self.output_file.closed:
            self.output_file.close()

    def _log(self, message: str, print_to_terminal: bool = False):
        """Helper to write to file and optionally to terminal."""
        if self.output_file and not self.output_file.closed:
            self.output_file.write(message + "\n")
        if print_to_terminal:
            print(message)

    def _handle_investigation_event(self, event_data: dict):
        """Callback for the Correlation Engine."""
        self._log(f"\n[!] INVESTIGATION EVENT: {event_data.get('event')}", False)
        self._log(self._pretty_format(event_data), False)
        if self.use_dashboard and self.publisher:
            # We safely extract the relevant data and pass to publisher
            safe_data = json.loads(self._pretty_format(event_data))
            self.publisher.publish(safe_data)

    def _pretty_format(self, obj) -> str:
        """Safely format dataclasses or dicts for logging."""
        try:
            if hasattr(obj, '__dataclass_fields__'):
                return json.dumps(asdict(obj), indent=2, default=str)
            elif hasattr(obj, '__dict__'):
                return json.dumps(vars(obj), indent=2, default=str)
            else:
                return json.dumps(obj, indent=2, default=str)
        except Exception:
            return str(obj)

    def _get_replay_stream(self):
        """Helper to initialize and return the replay generator."""
        loader = JsonLoader(DATASET_ALERTS_PATH) # May require passing ground truth path depending on your loader spec
        dataset = loader.load()
        engine = ReplayEngine(dataset, mode=ReplayMode.SEQUENTIAL)
        # Yielding in standard sequential mode for stream processing
        return engine.replay()


    # ==========================================
    # STAGE TESTING METHODS
    # ==========================================

    def test_stage_1_replay(self):
        """Tests only the Replay Engine."""
        self._setup_stage_logging("stage_1_replay")
        self._log("=== RUNNING STAGE 1 TEST: REPLAY ===", True)
        stream = self._get_replay_stream()
        
        for idx, envelope in enumerate(stream):
            terminal = idx < MAX_TERMINAL_OUTPUTS
            self._log(f"\n--- Alert {idx + 1} ---", terminal)
            self._log(f"[+] Replay Envelope Generated", terminal)
            self._log(self._pretty_format(envelope), terminal)
            
        self._log(f"\n[*] Stage 1 Complete. Processed {idx + 1} alerts.", True)

    def test_stage_2_ingest(self):
        """Tests Replay -> Ingest -> Normalization."""
        self._setup_stage_logging("stage_2_ingest")
        self._log("=== RUNNING STAGE 2 TEST: INGEST & NORMALIZE ===", True)
        stream = self._get_replay_stream()
        
        for idx, envelope in enumerate(stream):
            terminal = idx < MAX_TERMINAL_OUTPUTS
            self._log(f"\n--- Alert {idx + 1} ---", terminal)
            
            # Execute Pipeline Stage
            normalized_alert = self.ingest_pipeline.process(envelope) 
            
            self._log(f"[+] Normalized Alert to Canonical Schema", terminal)
            self._log(self._pretty_format(normalized_alert), terminal)

        self._log(f"\n[*] Stage 2 Complete. Processed {idx + 1} alerts.", True)

    def test_stage_3_enrichment(self):
        """Tests Replay -> Ingest -> Normalization -> Enrichment."""
        self._setup_stage_logging("stage_3_enrichment")
        self._log("=== RUNNING STAGE 3 TEST: ENRICHMENT ===", True)
        stream = self._get_replay_stream()
        
        for idx, envelope in enumerate(stream):
            terminal = idx < MAX_TERMINAL_OUTPUTS
            self._log(f"\n--- Alert {idx + 1} ---", terminal)
            
            # Execute Pipeline Stages
            normalized_alert = self.ingest_pipeline.process(envelope)
            enriched_alert = self.enricher.enrich(normalized_alert)
            
            self._log(f"[+] Alert Fully Enriched", terminal)
            self._log(self._pretty_format(enriched_alert), terminal)
            
            # Example of extracting key data to prove it worked
            if terminal:
                asset_crit = getattr(enriched_alert, 'asset_context', {}).get('criticality', 'N/A')
                threat_rep = getattr(enriched_alert, 'threat_intel', {}).get('highest_reputation', 'N/A')
                self._log(f"    -> Extracted Criticality: {asset_crit}", True)
                self._log(f"    -> Extracted Threat Rep: {threat_rep}", True)

        self._log(f"\n[*] Stage 3 Complete. Processed {idx + 1} alerts.", True)

    def test_stage_4_risk_score(self):
        """Tests Replay -> Ingest -> Normalization -> Enrichment -> Risk Score."""
        self._setup_stage_logging("stage_4_risk_score")
        self._log("=== RUNNING STAGE 4 TEST: RISK SCORE ===", True)
        stream = self._get_replay_stream()
        
        for idx, envelope in enumerate(stream):
            terminal = idx < MAX_TERMINAL_OUTPUTS
            self._log(f"\n--- Alert {idx + 1} ---", terminal)
            
            # Execute Pipeline Stages
            normalized_alert = self.ingest_pipeline.process(envelope)
            enriched_alert = self.enricher.enrich(normalized_alert)
            scored_output = self.risk_scorer.score(enriched_alert)
            
            self._log(f"[+] Alert Risk Scored", terminal)
            self._log(self._pretty_format(scored_output), terminal)
            
            if terminal:
                score = scored_output.get("risk_score", 0)
                self._log(f"    -> Calculated Risk Score: {score}", True)

        self._log(f"\n[*] Stage 4 Complete. Processed {idx + 1} alerts.", True)

    def test_stage_5_classification(self):
        """Tests Replay -> Ingest -> Normalization -> Enrichment -> Risk Score -> Classification."""
        self._setup_stage_logging("stage_5_classification")
        self._log("=== RUNNING STAGE 5 TEST: CLASSIFICATION ===", True)
        stream = self._get_replay_stream()
        
        for idx, envelope in enumerate(stream):
            terminal = idx < MAX_TERMINAL_OUTPUTS
            self._log(f"\n--- Alert {idx + 1} ---", terminal)
            
            # Execute Pipeline Stages
            normalized_alert = self.ingest_pipeline.process(envelope)
            enriched_alert = self.enricher.enrich(normalized_alert)
            scored_output = self.risk_scorer.score(enriched_alert)
            final_output = self.classifier.process(scored_output)
            
            # Phase 10: Storage
            self.storage.save_alert(final_output)
            
            self._log(f"[+] Alert Classified and Stored", terminal)
            self._log(self._pretty_format(final_output), terminal)
            
            if terminal:
                score = final_output.get("risk_score", 0)
                category = final_output.get("classification", "Unknown")
                self._log(f"    -> Calculated Risk Score: {score}", True)
                self._log(f"    -> Classification Category: {category}", True)

        self._log(f"\n[*] Stage 5 Complete. Processed {idx + 1} alerts.", True)

    def test_stage_6_correlation(self):
        """Tests the full pipeline including the Correlation Engine."""
        self._setup_stage_logging("stage_6_correlation")
        self._log("=== RUNNING STAGE 6 TEST: CORRELATION ===", True)
        stream = self._get_replay_stream()
        
        for idx, envelope in enumerate(stream):
            terminal = idx < MAX_TERMINAL_OUTPUTS
            if terminal:
                self._log(f"\n--- Alert {idx + 1} ---", terminal)
            
            # Execute Pipeline Stages
            normalized_alert = self.ingest_pipeline.process(envelope)
            enriched_alert = self.enricher.enrich(normalized_alert)
            scored_output = self.risk_scorer.score(enriched_alert)
            final_output = self.classifier.process(scored_output)
            
            # Phase 10: Storage
            storage_id = self.storage.save_alert(final_output)
            final_output["_storage_id"] = storage_id
            
            if terminal:
                self._log(f"[+] Alert Classified and Stored (ID: {storage_id})", terminal)
                
            # Phase 11: Correlation
            self.correlator.process_alert(final_output)

        self._log(f"\n[*] Stage 6 Complete. Processed {idx + 1} alerts.", True)

    def run_pipeline(self, batch_size=20):
        self._setup_stage_logging("stage_6_correlation")
        self._log("=== RUNNING PIPELINE ===", True)
        stream = self._get_replay_stream()
        
        batch = []
        for idx, envelope in enumerate(stream):
            batch.append(envelope)
            
            if len(batch) >= batch_size:
                self._process_batch(batch)
                batch = []
                
        if batch:
            self._process_batch(batch)

    def _process_batch(self, batch):
        # 1. Synchronous Ingest (Fast)
        normalized_alerts = [self.ingest_pipeline.process(env) for env in batch]
        
        # 2. Synchronous Enrichment
        enriched_alerts = [self.enricher.enrich(alert) for alert in normalized_alerts]
        
        # 3. Synchronous Scoring & Correlation (Maintains chronological order)
        for alert in enriched_alerts:
            scored_output = self.risk_scorer.score(alert)
            final_output = self.classifier.process(scored_output)
            
            storage_id = self.storage.save_alert(final_output)
            final_output["_storage_id"] = storage_id
            
            self.correlator.process_alert(final_output)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run the SOC Orchestrator Pipeline")
    parser.add_argument("--dashboard", action="store_true", help="Enable dashboard broadcasting")
    parser.add_argument("--headless", action="store_true", help="Run without dashboard (default behavior)")
    args = parser.parse_args()

    orchestrator = Orchestrator(use_dashboard=args.dashboard)
    
    # Uncomment the stage you wish to test:
    
    # orchestrator.test_stage_1_replay()
    # orchestrator.test_stage_2_ingest()
    # orchestrator.test_stage_3_enrichment()
    # orchestrator.test_stage_4_risk_score()
    # orchestrator.test_stage_5_classification()
    # orchestrator.test_stage_6_correlation()
    
    orchestrator.run_pipeline(batch_size=20)
