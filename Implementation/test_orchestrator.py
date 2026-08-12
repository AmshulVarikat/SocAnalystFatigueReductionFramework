import os
import sys
import json
from datetime import datetime
from dataclasses import asdict
import argparse

# ==========================================
# CONFIGURATION: Hardcoded Paths
# ==========================================
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Default to one of the newly created test datasets
DATASET_ALERTS_PATH = os.path.join(PROJECT_ROOT, "Implementation/inputs/Test_Data/benign_low_severity")

# Enrichment Databases
ASSET_DB_PATH = os.path.join(PROJECT_ROOT, "Implementation/inputs/Test_Data/assets.json")
THREAT_INTEL_DB_PATH = os.path.join(PROJECT_ROOT, "Implementation/inputs/Test_Data/threat_intel.json")
CLASSIFICATION_RULES_PATH = os.path.join(PROJECT_ROOT, "Implementation/classification/rules.json")

# Phase 6: Replay
from ReplayEngine.loader import JsonLoader
from ReplayEngine.engine import ReplayEngine
from ReplayEngine.modes import ReplayMode

# Phase 7: Ingest & Normalize
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

# Phase 8-11: Enrichment, Risk Scoring, Classification, Storage, Correlation
from Implementation.enrichment.asset_repository import JsonAssetRepository
from Implementation.enrichment.threat_intel_repository import JsonThreatIntelRepository, CompositeThreatIntelRepository
from Implementation.enrichment.alert_enricher import AlertEnricher
from Implementation.risk_score.scorer import AlertRiskScorer
from Implementation.classification.classifier import AlertClassifier
from Implementation.storage.sqlite_alert_storage import SqliteAlertStorage
from Implementation.correlation.correlation_engine import CorrelationEngine

class TestOrchestrator:
    """
    Minimal Base Pipeline for testing the Risk Scorer and Classification stages.
    Strips out dashboard and storage logic.
    """
    def __init__(self, dataset_path: str = None, run_name: str = "classification_output", out_dir: str = None):
        print(f"[*] Initializing Test Orchestrator Pipeline...")
        self.dataset_path = dataset_path if dataset_path else DATASET_ALERTS_PATH
        self.run_name = run_name
        self.out_dir = out_dir if out_dir else os.path.join(PROJECT_ROOT, "outputs", "tests", "risk_score")
        
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
        
        # Wipe old database files on run
        db_path = os.path.join(PROJECT_ROOT, "Implementation/storage/alerts.db")
        import glob
        for f in glob.glob(db_path + "*"):
            try:
                os.remove(f)
                print(f"[*] Wiped previous database file: {f}")
            except OSError:
                pass
                
        self.storage = SqliteAlertStorage(db_path)
        self.correlator = CorrelationEngine(
            db_repository=self.storage, 
            tick_interval=10, 
            rules_path=os.path.join(PROJECT_ROOT, "Implementation/correlation/rules.json"),
            on_investigation_event=self._handle_investigation_event
        )
        
        self.output_file = None

    def _setup_stage_logging(self, stage_name: str):
        if self.output_file and not self.output_file.closed:
            self.output_file.close()
            
        stage_dir = self.out_dir
        os.makedirs(stage_dir, exist_ok=True)
        
        dataset_name = os.path.splitext(os.path.basename(self.dataset_path))[0]
        # Use run_name and dataset_name cleanly so the parser can use them for readable headers
        log_filename = f"{self.run_name}_{dataset_name}.txt"
        log_path = os.path.join(stage_dir, log_filename)
        
        self.output_file = open(log_path, 'w', encoding='utf-8')
        print(f"[*] Outputs will be logged to: {log_path}")

    def __del__(self):
        if hasattr(self, 'output_file') and self.output_file and not self.output_file.closed:
            self.output_file.close()

    def _log(self, message: str, print_to_terminal: bool = False):
        if self.output_file and not self.output_file.closed:
            self.output_file.write(message + "\n")
        if print_to_terminal:
            print(message)

    def _handle_investigation_event(self, event_data: dict):
        """Callback for the Correlation Engine."""
        self._log(f"\n[!] INVESTIGATION EVENT: {event_data.get('event')}", True)
        self._log(self._pretty_format(event_data), False)

    def _pretty_format(self, obj) -> str:
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
        loader = JsonLoader(self.dataset_path)
        dataset = loader.load()
        engine = ReplayEngine(dataset, mode=ReplayMode.SEQUENTIAL)
        return engine.replay()

    def run_tests(self):
        """Runs the full pipeline including Storage and Correlation, logging outputs."""
        self._setup_stage_logging(self.run_name)
        self._log(f"=== RUNNING PIPELINE TEST ON: {self.dataset_path} ===", True)
        stream = self._get_replay_stream()
        
        processed_count = 0
        for idx, envelope in enumerate(stream):
            # Execute Pipeline Stages
            normalized_alert = self.ingest_pipeline.process(envelope)
            enriched_alert = self.enricher.enrich(normalized_alert)
            scored_output = self.risk_scorer.score(enriched_alert)
            final_output = self.classifier.process(scored_output)
            
            # Phase 10: Storage
            storage_id = self.storage.save_alert(final_output)
            if isinstance(final_output, dict):
                final_output["_storage_id"] = storage_id
            else:
                setattr(final_output, "_storage_id", storage_id)
            
            # Phase 11: Correlation
            self.correlator.process_alert(final_output)
            
            # The final_output contains stage 5 classification and retains stage 4 risk score
            self._log(f"\n--- Alert {idx + 1} ---")
            self._log(f"[+] Alert Scored, Classified, & Stored (ID: {storage_id})")
            
            # Print specific required elements to terminal for visibility
            score = final_output.get("risk_score", 0) if isinstance(final_output, dict) else getattr(final_output, "risk_score", 0)
            category = final_output.get("classification", "Unknown") if isinstance(final_output, dict) else getattr(final_output, "classification", "Unknown")
            rule_id = envelope.get('alert', {}).get('rule', {}).get('id', 'Unknown')
            
            self._log(f"    -> Rule ID: {rule_id}", True)
            self._log(f"    -> Calculated Risk Score: {score}", True)
            self._log(f"    -> Classification Category: {category}", True)
            
            # Log full output doc to file
            self._log("\n[Full Output Document]")
            self._log(self._pretty_format(final_output))
            processed_count += 1

        self._log(f"\n[*] Test Complete. Processed {processed_count} alerts.", True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Base SOC Pipeline for Risk Scoring")
    parser.add_argument("--dataset", type=str, default=DATASET_ALERTS_PATH, 
                        help="Path to the dataset alerts json to test against")
    parser.add_argument("--run-name", type=str, default="classification_output", 
                        help="Name of the test run to use as prefix for output log files")
    parser.add_argument("--out-dir", type=str, default=None,
                        help="Directory to save the log files")
    args = parser.parse_args()

    test_orch = TestOrchestrator(dataset_path=args.dataset, run_name=args.run_name, out_dir=args.out_dir)
    test_orch.run_tests()
