import os
import sys
import time
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

DATASET_ALERTS_PATH = os.path.join(PROJECT_ROOT, "Implementation/inputs/Dataset4")
DATASET_GROUND_TRUTH_PATH = os.path.join(PROJECT_ROOT, "Implementation/inputs/Dataset1/GroundTruth/ground_truth.json")

# Enrichment Databases
ASSET_DB_PATH = os.path.join(PROJECT_ROOT, "Implementation/inputs/Dataset4/assets.json")
THREAT_INTEL_DB_PATH = os.path.join(PROJECT_ROOT, "Implementation/inputs/Test_Data/threat_intel.json")

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
    def __init__(self, use_dashboard: bool = False, enable_threat_intel: bool = True, enable_entity_pivoting: bool = True, enable_temporal_grouping: bool = True):
        print(f"[*] Initializing Orchestrator Pipeline...")
        self.use_dashboard = use_dashboard
        if self.use_dashboard:
            print("[*] Dashboard Publisher Enabled")
            self.publisher = DashboardPublisher()
        else:
            self.publisher = None
        
        # 1. Initialize Enrichment Repositories
        self.asset_repo = JsonAssetRepository(ASSET_DB_PATH)
        
        self.enable_threat_intel = enable_threat_intel
        if self.enable_threat_intel:
            json_threat_repo = JsonThreatIntelRepository(THREAT_INTEL_DB_PATH)
            self.threat_repo = CompositeThreatIntelRepository([json_threat_repo])
        else:
            json_threat_repo = None
            self.threat_repo = None
        
        # 2. Initialize Pipeline Modules
        self.enricher = AlertEnricher(
            asset_repo=self.asset_repo, 
            local_threat_repo=json_threat_repo,
            enable_threat_intel=self.enable_threat_intel
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
            on_investigation_event=self._handle_investigation_event,
            enable_entity_pivoting=enable_entity_pivoting,
            enable_temporal_grouping=enable_temporal_grouping
        )

        # Setup Logging
        self.output_file = None
        self.metrics_file = None
        self.global_metrics = {
            'total_alerts': 0,
            'total_time': 0,
            'ingest_time': 0,
            'enrich_time': 0,
            'scoring_time': 0,
            'storage_time': 0,
            'correlation_time': 0
        }

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

    def _setup_metrics_logging(self):
        if self.metrics_file and not self.metrics_file.closed:
            self.metrics_file.close()
            
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        stage_dir = os.path.join(project_root, "outputs", "metrics")
        os.makedirs(stage_dir, exist_ok=True)
        
        log_filename = f"run_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        log_path = os.path.join(stage_dir, log_filename)
        
        self.metrics_file = open(log_path, 'w', encoding='utf-8')
        print(f"[*] Performance Metrics will be logged to: {log_path}")

    def _dump_ablation_metrics(self, run_name: str, pipeline_total_time: float):
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        stage_dir = os.path.join(project_root, "outputs", "Ablation")
        os.makedirs(stage_dir, exist_ok=True)
        
        log_path = os.path.join(stage_dir, f"{run_name}_results.txt")
        
        # Calculate derived metrics
        initial_alerts = self.global_metrics['total_alerts']
        active_investigations = len(self.correlator.active_investigations)
        compression_ratio = (active_investigations / initial_alerts * 100) if initial_alerts > 0 else 0
        
        avg_alerts_per_inv = initial_alerts / active_investigations if active_investigations > 0 else 0
        avg_eps = initial_alerts / pipeline_total_time if pipeline_total_time > 0 else 0
        
        avg_max_risk = sum(inv.max_risk_score for inv in self.correlator.active_investigations.values()) / active_investigations if active_investigations > 0 else 0
        avg_priority = sum(inv.current_priority for inv in self.correlator.active_investigations.values()) / active_investigations if active_investigations > 0 else 0
        
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(f"=== ABLATION STUDY RESULTS: {run_name} ===\n")
            f.write(f"Date: {datetime.now().isoformat()}\n")
            f.write(f"-----------------------------------------\n")
            f.write(f"Total Alerts Ingested: {initial_alerts}\n")
            f.write(f"Final Active Investigations: {active_investigations}\n")
            f.write(f"Alert Compression Rate: {compression_ratio:.2f}% (lower is better)\n")
            f.write(f"Average Alerts per Investigation: {avg_alerts_per_inv:.2f}\n")
            f.write(f"Synthetic Density Investigations Spawned: {len([i for i in self.correlator.active_investigations.values() if i.rule.get('rule_name') == 'High-Density Anomalous Activity'])}\n")
            f.write(f"Average Max Risk Score (Base): {avg_max_risk:.2f}\n")
            f.write(f"Average Current Priority (Elevated): {avg_priority:.2f}\n")
            f.write(f"-----------------------------------------\n")
            f.write(f"Total Pipeline Execution Time: {pipeline_total_time:.4f}s\n")
            f.write(f"Average Throughput: {avg_eps:.2f} EPS\n")
            f.write(f"Cumulative Times:\n")
            f.write(f"  -> Ingest & Normalize: {self.global_metrics['ingest_time']:.4f}s\n")
            f.write(f"  -> Enrichment: {self.global_metrics['enrich_time']:.4f}s\n")
            f.write(f"  -> Risk Scoring: {self.global_metrics['scoring_time']:.4f}s\n")
            f.write(f"  -> DB Storage: {self.global_metrics['storage_time']:.4f}s\n")
            f.write(f"  -> Correlation: {self.global_metrics['correlation_time']:.4f}s\n")
            
        print(f"[*] Ablation specific metrics for {run_name} saved to {log_path}")

    def __del__(self):
        if hasattr(self, 'output_file') and self.output_file and not self.output_file.closed:
            self.output_file.close()
        if hasattr(self, 'metrics_file') and self.metrics_file and not self.metrics_file.closed:
            self.metrics_file.close()

    def _log_metric(self, message: str, print_to_terminal: bool = False):
        if self.metrics_file and not self.metrics_file.closed:
            self.metrics_file.write(message + "\n")
            self.metrics_file.flush()
        if print_to_terminal:
            print(message)

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
        self._setup_metrics_logging()
        self._log("=== RUNNING PIPELINE ===", True)
        self._log_metric("=== PIPELINE PERFORMANCE METRICS ===", True)
        
        pipeline_start_time = time.perf_counter()
        stream = self._get_replay_stream()
        
        batch = []
        for idx, envelope in enumerate(stream):
            batch.append(envelope)
            
            if len(batch) >= batch_size:
                self._process_batch(batch)
                batch = []
                
        if batch:
            self._process_batch(batch)
            
        pipeline_total_time = time.perf_counter() - pipeline_start_time
        
        # Summary Report
        if self.global_metrics['total_alerts'] > 0:
            avg_eps = self.global_metrics['total_alerts'] / pipeline_total_time
            self._log_metric(f"\n=== FINAL PIPELINE SUMMARY ===", True)
            self._log_metric(f"Total Alerts Processed: {self.global_metrics['total_alerts']}", True)
            self._log_metric(f"Total Pipeline Execution Time: {pipeline_total_time:.4f}s", True)
            self._log_metric(f"Average Throughput: {avg_eps:.2f} EPS", True)
            self._log_metric(f"Cumulative Times (Across all batches):", True)
            self._log_metric(f"  -> Ingest & Normalize: {self.global_metrics['ingest_time']:.4f}s", True)
            self._log_metric(f"  -> Enrichment: {self.global_metrics['enrich_time']:.4f}s", True)
            self._log_metric(f"  -> Risk Scoring: {self.global_metrics['scoring_time']:.4f}s", True)
            self._log_metric(f"  -> DB Storage: {self.global_metrics['storage_time']:.4f}s", True)
            self._log_metric(f"  -> Correlation: {self.global_metrics['correlation_time']:.4f}s", True)
            self._log_metric(f"==================================", True)
            
        return pipeline_total_time

    def _process_batch(self, batch):
        batch_start_time = time.perf_counter()
        
        # 1. Synchronous Ingest (Fast)
        t0 = time.perf_counter()
        normalized_alerts = [self.ingest_pipeline.process(env) for env in batch]
        ingest_time = time.perf_counter() - t0
        
        # 2. Synchronous Enrichment
        t0 = time.perf_counter()
        enriched_alerts = [self.enricher.enrich(alert) for alert in normalized_alerts]
        enrich_time = time.perf_counter() - t0
        
        # 3. Synchronous Scoring & Correlation (Maintains chronological order)
        scoring_time = 0
        storage_time = 0
        correlation_time = 0
        
        for alert in enriched_alerts:
            t0 = time.perf_counter()
            scored_output = self.risk_scorer.score(alert)
            final_output = self.classifier.process(scored_output)
            scoring_time += time.perf_counter() - t0
            
            t0 = time.perf_counter()
            storage_id = self.storage.save_alert(final_output)
            if isinstance(final_output, dict):
                final_output["_storage_id"] = storage_id
            else:
                setattr(final_output, "_storage_id", storage_id)
            storage_time += time.perf_counter() - t0
            
            t0 = time.perf_counter()
            self.correlator.process_alert(final_output)
            correlation_time += time.perf_counter() - t0

        batch_total_time = time.perf_counter() - batch_start_time
        throughput_eps = len(batch) / batch_total_time if batch_total_time > 0 else 0
        
        # Update Globals
        self.global_metrics['total_alerts'] += len(batch)
        self.global_metrics['total_time'] += batch_total_time
        self.global_metrics['ingest_time'] += ingest_time
        self.global_metrics['enrich_time'] += enrich_time
        self.global_metrics['scoring_time'] += scoring_time
        self.global_metrics['storage_time'] += storage_time
        self.global_metrics['correlation_time'] += correlation_time
        
        # Log Batch Metrics
        self._log_metric(f"[Batch Metrics] Size: {len(batch)} | Time: {batch_total_time:.4f}s | Throughput: {throughput_eps:.2f} EPS")
        self._log_metric(f"  -> Ingest: {ingest_time:.4f}s | Enrich: {enrich_time:.4f}s | Score: {scoring_time:.4f}s")
        self._log_metric(f"  -> Storage: {storage_time:.4f}s | Correlate: {correlation_time:.4f}s\n")

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
