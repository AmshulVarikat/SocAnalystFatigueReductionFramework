import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from Implementation.test_orchestrator import TestOrchestrator

class MetricsOrchestrator(TestOrchestrator):
    def __init__(self, dataset_path: str):
        super().__init__(dataset_path=dataset_path, run_name="metrics_eval", out_dir=os.path.join(PROJECT_ROOT, "outputs", "tests", "correlation_eval"))
        self.total_alerts = 0
        self.investigation_opened = 0
        self.investigation_updated = 0
        self.isolated_noise_alerts = 0
        
        # We need to track if the current alert triggered an event
        self.current_alert_triggered = False

    def _handle_investigation_event(self, event_data: dict):
        # Override to track metrics instead of just logging
        super()._handle_investigation_event(event_data)
        self.current_alert_triggered = True
        event_type = event_data.get('event')
        if event_type == 'INVESTIGATION_OPENED':
            self.investigation_opened += 1
        elif event_type == 'INVESTIGATION_UPDATED':
            self.investigation_updated += 1

    def run_tests_with_metrics(self):
        print("[*] Running evaluation with metrics tracking...")
        stream = self._get_replay_stream()
        
        for idx, envelope in enumerate(stream):
            self.total_alerts += 1
            self.current_alert_triggered = False
            
            # Execute Pipeline Stages
            normalized_alert = self.ingest_pipeline.process(envelope)
            enriched_alert = self.enricher.enrich(normalized_alert)
            scored_output = self.risk_scorer.score(enriched_alert)
            final_output = self.classifier.process(scored_output)
            
            storage_id = self.storage.save_alert(final_output)
            if isinstance(final_output, dict):
                final_output["_storage_id"] = storage_id
            else:
                setattr(final_output, "_storage_id", storage_id)
            
            # Phase 11: Correlation
            self.correlator.process_alert(final_output)
            
            if not self.current_alert_triggered:
                self.isolated_noise_alerts += 1

    def run_tests_with_metrics_and_report(self, report_filename: str):
        self.run_tests_with_metrics()
        self.generate_report(report_filename)

    def generate_report(self, report_filename: str):
        compression_ratio = ((self.total_alerts - self.investigation_opened) / self.total_alerts) * 100 if self.total_alerts > 0 else 0
        noise_absorption_rate = (self.isolated_noise_alerts / self.total_alerts) * 100 if self.total_alerts > 0 else 0
        
        report_md = f"""# Correlation Engine Effectiveness Report

## Quantitative Metrics

| Metric | Value | Description |
|--------|-------|-------------|
| **Total Raw Alerts** | {self.total_alerts} | Total number of alerts processed by the framework |
| **Total Investigations Created** | {self.investigation_opened} | Actual number of actionable items presented to the analyst |
| **Alert Compression Ratio** | {compression_ratio:.1f}% | Percentage reduction in raw alert volume |
| **Correlated Updates** | {self.investigation_updated} | Number of alerts successfully merged into an existing investigation |
| **Isolated Noise Alerts** | {self.isolated_noise_alerts} | Alerts that were absorbed and suppressed without triggering escalations |
| **Noise Absorption Rate** | {noise_absorption_rate:.1f}% | Percentage of total alerts safely suppressed as noise |

## Conclusion
The correlation engine achieved a **{compression_ratio:.1f}%** reduction in alert volume. Instead of triaging {self.total_alerts} separate alerts, the analyst only needs to investigate {self.investigation_opened} highly contextualized incident(s). {self.isolated_noise_alerts} background noise alerts were successfully absorbed without causing unnecessary escalations, directly combatting alert fatigue.
"""
        
        out_path = os.path.join(PROJECT_ROOT, "outputs", "tests", report_filename)
        with open(out_path, "w") as f:
            f.write(report_md)
        print(f"\n[*] Metrics report successfully saved to: {out_path}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Evaluate Correlation Metrics")
    parser.add_argument("--dataset", type=str, default="Implementation/inputs/Correlation_Test_Data", help="Path to the dataset alerts json")
    parser.add_argument("--output", type=str, default="correlation_metrics_report.md", help="Output filename in outputs/tests/")
    args = parser.parse_args()

    dataset_path = os.path.join(PROJECT_ROOT, args.dataset) if not os.path.isabs(args.dataset) else args.dataset
    evaluator = MetricsOrchestrator(dataset_path=dataset_path)
    evaluator.run_tests_with_metrics_and_report(args.output)
