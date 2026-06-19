from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any


@dataclass
class NormalizedAlert:
    # Metadata
    source: str = ''
    original_id: str = ''
    raw_alert: Dict[str, Any] = field(default_factory=dict)
    ingest_id: str = ''
    normalized_timestamp: str = ''

    # Identifiers
    event_id: str = ''
    correlation_id: str = ''
    alert_id: str = ''

    # Timestamps
    event_time: str = ''
    detection_time: str = ''
    ingestion_time: str = ''
    timestamp_original: str = ''

    # Host / Agent
    agent_id: str = ''
    hostname: str = ''
    fqdn: str = ''
    host_ip: str = ''
    host_os: str = ''
    agent_name: str = ''

    # Network
    src_ip: str = ''
    src_port: str = ''
    dst_ip: str = ''
    dst_port: str = ''
    protocol: str = ''
    url: str = ''
    domain: str = ''

    # Process / File / User
    process_name: str = ''
    pid: str = ''
    parent_pid: str = ''
    cmdline: str = ''
    user_name: str = ''
    file_path: str = ''
    file_hashes: List[str] = field(default_factory=list)

    # Rule / Detection details
    rule_id: str = ''
    rule_level: str = ''
    rule_description: str = ''
    rule_group: str = ''
    rule_file: str = ''
    rule_decoder: str = ''

    # MITRE
    mitre_tactic: str = ''
    mitre_technique_id: str = ''
    mitre_technique_name: str = ''
    mitre_subtechnique: str = ''
    mitre_confidence: str = ''

    # Threat Intel / Scoring
    severity: str = ''
    confidence: str = ''
    score: str = ''
    tags: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)

    # Observables
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)

    # Enrichment / Context
    geolocation: Dict[str, Any] = field(default_factory=dict)
    geoip: Dict[str, Any] = field(default_factory=dict)
    whois: Dict[str, Any] = field(default_factory=dict)
    asn: str = ''

    # Misc
    message: str = ''
    full_log: str = ''
    location: str = ''
    detector_name: str = ''

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable dict representation."""
        return asdict(self)
