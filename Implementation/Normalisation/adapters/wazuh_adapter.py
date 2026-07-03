from typing import Dict, Any, Iterable, List

from ..normalized_alert import NormalizedAlert
from .base_adapter import register_adapter


@register_adapter('wazuh')
def normalize_wazuh(raw_alert: Dict[str, Any]) -> NormalizedAlert:
    """Map a Wazuh raw alert dict to `NormalizedAlert`.

    This function focuses only on normalization (no enrichment).
    Missing canonical fields are left as empty strings or empty lists. Wazuh
    places many useful details in nested ``data`` payloads, so this adapter also
    reads common Windows/Sysmon, network, file, and web keys from those payloads.
    """

    def _coerce_str(value: Any) -> str:
        if value is None:
            return ''
        if isinstance(value, (list, dict)):
            try:
                return str(value)
            except Exception:
                return ''
        return str(value)

    def _as_dict(value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def _first_present(*values: Any) -> str:
        for value in values:
            coerced = _coerce_str(value)
            if coerced:
                return coerced
        return ''

    def _join_list(value: Any) -> str:
        if isinstance(value, list):
            return ','.join([_coerce_str(x) for x in value if _coerce_str(x)])
        return _coerce_str(value)

    def _append_unique(target: List[str], values: Iterable[Any]) -> None:
        for value in values:
            if isinstance(value, list):
                _append_unique(target, value)
                continue
            coerced = _coerce_str(value)
            if coerced and coerced not in target:
                target.append(coerced)

    def _get_path(payload: Dict[str, Any], *path: str) -> Any:
        current: Any = payload
        for key in path:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
        return current

    def _basename(path: str) -> str:
        normalized = path.replace('\\', '/')
        return normalized.rsplit('/', 1)[-1] if normalized else ''

    na = NormalizedAlert()

    data = _as_dict(raw_alert.get('data'))
    win = _as_dict(data.get('win'))
    win_system = _as_dict(win.get('system'))
    win_eventdata = _as_dict(win.get('eventdata'))
    rule = _as_dict(raw_alert.get('rule'))
    agent = _as_dict(raw_alert.get('agent'))
    manager = _as_dict(raw_alert.get('manager'))
    decoder = _as_dict(raw_alert.get('decoder'))

    # Identifiers / timestamps
    na.original_id = _first_present(raw_alert.get('id'), raw_alert.get('event_id'))
    na.event_id = _first_present(
        win_system.get('eventID'),
        raw_alert.get('event_id'),
        raw_alert.get('eventID'),
        raw_alert.get('id'),
    )
    na.alert_id = na.original_id
    na.correlation_id = _first_present(
        raw_alert.get('correlation_id'),
        raw_alert.get('correlationId'),
        win_eventdata.get('processGuid'),
        win_eventdata.get('logonGuid'),
        win_system.get('eventRecordID'),
    )
    na.event_time = _first_present(
        raw_alert.get('timestamp'),
        raw_alert.get('time'),
        raw_alert.get('date'),
        win_eventdata.get('utcTime'),
        win_system.get('systemTime'),
    )
    na.detection_time = _first_present(raw_alert.get('timestamp'), raw_alert.get('time'), raw_alert.get('date'))
    predecoder = _as_dict(raw_alert.get('predecoder'))
    na.ingestion_time = _first_present(predecoder.get('timestamp'))
    na.timestamp_original = na.event_time

    # Rule details
    na.rule_id = _coerce_str(rule.get('id') or rule.get('rule_id'))
    na.rule_level = _coerce_str(rule.get('level'))
    na.rule_description = _coerce_str(rule.get('description') or rule.get('desc'))
    na.rule_group = _join_list(rule.get('groups') or rule.get('group'))
    na.rule_file = _first_present(rule.get('file'), rule.get('filename'), rule.get('gdpr'))
    na.rule_decoder = _first_present(rule.get('decoder'), decoder.get('name'), decoder.get('parent'))

    # Agent/host
    na.agent_id = _coerce_str(agent.get('id'))
    na.agent_name = _coerce_str(agent.get('name'))
    na.hostname = _first_present(
        agent.get('name'),
        agent.get('hostname'),
        win_system.get('computer'),
        raw_alert.get('hostname'),
        raw_alert.get('host'),
    )
    na.fqdn = _first_present(raw_alert.get('fqdn'), agent.get('fqdn'), win_system.get('computer'))
    na.host_ip = _join_list(agent.get('ip') or raw_alert.get('host_ip') or raw_alert.get('agent_ip'))
    na.host_os = _first_present(agent.get('os'), agent.get('os_name'), data.get('os'), raw_alert.get('os'))

    # Network observables
    na.src_ip = _first_present(
        raw_alert.get('srcip'),
        raw_alert.get('source_ip'),
        raw_alert.get('source'),
        data.get('srcip'),
        data.get('src_ip'),
        data.get('src_ipaddr'),
        win_eventdata.get('sourceIp'),
        win_eventdata.get('sourceAddress'),
        win_eventdata.get('sourceHostname'),
    )
    na.src_port = _first_present(
        raw_alert.get('srcport'),
        raw_alert.get('source_port'),
        data.get('srcport'),
        data.get('src_port'),
        win_eventdata.get('sourcePort'),
    )
    na.dst_ip = _first_present(
        raw_alert.get('dstip'),
        raw_alert.get('destination_ip'),
        raw_alert.get('destination'),
        data.get('dstip'),
        data.get('dst_ip'),
        data.get('dst_ipaddr'),
        win_eventdata.get('destinationIp'),
        win_eventdata.get('destinationAddress'),
        win_eventdata.get('destinationHostname'),
    )
    na.dst_port = _first_present(
        raw_alert.get('dstport'),
        raw_alert.get('destination_port'),
        data.get('dstport'),
        data.get('dst_port'),
        win_eventdata.get('destinationPort'),
    )
    na.protocol = _first_present(raw_alert.get('protocol'), data.get('protocol'), win_eventdata.get('protocol'))
    na.url = _first_present(raw_alert.get('url'), data.get('url'), data.get('uri'), win_eventdata.get('url'), win_eventdata.get('queryName'))
    na.domain = _first_present(raw_alert.get('domain'), data.get('domain'), data.get('hostname'), win_eventdata.get('queryName'))

    # Process / file / user
    process_image = _first_present(
        win_eventdata.get('image'),
        win_eventdata.get('processName'),
        data.get('process'),
        data.get('program_name'),
        raw_alert.get('process_name'),
    )
    na.process_name = _first_present(win_eventdata.get('originalFileName'), _basename(process_image), process_image)
    na.pid = _first_present(win_eventdata.get('processId'), win_system.get('processID'), raw_alert.get('pid'))
    na.parent_pid = _first_present(win_eventdata.get('parentProcessId'), raw_alert.get('parent_pid'))
    na.cmdline = _first_present(win_eventdata.get('commandLine'), raw_alert.get('command'), raw_alert.get('cmdline'))
    na.user_name = _first_present(
        win_eventdata.get('user'),
        win_eventdata.get('targetUserName'),
        win_eventdata.get('subjectUserName'),
        data.get('srcuser'),
        data.get('dstuser'),
        raw_alert.get('user'),
    )
    na.file_path = _first_present(
        win_eventdata.get('targetFilename'),
        win_eventdata.get('image'),
        win_eventdata.get('parentImage'),
        data.get('file'),
        raw_alert.get('file_path'),
    )
    hashes = _first_present(win_eventdata.get('hashes'), data.get('hashes'), raw_alert.get('hashes'))
    if hashes:
        na.file_hashes = [part.strip() for part in hashes.split(',') if part.strip()]

    # Tags / severity
    tags = raw_alert.get('tags')
    if isinstance(tags, list):
        na.tags = [str(x) for x in tags]
    elif tags:
        na.tags = [str(tags)]

    _append_unique(na.tags, [rule.get('pci_dss'), rule.get('gdpr'), rule.get('hipaa'), rule.get('nist_800_53'), rule.get('gpg13')])
    _append_unique(
        na.categories,
        [
            rule.get('groups'),
            win_system.get('providerName'),
            win_system.get('channel'),
            win_system.get('severityValue'),
            win_eventdata.get('integrityLevel'),
        ],
    )

    na.severity = _first_present(
        raw_alert.get('severity'),
        raw_alert.get('level'),
        rule.get('level'),
    )
    na.confidence = _first_present(rule.get('confidence'), raw_alert.get('confidence'))
    na.score = _first_present(rule.get('level'), raw_alert.get('score'))

    # MITRE details
    mitre = _as_dict(rule.get('mitre'))
    na.mitre_technique_id = _join_list(mitre.get('id'))
    na.mitre_tactic = _join_list(mitre.get('tactic'))
    na.mitre_technique_name = _join_list(mitre.get('technique'))
    na.mitre_subtechnique = _join_list(mitre.get('subtechnique') or mitre.get('sub_technique'))
    na.mitre_confidence = _coerce_str(mitre.get('confidence'))

    # Observables common fields
    _append_unique(na.ips, [na.host_ip, na.src_ip, na.dst_ip, data.get('srcip'), data.get('dstip')])
    _append_unique(na.domains, [na.domain, win_eventdata.get('queryName')])
    _append_unique(na.urls, [na.url])
    _append_unique(na.hashes, na.file_hashes)
    _append_unique(na.file_paths, [na.file_path, process_image, win_eventdata.get('parentImage'), win_eventdata.get('currentDirectory')])
    _append_unique(na.email_addresses, [data.get('srcemail'), data.get('dstemail'), raw_alert.get('srcemail'), raw_alert.get('dstemail')])

    # Enrichment / context already present in Wazuh alerts.
    na.geoip = _as_dict(raw_alert.get('GeoLocation') or raw_alert.get('geoip') or data.get('geoip'))
    na.geolocation = _as_dict(raw_alert.get('geolocation') or data.get('geolocation'))
    na.whois = _as_dict(raw_alert.get('whois') or data.get('whois'))
    na.asn = _first_present(raw_alert.get('asn'), data.get('asn'), _get_path(na.geoip, 'asn'))

    # Misc
    na.message = _first_present(
        raw_alert.get('message'),
        win_system.get('message'),
        win_eventdata.get('description'),
        rule.get('description'),
        raw_alert.get('full_log'),
    )
    na.full_log = _first_present(raw_alert.get('full_log'), raw_alert.get('full-log'), win_system.get('message'), na.message)
    na.location = _coerce_str(raw_alert.get('location'))
    na.detector_name = _first_present(decoder.get('name'), manager.get('name'), raw_alert.get('decoder'))

    # Preserve full raw alert for traceability (BaseAdapter will also set it)
    na.raw_alert = raw_alert

    return na
