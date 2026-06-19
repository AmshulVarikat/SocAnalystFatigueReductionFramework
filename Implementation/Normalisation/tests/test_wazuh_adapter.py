from Implementation.Normalisation.adapters.wazuh_adapter import normalize_wazuh
from Implementation.Normalisation.normalized_alert import NormalizedAlert


def test_normalize_wazuh_basic():
    raw = {
        'rule': {'id': 123, 'level': 5, 'description': 'Test rule', 'groups': ['syscheck']},
        'agent': {'id': '001', 'name': 'agent1', 'ip': '10.0.0.1'},
        'timestamp': '2026-06-15T12:00:00Z',
        'id': 'evt-1',
        'full_log': 'something happened',
    }

    na = normalize_wazuh(raw)
    assert isinstance(na, NormalizedAlert)
    assert na.rule_id == '123'
    assert na.rule_level == '5'
    assert na.rule_description == 'Test rule'
    assert na.hostname == 'agent1'
    assert na.host_ip == '10.0.0.1'
    assert na.event_time == '2026-06-15T12:00:00Z'


def test_normalize_wazuh_mitre_and_sysmon_details():
    raw = {
        'timestamp': '2026-06-11T15:10:48.735+0530',
        'id': '1781170848.5046997',
        'rule': {
            'level': 4,
            'description': 'Windows command prompt started by an abnormal process',
            'id': '92052',
            'mitre': {
                'id': ['T1059.003'],
                'tactic': ['Execution'],
                'technique': ['Windows Command Shell'],
            },
            'groups': ['sysmon', 'windows'],
        },
        'agent': {'id': '001', 'name': 'WIN11-SOC', 'ip': '10.211.55.7'},
        'manager': {'name': 'ubuntu-gnu-linux-24-04-3'},
        'decoder': {'name': 'windows_eventchannel'},
        'data': {
            'win': {
                'system': {
                    'eventID': '1',
                    'computer': 'AMSHULNINANEFDC',
                    'message': 'Process Create',
                    'providerName': 'Microsoft-Windows-Sysmon',
                    'channel': 'Microsoft-Windows-Sysmon/Operational',
                    'severityValue': 'INFORMATION',
                },
                'eventdata': {
                    'processGuid': '{process-guid}',
                    'processId': '6876',
                    'image': 'C:\\\\Windows\\\\System32\\\\cmd.exe',
                    'commandLine': '"cmd.exe" /c net user',
                    'user': 'AMSHULNINANEFDC\\\\amshul',
                    'hashes': 'MD5=abc,SHA256=def',
                    'parentProcessId': '10400',
                    'parentImage': 'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe',
                },
            }
        },
        'location': 'EventChannel',
    }

    na = normalize_wazuh(raw)

    assert na.original_id == '1781170848.5046997'
    assert na.event_id == '1'
    assert na.alert_id == '1781170848.5046997'
    assert na.correlation_id == '{process-guid}'
    assert na.hostname == 'AMSHULNINANEFDC'
    assert na.rule_decoder == 'windows_eventchannel'
    assert na.detector_name == 'windows_eventchannel'
    assert na.mitre_technique_id == 'T1059.003'
    assert na.mitre_tactic == 'Execution'
    assert na.mitre_technique_name == 'Windows Command Shell'
    assert na.process_name == 'cmd.exe'
    assert na.pid == '6876'
    assert na.parent_pid == '10400'
    assert na.cmdline == '"cmd.exe" /c net user'
    assert na.user_name == 'AMSHULNINANEFDC\\\\amshul'
    assert na.file_path == 'C:\\\\Windows\\\\System32\\\\cmd.exe'
    assert na.file_hashes == ['MD5=abc', 'SHA256=def']
    assert na.hashes == ['MD5=abc', 'SHA256=def']
    assert 'sysmon' in na.categories
    assert na.location == 'EventChannel'
