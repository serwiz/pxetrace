import json
import socket

from pxetrace.demo import demo_summary
from pxetrace.offline import inspect_capture


def test_offline_replay_never_contacts_server_or_trusts_external_paths(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError('network access during offline replay')
    monkeypatch.setattr(socket, 'socket', forbidden)
    summary = {'chain': [{'local_path': '/etc/passwd'}], 'configmgr': {
        'variable_inventory': [{'name': 'OSDJoinAccount', 'display': 'DEMO\\join'}, {'name': 'OSDJoinPassword', 'display': 'Replay!'}],
        'policy_details': [{'number': 1, 'category': 'NAAConfig', 'error': None,
                            'payloads': ['<Policy><var name="NetworkAccessUsername">DEMO\\naa</var><var name="NetworkAccessPassword">NaaReplay!</var></Policy>']}],
        'incomplete': [],
    }}
    report = tmp_path / 'audit-details.json'
    report.write_text(json.dumps(summary))
    before = report.read_bytes()
    result = inspect_capture(tmp_path)
    assert result['offline']
    assert {item['secret'] for item in result['configmgr']['credentials']} == {'Replay!', 'NaaReplay!'}
    assert report.read_bytes() == before
    assert list(tmp_path.iterdir()) == [report]
    assert result['image_audit']['scanned_files'] == 0


def test_demo_runs_real_decoders_and_cleans_up(monkeypatch, tmp_path):
    import tempfile
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))
    result = demo_summary()
    assert result['demo'] and result['offline']
    assert {item['secret'] for item in result['configmgr']['credentials']} == {'Demo-Join-Only!', 'Demo-NAA-Only!'}
    assert list(tmp_path.iterdir()) == []
