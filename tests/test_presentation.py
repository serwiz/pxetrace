import re

from pxetrace.presentation import render_audit_screen
from pxetrace.reports import save_reports


def test_screen_shows_evidence_and_groups_errors_without_raw_payloads(tmp_path):
    summary = {'boot': {'effective_boot_server': 'pxe.example.test'}, 'configmgr': {
        'credentials': [{'account': 'DEMO\\naa', 'secret': 'Exact-Password!', 'field': 'NetworkAccessPassword', 'source': 'NAAConfig.xml'}],
        'findings': [{'severity': 'critical', 'category': 'PFX média accessible'}],
        'policy_details': [{'category': 'TaskSequence', 'error': 'CMS refused', 'payloads': ['RAW_XML']}] * 8,
        'incomplete': ['CMS refused'] * 8, 'policies_downloaded': 162, 'policy_assignments': 170,
        'variable_inventory': [{'name': '_SMSTSMediaPFX', 'display': 'PRIVATE_PFX'}],
    }}
    screen = render_audit_screen(summary, color=True)
    assert 'Exact-Password!' in screen and 'TaskSequence × 8' in screen
    assert 'RAW_XML' not in screen and 'PRIVATE_PFX' not in screen
    assert len(screen.splitlines()) < 25
    assert '\x1b[' in screen
    summary['configmgr']['credentials'][0]['secret'] = '\x1b[2Jhidden'
    plain = render_audit_screen(summary)
    assert '\x1b' not in plain and '\\u001b' in plain
    save_reports(tmp_path, summary)
    report = tmp_path / 'audit-report.txt'
    assert report.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / 'audit-details.json').stat().st_mode & 0o777 == 0o600
    assert not re.search(r'\x1b\[', report.read_text())


def test_repeated_secret_and_errors_do_not_flood_screen():
    summary = {'configmgr': {
        'credentials': [{'account': 'DEMO\\naa', 'secret': 'Repeated!', 'field': 'Password',
                         'source': f'policy-{index}.xml'} for index in range(170)],
        'policy_details': [{'category': 'NAAConfig', 'error': 'UNWANTED_CRYPTO_DUMP'}] * 8,
        'incomplete': ['UNWANTED_CRYPTO_DUMP'] * 8,
    }}
    screen = render_audit_screen(summary)
    assert screen.count('Repeated!') == 1
    assert '1 secret(s)' in screen and '(+169)' in screen
    assert 'policy-0.xml' in screen and 'policy-169.xml' not in screen
    assert 'NAAConfig × 8' in screen and 'Secrets éventuels non vérifiés' in screen
    assert 'UNWANTED_CRYPTO_DUMP' not in screen
    assert 'ConfigMgr incomplet' not in screen  # Do not repeat the same errors.
    assert len(screen.splitlines()) < 24
    assert len(summary['configmgr']['credentials']) == 170  # Details intact.


def test_absence_is_only_reported_after_a_successful_inventory():
    images = {'scanned_files': 0, 'inventories_read': 1, 'known_configurations': [], 'incomplete': []}
    screen = render_audit_screen({'image_audit': images})
    assert 'Aucune configuration de déploiement connue trouvée' in screen
    assert 'vérification manuelle' in screen
    images['inventories_read'] = 0
    assert 'connue trouvée' not in render_audit_screen({'image_audit': images})
    images['inventories_read'] = 1
    images['incomplete'] = ['boot.wim: wimlib-imagex absent : installer wimtools'] * 100
    screen = render_audit_screen({'image_audit': images})
    assert 'connue trouvée' not in screen
    assert 'wimtools absent × 100' in screen and 'boot.wim:' not in screen
    assert len(screen.splitlines()) < 16


def test_found_but_uninterpreted_is_not_reported_as_absent():
    images = {'scanned_files': 1, 'inventories_read': 1, 'known_configurations': ['variables.dat'],
              'uninterpreted': [{'source': 'variables.dat', 'reason': 'contenu binaire ou encodage non pris en charge'}]}
    screen = render_audit_screen({'image_audit': images})
    assert '1 fichier(s) ciblé(s) lu(s), 0 interprété(s)' in screen
    assert 'Non interprétés' in screen
    assert 'connue trouvée' not in screen
