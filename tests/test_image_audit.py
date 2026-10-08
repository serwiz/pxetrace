import shutil
import zipfile

import pytest

from pxetrace.image_audit import audit_images, deployment_path
from pxetrace.models import BootTarget


def test_target_selection_skips_system_tree_and_traversal():
    assert deployment_path('/Deploy/Scripts/join.ps1')
    assert deployment_path('/Windows/System32/startnet.cmd')
    assert not deployment_path('/Windows/System32/arbitrary.xml')
    assert not deployment_path('/Deploy/../../secret.xml')
    assert not deployment_path('/Windows/WinSxS/Scripts/example.ps1')
    assert not deployment_path('/Windows/WinSxS/example/Unattend.xml')
    assert not deployment_path('/Windows/win.ini')


@pytest.mark.skipif(shutil.which('7z') is None, reason='7z absent')
def test_archive_is_read_without_extracting_paths_to_workspace(tmp_path):
    archive = tmp_path / 'boot.zip'
    with zipfile.ZipFile(archive, 'w') as stream:
        stream.writestr('Deploy/Bootstrap.ini', '[Default]\nUserID=deploy\nUserPassword=Archive-Only!\n')
        stream.writestr('../../outside/Bootstrap.ini', 'Password=Escape!')
        stream.writestr('Windows/System32/noise.xml', '<Password>Noise!</Password>')
    result = audit_images([BootTarget('tftp://pxe.example.test/boot.zip', local_path=archive)])
    assert result.scanned_files == 1
    assert result.inventories_read == 1
    assert result.candidate_files == 1
    assert result.known_configurations == ['bootstrap.ini']
    assert [item['secret'] for item in result.credentials] == ['Archive-Only!']
    assert list(tmp_path.iterdir()) == [archive]


def test_scan_limit_is_reported(tmp_path):
    path = tmp_path / 'Bootstrap.ini'
    path.write_bytes(b'Password=VeryLong!')
    result = audit_images([BootTarget('tftp://pxe.example.test/Bootstrap.ini', local_path=path)], max_bytes=4)
    assert result.incomplete and not result.credentials


@pytest.mark.skipif(shutil.which('7z') is None, reason='7z absent')
def test_configuration_has_priority_over_scripts_and_noise(tmp_path):
    archive = tmp_path / 'boot.zip'
    with zipfile.ZipFile(archive, 'w') as stream:
        for index in range(100):
            stream.writestr(f'Deploy/Scripts/{index}.ps1', '$Password = Get-Secret')
            stream.writestr(f'Windows/System32/{index}.ini', 'Password=Noise!')
        stream.writestr('Deploy/Bootstrap.ini', '[Default]\nUserPassword=Targeted!\n')
    result = audit_images([BootTarget('tftp://server/boot.zip', local_path=archive)], max_files=1)
    assert result.scanned_files == 1 and result.candidate_files == 101
    assert [item['secret'] for item in result.credentials] == ['Targeted!']
    assert result.incomplete  # Exhausting a budget is not an exhaustive audit.


@pytest.mark.skipif(shutil.which('7z') is None, reason='7z absent')
def test_no_known_config_is_distinct_from_non_interpreted_script(tmp_path):
    archive = tmp_path / 'boot.zip'
    with zipfile.ZipFile(archive, 'w') as stream:
        stream.writestr('Windows/System32/startnet.cmd', '@echo off\nwpeinit\n')
    result = audit_images([BootTarget('tftp://server/boot.zip', local_path=archive)])
    assert result.inventories_read == 1 and result.known_configurations == []
    assert result.scanned_files == 1
    assert result.uninterpreted[0]['reason'] == 'script non interprété'
    assert not result.credentials and not result.incomplete
