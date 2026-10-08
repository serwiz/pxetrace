from pxetrace.evidence import extract_credentials, inspect_credentials, text_content


def test_naa_pairs_values_inside_each_instance_not_across_accounts():
    xml = '<Policy>' + ''.join(
        f'<instance class="CCM_NetworkAccessAccount"><property name="NetworkAccessUsername"><value>{user}</value></property>'
        f'<property name="NetworkAccessPassword"><value>{password}</value></property></instance>'
        for user, password in [('DEMO\\first', 'First!'), ('DEMO\\second', 'Second!')]
    ) + '</Policy>'
    result = extract_credentials(xml.encode('utf-16le'), source='NAAConfig.xml')
    assert {(item.account, item.secret) for item in result} == {('DEMO\\first', 'First!'), ('DEMO\\second', 'Second!')}
    assert all(item.source == 'NAAConfig.xml' and len(item.sha256) == 64 for item in result)


def test_ciphertext_and_placeholders_are_not_plaintext_evidence():
    xml = ('<Policy><property name="NetworkAccessPassword" secret="1"><value>' + '12' * 100 + '</value></property>'
           '<var name="OSDJoinPassword">%RuntimePassword%</var>'
           '<Password><Value>BASE64VALUE</Value><PlainText>false</PlainText></Password></Policy>')
    assert extract_credentials(xml.encode(), source='policy.xml') == []
    assert extract_credentials(b'Password=' + b'\xff\x01' * 50, source='binary') == []


def test_ini_sections_and_xml_collection_variable():
    ini = b'[One]\nUserID=deploy\nUserDomain=DEMO\nUserPassword=Exact value!\n[Two]\nPassword=Another!\n'
    result = extract_credentials(ini, source='Bootstrap.ini')
    assert [(item.account, item.secret) for item in result] == [('DEMO\\deploy', 'Exact value!'), ('non précisé', 'Another!')]
    xml = b'<instance class="CCM_CollectionVariable"><property name="Name"><value>OSDJoinPassword</value></property><property name="Value"><value>Collection!</value></property></instance>'
    result = extract_credentials(xml, source='CollectionSettings')
    assert len(result) == 1 and result[0].secret == 'Collection!'
    assert result[0].account == 'non précisé'


def test_utf16_ascii_is_decoded_without_interleaved_nuls():
    assert text_content('Mot de passe'.encode('utf-16le')) == 'Mot de passe'


def test_password_settings_and_prose_are_not_credentials():
    data = b'[Settings]\nRequirePassword=true\nSkipDomainAdminPassword=YES\nUsePassword=0\nEnableBootPassword=1\nPasswordHint=example\nWrite-Host Password=not-a-secret\n'
    assert extract_credentials(data, source='CustomSettings.ini') == []
    xml = b'<Policy><property name="Password" type="11"><value>true</value></property></Policy>'
    assert extract_credentials(xml, source='policy.xml') == []


def test_unrelated_names_and_accounts_are_not_associated():
    data = b'[Settings]\nName=Join policy\nUsername=OtherAccount\nOSDJoinPassword=RealSecret!\n'
    assert extract_credentials(data, source='CustomSettings.ini')[0].account == 'non précisé'
    data = b'[Settings]\nUserDomain=OTHER\nOSDJoinAccount=join\nOSDJoinPassword=RealSecret!\n'
    assert extract_credentials(data, source='CustomSettings.ini')[0].account == 'join'
    data = b'[Settings]\nName=PolicyName\nPassword=RealSecret!\n'
    assert extract_credentials(data, source='CustomSettings.ini')[0].account == 'non précisé'
    data = b'[Settings]\nUser=deploy\nDomain=DEMO\nPassword=RealSecret!\n'
    assert extract_credentials(data, source='CustomSettings.ini')[0].account == 'DEMO\\deploy'


def test_known_unattend_local_account_name_is_preserved():
    xml = b'<LocalAccount><Name>localadmin</Name><Password><Value>RealSecret!</Value><PlainText>true</PlainText></Password></LocalAccount>'
    result = extract_credentials(xml, source='Unattend.xml')
    assert [(item.account, item.secret) for item in result] == [('localadmin', 'RealSecret!')]


def test_literal_password_is_not_rewritten_and_templates_are_ignored():
    data = b'[Settings]\nPassword=$tr0ng!\nApiKey=prefix-${RuntimeKey}\nUserPassword=prefix-%RuntimePassword%\n'
    assert [item.secret for item in extract_credentials(data, source='Bootstrap.ini')] == ['$tr0ng!']
    data = b'[Settings]\nPassword=\'EndsWithQuote\'\n'
    assert extract_credentials(data, source='Bootstrap.ini')[0].secret == "'EndsWithQuote'"


def test_scripts_and_binary_are_explicitly_not_interpreted():
    for filename in ('join.ps1', 'startnet.cmd', 'setup.bat', 'boot.ipxe'):
        result = inspect_credentials(b'$Password = Get-Secret\n', source=filename)
        assert not result.credentials and result.limitation == 'script non interprété'
    result = inspect_credentials(b'\xff\x01' * 50, source='variables.dat')
    assert result.limitation and not result.credentials


def test_protected_unattend_and_invalid_xml_have_a_coverage_limit():
    result = inspect_credentials(b'<Password><Value>encoded</Value><PlainText>false</PlainText></Password>', source='Unattend.xml')
    # Password can also be the document root.
    assert not result.credentials and result.limitation
    result = inspect_credentials(b'<Unattend><Password><Value>encoded</Value><PlainText>false</PlainText></Password></Unattend>', source='Unattend.xml')
    assert result.limitation == 'valeurs protégées non décodées'
    assert inspect_credentials(b'<broken', source='Unattend.xml').limitation == 'XML invalide'
