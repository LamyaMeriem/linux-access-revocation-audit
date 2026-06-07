from src.users import audit_users, parse_group, parse_passwd


def test_parse_passwd_detects_interactive_users():
    content = """
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
lamya:x:1000:1000:Lamya Admin:/home/lamya:/bin/bash
deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash
"""

    users = parse_passwd(content)

    interactive_users = [
        user["username"]
        for user in users
        if user["status"] == "valid" and user["is_interactive"]
    ]

    assert "lamya" in interactive_users
    assert "deploy" in interactive_users
    assert "www-data" not in interactive_users


def test_parse_group_extracts_members():
    content = """
sudo:x:27:lamya,old-provider
ssh-users:x:1002:lamya,deploy,old-provider
"""

    groups = parse_group(content)

    assert groups["sudo"]["members"] == ["lamya", "old-provider"]
    assert "old-provider" in groups["ssh-users"]["members"]


def test_audit_users_detects_sudo_and_ssh_risk():
    passwd_content = """
lamya:x:1000:1000:Lamya Admin:/home/lamya:/bin/bash
old-provider:x:1002:1002:Old Provider:/home/old-provider:/bin/bash
"""

    group_content = """
sudo:x:27:old-provider
ssh-users:x:1002:old-provider
"""

    users = parse_passwd(passwd_content)
    groups = parse_group(group_content)
    findings = audit_users(users, groups)

    critical_messages = [
        finding["message"]
        for finding in findings
        if finding["severity"] == "CRITICAL"
    ]

    assert any("old-provider belongs to the sudo group" in message for message in critical_messages)


def test_audit_users_detects_suspicious_account_name():
    passwd_content = """
old-provider:x:1002:1002:Old Provider:/home/old-provider:/bin/bash
"""

    group_content = """
sudo:x:27:
ssh-users:x:1002:old-provider
"""

    users = parse_passwd(passwd_content)
    groups = parse_group(group_content)
    findings = audit_users(users, groups)

    suspicious_findings = [
        finding for finding in findings
        if finding["control"] == "suspicious account name"
    ]

    assert len(suspicious_findings) == 1
    assert suspicious_findings[0]["severity"] == "WARNING"


def test_parse_passwd_detects_invalid_entries():
    content = """
invalid-passwd-line
"""

    users = parse_passwd(content)

    assert len(users) == 1
    assert users[0]["status"] == "invalid"