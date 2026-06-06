from src.audit import audit_sshd_config, calculate_score, parse_sshd_config


def test_parse_sshd_config_reads_valid_directives():
    content = """
# SSH server configuration
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowGroups ssh-users admins
"""

    config = parse_sshd_config(content)

    assert config["permitrootlogin"] == "no"
    assert config["passwordauthentication"] == "no"
    assert config["pubkeyauthentication"] == "yes"
    assert config["allowgroups"] == "ssh-users admins"


def test_secure_ssh_config_has_no_critical_findings():
    config = {
        "permitrootlogin": "no",
        "passwordauthentication": "no",
        "pubkeyauthentication": "yes",
        "allowgroups": "ssh-users",
    }

    findings = audit_sshd_config(config)

    critical_findings = [
        finding for finding in findings
        if finding["severity"] == "CRITICAL"
    ]

    assert len(critical_findings) == 0


def test_insecure_ssh_config_detects_critical_findings():
    config = {
        "permitrootlogin": "yes",
        "passwordauthentication": "yes",
        "pubkeyauthentication": "yes",
    }

    findings = audit_sshd_config(config)

    critical_controls = [
        finding["control"] for finding in findings
        if finding["severity"] == "CRITICAL"
    ]

    assert "PermitRootLogin" in critical_controls
    assert "PasswordAuthentication" in critical_controls


def test_score_decreases_when_findings_are_critical_or_warning():
    findings = [
        {"severity": "CRITICAL"},
        {"severity": "WARNING"},
        {"severity": "OK"},
    ]

    score = calculate_score(findings)

    assert score < 100