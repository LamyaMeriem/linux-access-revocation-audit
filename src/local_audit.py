from pathlib import Path

from audit import audit_sshd_config, calculate_score, parse_sshd_config
from authorized_keys import parse_authorized_keys
from local_sources import collect_local_sources
from report import (
    build_authorized_keys_report,
    build_full_audit_report,
    build_ssh_config_report,
    build_users_report,
)
from users import audit_users, parse_group, parse_passwd


def read_file_safely(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def build_missing_ssh_config_report(path: str) -> dict:
    findings = [
        {
            "severity": "WARNING",
            "control": "SSH config source",
            "message": f"SSH configuration file was not found or not readable: {path}",
            "recommendation": "Run this audit on a real Linux server with OpenSSH installed.",
        }
    ]

    return build_ssh_config_report(
        config_path=path,
        parsed_config={},
        findings=findings,
        score=calculate_score(findings),
    )


def run_local_audit() -> dict:
    sources = collect_local_sources()

    ssh_source = sources["ssh_config"]

    if ssh_source["readable"]:
        ssh_content = read_file_safely(ssh_source["path"])
        parsed_config = parse_sshd_config(ssh_content)
        ssh_findings = audit_sshd_config(parsed_config)

        ssh_report = build_ssh_config_report(
            config_path=ssh_source["path"],
            parsed_config=parsed_config,
            findings=ssh_findings,
            score=calculate_score(ssh_findings),
        )
    else:
        ssh_report = build_missing_ssh_config_report(ssh_source["path"])

    keys = []

    for key_source in sources["authorized_keys"]:
        if not key_source["readable"]:
            continue

        content = read_file_safely(key_source["path"])
        parsed_keys = parse_authorized_keys(content)

        for key in parsed_keys:
            key["source_file"] = key_source["path"]

        keys.extend(parsed_keys)

    authorized_keys_report = build_authorized_keys_report(
        file_path="local authorized_keys discovery",
        keys=keys,
    )

    passwd_source = sources["passwd"]
    group_source = sources["group"]

    if passwd_source["readable"] and group_source["readable"]:
        users = parse_passwd(read_file_safely(passwd_source["path"]))
        groups = parse_group(read_file_safely(group_source["path"]))
        user_findings = audit_users(users, groups)
    else:
        users = []
        user_findings = [
            {
                "severity": "WARNING",
                "control": "Linux users source",
                "message": "passwd or group file was not found or not readable.",
                "recommendation": "Run this audit on a Linux system with readable /etc/passwd and /etc/group.",
            }
        ]

    users_report = build_users_report(
        passwd_path=passwd_source["path"],
        group_path=group_source["path"],
        users=users,
        findings=user_findings,
    )

    return build_full_audit_report(
        ssh_report=ssh_report,
        authorized_keys_report=authorized_keys_report,
        users_report=users_report,
    )


def print_local_audit_summary(report: dict) -> None:
    print("\n===== Local Linux Access Governance Audit =====")
    print(f"Governance score: {report['governance_score']}/100")

    print("\nSummary:")
    for key, value in report["summary"].items():
        print(f"- {key}: {value}")