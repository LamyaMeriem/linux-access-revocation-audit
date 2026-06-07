import json
from datetime import datetime, timezone
from pathlib import Path


def build_ssh_config_report(
    config_path: str,
    parsed_config: dict,
    findings: list[dict],
    score: int,
) -> dict:
    return {
        "audit_type": "ssh_config",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": config_path,
        "score": score,
        "summary": {
            "critical": len([item for item in findings if item["severity"] == "CRITICAL"]),
            "warning": len([item for item in findings if item["severity"] == "WARNING"]),
            "ok": len([item for item in findings if item["severity"] == "OK"]),
        },
        "parsed_config": parsed_config,
        "findings": findings,
    }


def build_authorized_keys_report(file_path: str, keys: list[dict]) -> dict:
    valid_keys = [key for key in keys if key["status"] == "valid"]
    invalid_keys = [key for key in keys if key["status"] == "invalid"]
    suspicious_keys = [key for key in valid_keys if key.get("suspicious") is True]

    return {
        "audit_type": "authorized_keys",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": file_path,
        "summary": {
            "total_keys": len(keys),
            "valid_keys": len(valid_keys),
            "invalid_keys": len(invalid_keys),
            "suspicious_keys": len(suspicious_keys),
        },
        "keys": keys,
    }


def write_json_report(report: dict, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def build_ssh_config_markdown_report(report: dict) -> str:
    lines = []

    lines.append("# SSH Configuration Audit Report")
    lines.append("")
    lines.append(f"**Generated at:** `{report['generated_at']}`")
    lines.append(f"**Target:** `{report['target']}`")
    lines.append(f"**Security score:** `{report['score']}/100`")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Critical findings: **{report['summary']['critical']}**")
    lines.append(f"- Warnings: **{report['summary']['warning']}**")
    lines.append(f"- Passed checks: **{report['summary']['ok']}**")
    lines.append("")

    lines.append("## Findings")
    lines.append("")

    for severity in ["CRITICAL", "WARNING", "OK"]:
        items = [finding for finding in report["findings"] if finding["severity"] == severity]

        if not items:
            continue

        lines.append(f"### {severity}")
        lines.append("")

        for finding in items:
            lines.append(f"#### {finding['control']}")
            lines.append("")
            lines.append(f"- **Message:** {finding['message']}")

            if finding.get("recommendation"):
                lines.append(f"- **Recommendation:** {finding['recommendation']}")

            lines.append("")

    lines.append("## Parsed SSH Configuration")
    lines.append("")
    lines.append("```text")

    for key, value in sorted(report["parsed_config"].items()):
        lines.append(f"{key} {value}")

    lines.append("```")
    lines.append("")

    return "\n".join(lines)


def build_authorized_keys_markdown_report(report: dict) -> str:
    lines = []

    lines.append("# Authorized Keys Audit Report")
    lines.append("")
    lines.append(f"**Generated at:** `{report['generated_at']}`")
    lines.append(f"**Target:** `{report['target']}`")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Total keys: **{report['summary']['total_keys']}**")
    lines.append(f"- Valid keys: **{report['summary']['valid_keys']}**")
    lines.append(f"- Invalid keys: **{report['summary']['invalid_keys']}**")
    lines.append(f"- Suspicious keys: **{report['summary']['suspicious_keys']}**")
    lines.append("")

    lines.append("## Keys Review")
    lines.append("")

    for key in report["keys"]:
        status = key["status"].upper()
        line_number = key["line"]

        lines.append(f"### Line {line_number} — {status}")
        lines.append("")

        if key["status"] == "invalid":
            lines.append(f"- **Reason:** {key['reason']}")
            lines.append(f"- **Raw:** `{key['raw']}`")
            lines.append("")
            continue

        lines.append(f"- **Type:** `{key['type']}`")
        lines.append(f"- **Fingerprint:** `{key['fingerprint']}`")
        lines.append(f"- **Key preview:** `{key['key_preview']}`")
        lines.append(f"- **Comment:** `{key['comment'] or 'No comment'}`")
        lines.append(f"- **Suspicious:** `{key['suspicious']}`")

        if key["suspicious"]:
            lines.append("- **Risk:** Key comment may indicate old, external, test, or unmanaged access.")

        lines.append("")

    return "\n".join(lines)


def write_markdown_report(content: str, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

def build_users_report(
    passwd_path: str,
    group_path: str,
    users: list[dict],
    findings: list[dict],
) -> dict:
    valid_users = [user for user in users if user["status"] == "valid"]
    invalid_users = [user for user in users if user["status"] == "invalid"]
    interactive_users = [
        user for user in valid_users
        if user["is_interactive"]
    ]

    return {
        "audit_type": "linux_users",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": {
            "passwd": passwd_path,
            "group": group_path,
        },
        "summary": {
            "total_users": len(users),
            "valid_users": len(valid_users),
            "invalid_users": len(invalid_users),
            "interactive_users": len(interactive_users),
            "critical": len(
                [item for item in findings if item["severity"] == "CRITICAL"]
            ),
            "warning": len(
                [item for item in findings if item["severity"] == "WARNING"]
            ),
            "info": len(
                [item for item in findings if item["severity"] == "INFO"]
            ),
        },
        "users": users,
        "findings": findings,
    }


def build_users_markdown_report(report: dict) -> str:
    lines = []

    lines.append("# Linux Users and Sudo Audit Report")
    lines.append("")
    lines.append(f"**Generated at:** `{report['generated_at']}`")
    lines.append(f"**Passwd source:** `{report['targets']['passwd']}`")
    lines.append(f"**Group source:** `{report['targets']['group']}`")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Total users: **{report['summary']['total_users']}**")
    lines.append(f"- Valid users: **{report['summary']['valid_users']}**")
    lines.append(f"- Invalid users: **{report['summary']['invalid_users']}**")
    lines.append(
        f"- Interactive users: **{report['summary']['interactive_users']}**"
    )
    lines.append(f"- Critical findings: **{report['summary']['critical']}**")
    lines.append(f"- Warnings: **{report['summary']['warning']}**")
    lines.append(f"- Info findings: **{report['summary']['info']}**")
    lines.append("")

    lines.append("## Users")
    lines.append("")

    for user in report["users"]:
        if user["status"] == "invalid":
            lines.append(f"### Invalid entry line {user['line']}")
            lines.append("")
            lines.append(f"- **Reason:** {user['reason']}")
            lines.append(f"- **Raw:** `{user['raw']}`")
            lines.append("")
            continue

        user_type = "interactive" if user["is_interactive"] else "system/non-login"

        lines.append(f"### {user['username']}")
        lines.append("")
        lines.append(f"- **UID:** `{user['uid']}`")
        lines.append(f"- **Home:** `{user['home']}`")
        lines.append(f"- **Shell:** `{user['shell']}`")
        lines.append(f"- **Type:** `{user_type}`")
        lines.append("")

    lines.append("## Findings")
    lines.append("")

    for severity in ["CRITICAL", "WARNING", "INFO"]:
        items = [
            finding for finding in report["findings"]
            if finding["severity"] == severity
        ]

        if not items:
            continue

        lines.append(f"### {severity}")
        lines.append("")

        for finding in items:
            lines.append(f"#### {finding['control']}")
            lines.append("")
            lines.append(f"- **Message:** {finding['message']}")
            lines.append(f"- **Recommendation:** {finding['recommendation']}")
            lines.append("")

    return "\n".join(lines)

def build_full_audit_report(
    ssh_report: dict,
    authorized_keys_report: dict,
    users_report: dict,
) -> dict:
    user_critical = users_report["summary"]["critical"]
    user_warning = users_report["summary"]["warning"]
    suspicious_keys = authorized_keys_report["summary"]["suspicious_keys"]
    invalid_keys = authorized_keys_report["summary"]["invalid_keys"]

    governance_score = ssh_report["score"]
    governance_score -= user_critical * 15
    governance_score -= user_warning * 5
    governance_score -= suspicious_keys * 10
    governance_score -= invalid_keys * 5
    governance_score = max(governance_score, 0)

    return {
        "audit_type": "full_access_governance",
        "generated_at": ssh_report["generated_at"],
        "governance_score": governance_score,
        "summary": {
            "ssh_critical": ssh_report["summary"]["critical"],
            "ssh_warning": ssh_report["summary"]["warning"],
            "suspicious_ssh_keys": suspicious_keys,
            "invalid_ssh_keys": invalid_keys,
            "users_critical": user_critical,
            "users_warning": user_warning,
            "interactive_users": users_report["summary"]["interactive_users"],
        },
        "modules": {
            "ssh_config": ssh_report,
            "authorized_keys": authorized_keys_report,
            "users": users_report,
        },
    }


def build_full_audit_markdown_report(report: dict) -> str:
    lines = []

    lines.append("# Linux Access Governance Full Audit Report")
    lines.append("")
    lines.append(f"**Generated at:** `{report['generated_at']}`")
    lines.append(f"**Governance score:** `{report['governance_score']}/100`")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- SSH critical findings: **{report['summary']['ssh_critical']}**")
    lines.append(f"- SSH warnings: **{report['summary']['ssh_warning']}**")
    lines.append(f"- Suspicious SSH keys: **{report['summary']['suspicious_ssh_keys']}**")
    lines.append(f"- Invalid SSH keys: **{report['summary']['invalid_ssh_keys']}**")
    lines.append(f"- Users critical findings: **{report['summary']['users_critical']}**")
    lines.append(f"- Users warnings: **{report['summary']['users_warning']}**")
    lines.append(f"- Interactive users: **{report['summary']['interactive_users']}**")
    lines.append("")

    lines.append("## Key Question")
    lines.append("")
    lines.append("> Who can still access this Linux server, how, and with which privileges?")
    lines.append("")

    lines.append("## SSH Configuration Findings")
    lines.append("")

    for finding in report["modules"]["ssh_config"]["findings"]:
        lines.append(f"- **[{finding['severity']}] {finding['control']}** — {finding['message']}")

    lines.append("")
    lines.append("## Authorized Keys Review")
    lines.append("")

    for key in report["modules"]["authorized_keys"]["keys"]:
        if key["status"] == "invalid":
            lines.append(f"- **[WARNING] Line {key['line']}** — invalid SSH key entry")
            continue

        severity = "WARNING" if key["suspicious"] else "INFO"
        lines.append(
            f"- **[{severity}] Line {key['line']}** — "
            f"{key['type']} — `{key['fingerprint']}` — `{key['comment'] or 'No comment'}`"
        )

    lines.append("")
    lines.append("## Users and Sudo Findings")
    lines.append("")

    for finding in report["modules"]["users"]["findings"]:
        lines.append(f"- **[{finding['severity']}] {finding['control']}** — {finding['message']}")

    lines.append("")
    lines.append("## Recommended Next Actions")
    lines.append("")

    lines.append("- Review all suspicious SSH keys and confirm ownership.")
    lines.append("- Remove unmanaged or obsolete keys from `authorized_keys`.")
    lines.append("- Confirm every interactive Linux account has a valid business owner.")
    lines.append("- Review all users with sudo privileges.")
    lines.append("- Disable direct root SSH login.")
    lines.append("- Disable password-based SSH authentication when key-based access is validated.")
    lines.append("- Restrict SSH access with `AllowUsers` or `AllowGroups`.")
    lines.append("")

    return "\n".join(lines)