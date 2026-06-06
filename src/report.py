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