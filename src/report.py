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
    suspicious_keys = [
        key for key in valid_keys
        if key.get("suspicious") is True
    ]

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