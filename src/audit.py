import argparse
from pathlib import Path


def parse_sshd_config(content: str) -> dict:
    config = {}

    for line in content.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        parts = line.split(None, 1)

        if len(parts) == 2:
            key = parts[0].lower()
            value = parts[1].strip().lower()
            config[key] = value

    return config


def audit_sshd_config(config: dict) -> list[dict]:
    findings = []

    if config.get("permitrootlogin") == "no":
        findings.append({
            "severity": "OK",
            "control": "PermitRootLogin",
            "message": "Root SSH login is disabled."
        })
    else:
        findings.append({
            "severity": "CRITICAL",
            "control": "PermitRootLogin",
            "message": "Root SSH login is not explicitly disabled."
        })

    if config.get("passwordauthentication") == "no":
        findings.append({
            "severity": "OK",
            "control": "PasswordAuthentication",
            "message": "Password-based SSH authentication is disabled."
        })
    else:
        findings.append({
            "severity": "CRITICAL",
            "control": "PasswordAuthentication",
            "message": "Password-based SSH authentication is not disabled."
        })

    if config.get("pubkeyauthentication", "yes") == "yes":
        findings.append({
            "severity": "OK",
            "control": "PubkeyAuthentication",
            "message": "SSH public key authentication is enabled."
        })
    else:
        findings.append({
            "severity": "WARNING",
            "control": "PubkeyAuthentication",
            "message": "SSH public key authentication is disabled or not confirmed."
        })

    if "allowusers" in config or "allowgroups" in config:
        findings.append({
            "severity": "OK",
            "control": "SSH access restriction",
            "message": "SSH access is restricted with AllowUsers or AllowGroups."
        })
    else:
        findings.append({
            "severity": "WARNING",
            "control": "SSH access restriction",
            "message": "No AllowUsers or AllowGroups restriction found."
        })

    return findings


def print_audit_report(config_path: Path, parsed_config: dict, findings: list[dict]) -> None:
    score = calculate_score(findings)

    critical_count = len([finding for finding in findings if finding["severity"] == "CRITICAL"])
    warning_count = len([finding for finding in findings if finding["severity"] == "WARNING"])
    ok_count = len([finding for finding in findings if finding["severity"] == "OK"])

    print(f"\n===== SSH Audit Report: {config_path} =====")

    print("\nSecurity score:")
    print(f"{score}/100")

    print("\nSummary:")
    print(f"CRITICAL: {critical_count}")
    print(f"WARNING: {warning_count}")
    print(f"OK: {ok_count}")

    print("\nParsed SSH config:")
    print(parsed_config)

    print("\nAudit findings:")
    for finding in findings:
        print(f"[{finding['severity']}] {finding['control']} - {finding['message']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit SSH server configuration for access revocation risks."
    )

    parser.add_argument(
        "--config",
        required=True,
        help="Path to the sshd_config file to audit."
    )

    args = parser.parse_args()

    config_path = Path(args.config)

    if not config_path.exists():
        print(f"[ERROR] File not found: {config_path}")
        return

    content = config_path.read_text(encoding="utf-8", errors="ignore")

    parsed_config = parse_sshd_config(content)
    findings = audit_sshd_config(parsed_config)

    print_audit_report(config_path, parsed_config, findings)

def calculate_score(findings: list[dict]) -> int:
    score = 100

    for finding in findings:
        if finding["severity"] == "CRITICAL":
            score -= 25
        elif finding["severity"] == "WARNING":
            score -= 10

    return max(score, 0)


if __name__ == "__main__":
    main()