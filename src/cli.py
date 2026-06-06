import argparse
from pathlib import Path
from audit import audit_sshd_config, calculate_score, parse_sshd_config, print_audit_report
from report import build_authorized_keys_report, build_ssh_config_report, write_json_report
from authorized_keys import parse_authorized_keys, print_authorized_keys_report


def run_ssh_config_audit(config_path: str, output_path: str | None = None) -> None:
    path = Path(config_path)

    if not path.exists():
        print(f"[ERROR] SSH config file not found: {path}")
        return

    content = path.read_text(encoding="utf-8", errors="ignore")
    parsed_config = parse_sshd_config(content)
    findings = audit_sshd_config(parsed_config)

    print_audit_report(path, parsed_config, findings)

    if output_path:
        score = calculate_score(findings)
        report = build_ssh_config_report(
            config_path=str(path),
            parsed_config=parsed_config,
            findings=findings,
            score=score,
        )
        write_json_report(report, output_path)
        print(f"\n[OK] JSON report generated: {output_path}")


def run_authorized_keys_audit(file_path: str, output_path: str | None = None) -> None:
    path = Path(file_path)

    if not path.exists():
        print(f"[ERROR] authorized_keys file not found: {path}")
        return

    content = path.read_text(encoding="utf-8", errors="ignore")
    keys = parse_authorized_keys(content)

    print_authorized_keys_report(keys)

    if output_path:
        report = build_authorized_keys_report(
            file_path=str(path),
            keys=keys,
        )
        write_json_report(report, output_path)
        print(f"\n[OK] JSON report generated: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Linux Access Governance Audit CLI"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    ssh_parser = subparsers.add_parser(
        "ssh-config",
        help="Audit SSH server configuration."
    )

    ssh_parser.add_argument(
        "--config",
        required=True,
        help="Path to sshd_config file."
    )

    ssh_parser.add_argument(
        "--output",
        required=False,
        help="Path to JSON output report."
    )

    keys_parser = subparsers.add_parser(
        "authorized-keys",
        help="Audit SSH authorized_keys file."
    )

    keys_parser.add_argument(
        "--file",
        required=True,
        help="Path to authorized_keys file."
    )
    keys_parser.add_argument(
        "--output",
        required=False,
        help="Path to JSON output report."
    )
    args = parser.parse_args()

    if args.command == "ssh-config":
        run_ssh_config_audit(args.config, args.output)

    elif args.command == "authorized-keys":
        run_authorized_keys_audit(args.file, args.output)


if __name__ == "__main__":
    main()