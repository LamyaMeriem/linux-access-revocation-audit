import argparse
from pathlib import Path
from audit import audit_sshd_config, calculate_score, parse_sshd_config, print_audit_report
from report import (
    build_authorized_keys_markdown_report,
    build_authorized_keys_report,
    build_ssh_config_markdown_report,
    build_ssh_config_report,
    build_users_markdown_report,
    build_users_report,
    write_json_report,
    write_markdown_report,
)
from authorized_keys import parse_authorized_keys, print_authorized_keys_report
from users import audit_users, parse_group, parse_passwd, print_users_report

def run_ssh_config_audit(
    config_path: str,
    output_path: str | None = None,
    markdown_path: str | None = None,
) -> None:
    path = Path(config_path)

    if not path.exists():
        print(f"[ERROR] SSH config file not found: {path}")
        return

    content = path.read_text(encoding="utf-8", errors="ignore")
    parsed_config = parse_sshd_config(content)
    findings = audit_sshd_config(parsed_config)

    print_audit_report(path, parsed_config, findings)

    if output_path or markdown_path:
        score = calculate_score(findings)
        report = build_ssh_config_report(
            config_path=str(path),
            parsed_config=parsed_config,
            findings=findings,
            score=score,
        )

        if output_path:
            write_json_report(report, output_path)
            print(f"\n[OK] JSON report generated: {output_path}")

        if markdown_path:
            markdown = build_ssh_config_markdown_report(report)
            write_markdown_report(markdown, markdown_path)
            print(f"[OK] Markdown report generated: {markdown_path}")


def run_authorized_keys_audit(
    file_path: str,
    output_path: str | None = None,
    markdown_path: str | None = None,
) -> None:
    path = Path(file_path)

    if not path.exists():
        print(f"[ERROR] authorized_keys file not found: {path}")
        return

    content = path.read_text(encoding="utf-8", errors="ignore")
    keys = parse_authorized_keys(content)

    print_authorized_keys_report(keys)

    if output_path or markdown_path:
        report = build_authorized_keys_report(
            file_path=str(path),
            keys=keys,
        )

        if output_path:
            write_json_report(report, output_path)
            print(f"\n[OK] JSON report generated: {output_path}")

        if markdown_path:
            markdown = build_authorized_keys_markdown_report(report)
            write_markdown_report(markdown, markdown_path)
            print(f"[OK] Markdown report generated: {markdown_path}")

def run_users_audit(
    passwd_path: str,
    group_path: str,
    output_path: str | None = None,
    markdown_path: str | None = None,
) -> None:
    passwd_file = Path(passwd_path)
    group_file = Path(group_path)

    if not passwd_file.exists():
        print(f"[ERROR] passwd file not found: {passwd_file}")
        return

    if not group_file.exists():
        print(f"[ERROR] group file not found: {group_file}")
        return

    users = parse_passwd(
        passwd_file.read_text(encoding="utf-8", errors="ignore")
    )
    groups = parse_group(
        group_file.read_text(encoding="utf-8", errors="ignore")
    )
    findings = audit_users(users, groups)

    print_users_report(users, findings)

    if output_path or markdown_path:
        report = build_users_report(
            passwd_path=str(passwd_file),
            group_path=str(group_file),
            users=users,
            findings=findings,
        )

        if output_path:
            write_json_report(report, output_path)
            print(f"\n[OK] JSON report generated: {output_path}")

        if markdown_path:
            markdown = build_users_markdown_report(report)
            write_markdown_report(markdown, markdown_path)
            print(f"[OK] Markdown report generated: {markdown_path}")

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

    ssh_parser.add_argument(
        "--markdown",
        required=False,
        help="Path to Markdown output report."
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

    keys_parser.add_argument(
        "--markdown",
        required=False,
        help="Path to Markdown output report."
    )

    users_parser = subparsers.add_parser(
        "users",
        help="Audit Linux users and sudo exposure."
    )

    users_parser.add_argument(
        "--passwd",
        required=True,
        help="Path to passwd file."
    )

    users_parser.add_argument(
        "--group",
        required=True,
        help="Path to group file."
    )
    users_parser.add_argument(
        "--output",
        required=False,
        help="Path to JSON output report.",
    )

    users_parser.add_argument(
        "--markdown",
        required=False,
        help="Path to Markdown output report.",
    )
    args = parser.parse_args()

    if args.command == "ssh-config":
        run_ssh_config_audit(args.config, args.output, args.markdown)

    elif args.command == "authorized-keys":
        run_authorized_keys_audit(args.file, args.output, args.markdown)
    elif args.command == "users":
        run_users_audit(
            args.passwd,
            args.group,
            args.output,
            args.markdown,
        )

if __name__ == "__main__":
    main()