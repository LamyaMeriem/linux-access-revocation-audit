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
    build_full_audit_markdown_report,
    build_full_audit_report,
)
from local_audit import print_local_audit_summary, run_local_audit
from authorized_keys import parse_authorized_keys, print_authorized_keys_report
from users import audit_users, parse_group, parse_passwd, print_users_report
from local_sources import collect_local_sources, print_local_sources_report
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

def run_full_audit(
    ssh_config_path: str,
    authorized_keys_path: str,
    passwd_path: str,
    group_path: str,
    output_path: str | None = None,
    markdown_path: str | None = None,
) -> None:
    ssh_config_file = Path(ssh_config_path)
    authorized_keys_file = Path(authorized_keys_path)
    passwd_file = Path(passwd_path)
    group_file = Path(group_path)

    for file_path in [ssh_config_file, authorized_keys_file, passwd_file, group_file]:
        if not file_path.exists():
            print(f"[ERROR] File not found: {file_path}")
            return

    parsed_config = parse_sshd_config(
        ssh_config_file.read_text(encoding="utf-8", errors="ignore")
    )
    ssh_findings = audit_sshd_config(parsed_config)
    ssh_score = calculate_score(ssh_findings)

    ssh_report = build_ssh_config_report(
        config_path=str(ssh_config_file),
        parsed_config=parsed_config,
        findings=ssh_findings,
        score=ssh_score,
    )

    keys = parse_authorized_keys(
        authorized_keys_file.read_text(encoding="utf-8", errors="ignore")
    )
    keys_report = build_authorized_keys_report(
        file_path=str(authorized_keys_file),
        keys=keys,
    )

    users = parse_passwd(
        passwd_file.read_text(encoding="utf-8", errors="ignore")
    )
    groups = parse_group(
        group_file.read_text(encoding="utf-8", errors="ignore")
    )
    user_findings = audit_users(users, groups)

    users_report = build_users_report(
        passwd_path=str(passwd_file),
        group_path=str(group_file),
        users=users,
        findings=user_findings,
    )

    full_report = build_full_audit_report(
        ssh_report=ssh_report,
        authorized_keys_report=keys_report,
        users_report=users_report,
    )

    print("\n===== Linux Access Governance Full Audit =====")
    print(f"Governance score: {full_report['governance_score']}/100")
    print("\nSummary:")
    for key, value in full_report["summary"].items():
        print(f"- {key}: {value}")

    if output_path:
        write_json_report(full_report, output_path)
        print(f"\n[OK] JSON report generated: {output_path}")

    if markdown_path:
        markdown = build_full_audit_markdown_report(full_report)
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
    full_parser = subparsers.add_parser(
        "full-audit",
        help="Run a complete Linux access governance audit."
    )

    full_parser.add_argument(
        "--ssh-config",
        required=True,
        help="Path to sshd_config file."
    )

    full_parser.add_argument(
        "--authorized-keys",
        required=True,
        help="Path to authorized_keys file."
    )

    full_parser.add_argument(
        "--passwd",
        required=True,
        help="Path to passwd file."
    )

    full_parser.add_argument(
        "--group",
        required=True,
        help="Path to group file."
    )

    full_parser.add_argument(
        "--output",
        required=False,
        help="Path to JSON output report."
    )

    full_parser.add_argument(
        "--markdown",
        required=False,
        help="Path to Markdown output report."
    )
    subparsers.add_parser(
        "local-sources",
        help="Discover local Linux audit source files."
    )

    local_audit_parser = subparsers.add_parser(
        "local-audit",
        help="Run a read-only audit on the local Linux system.",
    )

    local_audit_parser.add_argument(
        "--output",
        required=False,
        help="Path to JSON output report.",
    )

    local_audit_parser.add_argument(
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
    elif args.command == "full-audit":
        run_full_audit(
            args.ssh_config,
            args.authorized_keys,
            args.passwd,
            args.group,
            args.output,
            args.markdown,
        )
    elif args.command == "local-sources":
        sources = collect_local_sources()
        print_local_sources_report(sources)
    elif args.command == "local-audit":
        report = run_local_audit()
        print_local_audit_summary(report)

        if args.output:
            write_json_report(report, args.output)
            print(f"\n[OK] JSON report generated: {args.output}")

        if args.markdown:
            markdown = build_full_audit_markdown_report(report)
            write_markdown_report(markdown, args.markdown)
            print(f"[OK] Markdown report generated: {args.markdown}")

if __name__ == "__main__":
    main()