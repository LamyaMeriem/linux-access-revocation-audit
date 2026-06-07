from pathlib import Path


def is_readable_file(path: Path) -> bool:
    return path.exists() and path.is_file()


def discover_authorized_keys_files() -> list[dict]:
    results = []

    search_roots = [
        Path("/home"),
        Path("/root"),
    ]

    for root in search_roots:
        if not root.exists():
            continue

        if root == Path("/root"):
            candidate = root / ".ssh" / "authorized_keys"

            results.append(
                {
                    "path": str(candidate),
                    "exists": candidate.exists(),
                    "readable": is_readable_file(candidate),
                }
            )
            continue

        for home_dir in root.iterdir():
            if not home_dir.is_dir():
                continue

            candidate = home_dir / ".ssh" / "authorized_keys"

            results.append(
                {
                    "path": str(candidate),
                    "exists": candidate.exists(),
                    "readable": is_readable_file(candidate),
                }
            )

    return results


def collect_local_sources() -> dict:
    ssh_config = Path("/etc/ssh/sshd_config")
    passwd_file = Path("/etc/passwd")
    group_file = Path("/etc/group")

    return {
        "ssh_config": {
            "path": str(ssh_config),
            "exists": ssh_config.exists(),
            "readable": is_readable_file(ssh_config),
        },
        "passwd": {
            "path": str(passwd_file),
            "exists": passwd_file.exists(),
            "readable": is_readable_file(passwd_file),
        },
        "group": {
            "path": str(group_file),
            "exists": group_file.exists(),
            "readable": is_readable_file(group_file),
        },
        "authorized_keys": discover_authorized_keys_files(),
    }


def print_local_sources_report(sources: dict) -> None:
    print("\n===== Local Linux Audit Sources =====")

    for name in ["ssh_config", "passwd", "group"]:
        source = sources[name]
        status = "FOUND" if source["readable"] else "MISSING"

        print(f"\n[{status}] {name}")
        print(f"Path: {source['path']}")

    print("\nAuthorized keys files:")

    if not sources["authorized_keys"]:
        print("No authorized_keys candidates found.")
        return

    for item in sources["authorized_keys"]:
        status = "FOUND" if item["readable"] else "MISSING"
        print(f"[{status}] {item['path']}")