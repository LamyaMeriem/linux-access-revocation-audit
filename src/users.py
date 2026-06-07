SHELLS_DISABLED = {
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
}


def parse_passwd(content: str) -> list[dict]:
    users = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split(":")

        if len(parts) != 7:
            users.append(
                {
                    "line": line_number,
                    "status": "invalid",
                    "raw": line,
                    "reason": "Invalid passwd entry format.",
                }
            )
            continue

        username, _, uid, gid, gecos, home, shell = parts

        try:
            uid_int = int(uid)
        except ValueError:
            uid_int = -1

        is_interactive = uid_int >= 1000 and shell not in SHELLS_DISABLED

        users.append(
            {
                "line": line_number,
                "status": "valid",
                "username": username,
                "uid": uid_int,
                "gid": gid,
                "gecos": gecos,
                "home": home,
                "shell": shell,
                "is_interactive": is_interactive,
            }
        )

    return users


def parse_group(content: str) -> dict:
    groups = {}

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split(":")

        if len(parts) != 4:
            continue

        group_name, _, gid, members = parts

        groups[group_name] = {
            "gid": gid,
            "members": [member for member in members.split(",") if member],
        }

    return groups


def audit_users(users: list[dict], groups: dict) -> list[dict]:
    findings = []

    sudo_members = set(groups.get("sudo", {}).get("members", []))
    ssh_users = set(groups.get("ssh-users", {}).get("members", []))

    for user in users:
        if user["status"] == "invalid":
            findings.append(
                {
                    "severity": "WARNING",
                    "control": "passwd format",
                    "message": f"Invalid passwd entry at line {user['line']}.",
                    "recommendation": "Review the passwd file format.",
                }
            )
            continue

        username = user["username"]

        if user["is_interactive"]:
            findings.append(
                {
                    "severity": "INFO",
                    "control": "interactive user",
                    "message": f"Interactive Linux user detected: {username}.",
                    "recommendation": "Verify that this account still has a valid business owner.",
                }
            )

        if username in sudo_members:
            severity = "CRITICAL" if username in ssh_users else "WARNING"

            findings.append(
                {
                    "severity": severity,
                    "control": "sudo privileges",
                    "message": f"User {username} belongs to the sudo group.",
                    "recommendation": "Confirm that sudo access is justified and still required.",
                }
            )

        suspicious_words = ["old", "provider", "external", "freelance", "test"]

        if any(word in username.lower() for word in suspicious_words):
            findings.append(
                {
                    "severity": "WARNING",
                    "control": "suspicious account name",
                    "message": f"Account name may indicate unmanaged or former access: {username}.",
                    "recommendation": "Confirm whether this account should still exist.",
                }
            )

    return findings


def print_users_report(users: list[dict], findings: list[dict]) -> None:
    print("\n===== Linux Users Audit =====")

    print("\nUsers:")
    for user in users:
        if user["status"] == "invalid":
            print(f"[WARNING] Invalid entry line {user['line']}")
            continue

        user_type = "interactive" if user["is_interactive"] else "system/non-login"
        print(f"- {user['username']} | UID={user['uid']} | shell={user['shell']} | {user_type}")

    print("\nFindings:")
    for finding in findings:
        print(f"[{finding['severity']}] {finding['control']} - {finding['message']}")