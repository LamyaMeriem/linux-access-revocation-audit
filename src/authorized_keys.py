from pathlib import Path


SUSPICIOUS_KEYWORDS = [
    "old",
    "provider",
    "agency",
    "external",
    "freelance",
    "test",
    "backup",
]


def parse_authorized_keys(content: str) -> list[dict]:
    keys = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split()

        if len(parts) < 2:
            keys.append({
                "line": line_number,
                "status": "invalid",
                "reason": "Line does not contain a valid SSH key structure.",
                "raw": line,
            })
            continue

        key_type = parts[0]
        key_body = parts[1]
        comment = " ".join(parts[2:]) if len(parts) > 2 else ""

        keys.append({
            "line": line_number,
            "status": "valid",
            "type": key_type,
            "key_preview": key_body[:20] + "...",
            "comment": comment,
            "suspicious": is_suspicious_comment(comment),
        })

    return keys


def is_suspicious_comment(comment: str) -> bool:
    comment_lower = comment.lower()

    return any(keyword in comment_lower for keyword in SUSPICIOUS_KEYWORDS)


def print_authorized_keys_report(keys: list[dict]) -> None:
    print("\n===== Authorized Keys Audit =====")

    if not keys:
        print("No SSH keys found.")
        return

    for key in keys:
        if key["status"] == "invalid":
            print(f"[WARNING] Line {key['line']} - Invalid SSH key format")
            print(f"Reason: {key['reason']}")
            continue

        severity = "WARNING" if key["suspicious"] else "INFO"

        print(f"\n[{severity}] Line {key['line']}")
        print(f"Type: {key['type']}")
        print(f"Key preview: {key['key_preview']}")
        print(f"Comment: {key['comment'] or 'No comment'}")

        if key["suspicious"]:
            print("Risk: key comment contains suspicious or unmanaged ownership indicators.")


def main() -> None:
    path = Path("examples/authorized_keys_sample")

    if not path.exists():
        print(f"[ERROR] File not found: {path}")
        return

    content = path.read_text(encoding="utf-8", errors="ignore")
    keys = parse_authorized_keys(content)

    print_authorized_keys_report(keys)


if __name__ == "__main__":
    main()