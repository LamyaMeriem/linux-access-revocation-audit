import base64
import hashlib


SUSPICIOUS_KEYWORDS = [
    "old",
    "provider",
    "agency",
    "external",
    "freelance",
    "test",
    "backup",
]


def calculate_fingerprint(key_body: str) -> str:
    try:
        missing_padding = len(key_body) % 4
        if missing_padding:
            key_body += "=" * (4 - missing_padding)

        decoded_key = base64.b64decode(key_body.encode(), validate=True)
        digest = hashlib.sha256(decoded_key).digest()
        fingerprint = base64.b64encode(digest).decode().rstrip("=")

        return f"SHA256:{fingerprint}"

    except Exception:
        return "INVALID_KEY"


def parse_authorized_keys(content: str) -> list[dict]:
    keys = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split()

        if len(parts) < 2:
            keys.append(
                {
                    "line": line_number,
                    "status": "invalid",
                    "reason": "Line does not contain a valid SSH key structure.",
                    "raw": line,
                }
            )
            continue

        key_type = parts[0]
        key_body = parts[1]
        comment = " ".join(parts[2:]) if len(parts) > 2 else ""
        fingerprint = calculate_fingerprint(key_body)

        status = "valid" if fingerprint != "INVALID_KEY" else "invalid"

        if status == "invalid":
            keys.append(
                {
                    "line": line_number,
                    "status": "invalid",
                    "reason": "SSH key body is not valid base64.",
                    "raw": line,
                }
            )
            continue

        keys.append(
            {
                "line": line_number,
                "status": "valid",
                "type": key_type,
                "key_preview": key_body[:20] + "...",
                "fingerprint": fingerprint,
                "comment": comment,
                "suspicious": is_suspicious_comment(comment),
            }
        )

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
        print(f"Fingerprint: {key['fingerprint']}")
        print(f"Key preview: {key['key_preview']}")
        print(f"Comment: {key['comment'] or 'No comment'}")

        if key["suspicious"]:
            print("Risk: key comment contains suspicious or unmanaged ownership indicators.")


def main() -> None:
    from pathlib import Path

    path = Path("examples/authorized_keys_sample")

    if not path.exists():
        print(f"[ERROR] File not found: {path}")
        return

    content = path.read_text(encoding="utf-8", errors="ignore")
    keys = parse_authorized_keys(content)

    print_authorized_keys_report(keys)


if __name__ == "__main__":
    main()