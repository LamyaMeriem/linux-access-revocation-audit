from src.authorized_keys import is_suspicious_comment, parse_authorized_keys


def test_parse_authorized_keys_extracts_key_information():
    content = """
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyExample lamya@admin-laptop
"""

    keys = parse_authorized_keys(content)

    assert len(keys) == 1
    assert keys[0]["status"] == "valid"
    assert keys[0]["type"] == "ssh-ed25519"
    assert keys[0]["comment"] == "lamya@admin-laptop"


def test_authorized_keys_detects_suspicious_provider_comment():
    content = """
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyExample old-provider@agency
"""

    keys = parse_authorized_keys(content)

    assert len(keys) == 1
    assert keys[0]["suspicious"] is True


def test_authorized_keys_detects_invalid_line():
    content = """
not-a-valid-key-line
"""

    keys = parse_authorized_keys(content)

    assert len(keys) == 1
    assert keys[0]["status"] == "invalid"


def test_suspicious_comment_detection():
    assert is_suspicious_comment("old-provider@agency") is True
    assert is_suspicious_comment("test-key") is True
    assert is_suspicious_comment("lamya@admin-laptop") is False