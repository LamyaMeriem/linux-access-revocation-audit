# Authorized Keys Audit Report

**Generated at:** `2026-06-06T20:45:47.076230+00:00`
**Target:** `examples/authorized_keys_sample`

## Executive Summary

- Total keys: **3**
- Valid keys: **3**
- Invalid keys: **0**
- Suspicious keys: **2**

## Keys Review

### Line 1 — VALID

- **Type:** `ssh-ed25519`
- **Key preview:** `AAAAC3NzaC1lZDI1NTE5...`
- **Comment:** `lamya@admin-laptop`
- **Suspicious:** `False`

### Line 2 — VALID

- **Type:** `ssh-ed25519`
- **Key preview:** `AAAAC3NzaC1lZDI1NTE5...`
- **Comment:** `old-provider@agency`
- **Suspicious:** `True`
- **Risk:** Key comment may indicate old, external, test, or unmanaged access.

### Line 3 — VALID

- **Type:** `ssh-rsa`
- **Key preview:** `AAAAB3NzaC1yc2EAAAAD...`
- **Comment:** `test-key`
- **Suspicious:** `True`
- **Risk:** Key comment may indicate old, external, test, or unmanaged access.
