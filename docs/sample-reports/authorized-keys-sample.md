# Authorized Keys Audit Report

**Generated at:** `2026-06-07T07:18:38.363212+00:00`
**Target:** `examples/authorized_keys_sample`

## Executive Summary

- Total keys: **3**
- Valid keys: **3**
- Invalid keys: **0**
- Suspicious keys: **2**

## Keys Review

### Line 1 — VALID

- **Type:** `ssh-ed25519`
- **Fingerprint:** `SHA256:n4rakPO6w6CYuTyBE/WxA5RpVJYWjzeUXFHRnzU7bC4`
- **Key preview:** `AAAAC3NzaC1lZDI1NTE5...`
- **Comment:** `lamya@admin-laptop`
- **Suspicious:** `False`

### Line 2 — VALID

- **Type:** `ssh-ed25519`
- **Fingerprint:** `SHA256:1fvK7SD4/uHk/b9+I2bdeMctGuIqd4+PJ+BwUB18NeE`
- **Key preview:** `AAAAC3NzaC1lZDI1NTE5...`
- **Comment:** `old-provider@agency`
- **Suspicious:** `True`
- **Risk:** Key comment may indicate old, external, test, or unmanaged access.

### Line 3 — VALID

- **Type:** `ssh-rsa`
- **Fingerprint:** `SHA256:C0BebhDDd0Hmo3ZGHdaw3sW7un8seOOiwB3DKx+RuYs`
- **Key preview:** `AAAAB3NzaC1yc2EAAAAD...`
- **Comment:** `test-key`
- **Suspicious:** `True`
- **Risk:** Key comment may indicate old, external, test, or unmanaged access.
