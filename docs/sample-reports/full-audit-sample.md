# Linux Access Governance Full Audit Report

**Generated at:** `2026-06-07T07:10:28.348826+00:00`
**Governance score:** `0/100`

## Executive Summary

- SSH critical findings: **2**
- SSH warnings: **1**
- Suspicious SSH keys: **2**
- Invalid SSH keys: **0**
- Users critical findings: **2**
- Users warnings: **1**
- Interactive users: **3**

## Key Question

> Who can still access this Linux server, how, and with which privileges?

## SSH Configuration Findings

- **[CRITICAL] PermitRootLogin** — Root SSH login is not explicitly disabled.
- **[CRITICAL] PasswordAuthentication** — Password-based SSH authentication is not disabled.
- **[OK] PubkeyAuthentication** — SSH public key authentication is enabled.
- **[WARNING] SSH access restriction** — No AllowUsers or AllowGroups restriction found.

## Authorized Keys Review

- **[INFO] Line 1** — ssh-ed25519 — `lamya@admin-laptop`
- **[WARNING] Line 2** — ssh-ed25519 — `old-provider@agency`
- **[WARNING] Line 3** — ssh-rsa — `test-key`

## Users and Sudo Findings

- **[INFO] interactive user** — Interactive Linux user detected: lamya.
- **[CRITICAL] sudo privileges** — User lamya belongs to the sudo group.
- **[INFO] interactive user** — Interactive Linux user detected: deploy.
- **[INFO] interactive user** — Interactive Linux user detected: old-provider.
- **[CRITICAL] sudo privileges** — User old-provider belongs to the sudo group.
- **[WARNING] suspicious account name** — Account name may indicate unmanaged or former access: old-provider.

## Recommended Next Actions

- Review all suspicious SSH keys and confirm ownership.
- Remove unmanaged or obsolete keys from `authorized_keys`.
- Confirm every interactive Linux account has a valid business owner.
- Review all users with sudo privileges.
- Disable direct root SSH login.
- Disable password-based SSH authentication when key-based access is validated.
- Restrict SSH access with `AllowUsers` or `AllowGroups`.
