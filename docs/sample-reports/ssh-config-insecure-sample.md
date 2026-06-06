# SSH Configuration Audit Report

**Generated at:** `2026-06-06T20:45:46.957895+00:00`
**Target:** `examples/sshd_config_insecure`
**Security score:** `40/100`

## Executive Summary

- Critical findings: **2**
- Warnings: **1**
- Passed checks: **1**

## Findings

### CRITICAL

#### PermitRootLogin

- **Message:** Root SSH login is not explicitly disabled.

#### PasswordAuthentication

- **Message:** Password-based SSH authentication is not disabled.

### WARNING

#### SSH access restriction

- **Message:** No AllowUsers or AllowGroups restriction found.

### OK

#### PubkeyAuthentication

- **Message:** SSH public key authentication is enabled.

## Parsed SSH Configuration

```text
passwordauthentication yes
permitrootlogin yes
pubkeyauthentication yes
```
