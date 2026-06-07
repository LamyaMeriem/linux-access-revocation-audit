# Linux Users and Sudo Audit Report

**Generated at:** `2026-06-07T07:02:14.794781+00:00`
**Passwd source:** `examples/passwd_sample`
**Group source:** `examples/group_sample`

## Executive Summary

- Total users: **7**
- Valid users: **7**
- Invalid users: **0**
- Interactive users: **3**
- Critical findings: **2**
- Warnings: **1**
- Info findings: **3**

## Users

### root

- **UID:** `0`
- **Home:** `/root`
- **Shell:** `/bin/bash`
- **Type:** `system/non-login`

### daemon

- **UID:** `1`
- **Home:** `/usr/sbin`
- **Shell:** `/usr/sbin/nologin`
- **Type:** `system/non-login`

### www-data

- **UID:** `33`
- **Home:** `/var/www`
- **Shell:** `/usr/sbin/nologin`
- **Type:** `system/non-login`

### lamya

- **UID:** `1000`
- **Home:** `/home/lamya`
- **Shell:** `/bin/bash`
- **Type:** `interactive`

### deploy

- **UID:** `1001`
- **Home:** `/home/deploy`
- **Shell:** `/bin/bash`
- **Type:** `interactive`

### old-provider

- **UID:** `1002`
- **Home:** `/home/old-provider`
- **Shell:** `/bin/bash`
- **Type:** `interactive`

### backup

- **UID:** `1003`
- **Home:** `/home/backup`
- **Shell:** `/usr/sbin/nologin`
- **Type:** `system/non-login`

## Findings

### CRITICAL

#### sudo privileges

- **Message:** User lamya belongs to the sudo group.
- **Recommendation:** Confirm that sudo access is justified and still required.

#### sudo privileges

- **Message:** User old-provider belongs to the sudo group.
- **Recommendation:** Confirm that sudo access is justified and still required.

### WARNING

#### suspicious account name

- **Message:** Account name may indicate unmanaged or former access: old-provider.
- **Recommendation:** Confirm whether this account should still exist.

### INFO

#### interactive user

- **Message:** Interactive Linux user detected: lamya.
- **Recommendation:** Verify that this account still has a valid business owner.

#### interactive user

- **Message:** Interactive Linux user detected: deploy.
- **Recommendation:** Verify that this account still has a valid business owner.

#### interactive user

- **Message:** Interactive Linux user detected: old-provider.
- **Recommendation:** Verify that this account still has a valid business owner.
