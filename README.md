# Linux Access Governance Audit

![CI](https://github.com/LamyaMeriem/linux-access-revocation-audit/actions/workflows/ci.yml/badge.svg)

## Overview

Linux Access Governance Audit is a Python-based security audit project focused on reviewing Linux server access governance.

The main security question is:

> Who can still access this Linux server, how, and with which privileges?

This project helps identify residual, excessive, or poorly controlled technical access through SSH configuration, authorized SSH keys, Linux users, sudo privileges, and human-readable audit reports.

The project started from a simple but critical security observation:

> Changing passwords does not always revoke access if SSH keys, Linux accounts, or sudo privileges remain active.

## Security Problem

In real infrastructure environments, access is often created quickly but not always reviewed or revoked properly.

Common risks include:

- SSH keys left in `authorized_keys`
- former provider or contractor accounts still active
- users with unnecessary sudo privileges
- password-based SSH authentication still enabled
- direct root SSH login allowed
- no `AllowUsers` or `AllowGroups` restriction
- unclear ownership of SSH keys
- unmanaged test, backup, or old accounts

The goal of this project is not to replace enterprise-grade security scanners.  
It is intentionally focused on Linux access governance and access review.

## What This Tool Answers

This tool helps answer:

- Who can still connect to the server?
- Which SSH keys are still trusted?
- Are there suspicious or unmanaged SSH key comments?
- Which Linux users are interactive accounts?
- Which users have sudo privileges?
- Are SSH settings aligned with basic hardening principles?
- Can audit results be exported into readable reports?

## Use Cases

- Periodic Linux access review
- SSH hardening validation
- Contractor or provider access review
- Cloud VM security baseline check
- Pre-production infrastructure audit
- Incident response support
- Infrastructure access governance documentation

## Current Features

- SSH configuration parsing
- Detection of risky SSH settings
- Authorized keys parsing
- Detection of suspicious SSH key comments
- Linux users audit
- Sudo exposure detection
- CLI with subcommands
- JSON report generation
- Markdown report generation
- Unit tests with Pytest
- Static analysis with Ruff
- GitHub Actions CI
- Full audit command combining SSH config, authorized keys, users, and sudo exposure
- Local read-only audit mode
- Local Linux audit source discovery

## Audit Modules

### 1. SSH Configuration Audit

The SSH configuration audit checks controls such as:

- `PermitRootLogin`
- `PasswordAuthentication`
- `PubkeyAuthentication`
- `AllowUsers`
- `AllowGroups`

Example risks detected:

- direct root SSH login not disabled
- password-based SSH authentication enabled
- no SSH user or group restriction configured

### 2. Authorized Keys Audit

The authorized keys audit reviews SSH public keys and detects:

- valid SSH key entries
- invalid key lines
- key type
- key comment
- suspicious ownership indicators

Suspicious comments may include terms such as:

- `old`
- `provider`
- `agency`
- `external`
- `freelance`
- `test`
- `backup`

Example risk:

> A key comment such as `old-provider@agency` may indicate unmanaged or former external access.

### 3. Linux Users and Sudo Audit

The users audit reviews Linux account and group data from sample `passwd` and `group` files.

It detects:

- interactive Linux users
- system or non-login users
- invalid passwd entries
- sudo group members
- users present in both `ssh-users` and `sudo`
- suspicious account names such as `old-provider`

Example risk:

> A former provider account still present in both `ssh-users` and `sudo` represents a critical access governance issue.

## Tech Stack

- Python
- Linux
- OpenSSH
- Git
- GitHub Actions
- Pytest
- Ruff
- Markdown
- JSON

## Project Structure

```text
.
├── .github/
│   └── workflows/
│       └── ci.yml
├── docs/
│   └── sample-reports/
│       ├── ssh-config-insecure-sample.md
│       ├── authorized-keys-sample.md
│       └── users-sudo-sample.md
├── examples/
│   ├── authorized_keys_sample
│   ├── group_sample
│   ├── passwd_sample
│   ├── sshd_config_insecure
│   └── sshd_config_secure
├── src/
│   ├── audit.py
│   ├── authorized_keys.py
│   ├── cli.py
│   ├── report.py
│   └── users.py
├── tests/
│   ├── test_audit.py
│   ├── test_authorized_keys.py
│   └── test_users.py
├── .gitignore
├── pyproject.toml
├── README.md
└── requirements-dev.txt
```

## Installation

Clone the repository:

```bash
git clone git@github.com:LamyaMeriem/linux-access-revocation-audit.git
cd linux-access-revocation-audit
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install development dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

## Usage

### Show CLI help

```bash
python src/cli.py --help
```

### Audit a secure SSH configuration file

```bash
python src/cli.py ssh-config --config examples/sshd_config_secure
```

### Audit a risky SSH configuration file

```bash
python src/cli.py ssh-config --config examples/sshd_config_insecure
```

### Generate SSH audit reports

```bash
python src/cli.py ssh-config \
  --config examples/sshd_config_insecure \
  --output reports/ssh-insecure.json \
  --markdown reports/ssh-insecure.md
```

### Audit an authorized_keys file

```bash
python src/cli.py authorized-keys --file examples/authorized_keys_sample
```

### Generate authorized_keys audit reports

```bash
python src/cli.py authorized-keys \
  --file examples/authorized_keys_sample \
  --output reports/authorized-keys.json \
  --markdown reports/authorized-keys.md
```

### Audit Linux users and sudo exposure

```bash
python src/cli.py users \
  --passwd examples/passwd_sample \
  --group examples/group_sample
```

### Generate users and sudo audit reports

```bash
python src/cli.py users \
  --passwd examples/passwd_sample \
  --group examples/group_sample \
  --output reports/users.json \
  --markdown reports/users.md
```
### Run a full Linux access governance audit

```bash
python src/cli.py full-audit \
  --ssh-config examples/sshd_config_insecure \
  --authorized-keys examples/authorized_keys_sample \
  --passwd examples/passwd_sample \
  --group examples/group_sample \
  --output reports/full-audit.json \
  --markdown reports/full-audit.md
```
### Run a local read-only audit

```bash
python src/cli.py local-audit
```

Generate local audit reports:

```bash
python src/cli.py local-audit \
  --output reports/local-audit.json \
  --markdown reports/local-audit.md
```

This command runs in read-only mode and attempts to discover local Linux audit sources such as:

- `/etc/ssh/sshd_config`
- `/etc/passwd`
- `/etc/group`
- `/home/*/.ssh/authorized_keys`
- `/root/.ssh/authorized_keys`


## Sample Reports

Sample Markdown reports are available in the repository:

- [SSH insecure configuration sample](docs/sample-reports/ssh-config-insecure-sample.md)
- [Authorized keys sample](docs/sample-reports/authorized-keys-sample.md)
- [Linux users and sudo sample](docs/sample-reports/users-sudo-sample.md)
- [Full access governance audit sample](docs/sample-reports/full-audit-sample.md)

## Example Findings

Example SSH configuration finding:

```text
[CRITICAL] PermitRootLogin - Root SSH login is not explicitly disabled.
```

Example authorized keys finding:

```text
[WARNING] Line 2
Comment: old-provider@agency
Risk: key comment contains suspicious or unmanaged ownership indicators.
```

Example users and sudo finding:

```text
[CRITICAL] sudo privileges - User old-provider belongs to the sudo group.
```

## Testing

Run all unit tests:

```bash
pytest
```

Run static analysis:

```bash
ruff check .
```

Run both checks:

```bash
ruff check .
pytest
```

## CI/CD

This project uses GitHub Actions for continuous integration.

On every push or pull request to `main`, the CI pipeline runs:

- dependency installation
- Ruff static analysis
- Pytest unit tests

Workflow file:

```text
.github/workflows/ci.yml
```

## Current Roadmap

- [x] Project structure
- [x] SSH configuration audit
- [x] Authorized keys audit
- [x] Linux users and sudo audit
- [x] Unit tests
- [x] GitHub Actions CI
- [x] JSON report generation
- [x] Markdown report generation
- [x] Sample Markdown reports
- [x] Full audit command combining all modules
- [x] Local read-only audit mode
- [ ] Advanced Linux access audit
- [ ] Remote server audit mode
- [ ] Dockerized execution
- [ ] HTML report generation
- [ ] Real Linux VM lab scenario

## Future Improvements

Planned improvements include:

- unified `full-audit` command
- remote audit mode through SSH
- Docker image for reproducible execution
- HTML report generation
- audit of real `/etc/passwd`, `/etc/group`, and `authorized_keys`
- sudoers file audit
- SSH key fingerprint extraction
- last login review
- firewall and exposed ports checks
- VM-based demonstration lab

## Why Not Lynis or OpenSCAP?

Tools such as Lynis and OpenSCAP already provide broad Linux security auditing and compliance checks.

This project is intentionally narrower.

Its goal is to focus on Linux access governance:

- SSH access paths
- authorized keys
- Linux users
- sudo exposure
- residual or excessive access
- human-readable access review reports

The value of this project is not to replace mature security scanners.  
The value is to demonstrate a focused access governance workflow and automate checks around a clear operational security question:

> Who can still access the server, how, and with which privileges?

## Security Disclaimer

This project is designed for educational, defensive, and portfolio purposes only.

It should be used only on systems you own or are explicitly authorized to audit.

The current version works with sample files and local inputs. Future remote audit features must be used only with proper authorization.

## Author

Lamya MERIEM

Project focus:

- Linux security
- SSH hardening
- access governance
- Python automation
- cloud and infrastructure security