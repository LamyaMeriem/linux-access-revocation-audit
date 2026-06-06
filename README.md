# Linux Access Revocation Audit

![CI](https://github.com/LamyaMeriem/linux-access-revocation-audit/actions/workflows/ci.yml/badge.svg)  


## Overview

Linux Access Revocation Audit is a Python-based security audit project focused on detecting residual access paths on Linux servers after a contractor, provider, or external administrator leaves a project.

The main security question is:

> Did we really revoke access, or did we only change passwords?

Changing passwords is not always enough. If a public SSH key remains authorized on the server, a former provider may still be able to authenticate using the corresponding private key.

## Security Problem

A common operational mistake is assuming that password rotation is equivalent to access revocation.

However, Linux servers often support SSH key-based authentication. If the provider's public key is still present in an `authorized_keys` file, changing passwords may not prevent access.

This project helps answer:

- Who can still connect to the server?
- By which authentication mechanism?
- With which privileges?
- Are old or unmanaged SSH keys still trusted?
- Is SSH configured according to basic hardening principles?

## Objectives

This project aims to audit:

- SSH hardening configuration
- root login exposure
- password-based SSH authentication
- public key authentication
- SSH access restrictions using AllowUsers or AllowGroups
- authorized SSH keys
- Linux users and privilege exposure
- sudo access
- SSH-related file permissions
- security posture through automated reports

## Tech Stack

- Python
- Linux
- OpenSSH
- Git
- GitHub Actions
- Pytest
- Ruff

## Roadmap

- [x] Project structure
- [ ] SSH configuration audit
- [ ] Unit tests
- [ ] GitHub Actions CI
- [ ] Authorized keys audit
- [ ] Markdown/JSON report generation
- [ ] Advanced Linux access audit

## Disclaimer

This project is designed for educational and defensive security purposes only.


## Usage

Audit an SSH server configuration file:

```bash
python src/cli.py ssh-config --config examples/sshd_config_secure
```

Audit a risky SSH configuration file:

```bash
python src/cli.py ssh-config --config examples/sshd_config_insecure
```

Audit an `authorized_keys` file:

```bash
python src/cli.py authorized-keys --file examples/authorized_keys_sample
```