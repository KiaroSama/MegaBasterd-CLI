# Security Policy

## Reporting a Vulnerability

Please do not open public GitHub issues for security vulnerabilities.

Use GitHub private vulnerability reporting if it is enabled for the repository.
If private reporting is not available, contact the author through the GitHub
profile:

https://github.com/KiaroSama

Include:

- A description of the issue and its impact.
- Steps to reproduce.
- A suggested fix, if one is known.
- Any relevant logs with secrets, account details, share keys, and local private
  paths removed.

## Supported Versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

## Scope

In scope:

- Credential storage and decryption.
- Network and protocol implementation.
- File integrity verification.
- Local file overwrite or deletion risks.
- Privilege escalation through CLI or launcher behavior.

Out of scope:

- Issues in MEGA's own service.
- Issues in upstream Python dependencies. Report those to the dependency
  maintainers.
- Local attacks requiring already-compromised user accounts.
