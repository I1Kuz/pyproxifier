# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

---

## Reporting a Vulnerability

The `pyproxifier` project takes the security of its native IPC mechanisms and Windows system integrations seriously.

If you believe you have discovered a security vulnerability regarding:
- Windows Filtering Platform (WFP) kernel driver communication
- Named Pipe or TCP Control Socket permissions / access controls
- Windows Registry privilege handling
- Buffer management or protocol parsing

**Please do NOT disclose it in a public GitHub issue.**

Instead, please report it via private email or GitHub Private Vulnerability Reporting:
- **Email**: security@pyproxifier.dev (or contact repository maintainers directly)
- **GitHub Security Advisories**: Use the "Report a vulnerability" button on the GitHub repository Security tab.

### What to include in your report:
- A clear description of the vulnerability and its potential impact.
- Steps or a minimal script to reproduce the behavior.
- Affected Windows version and Proxifier version.

We strive to acknowledge receipt within 48 hours and provide a fix or workaround in an expedited manner.

