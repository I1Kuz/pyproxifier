# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |

---

## Reporting a Vulnerability

The `pyproxifier` project implements low-level Windows networking and inter-process communication mechanisms. Security issues are treated with high priority.

If you discover a potential vulnerability regarding:
- Windows Filtering Platform (WFP) kernel driver communication
- Named Pipe or TCP Control Socket access controls
- Windows Registry credential and license handling
- Buffer safety or wire protocol framing

Please do not report vulnerabilities through public issue trackers.

Send vulnerability details directly to:
- **Email**: i1marqueeit@gmail.com
- **GitHub Security Advisories**: Via the repository's Security tab.

### Required Report Details:
- Detailed technical description of the vulnerability and attack vector.
- Minimal reproducible proof of concept.
- Affected Windows operating system versions and architecture (x86/x64).
- Relevant Proxifier application versions.
