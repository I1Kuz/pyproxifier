# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-11

### Added
- **Core Domain & Parser**:
  - Full bidirectional XML serialization/deserialization for Proxifier `.ppx` profile formats (v3 and v4).
  - Strongly-typed domain models: `ProxifierProfile`, `ProxyItem`, `RuleItem`, `ChainItem`, and `ProfileOptions`.
  - Profile presets: `create_default()`, `create_direct()`, and `create_lockdown()`.
- **Application Managers**:
  - `ProxyManager`: Full CRUD for SOCKS4, SOCKS5, HTTPS, and HTTP proxies with authentication and automatic ID allocation.
  - `RuleManager`: Rule priority management (`before`, `after`, `move_up`, `move_down`), target definitions, application filters, and default action handling.
  - `ConfigManager`: Profile loading, disk persistence, active profile resolution, and global profile management.
- **Validation Engine**:
  - Pre-flight syntax and semantic validation for IP addresses, CIDR notation (`10.0.0.0/8`), hostnames, wildcards, and port ranges.
  - Referential integrity checks ensuring all rule and chain targets reference valid proxy IDs.
- **Native IPC Architecture (Zero File Swapping & Zero Hard Restarts)**:
  - **Native TCP Control Socket (`ControlSocketClient`)**: In-memory profile hot-reload over TCP control socket with line framing and buffer safety.
  - **Window Message IPC (`WindowIPC`)**: Inter-process communication via `Proxifier32Cls` window class, `WM_COPYDATA`, `WM_COMMAND`, and `Global\Proxifier32Mutex1040`.
  - **Named Pipe IPC (`NamedPipeClient`)**: Duplex streaming over `\\.\pipe\proxifier`.
  - **WFP Kernel Driver IPC (`DriverIPC`)**: Direct IOCTL communication with `\\.\ProxifierDrv`.
  - **Service IPC (`ServiceIPC`)**: Windows Service control and configuration deployment via Service Control Manager (SCM).
  - **IPC Manager (`ProxifierIPCManager`)**: Unified automatic fallback dispatcher.
- **System & Fleet Automation**:
  - `SystemManager`: Silent license installation to Registry (`HKCU` and `HKLM`), kernel WFP driver status queries, and global profile deployment.
  - `ProcessController`: Discovery of official binaries (`Proxifier.exe`, `ProxyChecker.exe`) across registry hives and standard Program Files paths.
- **Diagnostic Health Checking**:
  - `ProxyChecker`: Fully asynchronous TCP, SOCKS5, and HTTP CONNECT protocol handshakes with latency measurement and concurrency throttling.
  - Integration with the official GUI `ProxyChecker.exe` utility.
- **Type Safety & Quality Standards**:
  - 100% statement test coverage across all 29 modules with 148 automated unit and integration tests.
  - Strict type checking compliance with `basedpyright` in strict mode (`0 errors, 0 warnings, 0 notes`).
  - PEP 561 compliance with `py.typed` marker.
  - Enforced layered architecture boundaries via `import-linter`.

