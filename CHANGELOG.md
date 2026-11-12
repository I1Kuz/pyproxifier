# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.0.2] - 2026-11-12

### Added
- **Complete XML Round-Trip Preservation Engine (`XMLElement`)**:
  - Introduced `XMLElement` recursive dataclass preserving unmodeled XML tags, attributes, text content, and arbitrary nested hierarchies.
  - Added `extra_attributes` and `extra_elements` extension hooks to `ProxifierProfile`, `ProfileOptions`, `DnsOptions`, `ProxyItem`, `ChainItem`, and `RuleItem`.
  - Added support for future XML sections, custom profile elements, and vendor extensions without data degradation during parse/serialize cycles.
- **Atomic File Persistence & Backup Protection**:
  - Re-engineered `ConfigManager.save()` with atomic file-replacement semantics (`.tmp` staging file -> `flush()` -> `os.fsync()` -> `os.replace()`), preventing profile corruption during sudden terminations.
  - Added pre-write XML syntax verification via `ET.fromstring()` before any filesystem modifications.
  - Added `backup=True` parameter to `save()` creating `.ppx.bak` snapshots prior to overwriting existing configurations.
- **Fine-Grained IPC Delivery Diagnostics**:
  - Introduced `ApplyStatus` enum (`SOCKET_CONFIRMED`, `PIPE_DISPATCHED`, `PROCESS_SPAWNED`, `COMMAND_DELIVERED`, `FAILED`) and `ApplyResult` dataclass with boolean coercion support.
  - Added `Proxifier.apply_detailed()` and `IPCManager.apply_profile_detailed()` for programmatic distinction between command dispatch, process launch, and socket confirmation.
  - Added `ProcessController.load_profile()` returning structured `ProcessExecutionResult` with explicit exit code diagnostics.
- **Cross-Platform Test Execution**:
  - Added cross-platform mock for Windows `ctypes.windll` in `tests/conftest.py`, enabling test execution on Linux/macOS CI runners.

### Changed
- Refactored `ProcessController.silent_load()` to build on `ProcessController.load_profile()`, hardening exit code detection against premature timeouts.
- Bumped test suite coverage to 100% statement coverage across all 31 modules (2,653 statements, 0 misses).

### Fixed
- **API Options Handling**: Fixed `Proxifier.apply()` and `IPCManager.apply_profile()` to properly respect `use_socket=False` (bypassing TCP control socket completely) and `silent=False` (omitting `silent-load` CLI argument).
- **Credential Whitespace Truncation**: Fixed `_get_elem_text(strip=False)` in `ProfileParser` for `Password` fields, preventing truncation of leading/trailing whitespace and supporting empty password strings.
- **Cross-Platform Path Resolution**: Fixed path separator concatenation in `test_find_tool_binary` to support non-Windows filesystem paths.

## [0.0.1] - 2026-11-11

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

