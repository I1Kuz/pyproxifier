# Proxifier v4 for Windows — Technical Reference & Documentation

Comprehensive reference compiled from the official Proxifier v4 documentation (https://www.proxifier.com/docs/win-v4/) combined with low-level binary reverse engineering of `Proxifier.exe` v4.

---

## Table of Contents
1. [Overview & Core Architecture](#1-overview--core-architecture)
2. [What's New in v4 & Migration from v3](#2-whats-new-in-v4--migration-from-v3)
3. [Editions: Standard vs. Portable](#3-editions-standard-vs-portable)
4. [Complete Profile Specification (.ppx XML Format)](#4-complete-profile-specification-ppx-xml-format)
5. [Proxy Servers & Supported Protocols](#5-proxy-servers--supported-protocols)
6. [Proxy Chains, Redundancy & Load Balancing](#6-proxy-chains-redundancy--load-balancing)
7. [Proxification Rules Engine](#7-proxification-rules-engine)
8. [DNS & Name Resolution](#8-dns--name-resolution)
9. [Advanced Settings, Loop Detection & Security](#9-advanced-settings-loop-detection--security)
10. [Profile Auto Update](#10-profile-auto-update)
11. [Manual Proxification](#11-manual-proxification)
12. [CLI & Automation Reference](#12-cli--automation-reference)
13. [Multi-Machine Deployment & Registry Reference](#13-multi-machine-deployment--registry-reference)
14. [Windows Service Mode](#14-windows-service-mode)
15. [WFP Driver Management](#15-wfp-driver-management)
16. [Logging, Diagnostics & Standalone Proxy Checker](#16-logging-diagnostics--standalone-proxy-checker)
17. [Reverse-Engineered Native IPC & Undocumented Internal APIs](#17-reverse-engineered-native-ipc--undocumented-internal-apis)

---

## 1. Overview & Core Architecture

Proxifier is a system-wide proxy client for Microsoft Windows that enables network applications that do not have native proxy support to operate through SOCKS or HTTPS proxy servers and chains.

### Key Capabilities
- **System-wide Network Interception**: Transparently tunnels outgoing TCP connections at the Windows Filtering Platform (WFP) driver level (Standard Edition) or Winsock API hooking level (Portable Edition).
- **Granular Routing**: Granular rules based on application executable name, process ID (PID), target IP address, subnet CIDR (`10.0.0.0/8`), hostname/wildcards (`*.example.com`), and target port ranges (`80; 443; 8000-8080`).
- **Proxy Chains & Clustering**: Sequential multi-hop proxy chains, failover proxy redundancy, and process-sticky load balancing.
- **DNS Leak Prevention**: Proxifier routes domain name resolution through remote proxy servers via local placeholder/fake IPs (`127.8.x.x`), preventing DNS leaks and bypassing ISP-level DNS filtering.
- **Full IPv6 & 64-bit Compatibility**: Complete support for 64-bit applications and IPv6 addresses across Windows 10, Windows 11, Windows Server 2016, 2019, and 2022.

---

## 2. What's New in v4 & Migration from v3

### Architectural Upgrades in Version 4
- **Windows Filtering Platform (WFP) Driver**: Version 4 Standard Edition uses a kernel-mode WFP callout driver (`ProxifierDrv.sys`), replacing legacy Winsock Layered Service Providers (LSP). This ensures rock-solid stability and compatibility with modern 64-bit Windows security mechanisms (Driver Signature Enforcement, HVCI).
- **Proxy Redundancy (Failover)**: Support for redundancy clusters where Proxifier transparently switches to secondary proxies on timeout or dropped connections.
- **Load Balancing**: Support for randomized round-robin load distribution with optional per-process PID stickiness.
- **Windows Service Mode & `ServiceManager.exe`**: Native support for running Proxifier as a headless Windows Service (`LocalSystem`), controlled via the dedicated `ServiceManager.exe` utility.
- **Profile Storage Directory**:
  - v3: `%APPDATA%\Proxifier\Profiles` (extensions `.prx` or `.ppx`)
  - v4: `%APPDATA%\Proxifier4\Profiles` (extension `.ppx`, schema version 102)
- **Profile Compatibility**: Profiles created in v3 are automatically upgraded when opened in v4. However, v4 profiles containing v4-specific features (chains, redundancy parameters, new encryption models) cannot be opened by v3.
- **Licensing**: v4 uses an updated license key format distinct from v3.

---

## 3. Editions: Standard vs. Portable

| Feature | Standard Edition v4 | Portable Edition v4 |
| :--- | :--- | :--- |
| **Distribution** | Single executable installer (`ProxifierSetup.exe`) | ZIP archive with standalone folder |
| **Administrative Privileges** | Required for installation (WFP driver setup) | Not required (runs under standard user account) |
| **Interception Engine** | Kernel-mode WFP callout driver (`ProxifierDrv.sys`) | User-mode Winsock API hooking engine |
| **System Services Interception** | **Yes** (Windows services, background tasks, Windows Update) | **No** (GUI user-mode applications only) |
| **Multi-User Sessions** | **Yes** (Terminal Services, Fast User Switching) | **No** (Current user session only) |
| **Windows Service Mode** | **Yes** (via `ServiceManager.exe`) | **No** |
| **Settings Storage** | XML profiles (`.ppx`) + Windows Registry | XML profiles (`.ppx`) in application folder |
| **Manual Proxification** | **Yes** (Windows Explorer context menu integration) | **No** |

*Note: Profiles (`.ppx`) are 100% interchangeable between Standard and Portable editions.*

---

## 4. Complete Profile Specification (.ppx XML Format)

Proxifier stores configurations as human-readable UTF-8 XML files ending with `.ppx`.

### Root Element Schema
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ProxifierProfile version="102" platform="Windows" product_id="0" product_minver="400">
    <Options>...</Options>
    <ProxyList>...</ProxyList>
    <ChainList>...</ChainList>
    <RuleList>...</RuleList>
</ProxifierProfile>
```

- `version`: Profile schema version (always `"102"` for v4).
- `platform`: Operating system platform (`"Windows"` or `"Mac"`).
- `product_id`: Product identifier (`"0"` for Proxifier).
- `product_minver`: Minimum product version required to open (`"400"` for v4.00+).

### Standard Profile File Locations
1. **User Profile Directory**:
   `C:\Users\<Username>\AppData\Roaming\Proxifier4\Profiles\<name>.ppx`
2. **Global Default Profile**:
   - `C:\ProgramData\Proxifier\Default.ppx`
   - `C:\Program Files (x86)\Proxifier\Default.ppx`  
   *If `Default.ppx` exists in either system location, Proxifier automatically loads it on startup for all users and background services.*

---

## 5. Proxy Servers & Supported Protocols

### Supported Protocols
1. **SOCKS v4 / SOCKS v4A**:
   - Legacy protocol. Does not support username/password authentication (User ID string only).
   - SOCKS4A extends SOCKS4 by delegating DNS name resolution to the remote proxy.
2. **SOCKS v5** (RFC 1928, RFC 1929):
   - Industry-standard protocol.
   - Supports Username/Password authentication, remote DNS resolution, IPv6 addressing, and UDP packet tunneling.
3. **HTTPS (CONNECT / SSL Tunnel)** (RFC 2817):
   - HTTP proxy supporting the HTTP `CONNECT` verb for arbitrary TCP tunneling.
   - Supports Basic authentication, NTLM, Kerberos, and logged-in Windows user authentication.
4. **HTTP (Plain Web Proxy)**:
   - Plain HTTP proxy handling HTTP (port 80) and standard HTTPS (port 443) only.
   - Cannot tunnel arbitrary TCP protocols (SSH, FTP, SMTP, games).
   - Requires enabling `HttpProxiesSupport` under `<Options>`.

### Complete `<Proxy>` XML Schema
```xml
<Proxy id="100" type="SOCKS5">
    <Address>proxy.example.com</Address>
    <Port>1080</Port>
    <Options>48</Options>
    <Label>Primary US Proxy</Label>
    <Authentication enabled="true">
        <Username>proxy_user</Username>
        <Password>proxy_pass</Password>
    </Authentication>
</Proxy>
```

- `id`: Unique integer identifier (`100`..`65535`).
- `type`: Protocol string: `SOCKS5`, `SOCKS4`, `HTTPS`, or `HTTP`.
- `Address`: Target hostname, IPv4, or IPv6 address.
- `Port`: Target TCP port integer (`1`..`65535`).
- `Options`: Integer bitmask configuration:
  - `48`: Standard default for SOCKS5 and HTTPS (hostname in request enabled).
  - `52`: SOCKS4 with SOCKS4A remote DNS name resolution enabled.
- `Label`: User-defined string label shown in the UI, logs, and rules.
- `Authentication`:
  - `enabled`: `"true"` or `"false"`.
  - `<Username>`: Authentication username string.
  - `<Password>`: Plaintext password, or base64-encoded encrypted string (depending on profile encryption mode).

### Advanced Proxy Server Settings
- **Use Target Hostname**: When enabled (default bitmask `48`), Proxifier sends the domain name instead of the resolved IP address to the proxy server during the handshake.
- **Custom Label**: Replaces raw IP:port across all UI views and routing rule targets.
- **Interactive Authentication Prompting**: When credentials are missing or rejected, Proxifier can prompt the user interactively or silently fail.

---

## 6. Proxy Chains, Redundancy & Load Balancing

Proxifier v4 allows grouping multiple proxy servers into chains.

### 1. Simple Sequential Chains (`type="simple"` or omitted)
- Connections hop sequentially: `Proxy A -> Proxy B -> Proxy C -> Destination`.
- **Latency**: Total latency is the cumulative sum of latencies across all hops.
- **Rule**: If an HTTP proxy is present in the chain, it **must always be the last hop**.
- **Failure**: If any proxy in the chain fails, the connection drops immediately.

### 2. Redundancy Chains (`type="redundancy"`)
- Automated failover mechanism.
- Proxifier attempts the first proxy in the list. If connection fails or times out, Proxifier marks it as `[failed]` and transparently attempts the next proxy in the chain without dropping the application's connection request.
- **Parameters**:
  - `timeout`: Connection timeout in seconds before failing over (e.g. `10`).
  - `recheck`: Background interval in seconds to re-verify failed proxies (e.g. `60`).
  - `try_direct`: When set to `"true"`, falls back to a direct connection if all proxies in the cluster fail.

### 3. Load Balancing Chains (`type="load_balancing"`)
- Distributes outgoing connections across all proxies in the chain.
- **Process-Sticky Mode (`same_pid="true"`)**: Guarantees that all connections originating from the same Process ID (PID) are routed through the exact same proxy server for the duration of the process lifecycle.

### Complete `<Chain>` XML Schema
```xml
<Chain id="1" type="redundancy">
    <Name>Failover-Cluster</Name>
    <Proxy id="100" />
    <Proxy id="101" />
    <Redundancy recheck="60" timeout="10" try_direct="false" />
</Chain>

<Chain id="2" type="load_balancing">
    <Name>LoadBalanced-Cluster</Name>
    <Proxy id="100" />
    <Proxy id="101" />
    <LoadBalancing same_pid="true" />
</Chain>
```

---

## 7. Proxification Rules Engine

Rules govern how outgoing connections are matched and routed.

### Evaluation Semantics
- Evaluated strictly **top to bottom**.
- The **first matching rule** handles the connection. Subsequent rules are ignored.
- **Conjunctive Matching (AND logic)**: A connection must match **all specified criteria**:
  `Application AND Target Host/IP AND Target Port`.
- Empty fields represent the `"Any"` wildcard.

### Predefined Mandatory Rules
1. **`Localhost` Rule**:
   - Matches: `localhost; 127.0.0.1; %ComputerName%; ::1`
   - Action: `Direct`
   - Purpose: Prevents local loopback connections from being proxified, avoiding deadlocks with local web servers and IPC sockets.
2. **`Default` Rule**:
   - Always located at the bottom of the list.
   - Matches all remaining unmatched traffic.
   - Action can be set to `Direct`, `Block`, `Proxy`, or `Chain`.

### Matching Criteria Syntax
- **`<Applications>`**:
  - Semicolon-delimited list of executable filenames: `chrome.exe; firefox.exe; git.exe`.
  - Wildcards supported: `*` (zero or more chars) and `?` (single char), e.g. `python*.exe`.
  - Explicit paths supported (quoted if containing spaces): `"C:\Tools\app.exe"`.
  - PID matching: `pid=1234`.
- **`<Targets>`**:
  - Domain names and wildcards: `*.google.com; api.openai.com`.
  - IPv4 addresses: `192.168.1.1`.
  - IPv6 addresses: `[2001:db8::1]`.
  - IP ranges: `192.168.1.1-192.168.1.254`.
  - CIDR subnets: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
  - Environment token: `%ComputerName%`.
- **`<Ports>`**:
  - Individual port integers: `80; 443; 8080`.
  - Port ranges: `8000-8088; 10000-20000`.
- **`<Action>`**:
  - `<Action type="Direct" />`: Direct connection without proxy.
  - `<Action type="Block" />`: Drops connection immediately.
  - `<Action type="Proxy">100</Action>`: Routes through proxy ID `100`.
  - `<Action type="Chain">1</Action>`: Routes through proxy chain ID `1`.

### Complete `<Rule>` XML Schema
```xml
<Rule enabled="true">
    <Name>Web Browsers</Name>
    <Applications>chrome.exe; msedge.exe; firefox.exe</Applications>
    <Targets>*.google.com; *.openai.com</Targets>
    <Ports>80; 443</Ports>
    <Action type="Proxy">100</Action>
</Rule>
```

---

## 8. DNS & Name Resolution

Configured under `<Options><Resolve>`.

### Placeholder (Fake) IP Architecture
When Proxifier resolves domain names through a proxy server:
1. An application requests DNS resolution for `api.example.com`.
2. Proxifier intercepts the request and assigns an internal placeholder IP from the `127.8.0.0/16` subnet (e.g. `127.8.1.42`).
3. Proxifier returns this placeholder IP to the application.
4. When the application connects to `127.8.1.42`, Proxifier intercepts the socket and passes the original domain name (`api.example.com`) directly to the proxy server during the handshake.
5. **Important Limitation**: Because applications receive placeholder IPs, rules filtering by destination IP address will not match remote domain traffic when proxy resolution is active.

### Name Resolution Modes
- **`<AutoModeDetection enabled="true"/>`**: Continuously monitors network reachability. If local system DNS queries fail or timeout, Proxifier automatically falls back to resolving through the proxy.
- **`<ViaProxy enabled="true"/>`**: Forces all DNS queries through the proxy unconditionally, guaranteeing zero DNS leaks.
- **`<BlockNonATypes enabled="true"/>`**: Drops IPv6 `AAAA` DNS requests if the proxy server or local interface only supports IPv4.
- **`<ExclusionList>`**: Semicolon-delimited hostnames excluded from proxy resolution:
  - Default: `%ComputerName%; localhost; *.local; dns.msftncsi.com`
  - Special token `%SimpleHostnames%`: Matches names without dots (intranet servers).
- **`OnlyFromListMode="true"`**: Inverts the exclusion list (only resolve hostnames matching the list through the proxy).
- **`<DnsUdpMode>`**: Integer flag (0 = default/standard UDP handling).

---

## 9. Advanced Settings, Loop Detection & Security

### Options XML Schema
```xml
<Options>
    <Resolve>
        <AutoModeDetection enabled="false" />
        <ViaProxy enabled="true" />
        <BlockNonATypes enabled="true" />
        <ExclusionList OnlyFromListMode="false">%ComputerName%; localhost; *.local</ExclusionList>
        <DnsUdpMode>0</DnsUdpMode>
    </Resolve>
    <Encryption mode="basic" />
    <ConnectionLoopDetection enabled="true" resolve="true" />
    <Udp mode="mode_block_all" />
    <LeakPreventionMode enabled="true" />
    <ProcessOtherUsers enabled="false" />
    <ProcessServices enabled="false" />
    <HandleDirectConnections enabled="false" />
    <HttpProxiesSupport enabled="false" />
</Options>
```

### Detailed Option Semantics
- **`ConnectionLoopDetection` (`enabled="true" resolve="true"`)**:
  - Automatically identifies recursive redirection loops between Proxifier and local proxy servers (e.g. Tor, Fiddler, Charles, local VPN tunnels, antiviruses).
  - When an infinite loop is detected, Proxifier logs an alert and drops the offending connection to prevent CPU saturation and socket exhaustion.
- **`LeakPreventionMode` (`enabled="true"`)**:
  - Blocks network traffic during network interface transitions, VPN re-connections, and proxy failovers, preventing unencrypted data leaks.
- **`Udp mode`**:
  - `mode_block_all`: Drops all outgoing UDP packets (recommended for strict TCP anonymity).
  - `mode_bypass`: Allows direct UDP connections to bypass Proxifier.
  - `mode_proxy`: Routes UDP packets through SOCKS5 UDP associate tunnels.
- **`Encryption mode`**:
  - `disabled`: Passwords stored in plaintext XML.
  - `basic`: Passwords encrypted using Windows DPAPI (`CryptProtectData`), tied to the current Windows user credentials.
  - `custom`: Passwords encrypted using AES-256 with a Master Password.
- **`HandleDirectConnections`**:
  - When enabled, Proxifier intercepts, monitors, and logs direct connections that do not pass through proxies. Useful for complete bandwidth accounting and traffic dumping.
- **`ProcessOtherUsers` & `ProcessServices`** (Standard Edition only):
  - Captures network connections initiated by other logged-in user accounts and background Windows system services (e.g. `svchost.exe`, Windows Update).
- **`HttpProxiesSupport`**:
  - Enables plain HTTP proxy support in the proxy list.

---

## 10. Profile Auto Update

Proxifier v4 supports downloading and refreshing profiles automatically from an HTTP/HTTPS endpoint on application startup.

### Configuration & Behavior
- Accessed via **File -> Profile Auto Update**.
- **URL**: Must start with `http://` or `https://` (HTTP 301/302 redirects are followed).
- **Credentials Protection (`ProfileUpdateKeepLogins`)**:
  - When enabled (`1`), Proxifier merges existing locally stored proxy usernames and passwords with the newly downloaded profile, ensuring centrally managed profiles do not overwrite private credentials.
- **Target Folder (`ProfileUpdateUrlToFolder`)**:
  - Saves the downloaded `.ppx` file into `%APPDATA%\Proxifier4\Profiles\`.

---

## 11. Manual Proxification

Available exclusively in Proxifier **Standard Edition**.

- **Windows Shell Integration**: Adds a **Proxifier** context menu to executable files in Windows Explorer.
- **Context Submenu**:
  - `Proxify with -> <Proxy or Chain>`
  - `Direct`
  - `Block`
- **Instance Override**: Launching an application via this menu bypasses all global Proxification Rules for that specific process instance (PID).

---

## 12. CLI & Automation Reference

### `Proxifier.exe` Command-Line Parameters

| Command Line | Description |
| :--- | :--- |
| `Proxifier.exe <path>.ppx` | Starts Proxifier and loads the specified profile. If already running, prompts to switch profile. |
| `Proxifier.exe <path>.ppx silent-load` | Dynamically reloads the specified profile into the running instance **without prompting or dialogs**. |
| `Proxifier.exe aut` | Starts Proxifier minimized in the system tray. |
| `Proxifier.exe control-socket <port>` | Starts Proxifier in **Control Socket Mode**, listening for TCP control commands on `127.0.0.1:<port>`. |
| `Proxifier.exe service-mode` | Starts Proxifier in background Windows Service mode (requires admin privileges). |
| `Proxifier.exe register <key> <owner>` | Silently registers the product license key from the command line. |
| `Proxifier.exe convert-and-quit` | Upgrades legacy v3 profiles to v4 XML format and exits immediately. |

### Setup Installer Automation (`ProxifierSetup.exe`)
Built on Inno Setup:
```cmd
ProxifierSetup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR="C:\Program Files\Proxifier"
```

- `/SILENT`: Shows installation progress bar only.
- `/VERYSILENT`: Completely silent installation without GUI windows.
- `/SUPPRESSMSGBOXES`: Automatically selects default answers on popups.
- `/NORESTART`: Prevents system reboot after driver installation.
- `/DIR="path"`: Custom destination installation directory.
- `/NOICONS`: Disables creation of desktop and start menu shortcuts.

---

## 13. Multi-Machine Deployment & Registry Reference

### Global Default Profile Deployment
Place `Default.ppx` into:
- `C:\ProgramData\Proxifier\Default.ppx` (preferred for Windows 10/11)
- `C:\Program Files (x86)\Proxifier\Default.ppx`

### Registry Configuration (`Software\Initex\Proxifier`)

#### 1. Licensing (`...\License`)
- `Key` (`REG_SZ`): 24-character license registration key.
- `Owner` (`REG_SZ`): Registration name / company identifier.
- Locations:
  - User: `HKEY_CURRENT_USER\Software\Initex\Proxifier\License`
  - System-wide: `HKEY_LOCAL_MACHINE\Software\Initex\Proxifier\License`
  - 64-bit WOW64: `HKEY_LOCAL_MACHINE\Software\WOW6432Node\Initex\Proxifier\License`

#### 2. Core Settings (`...\Settings`)
- `ActiveProfile4` (`REG_SZ`): Name of active profile without extension (e.g. `Default` or `bot`).
- `LogLevelScreen` (`REG_DWORD`): UI console log level (`0`=Disabled, `1`=Error, `2`=Normal, `3`=Verbose, `4`=Debug).
- `LogLevelFile` (`REG_DWORD`): File log level.
- `LogPath` (`REG_SZ`): Custom directory path for `Log.txt` and `Traffic/` dumps.
- `ProfileAutoUpdate` (`REG_DWORD`): `1` to enable startup auto-update, `0` to disable.
- `ProfileUpdateUrl` (`REG_SZ`): HTTP/HTTPS URL for profile sync.
- `ProfileUpdateKeepLogins` (`REG_DWORD`): `1` to preserve local proxy passwords.
- `SysTrayIcon` (`REG_DWORD`): `1` to display system tray icon.
- `SysTrayIconShowTraffic` (`REG_DWORD`): `1` to animate tray icon with network traffic.

---

## 14. Windows Service Mode

Standard Edition can run as a headless Windows service (`LocalSystem`) without an active user session.

### Architecture & Control
- Helper executable: `ServiceManager.exe` in Proxifier folder.
- Service Name: `ProxifierService`
- Configuration:
  - Service runs with empty profile initially until configured.
  - Reads global profile from `C:\ProgramData\Proxifier\Default.ppx` or imported via `ServiceManager.exe`.
  - Requires global machine registration in `HKLM\Software\Initex\Proxifier\License`.

---

## 15. WFP Driver Management

Standard Edition v4 relies on the Windows Filtering Platform callout driver:
- Driver Binary: `C:\Program Files (x86)\Proxifier\Driver\ProxifierDrv.sys`
- INF: `C:\Program Files (x86)\Proxifier\Driver\ProxifierDrv.inf`
- Catalog: `C:\Program Files (x86)\Proxifier\Driver\ProxifierDrv.cat`
- Service Name: `ProxifierDrv`

### Driver Management Commands:
```cmd
sc.exe query ProxifierDrv
net start ProxifierDrv
net stop ProxifierDrv
```

---

## 16. Logging, Diagnostics & Standalone Proxy Checker

### Log Output Levels
1. **Disabled**: Logging turned off.
2. **Error Only**: Captures connection failures and critical errors.
3. **Normal** (Default): Records connection opens, target addresses, assigned proxies, and close events.
4. **Verbose**: Records detailed routing rule evaluation and DNS query resolutions.
5. **Debug**: In-depth network engine debugging messages.
6. **Debug and Traffic**: Writes `Log.txt` and raw binary network dumps into the `Traffic/` subdirectory.

### Binary Traffic Dumps
- Stored as `.dmp` files in `Traffic/`.
- Naming convention: `<executable> (<PID>) <TO|FROM> <host>_<port> AT <YYYYMMDD HHMMSSmmm>.dmp`
- Example: `curl.exe (8214) TO api.example.com_443 AT 20261111 213015124.dmp`
- Proxifier alerts if the `Traffic` directory exceeds 1,000 files or 500 MB.

### Standalone `ProxyChecker.exe`
- Standalone utility located in the Proxifier installation folder.
- Verifies SOCKS4, SOCKS4A, SOCKS5, HTTPS, and HTTP proxy servers.
- Evaluates TCP latency, authentication support, and HTTP `CONNECT` tunneling.

---

## 17. Reverse-Engineered Native IPC & Undocumented Internal APIs

> [!NOTE]
> For the complete, dedicated reverse-engineering specification covering wire protocols, shared memory blocks, security descriptors, and ctypes safety, see the dedicated [Undocumented Proxifier IPC Reference](UNDOCUMENTED_IPC.md).

Discovered via binary reverse engineering of `Proxifier.exe` (PE64).

### 1. Undocumented TCP Control Socket API
When started with `Proxifier.exe control-socket <port>` (ports `1024`..`65535`), Proxifier opens a local TCP command server on `127.0.0.1:<port>`.

#### Wire Protocol Framing Specification
- **Request Framing**:
  ```
  <command_name> <body_length>\r\n<body_bytes>
  ```
  - `<command_name>`: ASCII command string (`get_version`, `exit`, `load_config`, `load_config_file`).
  - `<body_length>`: Base-10 integer string specifying the exact byte length of `<body_bytes>` (`0` if no payload).
  - `\r\n`: CRLF delimiter.
  - `<body_bytes>`: Exact payload bytes.
- **Response Framing**:
  ```
  OK <body_length>\r\n<body_bytes>
  ```
  or
  ```
  ERROR <error_code> <message>\r\n
  ```

#### Supported Commands Table (Offset `0x35ADD0` in executable):
1. **`get_version 0\r\n`**
   - Returns: `OK 4\r\n1000` (internal version `1000`).
2. **`load_config <length>\r\n<xml_body>`**
   - Ingests full XML profile into memory, writes temporary `ControlSocket.ppx`, and hot-reloads running proxy rules instantly without restarting.
   - Returns: `OK 0\r\n`.
3. **`load_config_file <length>\r\n<profile_path>`**
   - Dynamically loads and switches to the specified `.ppx` file.
   - Returns: `OK 0\r\n`.
4. **`exit 0\r\n`**
   - Gracefully terminates the Proxifier application process.
   - Returns: `OK 0\r\n`.

### 2. Window Message & Mutex IPC Hierarchy
- **Global Mutexes**:
  - `Global\ProxifierRunning`: Authoritative check indicating any instance of Proxifier is active on the system.
  - `Global\ProxifierProcIdMutex<PID>`: Per-process mutex created by each running Proxifier instance (`Global\ProxifierProcIdMutex%d`), enabling zero-guess process verification.
  - `Global\Proxifier32Mutex1040`: Primary Proxifier v4 UI instance mutex.
  - `Global\ProxifierStd300Mutex`: Legacy Proxifier v3 instance mutex.
  - `Global\ProxifierServiceRunning`: Active headless Windows Service mutex.
  - `Global\ProxifierExtraOptionSendDelay`: Internal mutex controlling the packet transmission delay option.
- **Top-level Window Class**: `Proxifier32Cls`. Window Title: `Proxifier`.
- **Window Messages**:
  - `WM_CLOSE` (`0x0010`): Requests graceful shutdown without process termination.
  - `ShowWindow(hwnd, SW_RESTORE)` & `SetForegroundWindow(hwnd)`: Brings Proxifier to front.
  - `ShowWindow(hwnd, SW_HIDE)`: Minimizes Proxifier to notification tray.
  - `IsHungAppWindow(hwnd)`: Verifies responsiveness of GUI message loop.

### 3. Named Pipe IPC (`\\.\pipe\proxifier`)
- **Pipe name**: `\\.\pipe\proxifier`.
- **Security Descriptor**: `D:(D;OICI;GA;;;S-1-5-20)(A;OICI;GRGW;;;S-1-1-0) S:(ML;;NW;;;LW)`.
  - Configured with Low Mandatory Integrity Level (`S:(ML;;NW;;;LW)`) and Everyone Read/Write (`(A;OICI;GRGW;;;S-1-1-0)`), enabling cross-session user/service communication without elevation.
- **Maximum Payload**: 5 MB (`5,242,880` bytes). Exceeding this triggers internal error: `File is too big. Size = ... MB (must be <5 MB).`.
- **Functionality**: Transmits configuration profiles and commands directly to running instances or the background Windows Service.

### 4. Direct Kernel WFP Driver IPC (`\\.\ProxifierDrv`)
- **Device Object**: `\\.\ProxifierDrv`.
- **Non-elevated Presence Check**: Query access `CreateFileW(L"\\\\.\\ProxifierDrv", 0, ...)` returns `ERROR_ACCESS_DENIED` (`5`) if driver is active, enabling non-admin status checks.
- **Direct Handle**: Opened with `GENERIC_READ | GENERIC_WRITE` by elevated callers for `DeviceIoControl`.
- **Driver Operations**:
  - `GetDriverVersion`: Queries installed `ProxifierDrv.sys` driver build.
  - `SetConfig`: Dispatches active network filtering rules to kernel callout filter.
  - `GetStat`: Queries real-time connection counters and byte telemetry.
  - `SetEngineOptions`: Configures loop detection, DNS interception, and socket options.

### 5. Windows Service Management (`ServiceManager.exe`)
Proxifier provides a dedicated service helper `ServiceManager.exe` with unattended command-line parameters:
- `ServiceManager.exe silent-install`: Installs the `Proxifier` Windows Service silently into SCM.
- `ServiceManager.exe silent-uninstall`: Removes the `Proxifier` Windows Service from SCM.
- `ServiceManager.exe silent-start`: Starts the background service process.
- `ServiceManager.exe silent-stop`: Gracefully stops the service process.
- `ServiceManager.exe service-mode`: Starts Proxifier engine in headless service daemon mode.
- **Service Profile Location**: `%ProgramData%\Proxifier4\Profiles\ServiceProfile.ppx`.

### 6. Standalone ProxyChecker Shared Memory IPC
- Proxifier communicates with `ProxyChecker.exe` via Windows Shared Memory:
  - Caller creates file mapping: `CreateFileMappingW(INVALID_HANDLE_VALUE, ..., "%s %d %d %X")`.
  - Maps view: `MapViewOfFile(...)`.
  - Executes: `ProxyChecker.exe handle=%I64X`.
  - Shared memory structure defines: `TargetHost`, `TargetPort`, `Proxy`, `Port`, `Type`, `Auth`, `User`, `AsIE`, `NTLM`, `Ext4a`, `CurUserAuth`, `TestData`.

### 7. Native Command-Line Switches
`Proxifier.exe` supports the following native command-line parameters:
- `Proxifier.exe <path_to_profile> silent-load`: Delivers profile to running instance via internal IPC without prompting.
- `Proxifier.exe <path_to_profile> convert-and-quit`: Upgrades an older format `.prx` profile to current schema and exits.
- `Proxifier.exe control-socket <port>`: Starts Proxifier with the native TCP Control Socket API on specified port.
- `Proxifier.exe service-mode`: Runs Proxifier as headless background daemon.
- `Proxifier.exe register <license_key>`: Activates software license directly from the command line.
