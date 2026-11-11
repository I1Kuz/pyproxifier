# pyproxifier

[![CI](https://github.com/I1Kuz/pyproxifier/actions/workflows/ci.yml/badge.svg)](https://github.com/I1Kuz/pyproxifier/actions)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Type Checking: Strict](https://img.shields.io/badge/types-basedpyright%20strict-blueviolet)](https://github.com/DetachHead/basedpyright)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/I1Kuz/pyproxifier)

Python library for programmatic configuration, automation, and real-time IPC control of Proxifier on Windows (v3 and v4).

---

## Features

- **Proxy Management (`ProxyManager`)**: CRUD operations for SOCKS5, SOCKS4, HTTPS, and HTTP proxies with user/password authentication and automatic identifier assignment.
- **Failover & Redundancy Chains**: Sequential proxy chains, automatic redundancy failover clusters with timeout detection, and load balancing configurations.
- **Routing Rules (`RuleManager`)**: Priority-ordered routing rules targeting executables, domain patterns, IPv4, IPv6, CIDR blocks (`10.0.0.0/8`), and port lists/ranges (`80; 443; 8000-8080`).
- **Profile Persistence (`ConfigManager`)**: Bidirectional `.ppx` XML parser (`from_xml`, `to_xml`) preserving profile attributes, encryption options, DNS resolution modes, and UDP policies.
- **Pre-flight Validation (`Validator`)**: Syntactic and semantic verification of network addresses, port boundaries (1-65535), and referential integrity between rules, chains, and proxy IDs.
- **Unified Native IPC (`IPCManager`)**: Programmatic control exclusively via native Windows IPC channels—eliminates manual XML file swapping and abrupt process restarts.
- **TCP Control Socket API (`ControlSocketClient`)**: In-memory profile reload and status querying over Proxifier's native TCP command protocol (`Proxifier.exe control-socket <port>`).
- **Window Message IPC (`WindowIPC`)**: Inter-process communication via `Proxifier32Cls` window class and `Global\Proxifier32Mutex1040` for state toggling, graceful close, and PID discovery.
- **Named Pipe IPC (`NamedPipeClient`)**: Duplex profile streaming over `\\.\pipe\proxifier`.
- **Kernel Driver IPC (`DriverIPC`)**: Direct IOCTL communication with `\\.\ProxifierDrv` Windows Filtering Platform driver.
- **System Administration (`SystemManager`)**: Automated registry license deployment (HKCU/HKLM), global profile installation, and WFP driver service management.
- **Diagnostics (`ProxyChecker`)**: Asynchronous TCP, SOCKS5, and HTTP CONNECT handshakes with latency measurement and concurrency throttling.

---

## Architecture

```
                      +---------------------------------------+
                      |               Proxifier               |  (Client Facade)
                      +-------------------+-------------------+
                                          |
        +------------------+--------------+---------------+------------------+
        |                  |                              |                  |
+-------v--------+  +------v---------+            +-------v--------+  +------v---------+
|  ProxyManager  |  |  RuleManager   |            | ConfigManager  |  |   Validator    |
| (Proxies &     |  | (Routing rules,|            | (Load/Save/    |  | (Ports, IPs,   |
|  Chains CRUD)  |  |  priorities)   |            |  Profiles)     |  |  ID Integrity) |
+----------------+  +----------------+            +----------------+  +----------------+
        |                  |                              |
        +------------------+--------------+---------------+
                                          |
                      +-------------------v-------------------+
                      |            ProxifierProfile           |  (Domain Model)
                      +-------------------+-------------------+
                                          |
                               +----------v-----------+
                               |    ProfileParser     |  (Bidirectional XML)
                               +----------------------+
```

---

## Installation

```bash
pip install pyproxifier
```

For development:
```bash
git clone https://github.com/I1Kuz/pyproxifier.git
cd pyproxifier
uv sync
```

---

## Quickstart

```python
from pyproxifier import ActionType, Proxifier, ProxyProtocol

# 1. Connect to Proxifier (loads active profile or creates a clean baseline)
prox = Proxifier()

# 2. Add a SOCKS5 proxy server
proxy = prox.proxies.add(
    address="198.51.100.10",
    port=1080,
    protocol=ProxyProtocol.SOCKS5,
    username="service_user",
    password="service_password",
    label="US-East-Primary",
)

# 3. Add a routing rule for specific applications and domains
prox.rules.add(
    name="RouteBrowsers",
    applications="chrome.exe; msedge.exe; firefox.exe",
    targets="*.internal.net; 10.0.0.0/8",
    ports="80; 443; 8080",
    action=ActionType.PROXY,
    target_id=proxy.id,
)

# 4. Run pre-flight validation
prox.validate()

# 5. Apply configuration via native IPC without interrupting active traffic
prox.apply()
```

---

## Usage Examples

### 1. High-Availability Failover (Redundancy Chains)

```python
from pyproxifier import ActionType, ChainType, Proxifier, ProxyProtocol

prox = Proxifier()

# Register primary and backup endpoints
p1 = prox.proxies.add("198.51.100.11", 1080, ProxyProtocol.SOCKS5, label="Node-01")
p2 = prox.proxies.add("198.51.100.12", 1080, ProxyProtocol.SOCKS5, label="Node-02")

# Create a redundancy cluster (auto-switches to Node-02 upon Node-01 timeout)
chain = prox.proxies.create_chain(
    name="FailoverCluster",
    chain_type=ChainType.REDUNDANCY,
    proxy_ids=[p1.id, p2.id],
    redundancy_timeout=10,
    redundancy_recheck=60,
)

# Bind worker processes to the failover cluster
prox.rules.add(
    name="CrawlerTraffic",
    applications="worker.exe; python.exe",
    action=ActionType.CHAIN,
    target_id=chain.id,
)

prox.apply()
```

### 2. Rule Ordering and Priorities

Proxifier evaluates rules sequentially from top to bottom. The first match determines the routing decision:

```python
# Insert a bypass rule immediately before an existing rule
prox.rules.add(
    name="BypassLocalSubnet",
    targets="192.168.0.0/16",
    action=ActionType.DIRECT,
    before="RouteBrowsers",
)

# Adjust rule ordering
prox.rules.move_up("BypassLocalSubnet")

# Enable or disable rules dynamically
prox.rules.disable("RouteBrowsers")
prox.rules.enable("RouteBrowsers")

# Define fallback policy for unmatched traffic
prox.rules.set_default_action(ActionType.BLOCK)
```

### 3. Native TCP Control Socket Hot-Reload

Proxifier supports real-time, in-memory reconfiguration over its internal TCP command server:

```python
from pyproxifier import ActionType, ControlSocketClient, Proxifier, ProxyProtocol

# Connect to running Proxifier instance (launched with: Proxifier.exe control-socket 19876)
with ControlSocketClient(port=19876) as client:
    version = client.get_version()

    # Construct configuration in memory
    prox = Proxifier(create_if_missing=True)
    p = prox.proxies.add("10.0.0.1", 1080, ProxyProtocol.SOCKS5)
    prox.rules.add("RouteAll", applications="*", action=ActionType.PROXY, target_id=p.id)

    # Hot reload running state without disk I/O
    client.load_config(prox.profile)
```

### 4. Asynchronous Proxy Health Checking

```python
import asyncio
from pyproxifier import ProxyChecker, ProxyItem, ProxyProtocol

async def main():
    proxies = [
        ProxyItem(id=1, address="198.51.100.10", port=1080, protocol_type=ProxyProtocol.SOCKS5),
        ProxyItem(id=2, address="198.51.100.20", port=1080, protocol_type=ProxyProtocol.SOCKS5),
    ]

    results = await ProxyChecker.check_all_async(proxies, max_concurrent=10, timeout=3.0)
    for r in results:
        status = "ALIVE" if r.is_alive else "FAILED"
        print(f"[{status}] {r.proxy.address}:{r.proxy.port} latency={r.latency_ms:.1f}ms err={r.error}")

asyncio.run(main())
```

### 5. Fleet Administration and Licensing

```python
from pyproxifier import Proxifier, SystemManager

# Verify WFP kernel filter driver status
if not SystemManager.is_driver_running():
    SystemManager.start_driver()

# Install license key into Windows Registry
SystemManager.install_license(
    key="2T3Z1-XXXXX-XXXXX-XXXXX-XXXXX",
    owner="Infrastructure Team",
    system_wide=True,  # HKEY_LOCAL_MACHINE (requires elevation)
)

# Deploy baseline profile for all local users and background services
prox = Proxifier()
SystemManager.deploy_global_profile(prox.profile)
```

---

## Exception Hierarchy

All library exceptions inherit from `ProxifierError`:

```
ProxifierError
├── ControlSocketError
│   ├── ControlSocketConnectionError
│   └── ControlSocketCommandError
├── ProfileError
│   ├── ProfileNotFoundError
│   ├── ProfileParseError
│   └── ProfileCorruptedError
├── ValidationError
│   ├── InvalidPortError
│   ├── InvalidAddressError
│   ├── ProxyReferenceNotFoundError
│   ├── ChainReferenceNotFoundError
│   └── RuleConfigurationError
├── EntityNotFoundError
│   ├── ProxyNotFoundError
│   ├── ChainNotFoundError
│   └── RuleNotFoundError
└── ProcessError
    ├── ProxifierNotFoundError
    ├── DriverError
    └── RegistryAccessError
```

---

## Testing & Quality Gates

Run the test suite with statement coverage:
```bash
uv run pytest --cov=pyproxifier --cov-report=term-missing
```

Run static type analysis in strict mode:
```bash
uv run basedpyright
```

Verify layered architecture boundaries:
```bash
uv run lint-imports
```

---

## Technical Documentation

- [Undocumented Proxifier IPC Specification](docs/UNDOCUMENTED_IPC.md): Reverse-engineered protocol specifications for native TCP Control Socket, Named Pipe, WFP Driver, Shared Memory, and Mutex interfaces.
- [Proxifier v4 Technical Reference](docs/PROXIFIER_V4_DOCS.md): Comprehensive schema and options reference.
- [Architecture & Layered Boundaries](docs/architecture.md): DDD layer definitions and import contracts.
- [Contributing Guide](CONTRIBUTING.md): Environment setup and pull request requirements.
- [Changelog](CHANGELOG.md): Version release history and migration notes.
- [Security Policy](SECURITY.md): Vulnerability reporting procedures.

---

## Disclaimer

`pyproxifier` is an independent open-source automation library and is not affiliated with, endorsed by, or sponsored by Initex LLC. "Proxifier" is a registered trademark of Initex LLC. This software interacts with locally installed instances strictly for interoperability, research, and automation purposes.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
