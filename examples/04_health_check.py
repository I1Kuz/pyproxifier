"""Example 4: Proxy Health Checking and Latency Measurement.

Demonstrates:
- Asynchronous TCP and SOCKS5 health check
- Batch concurrent checking of multiple proxies
- Launching the official Proxifier ProxyChecker.exe GUI
"""

import asyncio
from pyproxifier import ProxyChecker, ProxyItem, ProxyProtocol


async def async_main() -> None:
    print("=== Testing Proxies Concurrently ===")

    proxies = [
        ProxyItem(id=100, address="127.0.0.1", port=1080, protocol_type=ProxyProtocol.SOCKS5, label="LocalSOCKS"),
        ProxyItem(id=101, address="1.1.1.1", port=53, protocol_type=ProxyProtocol.HTTPS, label="CloudflareDNS"),
        ProxyItem(id=102, address="8.8.8.8", port=53, protocol_type=ProxyProtocol.HTTPS, label="GoogleDNS"),
        ProxyItem(id=103, address="192.0.2.1", port=1080, protocol_type=ProxyProtocol.SOCKS5, label="UnreachableHost"),
    ]

    # Perform concurrent health checks
    results = await ProxyChecker.check_all_async(proxies, max_concurrent=5, timeout=2.0)

    for res in results:
        print(res)


def main() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
