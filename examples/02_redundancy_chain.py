"""Example 2: Redundancy (Failover) and Load Balancing Chains.

Demonstrates:
- Adding multiple proxy servers
- Creating a Redundancy failover chain (auto-switches if primary proxy drops)
- Creating a Load Balancing chain
- Routing application traffic through the chain
"""

from pyproxifier import ActionType, ChainType, Proxifier, ProxyProtocol


def main() -> None:
    prox = Proxifier()

    # 1. Add primary and secondary proxies
    p1 = prox.proxies.add("198.51.100.11", 1080, ProxyProtocol.SOCKS5, label="Node-A")
    p2 = prox.proxies.add("198.51.100.12", 1080, ProxyProtocol.SOCKS5, label="Node-B")
    p3 = prox.proxies.add("198.51.100.13", 1080, ProxyProtocol.SOCKS5, label="Node-C")

    # 2. Create a Redundancy Chain with 10s connection timeout and 60s background recheck
    failover_chain = prox.proxies.create_chain(
        name="HighAvailabilityFailover",
        chain_type=ChainType.REDUNDANCY,
        proxy_ids=[p1.id, p2.id, p3.id],
        redundancy_timeout=10,
        redundancy_recheck=60,
    )
    print(f"Created Redundancy Chain: id={failover_chain.id}, name='{failover_chain.name}'")

    # 3. Route specific application traffic through the failover chain
    rule = prox.rules.add(
        name="MissionCriticalApps",
        applications="my_crawler.exe; python.exe",
        action=ActionType.CHAIN,
        target_id=failover_chain.id,
    )
    print(f"Added rule '{rule.name}' routing through Chain ID {rule.target_id}")

    # 4. Validate
    prox.validate()
    print("Redundancy chain profile successfully validated!")


if __name__ == "__main__":
    main()
