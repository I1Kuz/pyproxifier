"""Example 1: Basic Proxy and Routing Rule Configuration.

Demonstrates:
- Connecting to Proxifier
- Adding a SOCKS5 proxy
- Creating a rule routing Chrome through the proxy
- Validating and applying configuration silently on the fly
"""

from pyproxifier import ActionType, Proxifier, ProxyProtocol


def main() -> None:
    # 1. Connect to Proxifier (loads active profile or creates a default one)
    prox = Proxifier()
    print(f"Proxifier executable: {prox.executable}")
    print(f"Proxifier is running: {prox.is_running()}")
    print(f"Active profile path: {prox.profile_path}")

    # 2. Add a SOCKS5 proxy server
    proxy = prox.proxies.add(
        address="198.51.100.10",
        port=1080,
        protocol=ProxyProtocol.SOCKS5,
        username="proxy_user",
        password="secret_password",
        label="US-East-Primary",
    )
    print(f"Added proxy: id={proxy.id}, url={proxy.to_url()}")

    # 3. Add a routing rule for web browsers
    rule = prox.rules.add(
        name="RouteBrowsers",
        applications="chrome.exe; msedge.exe; firefox.exe",
        targets="*.google.com; *.openai.com",
        ports="80; 443",
        action=ActionType.PROXY,
        target_id=proxy.id,
    )
    print(f"Added rule: '{rule.name}' -> Action={rule.action_name} to Proxy ID {rule.target_id}")

    # 4. Validate the profile to ensure there are no configuration errors
    prox.validate()
    print("Configuration validation: SUCCESS")

    # 5. Apply the profile silently without disrupting the user
    # (If Proxifier is running, reloads into the active instance via silent-load)
    success = prox.apply(silent=True)
    print(f"Profile applied: {success}")


if __name__ == "__main__":
    main()
