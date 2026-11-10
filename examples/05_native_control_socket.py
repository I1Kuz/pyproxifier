"""Example 05: Real-time programmatic control of Proxifier via native TCP Control Socket API.

Demonstrates:
1. Connecting to Proxifier in Control Socket mode (zero restart required).
2. Dynamic in-memory profile updates without touching profile files on disk.
3. Querying internal application version.
"""

from pyproxifier import ActionType, ControlSocketClient, Proxifier, ProxyProtocol


def main() -> None:
    # 1. Connect to Proxifier's native TCP Control Socket
    # Start Proxifier with: Proxifier.exe control-socket 19876
    port = 19876
    print(f"Connecting to Proxifier Control Socket at 127.0.0.1:{port}...")

    try:
        with ControlSocketClient(port=port, timeout=2.0) as client:
            # Query version
            ver = client.get_version()
            print(f"Connected to Proxifier! Internal Version: {ver}")

            # Build in-memory profile
            prox = Proxifier(create_if_missing=True)
            p1 = prox.proxies.add("198.51.100.20", 1080, ProxyProtocol.SOCKS5, label="LiveSocketProxy")
            prox.rules.add("RouteLiveBrowsers", applications="chrome.exe", action=ActionType.PROXY, target_id=p1.id)

            # Hot reload in memory directly over TCP socket
            client.load_config(prox.profile)
            print("Successfully updated running Proxifier profile in-memory!")

    except Exception as e:
        print(f"Control Socket not active or error: {e}")
        print("Note: To run in Control Socket mode, launch Proxifier with: Proxifier.exe control-socket 19876")


if __name__ == "__main__":
    main()

