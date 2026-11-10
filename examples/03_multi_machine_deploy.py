"""Example 3: Multi-Machine Deployment and Fleet Automation.

Demonstrates:
- Silent license key deployment via Windows Registry
- Global profile (Default.ppx) deployment for all user sessions and services
- WFP network driver (ProxifierDrv) status check
"""

from pyproxifier import Proxifier, SystemManager


def main() -> None:
    print("=== Multi-Machine Deployment Demo ===")

    # 1. Check if the WFP network driver is active
    driver_active = SystemManager.is_driver_running()
    print(f"ProxifierDrv kernel driver is running: {driver_active}")

    # 2. Check currently installed license in the Registry
    current_license = SystemManager.get_installed_license(system_wide=False)
    print(f"Current User License: {current_license}")

    # 3. Simulate deploying a license (e.g. during an automated VM setup)
    # Note: Pass system_wide=True to register in HKEY_LOCAL_MACHINE (requires Administrator)
    try:
        # Example demonstration key format
        SystemManager.install_license(
            key="2T3Z1-XXXXX-XXXXX-XXXXX-XXXXX",
            owner="Company Automation Fleet",
            system_wide=False,
        )
        print("License installed successfully to HKCU.")
    except Exception as e:
        print(f"License installation note: {e}")

    # 4. Prepare and deploy a global baseline profile (Default.ppx) for all users
    prox = Proxifier()
    prox.rules.set_default_action("Direct")
    dest = SystemManager.deploy_global_profile(prox.profile)
    print(f"Global profile deployed to: {dest}")


if __name__ == "__main__":
    main()
