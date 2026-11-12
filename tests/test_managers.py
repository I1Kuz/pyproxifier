"""Unit tests for entity managers (ProxyManager, RuleManager, ConfigManager)."""

from pathlib import Path
import tempfile
from unittest import mock
import pytest

from pyproxifier.exceptions import (
    ChainNotFoundError,
    ProfileNotFoundError,
    ProfileParseError,
    ProxyNotFoundError,
    RuleNotFoundError,
    ValidationError,
)
from pyproxifier.managers.config_manager import ConfigManager
from pyproxifier.managers.proxy_manager import ProxyManager
from pyproxifier.managers.rule_manager import RuleManager
from pyproxifier.models import (
    ActionType,
    ChainType,
    ProxifierProfile,
    ProxyProtocol,
)
from pyproxifier.validator import Validator


def test_proxy_manager_crud() -> None:
    profile = ProxifierProfile.create_default()
    mgr = ProxyManager(profile)

    # Add
    p1 = mgr.add("1.1.1.1", 1080, ProxyProtocol.SOCKS5, label="Primary")
    assert p1.id == 100
    assert p1.label == "Primary"

    p2 = mgr.add("2.2.2.2", 1080, ProxyProtocol.SOCKS5, label="Backup")
    assert p2.id == 101

    # Invalid proxy ID <= 0
    with pytest.raises(ValidationError):
        mgr.add("3.3.3.3", 1080, proxy_id=-5)

    # Get & Find
    assert mgr.get(100).address == "1.1.1.1"
    assert mgr.get("Primary").id == 100
    assert mgr.find("NonExistent") is None

    # Update
    mgr.update(100, address="1.1.1.2")
    assert mgr.get(100).address == "1.1.1.2"

    # Remove
    assert mgr.remove(101)
    assert len(mgr.list()) == 1
    with pytest.raises(ProxyNotFoundError):
        mgr.get(101)


def test_proxy_removal_reference_check_and_force() -> None:
    profile = ProxifierProfile.create_default()
    p_mgr = ProxyManager(profile)
    r_mgr = RuleManager(profile)

    proxy = p_mgr.add("1.1.1.1", 1080)
    rule = r_mgr.add("ProxyRule", action=ActionType.PROXY, target_id=proxy.id)

    # Removing referenced proxy without force should fail
    with pytest.raises(ValidationError):
        p_mgr.remove(proxy.id, force=False)

    # With force=True, it succeeds AND resets referencing rule to Direct
    assert p_mgr.remove(proxy.id, force=True)
    assert rule.action_name == ActionType.DIRECT.value
    assert rule.target_id is None
    # Profile should remain 100% valid!
    Validator.validate_profile(profile)


def test_proxy_manager_chains() -> None:
    profile = ProxifierProfile.create_default()
    mgr = ProxyManager(profile)

    p1 = mgr.add("1.1.1.1", 1080)
    p2 = mgr.add("2.2.2.2", 1080)

    chain = mgr.create_chain(
        name="Failover",
        chain_type=ChainType.REDUNDANCY,
        proxy_ids=[p1.id, p2.id],
        redundancy_timeout=10,
        redundancy_recheck=60,
    )
    assert chain.id == 1
    assert len(mgr.list_chains()) == 1
    assert mgr.get_chain("Failover").id == 1

    assert mgr.remove_chain(1)
    assert len(mgr.list_chains()) == 0


def test_rule_manager_crud_and_ordering() -> None:
    profile = ProxifierProfile.create_default()
    mgr = RuleManager(profile)

    # Initial rules: Localhost, Default
    assert len(mgr.list()) == 2

    # Adding a rule places it before Default
    _ = mgr.add("Web", applications="chrome.exe", action=ActionType.DIRECT)
    rules = mgr.list()
    assert rules[1].name == "Web"
    assert rules[2].name == "Default"

    # Cannot add after Default
    with pytest.raises(ValidationError):
        mgr.add("IllegalAfterDefault", action=ActionType.DIRECT, after="Default")

    # Move up
    mgr.move_up("Web")
    assert mgr.list()[0].name == "Web"

    # Moving Default up is a no-op (Default must stay at bottom)
    mgr.move_up("Default")
    assert mgr.list()[-1].name == "Default"

    # Disable / Enable
    mgr.disable("Web")
    assert not mgr.get("Web").enabled
    mgr.enable("Web")
    assert mgr.get("Web").enabled

    # Removing Default rule directly is blocked
    with pytest.raises(ValidationError):
        mgr.remove("Default")

    # Set default action
    mgr.set_default_action(ActionType.BLOCK)
    assert mgr.get("Default").action_type == ActionType.BLOCK


def test_config_manager_save_load() -> None:
    profile = ProxifierProfile.create_default()
    p_mgr = ProxyManager(profile)
    p_mgr.add("192.168.1.10", 1080, ProxyProtocol.SOCKS5, label="TestProxy")

    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "test_profile.ppx"
        ConfigManager.save(file_path, profile)
        assert file_path.is_file()

        loaded = ConfigManager.load(file_path)
        assert len(loaded.proxies) == 1
        assert loaded.proxies[0].address == "192.168.1.10"


def test_config_manager_atomic_save_and_backup() -> None:
    profile = ProxifierProfile.create_default()
    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / "my_profile.ppx"
        ConfigManager.save(dest, profile)
        assert dest.is_file()
        orig_content = dest.read_text(encoding="utf-8")

        # 1. Test backup=True
        profile.rules[0].name = "UpdatedLocalhost"
        ConfigManager.save(dest, profile, backup=True)
        bak_file = dest.with_suffix(".ppx.bak")
        assert bak_file.is_file()
        assert bak_file.read_text(encoding="utf-8") == orig_content

        # 2. Test error recovery: if os.replace fails, original file remains intact
        with mock.patch("os.replace", side_effect=OSError("Disk write error")):
            with mock.patch.object(Path, "unlink", side_effect=OSError("Permission denied")):
                with pytest.raises(OSError, match="Disk write error"):
                    profile.rules[0].name = "CorruptedName"
                    ConfigManager.save(dest, profile)

        # File content must still be intact from before the failure
        reloaded = ConfigManager.load(dest)
        assert reloaded.rules[0].name == "UpdatedLocalhost"

        # 3. Test malformed XML prevents writing
        with mock.patch("pyproxifier.parser.ProfileParser.to_xml", return_value="<Incomplete"):
            with pytest.raises(ProfileParseError, match="Generated XML is malformed"):
                ConfigManager.save(dest, profile)
        assert ConfigManager.load(dest).rules[0].name == "UpdatedLocalhost"


def test_rule_manager_unbind_target() -> None:
    profile = ProxifierProfile.create_default()
    r_mgr = RuleManager(profile)

    r1 = r_mgr.add("Rule1", action=ActionType.PROXY, target_id=100)
    r2 = r_mgr.add("Rule2", action=ActionType.PROXY, target_id=101)
    r3 = r_mgr.add("Rule3", action=ActionType.CHAIN, target_id=1)

    assert r_mgr.has_target_reference(ActionType.PROXY, 100) == ["Rule1"]
    assert r_mgr.has_target_reference(ActionType.PROXY) == ["Rule1", "Rule2"]

    # Unbind target 100
    affected = r_mgr.unbind_target(ActionType.PROXY, 100)
    assert affected == 1
    assert r1.action_name == ActionType.DIRECT.value
    assert r1.target_id is None
    assert r2.action_name == ActionType.PROXY.value

    # Unbind all remaining proxies
    affected_all = r_mgr.unbind_target(ActionType.PROXY)
    assert affected_all == 1
    assert r2.action_name == ActionType.DIRECT.value
    assert r2.target_id is None

    # Chain rule unaffected
    assert r3.action_name == ActionType.CHAIN.value


def test_proxy_manager_http_auto_enables_option() -> None:
    profile = ProxifierProfile.create_default()
    assert not profile.options.http_proxies_support

    p_mgr = ProxyManager(profile)
    p_mgr.add("10.0.0.1", 8080, protocol=ProxyProtocol.HTTP)
    assert profile.options.http_proxies_support


def test_chain_removal_rule_unbind_and_force() -> None:
    profile = ProxifierProfile.create_default()
    p_mgr = ProxyManager(profile)
    r_mgr = RuleManager(profile)

    p1 = p_mgr.add("1.1.1.1", 1080)
    chain = p_mgr.create_chain("TestChain", proxy_ids=[p1.id])
    rule = r_mgr.add("ChainRule", action=ActionType.CHAIN, target_id=chain.id)

    # Cannot delete without force
    with pytest.raises(ValidationError):
        p_mgr.remove_chain(chain.id, force=False)

    # Force delete unbinds rule
    assert p_mgr.remove_chain(chain.id, force=True)
    assert rule.action_name == ActionType.DIRECT.value
    assert rule.target_id is None


def test_proxy_manager_add_url() -> None:
    profile = ProxifierProfile.create_default()
    p_mgr = ProxyManager(profile)
    p = p_mgr.add_url("socks5://user:pass@1.2.3.4:1080", label="FromURL")
    assert p.id == 100
    assert p.address == "1.2.3.4"
    assert p.username == "user"
    assert p.password == "pass"
    assert p.label == "FromURL"


def test_proxy_manager_update_id_cascades() -> None:
    profile = ProxifierProfile.create_default()
    p_mgr = ProxyManager(profile)
    r_mgr = RuleManager(profile)

    p1 = p_mgr.add("1.1.1.1", 1080)
    chain = p_mgr.create_chain("Chain1", proxy_ids=[p1.id])
    rule = r_mgr.add("Rule1", action=ActionType.PROXY, target_id=p1.id)

    # Update ID to 200
    p_mgr.update(p1.id, id=200)
    assert p1.id == 200
    assert rule.target_id == 200
    assert chain.proxy_ids == [200]

    # Cannot update to negative or existing ID
    with pytest.raises(ValidationError):
        p_mgr.update(200, id=-1)


def test_rule_manager_update_validation() -> None:
    profile = ProxifierProfile.create_default()
    r_mgr = RuleManager(profile)

    # Cannot rename Default rule
    with pytest.raises(ValidationError):
        r_mgr.update("Default", name="RenamedDefault")

    # Cannot rename to existing name
    _ = r_mgr.add("CustomRule")
    with pytest.raises(ValidationError):
        r_mgr.update("CustomRule", name="Localhost")


def test_proxy_manager_clear_checks_chains() -> None:
    profile = ProxifierProfile.create_default()
    p_mgr = ProxyManager(profile)

    p1 = p_mgr.add("1.1.1.1", 1080)
    _ = p_mgr.create_chain("ActiveChain", proxy_ids=[p1.id])

    # Clear without force must fail because chain references proxy
    with pytest.raises(ValidationError):
        p_mgr.clear(force=False)

    # Clear with force cleans up proxies and defunct chains
    assert p_mgr.clear(force=True) == 1
    assert len(p_mgr.list()) == 0
    assert len(p_mgr.list_chains()) == 0
    Validator.validate_profile(profile)


def test_proxy_removal_cleans_empty_chain_and_unbinds_chain_rule() -> None:
    profile = ProxifierProfile.create_default()
    p_mgr = ProxyManager(profile)
    r_mgr = RuleManager(profile)

    p1 = p_mgr.add("1.1.1.1", 1080)
    chain = p_mgr.create_chain("SoleChain", proxy_ids=[p1.id])
    chain_rule = r_mgr.add("ChainRule", action=ActionType.CHAIN, target_id=chain.id)

    # Force delete the proxy
    assert p_mgr.remove(p1.id, force=True)

    # Chain should be cleanly removed because it became empty
    assert len(p_mgr.list_chains()) == 0
    # Rule pointing to chain should be reset to Direct
    assert chain_rule.action_type == ActionType.DIRECT
    assert chain_rule.target_id is None
    Validator.validate_profile(profile)


def test_proxy_manager_update_chain_cascades() -> None:
    profile = ProxifierProfile.create_default()
    p_mgr = ProxyManager(profile)
    r_mgr = RuleManager(profile)

    p1 = p_mgr.add("1.1.1.1", 1080)
    _ = p_mgr.create_chain("OldChain", proxy_ids=[p1.id], chain_id=5)
    rule = r_mgr.add("RuleToChain", action=ActionType.CHAIN, target_id=5)

    # Update chain ID to 15
    updated = p_mgr.update_chain(5, id=15, name="NewChain")
    assert updated.id == 15
    assert updated.name == "NewChain"
    assert rule.target_id == 15
    Validator.validate_profile(profile)


def test_rule_manager_ensure_localhost_reorders() -> None:
    profile = ProxifierProfile()
    r_mgr = RuleManager(profile)
    # Add rules with Localhost not at index 0
    r_mgr.add("Rule1", action=ActionType.DIRECT)
    lh = r_mgr.add("Localhost", action=ActionType.DIRECT)
    r_mgr.add("Default", action=ActionType.DIRECT)

    assert profile.rules.index(lh) == 1
    # Calling ensure_localhost_rule must move it to index 0
    r_mgr.ensure_localhost_rule()
    assert profile.rules[0].name == "Localhost"
    Validator.validate_profile(profile)


def test_config_manager_paths_and_presets() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        with mock.patch.dict("os.environ", {"APPDATA": tmpdir, "ProgramData": tmpdir}):
            # get_global_profile_path
            global_path = ConfigManager.get_global_profile_path()
            assert "Proxifier" in str(global_path)
            assert global_path.name == "Default.ppx"

            # resolve_profile_path(None)
            default_path = ConfigManager.resolve_profile_path(None)
            assert default_path.name == "Default.ppx"

            # resolve_profile_path bare name
            bare_path = ConfigManager.resolve_profile_path("MyBareProfile")
            assert bare_path.name == "MyBareProfile.ppx"

            # resolve_profile_path relative without suffix
            rel_path = ConfigManager.resolve_profile_path("sub/profile")
            assert rel_path.name == "profile.ppx"

            # list_user_profiles
            profiles = ConfigManager.list_user_profiles(v3=False)
            assert isinstance(profiles, list)

            # list_user_profiles v3
            profiles_v3 = ConfigManager.list_user_profiles(v3=True)
            assert isinstance(profiles_v3, list)

            # load non-existent
            with pytest.raises(ProfileNotFoundError):
                ConfigManager.load(Path(tmpdir) / "missing_file.ppx")

            # save without suffix
            dest = ConfigManager.save(Path(tmpdir) / "saved_profile", ProxifierProfile.create_default())
            assert dest.suffix == ".ppx"
            assert dest.is_file()

            # new_default
            p_def = ConfigManager.new_default()
            assert len(p_def.rules) == 2

            # new_direct
            p_dir = ConfigManager.new_direct()
            assert p_dir.options.handle_direct_connections is False

            # new_lockdown
            p_lock = ConfigManager.new_lockdown(allowed_targets="1.2.3.4")
            assert any(r.name == "AllowedHosts" for r in p_lock.rules)

            # resolve_profile_path when candidate file exists in user dir
            user_dir = ConfigManager.get_user_profiles_dir()
            (user_dir / "Candidate.ppx").write_text("<ProxifierProfile />", encoding="utf-8")
            resolved_cand = ConfigManager.resolve_profile_path("Candidate")
            assert resolved_cand == (user_dir / "Candidate.ppx").resolve()

            # list_user_profiles when dir does not exist
            with mock.patch.object(Path, "exists", return_value=False):
                assert ConfigManager.list_user_profiles() == []


def test_proxy_manager_edge_cases() -> None:
    profile = ProxifierProfile.create_default()
    p_mgr = ProxyManager(profile)

    # profile property
    assert p_mgr.profile is profile

    # add with existing proxy_id
    p1 = p_mgr.add("1.1.1.1", 1080, proxy_id=100)
    with pytest.raises(ValidationError, match="already exists"):
        p_mgr.add("1.1.1.2", 1080, proxy_id=100)

    # update with id <= 0
    with pytest.raises(ValidationError, match="positive integer"):
        p_mgr.update(p1.id, id=0)

    # update with existing new_id
    p2 = p_mgr.add("1.1.1.3", 1080, proxy_id=101)
    with pytest.raises(ValidationError, match="already exists"):
        p_mgr.update(p1.id, id=101)

    # update cascading to chain
    c1 = p_mgr.create_chain("Chain1", proxy_ids=[100])
    p_mgr.update(100, id=105)
    assert c1.proxy_ids == [105]

    # update with non-existent attribute
    with pytest.raises(AttributeError, match="has no attribute"):
        p_mgr.update(105, non_existent_attr=123)

    # update with HTTP protocol auto-activates http_proxies_support
    profile.options.http_proxies_support = False
    p_mgr.update(105, protocol_type=ProxyProtocol.HTTP)
    assert profile.options.http_proxies_support is True

    # remove(force=False) when referenced in chains
    with pytest.raises(ValidationError, match="currently referenced in chains"):
        p_mgr.remove(105, force=False)

    # clear(force=False) when referencing rules exist
    r_mgr = RuleManager(profile)
    r_mgr.add("RefRule", action=ActionType.PROXY, target_id=105)
    with pytest.raises(ValidationError, match="active references found in rules"):
        p_mgr.clear(force=False)

    # create_chain with chain_id <= 0
    with pytest.raises(ValidationError, match="positive integer"):
        p_mgr.create_chain("BadChain", chain_id=0)

    # create_chain with existing chain_id
    with pytest.raises(ValidationError, match="already exists"):
        p_mgr.create_chain("BadChain", chain_id=c1.id)

    # get_chain not found
    with pytest.raises(ChainNotFoundError):
        p_mgr.get_chain(99999)

    # update_chain with id <= 0
    with pytest.raises(ValidationError, match="positive integer"):
        p_mgr.update_chain(c1.id, id=0)

    # update_chain with existing new_id
    _ = p_mgr.create_chain("Chain2", chain_id=200, proxy_ids=[p2.id])
    with pytest.raises(ValidationError, match="already exists"):
        p_mgr.update_chain(c1.id, id=200)

    # update_chain with non-existent attribute
    with pytest.raises(AttributeError, match="has no attribute"):
        p_mgr.update_chain(c1.id, fake_attr="val")


def test_rule_manager_edge_cases() -> None:
    profile = ProxifierProfile.create_default()
    r_mgr = RuleManager(profile)

    # profile property
    assert r_mgr.profile is profile

    # add with duplicate name
    with pytest.raises(ValidationError, match="already exists"):
        r_mgr.add("Localhost")

    # add with before
    r_before = r_mgr.add("BeforeDefault", before="Default")
    target_def = profile.find_rule("Default")
    assert target_def is not None
    assert profile.rules.index(r_before) == profile.rules.index(target_def) - 1

    # add with after
    r_after = r_mgr.add("AfterLocalhost", after="Localhost")
    target_lh = profile.find_rule("Localhost")
    assert target_lh is not None
    assert profile.rules.index(r_after) == profile.rules.index(target_lh) + 1

    # get not found
    with pytest.raises(RuleNotFoundError):
        r_mgr.get("NonExistentRule")

    # update with empty name
    with pytest.raises(ValidationError, match="cannot be empty"):
        r_mgr.update("BeforeDefault", name="   ")

    # update with non-existent attribute
    with pytest.raises(AttributeError, match="has no attribute"):
        r_mgr.update("BeforeDefault", non_existent_attr="val")

    # remove Default rule fails
    with pytest.raises(ValidationError, match="cannot be removed"):
        r_mgr.remove("Default")

    # remove non-default rule succeeds
    assert r_mgr.remove("BeforeDefault") is True

    # move_up when already at top
    top_rule_name = profile.rules[0].name
    r_mgr.move_up(top_rule_name)
    assert profile.rules[0].name == top_rule_name

    # move_up on Default does nothing
    r_mgr.move_up("Default")
    assert profile.rules[-1].name == "Default"

    # move_down
    first_name = profile.rules[0].name
    second_name = profile.rules[1].name
    r_mgr.move_down(first_name)
    assert profile.rules[1].name == first_name
    assert profile.rules[0].name == second_name

    # move_down when already at bottom (before Default)
    penultimate = profile.rules[-2].name
    r_mgr.move_down(penultimate)
    assert profile.rules[-2].name == penultimate

    # set_default_action when Default does not exist
    profile.rules.clear()
    r_def = r_mgr.set_default_action(ActionType.DIRECT)
    assert r_def.name == "Default"
    assert profile.rules[0] == r_def

    # ensure_localhost_rule when Localhost does not exist
    profile.rules.clear()
    r_lh = r_mgr.ensure_localhost_rule()
    assert r_lh.name == "Localhost"
    assert profile.rules[0] == r_lh

    # _index_of when not found raises RuleNotFoundError
    with pytest.raises(RuleNotFoundError):
        r_mgr._index_of("UnknownRuleName")  # pyright: ignore[reportPrivateUsage]

