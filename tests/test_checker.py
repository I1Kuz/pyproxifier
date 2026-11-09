"""Unit tests for ProxyChecker service, handshakes, and diagnostic utilities."""

from __future__ import annotations

import asyncio
from unittest import mock
import pytest

from pyproxifier.checker import (
    ProxyCheckResult,
    ProxyChecker,
    _ensure_no_running_loop,  # pyright: ignore[reportPrivateUsage]
)
from pyproxifier.models.proxy import ProxyItem, ProxyProtocol


def test_proxy_check_result_str() -> None:
    proxy = ProxyItem(id=100, address="1.2.3.4", port=1080, protocol_type=ProxyProtocol.SOCKS5)

    # Alive result
    res_alive = ProxyCheckResult(proxy=proxy, is_alive=True, latency_ms=45.2, external_ip="203.0.113.1")
    s_alive = str(res_alive)
    assert "[ALIVE]" in s_alive
    assert "IP=203.0.113.1" in s_alive
    assert "45.2ms" in s_alive

    # Failed result with error
    res_failed = ProxyCheckResult(proxy=proxy, is_alive=False, latency_ms=120.0, error="Connection timeout")
    s_failed = str(res_failed)
    assert "[FAILED]" in s_failed
    assert "error=Connection timeout" in s_failed


def test_ensure_no_running_loop_raises_in_async() -> None:
    async def run_check() -> None:
        with pytest.raises(RuntimeError, match="An asyncio event loop is already running"):
            _ensure_no_running_loop("test_func", "test_func_async")

    asyncio.run(run_check())


def test_check_tcp_async_success_and_failure() -> None:
    async def run_test() -> None:
        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            # Success path
            ok, latency, err = await ProxyChecker.check_tcp_async("127.0.0.1", port, timeout=2.0)
            assert ok is True
            assert latency >= 0.0
            assert err is None

            # Failure path (connect to closed port)
            ok_fail, lat_fail, err_fail = await ProxyChecker.check_tcp_async("127.0.0.1", 1, timeout=0.2)
            assert ok_fail is False
            assert lat_fail >= 0.0
            assert err_fail is not None
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run_test())


def test_check_socks5_handshake_scenarios() -> None:
    async def run_test() -> None:
        mode = "no_auth"

        async def socks_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            _ = await reader.read(4)
            if mode == "no_auth":
                writer.write(b"\x05\x00")
                await writer.drain()
            elif mode == "reject":
                writer.write(b"\x05\xFF")
                await writer.drain()
            elif mode == "bad_greeting":
                writer.write(b"\x04\x00")
                await writer.drain()
            elif mode == "auth_ok":
                writer.write(b"\x05\x02")
                await writer.drain()
                _ = await reader.read(128)
                writer.write(b"\x01\x00")
                await writer.drain()
            elif mode == "auth_fail":
                writer.write(b"\x05\x02")
                await writer.drain()
                _ = await reader.read(128)
                writer.write(b"\x01\x01")
                await writer.drain()

            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(socks_server, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        proxy = ProxyItem(id=100, address="127.0.0.1", port=port, protocol_type=ProxyProtocol.SOCKS5)

        try:
            # 1. No auth success
            mode = "no_auth"
            ok, _, err = await ProxyChecker.check_socks5_handshake(proxy, timeout=2.0)
            assert ok is True
            assert err is None

            # 2. Auth rejected
            mode = "reject"
            ok, _, err = await ProxyChecker.check_socks5_handshake(proxy, timeout=2.0)
            assert ok is False
            assert "rejected" in str(err)

            # 3. Bad greeting
            mode = "bad_greeting"
            ok, _, err = await ProxyChecker.check_socks5_handshake(proxy, timeout=2.0)
            assert ok is False
            assert "Invalid SOCKS5 greeting" in str(err)

            # 4. Auth success
            mode = "auth_ok"
            proxy.username = "user"
            proxy.password = "pass"
            ok, _, err = await ProxyChecker.check_socks5_handshake(proxy, timeout=2.0)
            assert ok is True
            assert err is None

            # 5. Auth fail
            mode = "auth_fail"
            ok, _, err = await ProxyChecker.check_socks5_handshake(proxy, timeout=2.0)
            assert ok is False
            assert "authentication failed" in str(err)

            # 6. Connection error
            bad_proxy = ProxyItem(id=101, address="127.0.0.1", port=1, protocol_type=ProxyProtocol.SOCKS5)
            ok, _, err = await ProxyChecker.check_socks5_handshake(bad_proxy, timeout=0.2)
            assert ok is False
            assert err is not None

        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run_test())


def test_check_http_connect_handshake_scenarios() -> None:
    async def run_test() -> None:
        http_resp = b"HTTP/1.1 200 Connection established\r\n\r\n"

        async def http_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            _ = await reader.read(512)
            if http_resp:
                writer.write(http_resp)
                await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(http_server, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        proxy = ProxyItem(
            id=100,
            address="127.0.0.1",
            port=port,
            protocol_type=ProxyProtocol.HTTPS,
            username="usr",
            password="pwd",
        )

        try:
            # 1. 200 OK
            http_resp = b"HTTP/1.1 200 Connection established\r\n\r\n"
            ok, _, err = await ProxyChecker.check_http_connect_handshake(proxy, timeout=2.0)
            assert ok is True
            assert err is None

            # 2. 407 Proxy Authentication Required
            http_resp = b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"
            ok, _, err = await ProxyChecker.check_http_connect_handshake(proxy, timeout=2.0)
            assert ok is False
            assert "HTTP 407" in str(err)

            # 3. 502 Bad Gateway
            http_resp = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
            ok, _, err = await ProxyChecker.check_http_connect_handshake(proxy, timeout=2.0)
            assert ok is False
            assert "CONNECT failed" in str(err)

            # 4. Connection closed without response
            http_resp = b""
            ok, _, err = await ProxyChecker.check_http_connect_handshake(proxy, timeout=2.0)
            assert ok is False
            assert "Connection closed" in str(err)

            # 5. Connection refused
            bad_proxy = ProxyItem(id=101, address="127.0.0.1", port=1, protocol_type=ProxyProtocol.HTTPS)
            ok, _, err = await ProxyChecker.check_http_connect_handshake(bad_proxy, timeout=0.2)
            assert ok is False
            assert err is not None

        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run_test())


def test_check_proxy_async_and_check_all_async() -> None:
    async def run_test() -> None:
        # Empty address check
        empty_proxy = ProxyItem(id=100, address="", port=1080)
        res_empty = await ProxyChecker.check_proxy_async(empty_proxy)
        assert res_empty.is_alive is False
        assert res_empty.error == "Proxy address is empty"

        # Check different protocol routing
        p_socks5 = ProxyItem(id=1, address="127.0.0.1", port=1, protocol_type=ProxyProtocol.SOCKS5)
        p_https = ProxyItem(id=2, address="127.0.0.1", port=1, protocol_type=ProxyProtocol.HTTPS)
        p_tcp = ProxyItem(id=3, address="127.0.0.1", port=1, protocol_type=ProxyProtocol.HTTP)

        results = await ProxyChecker.check_all_async([p_socks5, p_https, p_tcp], max_concurrent=2, timeout=0.2)
        assert len(results) == 3
        for r in results:
            assert r.is_alive is False

    asyncio.run(run_test())


def test_sync_check_and_check_all() -> None:
    p = ProxyItem(id=100, address="127.0.0.1", port=1, protocol_type=ProxyProtocol.SOCKS5)
    res = ProxyChecker.check(p, timeout=0.1)
    assert res.is_alive is False

    results = ProxyChecker.check_all([p], max_concurrent=1, timeout=0.1)
    assert len(results) == 1
    assert results[0].is_alive is False


def test_launch_official_checker() -> None:
    # 1. Binary not found
    with mock.patch("pyproxifier.process.ProcessController.find_tool_binary", return_value=None):
        assert ProxyChecker.launch_official_checker() is False

    # 2. Binary found, proxy is None
    from pathlib import Path

    fake_exe = Path(r"C:\Proxifier\ProxyChecker.exe")

    with (
        mock.patch("pyproxifier.process.ProcessController.find_tool_binary", return_value=fake_exe),
        mock.patch.object(Path, "is_file", return_value=True),
        mock.patch("subprocess.Popen") as mock_popen,
    ):
        # None proxy
        assert ProxyChecker.launch_official_checker(None) is True
        mock_popen.assert_called_with([r"C:\Proxifier\ProxyChecker.exe"])

        # String proxy
        assert ProxyChecker.launch_official_checker("10.0.0.1:8080") is True
        mock_popen.assert_called_with([r"C:\Proxifier\ProxyChecker.exe", "10.0.0.1:8080"])

        # ProxyItem
        p = ProxyItem(id=1, address="10.0.0.2", port=1080)
        assert ProxyChecker.launch_official_checker(p) is True
        mock_popen.assert_called_with([r"C:\Proxifier\ProxyChecker.exe", "10.0.0.2:1080"])
