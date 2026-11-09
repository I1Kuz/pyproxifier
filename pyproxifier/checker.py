"""Proxy health checker and telemetry service.

Provides asynchronous TCP, SOCKS5, and HTTP proxy validation, latency measurement,
and integration with the official Proxifier ProxyChecker.exe utility.
Uses native protocol handshakes without relying on third-party external IP lookup services.
"""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
import subprocess
import time

from pyproxifier.models.proxy import ProxyItem, ProxyProtocol
from pyproxifier.process import ProcessController


@dataclass
class ProxyCheckResult:
    """Outcome of a proxy server health check."""

    proxy: ProxyItem
    is_alive: bool
    latency_ms: float = 0.0
    external_ip: str | None = None
    error: str | None = None

    def __str__(self) -> str:
        status = "ALIVE" if self.is_alive else "FAILED"
        ip_info = f", IP={self.external_ip}" if self.external_ip else ""
        err_info = f", error={self.error}" if self.error else ""
        return f"[{status}] {self.proxy.protocol_name} {self.proxy.address}:{self.proxy.port} ({self.latency_ms:.1f}ms{ip_info}{err_info})"


def _ensure_no_running_loop(caller: str, async_alt: str) -> None:
    """Verifies that no asyncio loop is currently running before calling synchronous blocking helpers."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        raise RuntimeError(
            f"An asyncio event loop is already running in this thread. "
            f"Use 'await ProxyChecker.{async_alt}(...)' instead of synchronous '{caller}()'."
        )


class ProxyChecker:
    """Performs proxy server availability and routing tests."""

    @classmethod
    async def check_tcp_async(
        cls, host: str, port: int, timeout: float = 3.0
    ) -> tuple[bool, float, str | None]:
        """Tests basic TCP socket connection and returns (success, latency_ms, error)."""
        start = time.perf_counter()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            latency = (time.perf_counter() - start) * 1000.0
            writer.close()
            await writer.wait_closed()
            return True, latency, None
        except Exception as e:
            latency = (time.perf_counter() - start) * 1000.0
            return False, latency, str(e)

    @classmethod
    async def check_socks5_handshake(
        cls, proxy: ProxyItem, timeout: float = 4.0
    ) -> tuple[bool, float, str | None]:
        """Performs initial SOCKS5 protocol handshake."""
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy.address, proxy.port), timeout=timeout
            )

            # SOCKS5 greeting
            if proxy.username and proxy.password:
                writer.write(b"\x05\x02\x00\x02")
            else:
                writer.write(b"\x05\x01\x00")
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(2), timeout=timeout)
            if len(resp) < 2 or resp[0] != 5:
                writer.close()
                await writer.wait_closed()
                return False, (time.perf_counter() - start) * 1000.0, "Invalid SOCKS5 greeting response"

            auth_method = resp[1]
            if auth_method == 0xFF:
                writer.close()
                await writer.wait_closed()
                return False, (time.perf_counter() - start) * 1000.0, "SOCKS5 authentication method rejected"

            # If user/pass requested
            if auth_method == 0x02 and proxy.username and proxy.password:
                u_bytes = proxy.username.encode("utf-8")
                p_bytes = proxy.password.encode("utf-8")
                req = bytearray([0x01, len(u_bytes)]) + u_bytes + bytearray([len(p_bytes)]) + p_bytes
                writer.write(req)
                await writer.drain()

                auth_resp = await asyncio.wait_for(reader.read(2), timeout=timeout)
                if len(auth_resp) < 2 or auth_resp[1] != 0:
                    writer.close()
                    await writer.wait_closed()
                    return False, (time.perf_counter() - start) * 1000.0, "SOCKS5 authentication failed"

            latency = (time.perf_counter() - start) * 1000.0
            writer.close()
            await writer.wait_closed()
            return True, latency, None
        except Exception as e:
            return False, (time.perf_counter() - start) * 1000.0, str(e)

    @classmethod
    async def check_http_connect_handshake(
        cls,
        proxy: ProxyItem,
        target_host: str = "1.1.1.1",
        target_port: int = 443,
        timeout: float = 4.0,
    ) -> tuple[bool, float, str | None]:
        """Tests HTTPS HTTP CONNECT tunneling capability (SSL proxy support)."""
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy.address, proxy.port), timeout=timeout
            )

            req_lines = [
                f"CONNECT {target_host}:{target_port} HTTP/1.1",
                f"Host: {target_host}:{target_port}",
            ]
            if proxy.username and proxy.password:
                cred = f"{proxy.username}:{proxy.password}"
                token = base64.b64encode(cred.encode("utf-8")).decode("ascii")
                req_lines.append(f"Proxy-Authorization: Basic {token}")

            raw_request = "\r\n".join(req_lines) + "\r\n\r\n"
            writer.write(raw_request.encode("utf-8"))
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            latency = (time.perf_counter() - start) * 1000.0
            writer.close()
            await writer.wait_closed()

            if not resp:
                return False, latency, "Connection closed by proxy without response"

            first_line = resp.split(b"\r\n")[0].decode("utf-8", errors="replace")
            if " 200 " in first_line:
                return True, latency, None
            if " 407 " in first_line:
                return False, latency, "Proxy Authentication Required (HTTP 407)"
            return False, latency, f"CONNECT failed: {first_line}"
        except Exception as e:
            return False, (time.perf_counter() - start) * 1000.0, str(e)

    @classmethod
    async def check_proxy_async(
        cls, proxy: ProxyItem, timeout: float = 4.0
    ) -> ProxyCheckResult:
        """Asynchronously tests proxy availability according to its protocol."""
        if not proxy.address.strip():
            return ProxyCheckResult(
                proxy=proxy,
                is_alive=False,
                error="Proxy address is empty",
            )

        if proxy.protocol_type == ProxyProtocol.SOCKS5:
            ok, latency, err = await cls.check_socks5_handshake(proxy, timeout=timeout)
        elif proxy.protocol_type == ProxyProtocol.HTTPS:
            ok, latency, err = await cls.check_http_connect_handshake(proxy, timeout=timeout)
        else:
            ok, latency, err = await cls.check_tcp_async(proxy.address, proxy.port, timeout=timeout)

        return ProxyCheckResult(
            proxy=proxy,
            is_alive=ok,
            latency_ms=latency,
            error=err,
        )

    @classmethod
    async def check_all_async(
        cls,
        proxies: list[ProxyItem],
        max_concurrent: int = 20,
        timeout: float = 4.0,
    ) -> list[ProxyCheckResult]:
        """Tests multiple proxies concurrently with a concurrency limit."""
        sem = asyncio.Semaphore(max_concurrent)

        async def worker(p: ProxyItem) -> ProxyCheckResult:
            async with sem:
                return await cls.check_proxy_async(p, timeout=timeout)

        return await asyncio.gather(*(worker(p) for p in proxies))

    @classmethod
    def check(cls, proxy: ProxyItem, timeout: float = 4.0) -> ProxyCheckResult:
        """Synchronously checks a single proxy."""
        _ensure_no_running_loop("check", "check_proxy_async")
        return asyncio.run(cls.check_proxy_async(proxy, timeout=timeout))

    @classmethod
    def check_all(
        cls,
        proxies: list[ProxyItem],
        max_concurrent: int = 20,
        timeout: float = 4.0,
    ) -> list[ProxyCheckResult]:
        """Synchronously checks a list of proxies."""
        _ensure_no_running_loop("check_all", "check_all_async")
        return asyncio.run(cls.check_all_async(proxies, max_concurrent, timeout))

    @classmethod
    def launch_official_checker(
        cls,
        proxy: ProxyItem | str | None = None,
    ) -> bool:
        """Launches the official GUI ProxyChecker.exe utility from the Proxifier installation.

        Args:
            proxy: Optional proxy item or address string ('host:port') to prefill in the checker.

        Returns:
            True if ProxyChecker.exe was located and successfully launched, False otherwise.
        """
        exe = ProcessController.find_tool_binary("ProxyChecker.exe")
        if not exe or not exe.is_file():
            return False

        cmd = [str(exe)]
        if proxy is not None:
            if isinstance(proxy, ProxyItem):
                cmd.append(f"{proxy.address}:{proxy.port}")
            else:
                cmd.append(str(proxy))

        subprocess.Popen(cmd)
        return True
