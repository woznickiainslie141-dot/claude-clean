# SPDX-License-Identifier: MIT
import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

import desktop_guard
import exit_guard as guard


class DesktopTests(unittest.IsolatedAsyncioTestCase):
    def test_proxy_and_dns_settings_are_private_to_child(self):
        original = {"HTTP_PROXY": "old", "NO_PROXY": "*", "PRESERVE": "yes"}
        args, child = desktop_guard.launch_options(12345, original)
        self.assertIn("--proxy-server=http://127.0.0.1:12345", args)
        self.assertTrue(any("--host-resolver-rules=MAP * ~NOTFOUND" in flag for flag in args))
        self.assertIn("--disable-quic", args)
        self.assertEqual(original["NO_PROXY"], "*")
        self.assertEqual(child["NO_PROXY"], "")
        self.assertEqual(child["HTTPS_PROXY"], "http://127.0.0.1:12345")
        self.assertEqual(child["PRESERVE"], "yes")

    async def test_missing_or_mismatched_pin_never_enrolls_or_launches(self):
        pair = ("192.0.2.4", "192.0.2.4")
        desktop = Mock()
        with tempfile.TemporaryDirectory() as folder, patch.object(guard, "ROOT", Path(folder)), \
             patch.object(guard, "route_at", return_value=(("fixed",), "trojan")), \
             patch.object(guard, "observed_ips", AsyncMock(return_value=pair)), \
             patch.object(guard, "observed_ipv6", AsyncMock(return_value=None)), \
             patch.object(guard, "confirm_pin", side_effect=AssertionError), \
             patch.object(asyncio, "start_server", side_effect=AssertionError), patch("builtins.print"):
            pin = Path(folder) / "state" / "web-exit.json"
            for saved in (None, ["192.0.2.5", "192.0.2.5"]):
                if saved:
                    pin.parent.mkdir()
                    pin.write_text(json.dumps(saved), encoding="utf-8")
                for check in (False, True):
                    with self.assertRaises(guard.GuardError):
                        await guard.run_session(1, 2, check_only=check, desktop=desktop)
            desktop.run.assert_not_called()

    @unittest.skipUnless(sys.platform == "win32", "uses Windows exclusive socket binding")
    async def test_desktop_incidents_cut_only_its_relay(self):
        baseline = ("192.0.2.4", "192.0.2.4")
        selected = (("fixed",), "trojan")
        watch = guard.watch

        async def fast_watch(gate, key, sample, expected, interval, ttl):
            await watch(gate, key, sample, expected, .01, ttl)

        async def echo(reader, writer):
            try:
                while data := await reader.read(4096):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()

        async with await asyncio.start_server(echo, "127.0.0.1", 0) as upstream:
            upstream_port = upstream.sockets[0].getsockname()[1]
            for incident in ("direct", "different IP", "client gone"):
                with self.subTest(incident=incident):
                    changed = asyncio.Event()

                    def route(*_):
                        if changed.is_set() and incident == "direct":
                            raise guard.GuardError("DIRECT")
                        return selected

                    def health():
                        if changed.is_set() and incident == "client gone":
                            raise guard.GuardError("client gone")

                    async def ips(_):
                        return ("192.0.2.5",) * 2 if changed.is_set() and incident == "different IP" else baseline

                    async def stand_in(gate, port, expected):
                        self.assertEqual(expected, baseline[0])
                        reader, writer = await asyncio.open_connection("127.0.0.1", port)
                        try:
                            request = b"CONNECT example.invalid:443 HTTP/1.1\r\n\r\n"
                            writer.write(request)
                            self.assertEqual(await reader.readexactly(len(request)), request)
                            changed.set()
                            await asyncio.wait_for(gate.stopped.wait(), 3)
                            try:
                                self.assertFalse(await reader.read(1))
                            except ConnectionResetError:
                                pass
                            second, closed = await asyncio.open_connection("127.0.0.1", port)
                            try:
                                self.assertFalse(await second.read(1))
                            finally:
                                closed.close()
                            control, unaffected = await asyncio.open_connection("127.0.0.1", upstream_port)
                            try:
                                unaffected.write(b"ok")
                                self.assertEqual(await control.readexactly(2), b"ok")
                            finally:
                                unaffected.close()
                        finally:
                            writer.close()

                    desktop = Mock(check_client=health, run=stand_in)
                    with tempfile.TemporaryDirectory() as folder, patch.object(guard, "ROOT", Path(folder)), \
                         patch.object(guard, "route_at", side_effect=route), patch.object(guard, "observed_ips", ips), \
                         patch.object(guard, "observed_ipv6", AsyncMock(return_value=None)), \
                         patch.object(guard, "watch", fast_watch), patch.object(guard, "verify_flows"), \
                         patch("builtins.print"):
                        state = Path(folder) / "state"
                        state.mkdir()
                        (state / "web-exit.json").write_text(json.dumps(baseline))
                        await asyncio.wait_for(guard.run_session(upstream_port, 2, desktop=desktop), 6)
