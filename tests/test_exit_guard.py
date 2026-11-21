import asyncio
import json
import ssl
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch

import exit_guard as guard
import phone_guard


class RouteTests(unittest.TestCase):
    def test_only_manual_remote_chain(self):
        table = {"GLOBAL": {"type": "Selector", "now": "group"},
                 "group": {"type": "Selector", "now": "node"}, "node": {"type": "Trojan"}}
        self.assertEqual(guard.selected_route("global", table)[0], ("GLOBAL", "group", "node"))
        for mode in ("direct", "rule"):
            with self.assertRaises(guard.GuardError):
                guard.selected_route(mode, table)
        for bad in ({"type": "Direct"}, {"type": "URLTest", "now": "node"},
                    {"type": "Selector", "now": "GLOBAL"}, {"type": "Unknown"}):
            with self.assertRaises(guard.GuardError):
                guard.selected_route("global", {**table, "group": bad})

    def test_pin_enrollment_and_stale_pin(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "pin.json"
            sample = ("192.0.2.1", "2001:db8::1", "2001:db8::1")
            with patch.object(guard, "dialog", return_value=False), self.assertRaises(guard.GuardError):
                guard.confirm_pin(path, sample)
            self.assertFalse(path.exists())
            with patch.object(guard, "dialog", return_value=True):
                guard.confirm_pin(path, sample)
            with patch.object(guard, "dialog", side_effect=AssertionError):
                guard.confirm_pin(path, sample)
                with self.assertRaises(guard.GuardError):
                    guard.confirm_pin(path, ("192.0.2.2", *sample[1:]))

    def test_legacy_pins_never_trust_unobserved_ipv6(self):
        ip4, ip6 = "192.0.2.1", "2001:db8::1"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "pin.json"
            path.write_text(json.dumps([ip4, ip4]), encoding="utf8")
            guard.verify_saved_pin(path, (ip4, ip4, None))
            with self.assertRaises(guard.GuardError):
                guard.verify_saved_pin(path, (ip4, ip4, ip6))
            path.write_text(json.dumps([ip4, ip6]), encoding="utf8")
            guard.verify_saved_pin(path, (ip4, ip6, ip6))
            with self.assertRaises(guard.GuardError):
                guard.verify_saved_pin(path, (ip4, ip6, None))

    def test_ipv6_coverage_and_conflicting_paths(self):
        v4, v6 = "192.0.2.1", "2001:db8::1"
        guard.check_families((v4, v4), None, False)
        guard.check_families((v4, v6), v6, True)
        for dual, independent, required in [(v4, None, True), (v6, None, False), (v6, "2001:db8::2", False),
                                             ("192.0.2.2", None, False)]:
            with self.assertRaises(guard.GuardError):
                guard.check_families((v4, dual), independent, required)

    def test_only_this_relays_reported_connections_are_checked(self):
        selected = ("GLOBAL", "fixed")
        meta = {"sourceIP": "127.0.0.1", "sourcePort": 50001, "inboundPort": 7890}
        unrelated = {"metadata": dict(meta, sourcePort=50002), "chains": ["DIRECT"]}
        def verify(chain):
            data = {"connections": [unrelated, {"metadata": meta, "chains": chain}]}
            with patch.object(guard, "read_reply", return_value=json.dumps(data)):
                guard.verify_flows(1234, 7890, {"50001"}, selected)
        verify(["fixed", "GLOBAL"])
        for chain in ([], ["DIRECT", "GLOBAL"], ["other", "GLOBAL"]):
            with self.assertRaises(guard.GuardError):
                verify(chain)


class GateTests(unittest.IsolatedAsyncioTestCase):
    async def test_ipv6_timeout_unknown_but_bad_tls_fails(self):
        with patch.object(guard, "exit_at", side_effect=TimeoutError):
            self.assertIsNone(await guard.observed_ipv6(7890))
        with patch.object(guard, "exit_at", side_effect=ssl.SSLCertVerificationError):
            with self.assertRaises(guard.GuardError):
                await guard.observed_ipv6(7890)

    async def test_inspection_never_launches_or_enrolls(self):
        pair = ("192.0.2.1", "192.0.2.1")
        with tempfile.TemporaryDirectory() as folder, patch.object(guard, "ROOT", Path(folder)), \
             patch.object(guard, "route_at", return_value=(("GLOBAL", "node"), "trojan")), \
             patch.object(guard, "observed_ips", AsyncMock(return_value=pair)), \
             patch.object(guard, "observed_ipv6", AsyncMock(return_value=None)), \
             patch.object(guard, "dialog", side_effect=AssertionError), \
             patch.object(asyncio, "create_subprocess_exec", side_effect=AssertionError), patch("builtins.print"):
            await guard.run_session(7890, 1234, check_only=True)
            with self.assertRaises(guard.GuardError):
                await guard.run_session(7890, 1234, require_ipv6=True, check_only=True)
            self.assertEqual(list(Path(folder).iterdir()), [])

    async def test_ipv6_appears_changes_or_vanishes(self):
        v6 = "2001:db8::1"
        for initial, current in [(None, v6), (v6, None), (v6, "2001:db8::2")]:
            gate = guard.Gate(1)
            gate.deadlines.update(route=time.monotonic()+3, ip=time.monotonic()+10, ipv6=time.monotonic()+10)
            await guard.watch(gate, "ipv6", AsyncMock(return_value=current), initial, 0, 16)
            self.assertTrue(gate.stopped.is_set())
            self.assertIn("IPv6", gate.reason)

    async def test_change_kills_existing_tunnel_and_rejects_new_clients(self):
        upstream_closed = asyncio.Event()

        async def echo(reader, writer):
            try:
                while data := await reader.read(100):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                upstream_closed.set()

        async with await asyncio.start_server(echo, "127.0.0.1", 0) as upstream:
            gate = guard.Gate(upstream.sockets[0].getsockname()[1])
            gate.deadlines.update(route=time.monotonic() + 5, ip=time.monotonic() + 16)
            async with await asyncio.start_server(gate.handle, "127.0.0.1", 0) as server:
                port = server.sockets[0].getsockname()[1]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"example payload")
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.read(100), 2), b"example payload")
                await guard.watch(gate, "ip", AsyncMock(return_value="changed"), "original", 0, 16)
                await asyncio.wait_for(upstream_closed.wait(), 2)
                for attempt in range(2):
                    if attempt:
                        reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    try:
                        self.assertEqual(await asyncio.wait_for(reader.read(1), 2), b"")
                    except ConnectionResetError:
                        pass
                    finally:
                        writer.close()
                self.assertFalse(gate.allowed())

    async def test_stale_and_failed_checks_latch(self):
        for expired, fails in ((True, False), (False, True)):
            gate = guard.Gate(1)
            gate.deadlines.update(route=time.monotonic() + 3, ip=time.monotonic() + 10)
            async def sample():
                if fails:
                    raise OSError("no result")
                if expired:
                    gate.deadlines["route"] = time.monotonic() - 1
                return "original"
            await guard.watch(gate, "route", sample, "original", 0, 5)
            self.assertTrue(gate.stopped.is_set())
            self.assertFalse(gate.allowed())

    async def test_phone_never_probes_before_lockdown(self):
        phone = Mock()
        phone.protection.return_value = {"locked": False}
        with self.assertRaises(guard.GuardError):
            await phone_guard.monitor(phone, True)
        phone.exit_ip.assert_not_called()
        phone.shell.assert_not_called()

    async def test_phone_optional_stop_on_trip_only(self):
        for stop in (False, True):
            phone = Mock(user="0")
            phone.protection.return_value = {"locked": True}
            phone.route.return_value = ("fixed",)
            phone.exit_ip.side_effect = ["192.0.2.1", "192.0.2.2"]
            with patch.object(phone_guard, "dialog", return_value=True):
                self.assertEqual(await phone_guard.monitor(phone, stop), 1)
            if stop:
                phone.shell.assert_called_once_with("am", "force-stop", "--user", "0", phone_guard.APP)
            else:
                phone.shell.assert_not_called()
