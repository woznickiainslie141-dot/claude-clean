import asyncio
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
            sample = ("192.0.2.1", "2001:db8::1")
            with patch.object(guard, "dialog", return_value=False), self.assertRaises(guard.GuardError):
                guard.confirm_pin(path, sample)
            self.assertFalse(path.exists())
            with patch.object(guard, "dialog", return_value=True):
                guard.confirm_pin(path, sample)
            with patch.object(guard, "dialog", side_effect=AssertionError):
                guard.confirm_pin(path, sample)
                with self.assertRaises(guard.GuardError):
                    guard.confirm_pin(path, ("192.0.2.2", sample[1]))


class GateTests(unittest.IsolatedAsyncioTestCase):
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
