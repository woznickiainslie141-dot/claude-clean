"""Monitor the explicit SakuraCat path and relay a single native Chrome session."""
# SPDX-License-Identifier: MIT
import argparse
import asyncio
import ctypes
import http.client
import ipaddress
import json
from pathlib import Path
import ssl
import sys
import time


ROOT = Path(__file__).resolve().parent
IP_HOSTS = ("api.ipify.org", "api64.ipify.org")
REMOTE_TYPES = {
    "trojan", "shadowsocks", "shadowsocksr", "vmess", "vless", "wireguard",
    "hysteria", "hysteria2", "tuic", "snell", "http", "socks5", "anytls",
}


class GuardError(Exception):
    pass


def read_reply(conn, path, limit):
    try:
        conn.request("GET", path, headers={"Connection": "close", "Cache-Control": "no-cache"})
        response = conn.getresponse()
        if response.status != 200:
            raise GuardError("检测服务未返回有效结果。")
        body = response.read(limit + 1)
        if len(body) > limit:
            raise GuardError("检测结果过长。")
        return body
    finally:
        conn.close()


def selected_route(mode, proxies):
    if mode.lower() != "global":
        raise GuardError("SakuraCat 已离开全局代理模式。")
    chain = []
    name = "GLOBAL"
    while name and name not in chain and len(chain) < 16:
        chain.append(name)
        item = proxies.get(name, {})
        kind = str(item.get("type", "")).lower()
        if name.upper() in {"DIRECT", "REJECT", "PASS"}:
            break
        if kind == "selector":
            name = item.get("now")
        elif kind in REMOTE_TYPES:
            return tuple(chain), kind
        else:
            break
    raise GuardError("当前代理链为直连、自动分流或无法核实。请选择固定远程节点。")


def route_at(port):
    def get(path):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        return json.loads(read_reply(conn, path, 4_000_000))
    return selected_route(get("/configs")["mode"], get("/proxies")["proxies"])


def exit_at(port, host):
    # CONNECT to the loopback proxy only. TLS verifies the remote IP service.
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=4, context=ssl.create_default_context())
    conn.set_tunnel(host, 443)
    address = ipaddress.ip_address(read_reply(conn, "/", 80).strip().decode("ascii"))
    if not address.is_global or (host == IP_HOSTS[0] and address.version != 4):
        raise GuardError("检测站返回的地址无效。")
    return str(address)


def dialog(message, confirm=False, title="Chrome 出口保护"):
    # Default to No for enrollment. Errors are shown after traffic has been cut.
    style = 0x10000 | (0x124 if confirm else 0x10)
    return ctypes.windll.user32.MessageBoxW(None, message, title, style) == 6


def confirm_pin(path, observed):
    if not path.exists():
        addresses = " / ".join(dict.fromkeys(observed))
        if not dialog(f"本次通过代理测到的出口为 {addresses}。请核对这是你信任的出口。保存到本机并继续吗？", True):
            raise GuardError("未确认可信出口。")
        path.parent.mkdir(exist_ok=True, parents=True)
        try:
            with path.open("x", encoding="utf-8") as stream:
                json.dump(observed, stream)
        except FileExistsError:
            pass  # Concurrent enrollment must agree with the other writer.
    if json.loads(path.read_text(encoding="utf-8")) != list(observed):
        raise GuardError("出口与本机已确认的地址不符。请检查节点。")


async def observed_ips(upstream):
    return tuple(await asyncio.wait_for(asyncio.gather(*(
        asyncio.to_thread(exit_at, upstream, host) for host in IP_HOSTS
    )), 6))


class Gate:
    def __init__(self, upstream):
        self.upstream = upstream
        self.deadlines = {"route": 0.0, "ip": 0.0}
        self.writers = set()
        self.reason = None
        self.stopped = asyncio.Event()

    def block(self, reason):
        if self.reason is None:
            self.reason = reason
            for writer in tuple(self.writers):
                writer.transport.abort()
            self.stopped.set()

    def allowed(self):
        if self.reason is None and time.monotonic() >= min(self.deadlines.values()):
            self.block("未能及时核实代理路径或出口。")
        return self.reason is None

    async def pump(self, reader, writer):
        while data := await reader.read(65536):
            if not self.allowed():
                return
            writer.write(data)
            await writer.drain()

    async def handle(self, client, downstream):
        writers = [downstream]
        tasks = []
        self.writers.add(downstream)
        try:
            if not self.allowed():
                return
            remote, upstream = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", self.upstream), 2)
            writers.append(upstream)
            self.writers.add(upstream)
            if not self.allowed():
                return
            tasks = [asyncio.create_task(self.pump(client, upstream)),
                     asyncio.create_task(self.pump(remote, downstream))]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            for writer in writers:
                self.writers.discard(writer)
                writer.close()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


async def watch(gate, key, sample, expected, interval, ttl):
    try:
        while gate.allowed():
            start = time.monotonic()
            if await sample() != expected:
                gate.block("代理节点或路由发生变化。" if key == "route" else "检测到出口 IP 变化。")
                return
            # A timeout or machine resume must never silently renew a stale lease.
            if not gate.allowed():
                return
            gate.deadlines[key] = start + ttl
            await asyncio.sleep(interval)
    except Exception:
        gate.block("无法核实代理路径或出口。")


async def run_session(upstream, controller):
    async def route():
        return await asyncio.wait_for(asyncio.to_thread(route_at, controller), 2.5)

    async def ips():
        return await observed_ips(upstream)

    selection = await route()
    baseline = await ips()
    confirm_pin(ROOT / "state" / "web-exit.json", baseline)
    # Recheck both after any dialog, before binding the relay or starting Chrome.
    if await ips() != baseline or await route() != selection:
        raise GuardError("确认期间代理路径或出口已变。")
    gate = Gate(upstream)
    now = time.monotonic()
    gate.deadlines.update(route=now + 5, ip=now + 16)
    async with await asyncio.start_server(gate.handle, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        tasks = [asyncio.create_task(watch(gate, "route", route, selection, 1, 5)),
                 asyncio.create_task(watch(gate, "ip", ips, baseline, 5, 16))]
        try:
            chrome = await asyncio.create_subprocess_exec(
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                str(ROOT / "web-guard.ps1"), "-Mode", "Open", "-LocalProxyPort", str(port), "-WaitForGuardedChrome")
            closed = asyncio.create_task(chrome.wait())
            tripped = asyncio.create_task(gate.stopped.wait())
            tasks.extend([closed, tripped])
            await asyncio.wait([closed, tripped], return_when=asyncio.FIRST_COMPLETED)
            if gate.stopped.is_set():
                await asyncio.to_thread(dialog, f"{gate.reason} 已断开本次 Chrome 会话的代理连接。请保存工作、完全退出 Chrome，核实节点后从桌面检查入口重开。")
            # Keep the dead listener reserved until this Chrome exits. No auto-resume.
            if await closed:
                raise GuardError("Chrome 未能在已核验的防火墙保护下启动。")
        finally:
            gate.block("保护会话已结束。")
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True, type=int)
    parser.add_argument("--controller", required=True, type=int)
    args = parser.parse_args()
    try:
        asyncio.run(run_session(args.upstream, args.controller))
    except (Exception, KeyboardInterrupt) as exc:
        reason = str(exc) if isinstance(exc, GuardError) else "出口核验未完成或守护程序已停止。"
        dialog(reason)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
