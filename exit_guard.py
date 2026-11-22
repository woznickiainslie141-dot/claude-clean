"""Monitor the explicit SakuraCat path and relay a single native Chrome session."""
# SPDX-License-Identifier: MIT
import argparse
import asyncio
import ctypes
import http.client
import ipaddress
import json
import socket
from pathlib import Path
import ssl
import sys
import time


ROOT = Path(__file__).resolve().parent
IP_HOSTS = ("api.ipify.org", "api64.ipify.org")
IPV6_HOST = "api6.ipify.org"
REMOTE_TYPES = {
    "trojan", "shadowsocks", "shadowsocksr", "vmess", "vless", "wireguard",
    "hysteria", "hysteria2", "tuic", "snell", "http", "socks5", "anytls",
}


class GuardError(Exception):
    pass


def check_egress_policy():
    try:
        cfg = json.loads((ROOT / "config.json").read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise GuardError("无法读取 Chrome 保护设置。已停止转发。") from exc
    if not isinstance(cfg, dict):
        raise GuardError("Chrome 保护设置格式无效。已停止转发。")
    required = cfg.get("web_require_verified_ipv4", True)
    if type(required) is not bool:
        raise GuardError("web_require_verified_ipv4 必须为 true 或 false。已停止转发。")
    if required:
        raise GuardError("当前代理无法保证所有网站都看到已核验的那个 IPv4。已停止转发。")


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


def verify_flows(controller, upstream, source_ports, selected):
    """Check only flows attributable to open sockets of this browser relay."""
    conn = http.client.HTTPConnection("127.0.0.1", controller, timeout=1)
    flows = json.loads(read_reply(conn, "/connections", 4_000_000))["connections"]
    if not isinstance(flows, list):
        raise GuardError("无法读取 SakuraCat 活动连接。")
    for flow in flows:
        meta = flow["metadata"]
        if (meta.get("sourceIP") not in {"127.0.0.1", "::ffff:127.0.0.1"} or
                str(meta.get("sourcePort")) not in source_ports or str(meta.get("inboundPort")) != str(upstream)):
            continue
        if tuple(reversed(flow.get("chains") or ())) != selected:
            raise GuardError("SakuraCat 报告此 Chrome 连接的实际路径与登记节点不符。")


def exit_at(port, host):
    # CONNECT to the loopback proxy only. TLS verifies the remote IP service.
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=4, context=ssl.create_default_context())
    conn.set_tunnel(host, 443)
    address = ipaddress.ip_address(read_reply(conn, "/", 80).strip().decode("ascii"))
    required_family = {IP_HOSTS[0]: 4, IPV6_HOST: 6}.get(host)
    if not address.is_global or (required_family and address.version != required_family):
        raise GuardError("检测站返回的地址无效。")
    return str(address)


def dialog(message, confirm=False, title="Chrome 出口保护"):
    # Default to No for enrollment. Errors are shown after traffic has been cut.
    style = 0x10000 | (0x124 if confirm else 0x10)
    return ctypes.windll.user32.MessageBoxW(None, message, title, style) == 6


def verify_saved_pin(path, observed):
    saved = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(saved, list) and len(saved) == 2:
        # Older installs recorded IPv4 and dual stack. Two IPv4 answers never establish IPv6 trust.
        saved.append(saved[1] if ipaddress.ip_address(saved[1]).version == 6 else None)
    if not isinstance(saved, list) or len(saved) != 3 or saved[:2] != list(observed[:2]):
        raise GuardError("出口与本机已确认的地址不符。请检查节点。")
    if saved[2] != observed[2]:
        if observed[2] is None:
            raise GuardError("此前登记的 IPv6 出口未能核验。请检查代理。")
        raise GuardError("发现新增或变化的 IPv6 出口。请核实节点，确需重新登记时使用 ResetExit。")


def confirm_pin(path, observed):
    prompted = False
    if not path.exists():
        prompted = True
        addresses = " / ".join(dict.fromkeys(ip for ip in observed if ip))
        note = "" if observed[2] else " IPv6 未核验。"
        if not dialog(f"本次通过代理测到的出口为 {addresses}。{note}请核对这是你信任的出口。保存到本机并继续吗？", True):
            raise GuardError("未确认可信出口。")
        path.parent.mkdir(exist_ok=True, parents=True)
        try:
            with path.open("x", encoding="utf-8") as stream:
                json.dump(observed, stream)
        except FileExistsError:
            pass  # Concurrent enrollment must agree with the other writer.
    verify_saved_pin(path, observed)
    return prompted


async def observed_ips(upstream):
    return tuple(await asyncio.wait_for(asyncio.gather(*(
        asyncio.to_thread(exit_at, upstream, host) for host in IP_HOSTS
    )), 6))


async def observed_ipv6(upstream):
    try:
        return await asyncio.wait_for(asyncio.to_thread(exit_at, upstream, IPV6_HOST), 5)
    except ssl.SSLError as error:
        raise GuardError("IPv6 检测的 TLS 校验或连接失败。") from error
    except (OSError, asyncio.TimeoutError):
        return None  # Unknown coverage, not proof of an IPv4-only network.


def check_families(ips, ipv6, required):
    dual_v6 = ipaddress.ip_address(ips[1]).version == 6
    if not dual_v6 and ips[0] != ips[1]:
        raise GuardError("IPv4 与双栈检测看到了不同的 IPv4 出口。请核实代理。")
    if ipv6 is None and (required or dual_v6):
        raise GuardError("独立 IPv6 出口未能核验，已停止启动。")
    if dual_v6 and ips[1] != ipv6:
        raise GuardError("双栈与 IPv6 专用检测看到了不同的 IPv6 出口。请核实代理。")


class Gate:
    def __init__(self, upstream):
        self.upstream = upstream
        self.deadlines = {"route": 0.0, "ip": 0.0}
        self.writers = set()
        self.source_ports = set()
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
        source_port = None
        self.writers.add(downstream)
        try:
            if not self.allowed():
                return
            remote, upstream = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", self.upstream), 2)
            writers.append(upstream)
            self.writers.add(upstream)
            source_port = str(upstream.get_extra_info("sockname")[1])
            self.source_ports.add(source_port)
            if not self.allowed():
                return
            tasks = [asyncio.create_task(self.pump(client, upstream)),
                     asyncio.create_task(self.pump(remote, downstream))]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            self.source_ports.discard(source_port)
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
                reasons = {"route": "代理节点或路由发生变化。", "ip": "检测到出口 IP 变化。",
                           "ipv6": "IPv6 出口新增、改变或无法继续核验。"}
                gate.block(reasons[key])
                return
            # A timeout or machine resume must never silently renew a stale lease.
            if not gate.allowed():
                return
            gate.deadlines[key] = start + ttl
            await asyncio.sleep(interval)
    except GuardError as error:
        gate.block(str(error))
    except Exception:
        gate.block("无法核实代理路径或出口。")


async def run_session(upstream, controller, require_ipv6=False, check_only=False, desktop=None):
    if desktop is None:
        check_egress_policy()
    else:
        desktop.check_client()

    async def route():
        return await asyncio.wait_for(asyncio.to_thread(route_at, controller), 2.5)

    async def ips():
        return await observed_ips(upstream)

    async def ipv6():
        return await observed_ipv6(upstream)

    selection = await route()
    baseline, v6 = await asyncio.gather(ips(), ipv6())
    pin = ROOT / "state" / "web-exit.json"
    observed = (*baseline, v6)
    family = ipaddress.ip_address(baseline[1]).version
    coverage = "独立 IPv6 已测得。" if v6 else "独立 IPv6 未核验，特定网站可能仍有 IPv6 出口。"
    print(f"IPv4 已测得；双栈接口本次返回 IPv{family}；{coverage}", flush=True)
    check_families(baseline, v6, require_ipv6)
    if desktop is not None:
        if not pin.is_file():
            raise GuardError("尚无已确认的出口。请先在网页保护入口登记可信出口。")
        verify_saved_pin(pin, observed)
    if check_only:
        if pin.exists():
            verify_saved_pin(pin, observed)
            print("已测得的出口与本机登记一致。", flush=True)
        else:
            print("本机尚未登记可信出口。", flush=True)
        return
    if desktop is None and confirm_pin(pin, observed):
        # A user may have kept the confirmation dialog open while the network changed.
        if await asyncio.gather(ips(), ipv6()) != [baseline, v6]:
            raise GuardError("确认期间代理出口已变。")
    if await route() != selection:
        raise GuardError("确认期间代理路径已变。")
    if desktop is None:
        check_egress_policy()
    gate = Gate(upstream)

    async def active_route():
        if desktop is None:
            check_egress_policy()
        else:
            desktop.check_client()
        selected = await route()
        if selected == selection and gate.source_ports:
            ports = gate.source_ports.copy()
            await asyncio.wait_for(asyncio.to_thread(verify_flows, controller, upstream, ports, selection[0]), 1.5)
        return selected

    now = time.monotonic()
    gate.deadlines.update(route=now + 5, ip=now + 16, ipv6=now + 16)
    if desktop is None:
        listener = await asyncio.start_server(gate.handle, "127.0.0.1", 0)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind(("127.0.0.1", 0))
            listener = await asyncio.start_server(gate.handle, sock=sock)
        except BaseException:
            sock.close()
            raise
    async with listener as server:
        port = server.sockets[0].getsockname()[1]
        tasks = [asyncio.create_task(watch(gate, "route", active_route, selection, 1, 5)),
                 asyncio.create_task(watch(gate, "ip", ips, baseline, 5, 16)),
                 asyncio.create_task(watch(gate, "ipv6", ipv6, v6, 5, 16))]
        try:
            if desktop is not None:
                await desktop.run(gate, port, baseline[0])
                return
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
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--require-ipv6", action="store_true")
    parser.add_argument("--desktop", metavar="APP_DIRECTORY")
    parser.add_argument("--client-pid", type=int)
    parser.add_argument("--worker-pid", type=int)
    parser.add_argument("--test-desktop-relay", action="store_true")
    args = parser.parse_args()
    if args.test_desktop_relay and not args.desktop:
        parser.error("--test-desktop-relay requires --desktop")
    try:
        if args.desktop:
            from desktop_guard import DesktopSession
            if not args.client_pid or not args.worker_pid:
                raise GuardError("桌面版守护缺少已核验的 SakuraCat 进程。")
            with DesktopSession(ROOT, args.desktop, args.client_pid, args.worker_pid, args.upstream, args.controller,
                                args.test_desktop_relay) as desktop:
                asyncio.run(run_session(args.upstream, args.controller, args.require_ipv6, args.check, desktop))
        else:
            asyncio.run(run_session(args.upstream, args.controller, args.require_ipv6, args.check))
    except (Exception, KeyboardInterrupt) as exc:
        reason = str(exc) if isinstance(exc, GuardError) else "出口核验未完成或守护程序已停止。"
        if args.check or args.test_desktop_relay:
            print(reason, file=sys.stderr)
            return 1
        dialog(reason, title="Claude 桌面版断线保护" if args.desktop else "Chrome 出口保护")
        return 20  # The desktop launcher can suppress a duplicate error dialog.
    return 0


if __name__ == "__main__":
    # The desktop session imports GuardError and dialog from this running module.
    sys.modules.setdefault("exit_guard", sys.modules[__name__])
    sys.stdout.reconfigure(errors="backslashreplace")
    sys.stderr.reconfigure(errors="backslashreplace")
    sys.exit(main())
