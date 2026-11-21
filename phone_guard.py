"""Read-only Android VPN inspection, with opt-in USB session monitoring."""
# SPDX-License-Identifier: MIT
import argparse
import asyncio
import http.client
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys

from exit_guard import GuardError, dialog, read_reply, selected_route


VPN = "com.sakura.app"
APP = "com.anthropic.claude"
TITLE = "手机 USB 出口检查"


def adb(*args, data=None):
    result = subprocess.run(["adb", *args], input=data, capture_output=True, timeout=6)
    if result.returncode:
        raise GuardError("USB 或手机检查命令不可用，请确认手机已解锁、调试已授权。")
    return result.stdout.decode("utf-8", errors="replace").strip()


class Phone:
    def __init__(self, serial, controller):
        self.serial = serial
        self.controller = controller
        self.user = self.shell("am", "get-current-user")
        if not self.user.isdigit():
            raise GuardError("无法确认手机的当前用户。")

    def shell(self, *args):
        return adb("-s", self.serial, "shell", *args)

    def uid(self, package):
        line = self.shell("cmd", "package", "list", "packages", "--user", self.user, "-U", package)
        match = re.search(rf"^package:{re.escape(package)}\s+uid:(\d+)$", line, re.M)
        return match[1] if match else None

    def device_socket(self, service):
        # ADB smart socket. Keep binary TLS intact even on older Windows clients.
        sock = socket.create_connection(("127.0.0.1", 5037), timeout=4)
        try:
            for command in (f"host:transport:{self.serial}", service):
                payload = command.encode("utf-8")
                sock.sendall(f"{len(payload):04x}".encode("ascii") + payload)
                status = bytearray()
                while len(status) < 4:
                    part = sock.recv(4 - len(status))
                    if not part:
                        raise GuardError("USB 连接已断开。")
                    status.extend(part)
                if status != b"OKAY":
                    raise GuardError("手机无法建立检测连接。")
            return sock
        except BaseException:
            sock.close()
            raise

    def route(self):
        def get(path):
            conn = http.client.HTTPConnection("127.0.0.1", timeout=4)
            conn.sock = self.device_socket(f"tcp:{self.controller}")
            return json.loads(read_reply(conn, path, 4_000_000))
        return selected_route(get("/configs")["mode"], get("/proxies")["proxies"])

    def protection(self):
        if self.shell("am", "get-current-user") != self.user:
            raise GuardError("手机当前用户已切换。")
        def setting(key):
            return self.shell("settings", "--user", self.user, "get", "secure", key)
        vpn_uid = self.uid(VPN)
        app_uid = self.uid(APP)
        networks = self.shell("dumpsys", "connectivity").splitlines()
        owners = set()
        for line in networks:
            if re.search(r"\bVPN CONNECTED\b|Transports:\s*VPN\b", line, re.I):
                owners.update(re.findall(r"\bOwnerUid:\s*(\d+)", line, re.I))
        def interface(uid):
            if not uid:
                return None
            # Kernel route lookup only. No packets go to the documentation address.
            line = self.shell("ip", "route", "get", "192.0.2.1", "uid", uid)
            match = re.search(r"\bdev\s+(tun\d+)\b", line)
            return match[1] if match else None
        shell_tun = interface("2000")
        return {
            "当前 VPN 属于 SakuraCat": bool(vpn_uid and owners == {vpn_uid}),
            "始终开启 SakuraCat VPN": setting("always_on_vpn_app") == VPN,
            "阻止未使用 VPN 的连接": setting("always_on_vpn_lockdown") == "1",
            "断线绕行名单为空": setting("always_on_vpn_lockdown_whitelist") in {"", "null"},
            "检测流量与目标应用的 IPv4 路由均进入同一 VPN": bool(shell_tun and shell_tun == interface(app_uid)),
        }

    def exit_ip(self):
        # nc runs as Android's shell UID. TLS is verified on the PC over USB.
        host = "api.ipify.org"
        service = f"exec:exec toybox nc -4 -w 4 {host} 443"
        with self.device_socket(service) as sock:
            conn = http.client.HTTPConnection(host, timeout=4)
            conn.sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            body = read_reply(conn, "/", 80)
        ip = ipaddress.IPv4Address(body.decode("ascii").strip())
        if not ip.is_global:
            raise GuardError("手机检测返回的地址无效。")
        return str(ip)


def require_protection(phone):
    if not all(phone.protection().values()):
        raise GuardError("手机的 VPN 锁定或应用路由未通过核验。")


async def monitor(phone, stop_app):
    await asyncio.to_thread(require_protection, phone)
    route = await asyncio.to_thread(phone.route)
    pinned = await asyncio.wait_for(asyncio.to_thread(phone.exit_ip), 7)
    action = "异常时将通过 USB 请求停止手机上的 Claude。" if stop_app else "异常时将在电脑上提醒。"
    if not dialog(f"手机 IPv4 出口为 {pinned}，请确认这是你信任的节点。{action} 开始本次监测吗？", True, TITLE):
        return
    print("USB 监测中。关闭窗口结束监测。", flush=True)
    try:
        while True:
            await asyncio.to_thread(require_protection, phone)
            if await asyncio.to_thread(phone.route) != route or await asyncio.wait_for(asyncio.to_thread(phone.exit_ip), 7) != pinned:
                raise GuardError("手机的代理路径或 IPv4 出口发生变化。")
            await asyncio.sleep(3)
    except Exception as exc:
        action = "请在手机上检查 VPN。"
        if stop_app:
            try:
                # Address only the enrolled device and Android user. Never launch the app.
                await asyncio.to_thread(phone.shell, "am", "force-stop", "--user", phone.user, APP)
                action = "已向手机发送停止 Claude 的命令，重新打开前请核实节点。"
            except Exception:
                action = "USB 停止命令未能送达，请在手机上手动停止应用。"
        reason = str(exc) if isinstance(exc, GuardError) else "USB 或出口状态无法核验。"
        dialog(reason + " " + action, title=TITLE)
        return 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("check", "settings", "watch", "watch-stop"), default="check", nargs="?")
    parser.add_argument("--controller", default=39797, type=int)
    args = parser.parse_args()
    try:
        serial = adb("-d", "get-serialno")
        if not serial or serial == "unknown" or not 0 < args.controller < 65536:
            raise GuardError("请选择唯一已授权的 USB 手机和有效控制端口。")
        phone = Phone(serial, args.controller)
        if args.mode == "settings":
            phone.shell("am", "start", "-a", "android.settings.VPN_SETTINGS")
        elif args.mode == "check":
            for label, ok in phone.protection().items():
                print(f"{label}：{'是' if ok else '否或无法核验'}")
            phone.route()
            print("SakuraCat 处于全局模式，已选择固定远程节点。")
        else:
            return asyncio.run(monitor(phone, args.mode == "watch-stop"))
    except (Exception, KeyboardInterrupt) as exc:
        print(str(exc) if isinstance(exc, GuardError) else "USB 检查未完成，请核实设备和 SakuraCat 控制接口。", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
