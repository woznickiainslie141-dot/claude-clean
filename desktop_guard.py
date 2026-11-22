"""Ordinary-user session for the Windows desktop application. No system proxy settings."""
# SPDX-License-Identifier: MIT
import asyncio
from contextlib import ExitStack
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import socket
import struct
import uuid

from exit_guard import GuardError, IP_HOSTS, dialog, exit_at


def launch_options(port, environ):
    proxy = f"http://127.0.0.1:{port}"
    env = dict(environ)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "GRPC_PROXY"):
        env[name] = proxy
    env.update(NO_PROXY="", NO_GRPC_PROXY="", NODE_USE_ENV_PROXY="1")
    args = [f"--proxy-server={proxy}", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
            "--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--dns-prefetch-disable"]
    return args, env


class DesktopSession:
    def __init__(self, root, app_dir, client_pid, worker_pid, upstream, controller, test_only=False):
        self.root = root
        self.app_dir = Path(app_dir)
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        H, D, B = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL
        for name, result, args in (
            ("OpenProcess", H, [D, B, D]), ("CloseHandle", B, [H]), ("WaitForSingleObject", D, [H, D]),
            ("CreateEventW", H, [ctypes.c_void_p, B, B, wintypes.LPCWSTR]), ("SetEvent", B, [H]),
            ("CreateFileW", H, [wintypes.LPCWSTR, D, D, ctypes.c_void_p, D, D, H]),
            ("DeviceIoControl", B, [H, D, ctypes.c_void_p, D, ctypes.c_void_p, D,
                                    ctypes.POINTER(D), ctypes.c_void_p]),
        ):
            fn = getattr(self.k, name)
            fn.restype, fn.argtypes = result, args
        self.client_pid, self.worker_pid = client_pid, worker_pid
        self.ports = {upstream, controller}
        self.test_only = test_only
        self.tcp_table = ctypes.WinDLL("iphlpapi").GetExtendedTcpTable
        self.tcp_table.argtypes = [ctypes.c_void_p, ctypes.POINTER(D), B, D, D, D]
        self.tcp_table.restype = D
        self.handles = ExitStack()

    def registered_launcher(self):
        # MSIX full-trust apps may deny ordinary users direct execution of the WindowsApps file.
        # Inspect the package-specific Windows execution alias as data, without activating it.
        family = "Claude_pzs8sxrjxfjjc"
        alias = Path(os.environ["LOCALAPPDATA"]) / "Microsoft" / "WindowsApps" / family / "claude-desktop.exe"
        handle = self.k.CreateFileW(str(alias), 0, 7, None, 3, 0x00200000, None)  # OPEN_REPARSE_POINT
        if handle == ctypes.c_void_p(-1).value:
            raise GuardError("未找到桌面版的 Windows 启动别名，请检查应用安装。")
        try:
            data = ctypes.create_string_buffer(16384)
            size = wintypes.DWORD()
            if not self.k.DeviceIoControl(handle, 0x900A8, None, 0, data, len(data), ctypes.byref(size), None):
                raise GuardError("无法核验桌面版的 Windows 启动别名。")
            raw = data.raw[:size.value]
            if len(raw) < 12 or struct.unpack_from("<I", raw)[0] != 0x8000001B:  # IO_REPARSE_TAG_APPEXECLINK
                raise GuardError("此启动别名未登记为 Windows 应用。")
            fields = raw[12:].decode("utf-16-le").split("\0")
            if len(fields) < 3 or fields[:2] != [family, family + "!Claude"] or Path(fields[2]) != self.app_dir / "Claude.exe":
                raise GuardError("桌面版启动别名与已核验的安装包不符，请重新检查。")
            return alias
        finally:
            self.k.CloseHandle(handle)

    def __enter__(self):
        try:
            self.registered_launcher()
            self.client = self.k.OpenProcess(0x00100000, False, self.client_pid)
            if not self.client:
                raise GuardError("无法持续核验 SakuraCat 客户端。")
            self.handles.callback(self.k.CloseHandle, self.client)
            self.check_client()
            return self
        except BaseException:
            self.handles.close()
            raise

    def __exit__(self, *error):
        self.handles.close()

    def check_client(self):
        if self.k.WaitForSingleObject(self.client, 0) != 258:  # WAIT_TIMEOUT = still alive
            raise GuardError("SakuraCat 客户端已退出。")
        # The service denies ordinary users OpenProcess. Check its two actual listening sockets instead.
        owners = {port: set() for port in self.ports}
        for family, layout in ((socket.AF_INET, struct.Struct("<I4sI4sII")),
                               (socket.AF_INET6, struct.Struct("<16sII16sIIII"))):
            size = wintypes.DWORD()
            buf = None
            for _ in range(4):
                code = self.tcp_table(buf, ctypes.byref(size), False, family, 3, 0)  # OWNER_PID_LISTENER
                if not code and buf is not None:
                    break
                if code != 122:  # ERROR_INSUFFICIENT_BUFFER
                    raise GuardError("无法核验 SakuraCat 监听端口。")
                buf = ctypes.create_string_buffer(size.value)
            else:
                raise GuardError("SakuraCat 监听端口列表持续变化。")
            count, = struct.unpack_from("<I", buf)
            for i in range(count):
                row = layout.unpack_from(buf, 4 + i * layout.size)
                addr, port, pid = row[1 if family == socket.AF_INET else 0], socket.ntohs(row[2] & 0xffff), row[-1]
                if port in owners and socket.inet_ntop(family, addr) in ("127.0.0.1", "0.0.0.0", "::", "::ffff:127.0.0.1"):
                    owners[port].add(pid)
        if any(found != {self.worker_pid} for found in owners.values()):
            raise GuardError("SakuraCat 的代理或控制端口已退出或被其他进程接管。")

    async def run(self, gate, port, expected_ipv4):
        token = uuid.uuid4().hex
        with ExitStack() as events:
            def new_event(suffix):
                h = self.k.CreateEventW(None, True, False, f"Local\\ClaudeCleanDesktop-{token}-{suffix}")
                if not h:
                    raise GuardError("无法建立桌面守护会话。")
                events.callback(self.k.CloseHandle, h)
                return h

            ready, stop = new_event("ready"), new_event("stop")
            broker = await asyncio.create_subprocess_exec(
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                str(self.root / "desktop-guard.ps1"), "-Mode", "Lease", "-Port", str(port),
                "-RelayPid", str(os.getpid()), "-Token", token, "-ExpectedApp", str(self.app_dir))
            broker_exit = asyncio.create_task(broker.wait())
            tripped = asyncio.create_task(gate.stopped.wait())
            app_exit = None
            try:
                while not broker_exit.done() and gate.allowed():
                    if self.k.WaitForSingleObject(ready, 0) == 0:
                        break
                    await asyncio.wait([broker_exit, tripped], timeout=0.2, return_when=asyncio.FIRST_COMPLETED)
                if not gate.allowed():
                    raise GuardError(gate.reason)
                if broker_exit.done() or self.k.WaitForSingleObject(ready, 0) != 0:
                    raise GuardError("Windows 未授予桌面版专用连接，或程序包已更新。请重新从保护入口启动。")
                # UAC can remain open for a long time. Check via the actual guarded port before launch.
                actual = await asyncio.to_thread(exit_at, port, IP_HOSTS[0])
                if actual != expected_ipv4 or not gate.allowed() or broker_exit.done():
                    raise GuardError("临时放行前，专用转发的 IPv4 或保护状态已改变。")
                if self.test_only:
                    print("已通过桌面专用转发核对可信 IPv4；正在撤销测试会话授权。", flush=True)
                    return
                args, env = launch_options(port, os.environ)
                app = await asyncio.create_subprocess_exec(str(self.registered_launcher()), *args,
                                                          env=env, cwd=self.app_dir)
                app_exit = asyncio.create_task(app.wait())
                await asyncio.wait([app_exit, broker_exit, tripped], return_when=asyncio.FIRST_COMPLETED)
                if broker_exit.done() and not app_exit.done():
                    gate.block("Windows 专用连接授权已结束。")
                if gate.stopped.is_set():
                    self.k.SetEvent(stop)
                    await asyncio.to_thread(dialog, f"{gate.reason}\n桌面版连接已断开，请保存工作，退出后从保护入口重开。",
                                            False, "Claude 桌面版断线保护")
                elif await app_exit:
                    raise GuardError("桌面版启动失败或已异常退出。")
            finally:
                gate.block("桌面会话已结束。")
                self.k.SetEvent(stop)
                for task in (tripped, app_exit):
                    if task is not None:
                        task.cancel()
                # Even if UAC is still pending, the broker can only open events belonging to this session.
                if not broker_exit.done():
                    try:
                        await asyncio.wait_for(asyncio.shield(broker_exit), 4)
                    except asyncio.TimeoutError:
                        broker_exit.cancel()
                await asyncio.gather(*(t for t in (tripped, app_exit, broker_exit) if t), return_exceptions=True)
