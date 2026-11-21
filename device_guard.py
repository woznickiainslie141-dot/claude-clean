"""Manage the phone-resident session over an authorized USB Android debug connection."""
# SPDX-License-Identifier: MIT
import argparse
import hashlib
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

from exit_guard import GuardError
from phone_guard import adb

DIR = "/data/local/tmp/claude-clean-watch"
CLASS = "org.claudeclean.RouteWatch"
JAR = Path(__file__).resolve().parent / "android" / "route-watch.jar"


class Session:
    def __init__(self):
        self.serial = adb("-d", "get-serialno")
        if not self.serial or self.serial == "unknown":
            raise GuardError("请连接一台已授权的 USB 手机。")

    def shell(self, command, timeout=12):
        result = subprocess.run(["adb", "-s", self.serial, "shell", command], capture_output=True, timeout=timeout)
        if result.returncode:
            raise GuardError("手机命令未完成，请检查 USB 授权、SakuraCat 和手机守护状态。")
        return result.stdout.decode("utf-8", errors="replace").strip()

    def install(self):
        digest = hashlib.sha256(JAR.read_bytes()).hexdigest()
        remote = f"{DIR}/watch-{digest}.jar"
        self.shell(f"umask 077; mkdir -p {DIR} && chmod 700 {DIR}")
        if self.shell(f"test ! -f {remote} || sha256sum {remote}").split()[:1] != [digest]:
            # A unique temporary file avoids overwriting a running monitor.
            temp = f"{DIR}/upload-{uuid.uuid4().hex}"
            adb("-s", self.serial, "push", str(JAR), temp)
            try:
                if self.shell(f"sha256sum {temp}").split()[0] != digest:
                    raise GuardError("手机上的守护文件校验失败。")
                self.shell(f"chmod 400 {temp} && mv {temp} {remote}")
            finally:
                self.shell(f"rm -f {temp}")
        return remote

    def alive(self):
        result = self.shell(f"if [ -r {DIR}/pid ]; then p=$(cat {DIR}/pid); "
                            'case "$p" in *[!0-9]*|"") exit 0;; esac; '
                            'if [ -r /proc/$p/cmdline ]; then tr "\\000" "\\n" </proc/$p/cmdline | head -1; fi; fi')
        return result == "claude-clean-watch"

    def status(self):
        if not self.alive():
            return "STOPPED"
        record = self.shell(f"cat {DIR}/status 2>/dev/null || true").split()
        if len(record) != 2 or not record[1].isdigit():
            return "STARTING"
        uptime = float(self.shell("cat /proc/uptime").split()[0]) * 1000
        if abs(uptime - int(record[1])) > 15000:
            return "STALE"
        return record[0]

    def start(self):
        if self.alive():
            if self.status() == "ARMED":
                return
            raise GuardError("已有守护会话。请查看状态并核实节点。")
        jar = self.install()
        probe = self.shell(f"CLASSPATH={jar} app_process /system/bin {CLASS} probe", timeout=35).split()
        if len(probe) != 2 or not all(re.fullmatch("[a-f0-9]{64}", value) for value in probe):
            raise GuardError("未核实手机的 VPN、固定节点和出口，本次没有启动守护。")
        pins = " ".join(probe)
        # Never overwrite an enrolled endpoint, even on concurrent first starts.
        self.shell(f"umask 077; (set -C; echo '{pins}' >{DIR}/pin) 2>/dev/null || test -f {DIR}/pin")
        if self.shell(f"cat {DIR}/pin").split() != probe:
            raise GuardError("手机节点或出口与此前登记值不同。核实后可停止守护并选择 reset 重新登记。")
        self.shell(f"cd {DIR} || exit 1; rm -f stop || exit 1; umask 077; export CLASSPATH={jar}; "
                   f"setsid nohup app_process /system/bin --nice-name=claude-clean-watch "
                   f"{CLASS} run </dev/null >{DIR}/watch.log 2>&1 &")
        until = time.monotonic() + 32
        while time.monotonic() < until:
            state = self.status()
            if state == "ARMED":
                return
            if state == "LOCKED":
                raise GuardError("守护已启动，但手机端检测到异常。请查看手机通知。")
            if state == "ALERT_ERROR":
                raise GuardError("手机守护已启动，但未能发出手机通知。请检查通知权限。")
            time.sleep(.5)
        raise GuardError("在等待时间内未核验到手机守护心跳。请检查 status 和手机通知。")

    def stop(self):
        if self.alive():
            self.shell(f"touch {DIR}/stop")
            for _ in range(30):
                time.sleep(.5)
                if not self.alive():
                    return
            raise GuardError("手机进程尚未确认停止。")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("start", "status", "stop", "reset", "selftest"))
    args = parser.parse_args()
    session = Session()
    if args.action == "start":
        session.start()
        print("已核验手机守护正在运行，可以拔掉 USB。")
    elif args.action == "status":
        state = session.status()
        print({"ARMED":"手机守护正常", "LOCKED":"检测到异常，正在执行保护", "STARTING":"正在启动",
               "CHECKING":"正在核验出口", "ALERT_ERROR":"手机通知发送失败", "STALE":"心跳过期，请检查手机",
               "STOPPED":"手机守护未运行"}.get(state, "状态未知"))
    elif args.action == "stop":
        session.stop()
        print("手机守护已停止。")
    elif args.action == "reset":
        if session.alive():
            raise GuardError("请先停止手机守护。")
        session.shell(f"rm -f {DIR}/pin")
        print("下次开始时将记录当时的手机节点和出口。")
    else:
        jar = session.install()
        print(session.shell(f"CLASSPATH={jar} app_process /system/bin {CLASS} selftest", timeout=30))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    try:
        main()
    except (OSError, GuardError, subprocess.TimeoutExpired, ValueError) as error:
        print(str(error) if isinstance(error, GuardError) else "设备检查未完成。请查看 USB 和手机状态。", file=sys.stderr)
        sys.exit(1)
