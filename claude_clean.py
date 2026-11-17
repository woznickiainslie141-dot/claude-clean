#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Claude Clean: isolated browser launcher and local proxy utilities.

Requires an existing HTTP or SOCKS5 proxy; does not supply an IP address.
Optional fingerprint-chromium is downloaded separately from its upstream.
See README.md and THIRD_PARTY_NOTICES.md for setup, limitations and provenance.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import queue
import re
import secrets
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone as dt_timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, unquote

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "config.json"
STATE_PATH = HERE / "state.json"
PROFILE_ROOT = HERE / "profiles"
LOG_PATH = HERE / "last_report.txt"

UA = "claude-clean/0.1.0"

# Claude 网页端当前开放的地区（用于本地预警，实际以 Cloudflare 的 loc 为准）
SUPPORTED_CC = {
    "US", "CA", "GB", "IE", "AU", "NZ", "JP", "KR", "SG", "IN", "TW",
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IS", "IT", "LV", "LI", "LT", "LU", "MT", "NL", "NO", "PL", "PT",
    "RO", "SK", "SI", "ES", "SE", "CH", "IL", "AE", "BR", "MX", "ZA",
}

# 出口国家 -> 浏览器 locale（取该地区最常见的那一个）
LOCALE_BY_CC = {
    "US": "en-US", "CA": "en-CA", "GB": "en-GB", "IE": "en-IE", "AU": "en-AU",
    "NZ": "en-NZ", "SG": "en-SG", "IN": "en-IN", "ZA": "en-ZA", "AE": "en-AE",
    "JP": "ja-JP", "KR": "ko-KR", "TW": "zh-TW", "HK": "zh-HK",
    "DE": "de-DE", "AT": "de-AT", "CH": "de-CH", "FR": "fr-FR", "BE": "nl-BE",
    "NL": "nl-NL", "ES": "es-ES", "MX": "es-MX", "BR": "pt-BR", "PT": "pt-PT",
    "IT": "it-IT", "SE": "sv-SE", "NO": "nb-NO", "DK": "da-DK", "FI": "fi-FI",
    "PL": "pl-PL", "CZ": "cs-CZ", "SK": "sk-SK", "HU": "hu-HU", "RO": "ro-RO",
    "GR": "el-GR", "TR": "tr-TR", "IL": "he-IL", "RU": "ru-RU", "UA": "uk-UA",
}

# 机房 / 云厂商特征词（命中即判定为"机房出口"，这类 IP 在 Claude 风控里最吃亏）
DC_KEYWORDS = [
    "amazon", "aws", "google", "gcp", "microsoft", "azure", "digitalocean",
    "vultr", "linode", "akamai", "hetzner", "ovh", "contabo", "oracle",
    "cloudflare", "alibaba", "aliyun", "tencent", "huawei", "racknerd",
    "hostdare", "bandwagon", "ionos", "scaleway", "equinix", "leaseweb",
    "choopa", "upcloud", "kamatera", "hostwinds", "hostinger", "interserver",
    "godaddy", "namecheap", "cloudsigma", "servers", "server", "hosting",
    "datacenter", "data center", "colocation", "vps", "cloud", "idc",
    "radishcloud", "sharktech", "psychz", "quadranet", "cogent", "ntt",
    "level3", "gcore", "beeline", "selectel", "timeweb", "melbicom",
]

RESIDENTIAL_HINTS = [
    "china mobile", "china unicom", "china telecom", "comcast", "at&t",
    "verizon", "spectrum", "charter", "cox", "centurylink", "frontier",
    "kddi", "ntt docomo", "softbank", "sk telecom", "kt corp", "lg u+",
    "bt ", "virgin media", "sky ", "talktalk", "orange", "free sas",
    "deutsche telekom", "vodafone", "telefonica", "movistar", "swisscom",
    "telia", "elisa", "nuro", "kpn", "ziggo", "comcast", "xfinity",
    "j:com", "nuuro", "spectrum", "optimum", "telstra", "optus",
]


# --------------------------------------------------------------------------- #
# 输出
# --------------------------------------------------------------------------- #
def log(msg: str = "") -> None:
    print(msg, flush=True)


def ok(msg: str) -> None:
    print(f"  [OK] {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"  [!!] {msg}", flush=True)


def note(msg: str) -> None:
    print(f"  [--] {msg}", flush=True)


def line(title: str) -> None:
    print(f"\n== {title} " + "=" * max(0, 46 - len(title)), flush=True)


# --------------------------------------------------------------------------- #
# 代理规格
# --------------------------------------------------------------------------- #
class ProxySpec:
    """HTTP CONNECT or SOCKS5 TCP proxy with optional URL-encoded credentials."""

    def __init__(self, url: str):
        u = urlsplit(url.strip())
        if u.scheme not in ("http", "socks5", "socks5h"):
            raise ValueError("Supported proxy schemes: http://, socks5://, socks5h://")
        if not u.hostname or u.query or u.fragment or u.path not in ("", "/"):
            raise ValueError("Proxy URL must contain a host and optional port, without a path/query")
        self.scheme = "http" if u.scheme == "http" else "socks5"
        self.host = u.hostname
        self.port = u.port or (8080 if self.scheme == "http" else 1080)
        if not 1 <= self.port <= 65535:
            raise ValueError("Proxy port must be between 1 and 65535")
        self.user = unquote(u.username or "")
        self.password = unquote(u.password or "")
        if u.username is not None and not self.user:
            raise ValueError("Proxy username cannot be empty")

    @property
    def auth_header(self) -> str:
        if not self.user:
            return ""
        token = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        return f"Proxy-Authorization: Basic {token}\r\n"

    def __repr__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}" + (" (auth)" if self.user else "")

    def connect_tunnel(self, host: str, port: int, timeout: float = 25.0) -> socket.socket:
        if not 1 <= port <= 65535 or not host or any(c in host for c in "\r\n"):
            raise ValueError("Invalid tunnel destination")
        if self.scheme == "http":
            return self._http_connect(host, port, timeout)
        return self._socks5_connect(host, port, timeout)

    def _http_connect(self, host: str, port: int, timeout: float) -> socket.socket:
        s = socket.create_connection((self.host, self.port), timeout=timeout)
        try:
            s.settimeout(timeout)
            authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            s.sendall((f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
                       f"{self.auth_header}\r\n").encode("latin1"))
            head = _read_head(s, 8192, exact=True)
            status = head.split(b"\r\n", 1)[0].split()
            if len(status) < 2 or status[1] != b"200":
                raise RuntimeError("Upstream proxy rejected CONNECT")
            s.settimeout(None)
            return s
        except BaseException:
            s.close()
            raise

    def _socks5_connect(self, host: str, port: int, timeout: float) -> socket.socket:
        # RFC 1928 section 3: server replies with VER, METHOD (exactly 2 bytes).
        s = socket.create_connection((self.host, self.port), timeout=timeout)
        try:
            s.settimeout(timeout)
            offered = (0x00, 0x02) if self.user else (0x00,)
            s.sendall(bytes([5, len(offered), *offered]))
            version, method = _read_exact(s, 2)
            if version != 5 or method not in offered:
                raise RuntimeError("SOCKS5 server rejected authentication methods or sent an invalid version")
            if method == 0x02:
                username, password = self.user.encode(), self.password.encode()
                if not (1 <= len(username) <= 255 and 1 <= len(password) <= 255):
                    raise ValueError("SOCKS5 username and password must each contain 1-255 UTF-8 bytes")
                s.sendall(bytes([1, len(username)]) + username + bytes([len(password)]) + password)
                auth_version, status = _read_exact(s, 2)
                if auth_version != 1 or status != 0:
                    raise RuntimeError("SOCKS5 username/password authentication failed")
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                name = host.encode("idna")
                if not 1 <= len(name) <= 255:
                    raise ValueError("SOCKS5 domain name must contain 1-255 bytes")
                destination = bytes([3, len(name)]) + name
            else:
                destination = bytes([1 if address.version == 4 else 4]) + address.packed
            s.sendall(bytes([5, 1, 0]) + destination + port.to_bytes(2, "big"))
            version, reply, reserved, atyp = _read_exact(s, 4)
            if version != 5 or reserved != 0 or reply != 0:
                raise RuntimeError(f"SOCKS5 CONNECT failed (reply={reply})")
            if atyp == 1:
                _read_exact(s, 6)
            elif atyp == 4:
                _read_exact(s, 18)
            elif atyp == 3:
                size = _read_exact(s, 1)[0]
                if not size:
                    raise RuntimeError("SOCKS5 reply contains an empty address")
                _read_exact(s, size + 2)
            else:
                raise RuntimeError("SOCKS5 reply contains an invalid address type")
            s.settimeout(None)
            return s
        except BaseException:
            s.close()
            raise


def redact_proxy(raw: str) -> str:
    if not raw:
        return "DIRECT"
    try:
        return repr(ProxySpec(raw))
    except (ValueError, TypeError):
        return "<invalid proxy URL>"


def proxy_key(raw: str) -> str:
    return hashlib.sha256(raw.strip().encode()).hexdigest()


def _read_head(sock: socket.socket, cap: int, exact: bool = False) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(1 if exact else 4096)
        if not chunk:
            raise RuntimeError("Connection closed before complete HTTP headers")
        buf += chunk
        if len(buf) > cap:
            raise RuntimeError("头部过大")
    return buf


def _read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("连接被对端关闭")
        buf += chunk
    return buf


# --------------------------------------------------------------------------- #
# 本地中继（链式代理）
# --------------------------------------------------------------------------- #
class Relay:
    """
    upstream 为 None 时：直连出口（仍然是一个 HTTP 代理，便于浏览器统一走它）
    require_auth 仅用于自测：要求客户端带 Proxy-Authorization
    """

    def __init__(self, upstream: ProxySpec | None = None,
                 require_auth: tuple[str, str] | None = None,
                 host: str = "127.0.0.1", port: int = 0):
        self.upstream = upstream
        self.require_auth = require_auth
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(128)
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]
        self._run = True
        self._threads: list[threading.Thread] = []

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> "Relay":
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        self._threads.append(t)
        return self

    def stop(self) -> None:
        self._run = False
        try:
            self._sock.close()
        except OSError:
            pass

    def _accept_loop(self) -> None:
        while self._run:
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    # -- 单连接处理 ------------------------------------------------------ #
    def _handle(self, client: socket.socket) -> None:
        upstream_sock = None
        _tune(client)
        try:
            client.settimeout(30)
            head = _read_head(client, 65536)
            if not head:
                return
            sep = head.find(b"\r\n\r\n")
            hdr, rest = head[:sep + 4], head[sep + 4:]

            if self.require_auth and not self._auth_ok(hdr):
                client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                               b"Proxy-Authenticate: Basic realm=\"relay\"\r\n"
                               b"Content-Length: 0\r\n\r\n")
                return

            req_line = hdr.split(b"\r\n", 1)[0].decode("latin1")
            parts = req_line.split(" ")
            if len(parts) < 3:
                return
            method, target, version = parts[0], parts[1], parts[2]

            if method.upper() == "CONNECT":
                host, _, port_s = target.rpartition(":")
                host = host.strip("[]")
                if not host:
                    host, port_s = target, "443"
                try:
                    port = int(port_s)
                except ValueError:
                    port = 443
                upstream_sock = self._open_upstream(host, port)
                if upstream_sock is None:
                    client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length:0\r\n\r\n")
                    return
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                client.settimeout(None)
                if rest:
                    upstream_sock.sendall(rest)
                _pump(client, upstream_sock)
                return

            # 明文 HTTP：绝对 URI
            u = urlsplit(target)
            if not u.hostname:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length:0\r\n\r\n")
                return
            host, port = u.hostname, (u.port or 80)
            path = u.path or "/"
            if u.query:
                path += "?" + u.query

            lines = hdr.split(b"\r\n")
            keep: list[bytes] = []
            first_done = False
            for ln in lines[1:]:
                if not ln:
                    continue
                name = ln.split(b":", 1)[0].strip().lower()
                if name in (b"proxy-authorization", b"proxy-connection"):
                    continue
                if name == b"connection":
                    continue
                keep.append(ln)

            # CONNECT has already reached the origin. Never forward proxy credentials
            # inside that tunnel: Proxy-Authorization belongs only to the proxy.
            upstream_sock = self._open_upstream(host, port)
            if upstream_sock is None:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length:0\r\n\r\n")
                return
            request_target = path

            head_out = (f"{method} {request_target} {version}\r\n").encode("latin1")
            head_out += b"\r\n".join(keep) + b"\r\n"
            head_out += b"Connection: close\r\n\r\n"
            upstream_sock.sendall(head_out + rest)
            client.settimeout(None)
            _pump(client, upstream_sock)
        except Exception:
            pass
        finally:
            for s in (upstream_sock, client):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    def _auth_ok(self, hdr: bytes) -> bool:
        user, pw = self.require_auth
        want = base64.b64encode(f"{user}:{pw}".encode()).decode()
        for ln in hdr.split(b"\r\n"):
            if ln.lower().startswith(b"proxy-authorization:"):
                if ln.split(b":", 1)[1].strip().decode("latin1") == f"Basic {want}":
                    return True
        return False

    def _open_upstream(self, host: str, port: int) -> socket.socket | None:
        try:
            if self.upstream is None:
                s = socket.create_connection((host, port), timeout=25)
                s.settimeout(None)
                _tune(s)
                return s
            s = self.upstream.connect_tunnel(host, port)
            _tune(s)
            return s
        except Exception:
            return None


def _tune(sock: socket.socket) -> None:
    """代理转发最怕 Nagle + 延迟 ACK：每个小包多 40ms，页面就是几百个包"""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


def _pump(a: socket.socket, b: socket.socket, idle: int = 300) -> None:
    peers = {a: b, b: a}
    buf = bytearray(131072)
    try:
        while True:
            rlist, _, _ = select.select([a, b], [], [], idle)
            if not rlist:
                return
            for s in rlist:
                n = s.recv_into(buf)
                if not n:
                    return
                peers[s].sendall(memoryview(buf)[:n])
    except Exception:
        return


# --------------------------------------------------------------------------- #
# 出口预检
# --------------------------------------------------------------------------- #
@dataclass
class GeoInfo:
    ip: str = ""
    probe_ip: str = ""
    country_code: str = ""
    country: str = ""
    city: str = ""
    region: str = ""
    timezone: str = ""
    asn: str = ""
    org: str = ""
    isp: str = ""
    source: str = ""


def _http_get(session, url: str, proxy_url: str, timeout: float = 12.0):
    return session.get(url, timeout=timeout,
                       proxies={"http": proxy_url, "https": proxy_url},
                       headers={"User-Agent": UA, "Accept": "*/*"})


def probe_exit(proxy_url: str) -> tuple[GeoInfo, dict]:
    import requests  # 延迟导入，--selftest 时不需要

    s = requests.Session()
    s.trust_env = False
    geo = GeoInfo()
    traces: dict[str, dict] = {}
    skew = None

    # 1) Claude / Cloudflare 边缘真实看到的地址
    for name, url in (
        ("claude.ai", "https://claude.ai/cdn-cgi/trace"),
        ("api.anthropic.com", "https://api.anthropic.com/cdn-cgi/trace"),
        ("platform.claude.com", "https://platform.claude.com/cdn-cgi/trace"),
    ):
        try:
            r = _http_get(s, url, proxy_url, 15)
            data = {}
            for raw in r.text.splitlines():
                if "=" in raw:
                    k, v = raw.split("=", 1)
                    data[k.strip()] = v.strip()
            data["_status"] = str(r.status_code)
            traces[name] = data
            if name == "api.anthropic.com":
                date_hdr = r.headers.get("Date")
                if date_hdr:
                    try:
                        from email.utils import parsedate_to_datetime
                        dt = parsedate_to_datetime(date_hdr)
                        skew = abs((datetime.now(dt_timezone.utc) - dt).total_seconds())
                    except Exception:
                        pass
        except Exception as e:
            traces[name] = {"_error": str(e)}

    if traces.get("api.anthropic.com", {}).get("ip"):
        geo.ip = traces["api.anthropic.com"]["ip"]

    # 2) Query multiple geolocation sources in order of preference.
    # Databases may disagree; this is a heuristic, not proof of location.
    def _rec(kind: str, d: dict) -> dict:
        r = {"src": kind, "cc": "", "country": "", "city": "", "region": "",
             "tz": "", "asn": "", "org": "", "isp": "", "ip": ""}
        if kind == "ip-api":
            r.update(cc=d.get("countryCode") or "", country=d.get("country") or "",
                     city=d.get("city") or "", region=d.get("regionName") or "",
                     tz=d.get("timezone") or "",
                     asn=(d.get("as") or "").split(" ")[0] or "",
                     org=((d.get("org") or "") + " " + (d.get("as") or "")).strip(), isp=d.get("isp") or "",
                     ip=d.get("query") or "")
        elif kind == "ipwho":
            conn = d.get("connection") or {}
            r.update(cc=d.get("country_code") or "", country=d.get("country") or "",
                     city=d.get("city") or "", region=d.get("region") or "",
                     tz=(d.get("timezone") or {}).get("id") or "",
                     asn=(f"AS{conn.get('asn')}" if conn.get("asn") else ""),
                     org=conn.get("org") or "", isp=conn.get("isp") or "",
                     ip=d.get("ip") or "")
        else:  # ipapi.co
            r.update(cc=d.get("country_code") or "",
                     country=d.get("country_name") or "",
                     city=d.get("city") or "", region=d.get("region") or "",
                     tz=d.get("timezone") or "", asn=d.get("asn") or "",
                     org=d.get("org") or "", isp=d.get("org") or "",
                     ip=d.get("ip") or "")
        return r

    FIELDS = ("status,query,country,countryCode,regionName,city,timezone,isp,org,as")

    def _lookup(ip: str) -> list[dict]:
        q = [
            ("ip-api", (f"http://ip-api.com/json/{ip}?fields={FIELDS}" if ip
                        else f"http://ip-api.com/json/?fields={FIELDS}")),
            ("ipwho", f"https://ipwho.is/{ip}" if ip else "https://ipwho.is/"),
            ("ipapi.co", f"https://ipapi.co/{ip}/json/" if ip else "https://ipapi.co/json/"),
        ]
        out = []
        for kind, url in q:
            try:
                r = _http_get(s, url, proxy_url, 12)
                d = r.json()
                if kind == "ip-api" and d.get("status") != "success":
                    continue
                if kind == "ipwho" and not d.get("success", True):
                    continue
                out.append(_rec(kind, d))
            except Exception:
                continue
        return out

    generic = _lookup("")            # 第三方站点看到的地址
    if generic:
        geo.probe_ip = next((g["ip"] for g in generic if g.get("ip")), "")

    recs = _lookup(geo.ip) if geo.ip else generic
    if not recs:
        recs = generic

    tz_sources = [(r["src"], r["tz"]) for r in recs if r.get("tz")]
    primary = next((r for r in recs if r.get("tz")), recs[0] if recs else None)
    split = False
    if primary:
        geo.country_code = primary["cc"] or geo.country_code
        geo.country = primary["country"] or geo.country
        geo.city = primary["city"] or geo.city
        geo.region = primary["region"] or geo.region
        geo.timezone = primary["tz"] or geo.timezone
        geo.asn = primary["asn"] or geo.asn
        geo.org = primary["org"] or geo.org
        geo.isp = primary["isp"] or geo.isp
        geo.source = primary["src"]

    split = False
    dual = False
    if geo.ip and geo.probe_ip and geo.ip != geo.probe_ip:
        # 同为一条线路、只是 IPv4/IPv6 各走一边 → 不算分流；
        # 国家都不一样才是真的"两条出口"。
        gcc = (next((g["cc"] for g in generic if g.get("cc")), "") or "").upper()
        ecc = (primary["cc"] if primary else geo.country_code or "").upper()
        if gcc and ecc and gcc != ecc:
            split = True
        else:
            dual = True

    geo.ip = geo.ip or geo.probe_ip

    if not geo.country_code:
        for t in traces.values():
            if t.get("loc"):
                geo.country_code = t["loc"]
                break

    return geo, {"traces": traces, "skew": skew, "split": split,
                 "dual": dual, "tz_sources": tz_sources}



def ip_kind(geo: GeoInfo) -> tuple[str, str]:
    blob = f"{geo.org} {geo.isp} {geo.asn}".lower()
    for kw in RESIDENTIAL_HINTS:
        if kw in blob:
            return "residential", f"命中住宅运营商特征: {kw}"
    for kw in DC_KEYWORDS:
        if kw in blob:
            return "datacenter", f"命中机房/云厂商特征: {kw}"
    return "unknown", "未命中已知特征，需人工确认"


def local_offset_hours() -> float:
    return datetime.now().astimezone().utcoffset().total_seconds() / 3600


def tz_offset_hours(name: str) -> float | None:
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo(name)).utcoffset().total_seconds() / 3600
    except Exception:
        return None


def build_report(geo: GeoInfo, extra: dict, cfg: dict, direct: bool) -> tuple[list[str], dict]:
    out: list[str] = []
    verdict: dict[str, str] = {}

    traces = extra["traces"]
    ips = {name: t.get("ip") for name, t in traces.items() if t.get("ip")}
    locs = {name: t.get("loc") for name, t in traces.items() if t.get("loc")}

    line("01 出口 IP（Anthropic / Cloudflare 实际看到的地址）")
    if ips:
        uniq = set(ips.values())
        for name, t in traces.items():
            if t.get("_error"):
                warn(f"{name}: 连接失败 — {t['_error'][:80]}")
            else:
                note(f"{name}: {t.get('ip')} loc={t.get('loc','?')} colo={t.get('colo','?')} "
                     f"warp={t.get('warp','?')}")
        if len(uniq) == 1:
            ok(f"成功响应的 {len(ips)} 个域名出口一致（未响应的域名无法判断）")
            verdict["exit_consistency"] = "pass"
        else:
            warn(f"出口不一致，出现 {len(uniq)} 个不同地址：{sorted(uniq)}")
            verdict["exit_consistency"] = "fail"
        if extra.get("split"):
            warn(f"分流出站：Claude 看到 {geo.ip}，第三方站点看到 {geo.probe_ip}")
            note("这是 Clash 规则模式最常见的一刀：Anthropic 域名走了代理，其它域名走 DIRECT。")
            note("处理：Clash 切「全局模式」，或给 claude.ai / api.anthropic.com / "
                 "platform.claude.com 单独加代理规则。")
            verdict["split"] = "fail"
        elif extra.get("dual"):
            warn(f"出口地址不同：服务域名 {geo.ip}，检测域名 {geo.probe_ip}")
            note("可能是双栈或分流；同国家不能证明同一节点，请检查代理规则")
            verdict["split"] = "unknown"
        elif geo.ip and geo.probe_ip:
            ok("第三方站点看到的出口与 Claude 一致（没有分流）")
    else:
        warn("拿不到 Cloudflare trace（代理可能不通，或 Anthropic 直接拒绝）")
        verdict["exit_consistency"] = "unknown"

    line("02 地区是否受支持")
    cc = (geo.country_code or "").upper()
    if cc:
        if cc in SUPPORTED_CC:
            ok(f"出口地区 {cc}（{geo.country}）在支持列表内")
            verdict["region"] = "pass"
        else:
            warn(f"出口地区 {cc} 不在本地支持列表内，此列表可能过期，请查看服务官方地区说明")
            verdict["region"] = "fail"
        if locs and len(set(locs.values())) > 1:
            warn(f"Cloudflare 对三个域名的 loc 判断不一致：{locs}")
    else:
        warn("无法确定出口国家")
        verdict["region"] = "unknown"

    line("03 IP 环境（这一项浏览器改不了，只能换线路）")
    if geo.ip:
        kind, why = ip_kind(geo)
        note(f"IP: {geo.ip}")
        note(f"ASN: {geo.asn or '?'}  组织: {geo.org or '?'}")
        note(f"位置: {geo.country} {geo.region} {geo.city}  时区: {geo.timezone or '?'}")
        if kind == "datacenter":
            warn(f"线路类型 = 机房/云服务器（{why}）→ 这类出口在多数检测里都吃亏")
            verdict["ip_kind"] = "fail"
        elif kind == "residential":
            ok(f"线路类型 = 住宅/运营商（{why}）")
            verdict["ip_kind"] = "pass"
        else:
            warn(f"线路类型不明（{why}）")
            verdict["ip_kind"] = "unknown"
        note("机房标签本身不一定封号，但它 + 共享 + 历史滥用 = 高风险组合")

    line("04 环境一致性（浏览器侧，启动器负责）")
    srcs = extra.get("tz_sources") or []
    if srcs:
        note("时区来源: " + ", ".join(f"{k}={t}" for k, t in srcs))
        if len({t for _, t in srcs}) > 1:
            warn(f"不同 IP 库口径不一致，已按 {geo.source or 'ip-api'} 的时区为准")
    exit_tz = geo.timezone
    if exit_tz:
        off_exit = tz_offset_hours(exit_tz)
        off_local = local_offset_hours()
        note(f"出口时区 {exit_tz} (UTC offset={off_exit}) / 本机时区 UTC{off_local:+g}")
        if off_exit == off_local:
            ok("系统时区与出口时区一致（这一项本来就干净）")
        else:
            warn("系统时区与出口时区不一致 → 启动器会在浏览器内覆盖为出口时区")
            note("注意：只覆盖浏览器，操作系统的时区仍然是本机设置，Claude Code 会读到系统值")
        verdict["timezone"] = "fixed_by_launcher" if off_exit != off_local else "pass"
    else:
        warn("出口时区未知，将回落到配置里的 timezone")
        verdict["timezone"] = "unknown"

    loc, loc_why = choose_locale(cfg, geo, direct)
    note(f"浏览器将声明 locale={loc}（{loc_why}）")
    verdict["locale"] = "fixed_by_launcher"

    skew = extra.get("skew")
    if skew is not None:
        if skew > 300:
            warn(f"本机时钟与 Anthropic 边缘偏差 {int(skew)} 秒，TLS/风控都会觉得可疑，先校时")
            verdict["clock"] = "fail"
        else:
            ok(f"本机时钟偏差 {int(skew)} 秒，正常")
            verdict["clock"] = "pass"

    line("05 浏览器启动配置（实际效果需验证）")
    note("WebRTC：请求禁用非代理 UDP；是否生效依赖内核，请运行 --verify")
    note("DNS：通过代理传递目标域名；代理服务器自身的域名仍可能由本机解析")
    note("IPv6：代理承载的 TCP 流量由出口决定；此工具不是全系统防火墙")
    note("浏览器由 CDP 配置；网站仍可能识别其特征")
    note("指纹稳定：独立 profile + 固定 fingerprint seed，同一身份跨会话不变")

    line("06 结论")
    fails = [k for k, v in verdict.items() if v == "fail"]
    if not fails:
        ok("已完成可用的本地预检；未知项和网站端判断不在此结论内")
    else:
        warn(f"仍有硬伤：{', '.join(fails)}")
        note("其中 ip_kind / region 只能靠换线路解决，浏览器怎么改都没用")

    return out, verdict


# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #
DEFAULT_CFG = {
    "proxy": "",
    "relay": "auto",
    "locale": "",
    "timezone": "",
    "engine": "chrome",
    "engine_path": "",
    "profile": "claude",
    "fingerprint_seed": 0,
    "start_urls": ["https://claude.ai/new"],
    "open_check_page": False,
    "extra_args": [],
    "window_size": "1600,1000",
}


def load_cfg() -> dict:
    cfg = dict(DEFAULT_CFG)
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig")))
        except Exception as e:
            raise ValueError("config.json is invalid; fix it before starting") from e
    return cfg


def write_cfg(cfg: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def choose_locale(cfg: dict, geo: GeoInfo, direct: bool) -> tuple[str, str]:
    if cfg.get("locale"):
        return cfg["locale"], "config.json 指定"
    cc = (geo.country_code or "").upper()
    if cc and cc in LOCALE_BY_CC:
        return LOCALE_BY_CC[cc], f"按出口国家 {cc} 自动"
    return "en-US", "兜底"


def choose_timezone(cfg: dict, geo: GeoInfo) -> tuple[str, str]:
    if cfg.get("timezone"):
        return cfg["timezone"], "config.json 指定"
    if geo.timezone:
        return geo.timezone, "按出口 IP 自动"
    return "UTC", "兜底"


# --------------------------------------------------------------------------- #
# CDP（裸 websocket，不依赖 playwright/selenium）
# --------------------------------------------------------------------------- #
class CDPError(RuntimeError):
    pass


class CDP:
    def __init__(self, ws_url: str, timeout: float = 20.0):
        import websocket  # websocket-client
        self._ws = websocket.create_connection(
            ws_url, timeout=timeout, suppress_origin=True,
            enable_multithread=True, http_proxy_host=None,
        )
        self._lock = threading.Lock()
        self._ids = 0
        self._pending: dict[int, list] = {}
        self._q: queue.Queue = queue.Queue()
        self.closed = False
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self._worker = threading.Thread(target=self._work_loop, daemon=True)
        self._worker.start()

    # -- 发送 ------------------------------------------------------------ #
    def send(self, method: str, params: dict | None = None,
             session_id: str | None = None, timeout: float = 15.0) -> dict:
        with self._lock:
            self._ids += 1
            mid = self._ids
            msg = {"id": mid, "method": method}
            if params:
                msg["params"] = params
            if session_id:
                msg["sessionId"] = session_id
            ev = threading.Event()
            slot = [ev, None]
            self._pending[mid] = slot
            try:
                self._ws.send(json.dumps(msg))
            except Exception as e:
                self._pending.pop(mid, None)
                raise CDPError(f"发送失败: {e}")
        if not ev.wait(timeout):
            self._pending.pop(mid, None)
            raise CDPError(f"CDP 超时: {method}")
        self._pending.pop(mid, None)
        res = slot[1]
        if isinstance(res, dict) and "error" in res:
            err = res["error"]
            raise CDPError(f"{method}: {err.get('message', err)}")
        return (res or {}).get("result", {}) if isinstance(res, dict) else {}

    # -- 收 -- #
    def _read_loop(self) -> None:
        import websocket
        while True:
            try:
                raw = self._ws.recv()
            except Exception:
                break
            if not raw:
                break
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            if "id" in msg:
                slot = self._pending.get(msg["id"])
                if slot:
                    slot[1] = msg
                    slot[0].set()
            elif "method" in msg:
                self._q.put(msg)
        self.closed = True
        for slot in list(self._pending.values()):
            slot[1] = {"error": {"message": "连接已关闭"}}
            slot[0].set()

    def _work_loop(self) -> None:
        while True:
            item = self._q.get()
            handler = getattr(self, "_on_event", None)
            if handler:
                try:
                    handler(item.get("method", ""), item.get("params") or {})
                except Exception:
                    pass

    def _on_event(self, method: str, params: dict) -> None:
        pass

    def close(self) -> None:
        try:
            self._ws.close()
        except Exception:
            pass


class Aligner:
    """Attempt timezone/locale overrides on page targets, including new tabs."""

    def __init__(self, cdp: CDP, timezone: str, locale: str):
        self.cdp = cdp
        self.timezone = timezone
        self.locale = locale
        self.sessions: dict[str, str] = {}
        self._lock = threading.Lock()
        self._stop = False
        self.cdp._on_event = self._on_event

    def install(self) -> None:
        try:
            self.cdp.send("Target.setDiscoverTargets", {"discover": True})
        except CDPError:
            pass
        try:
            self.cdp.send("Target.setAutoAttach", {
                "autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True,
                "filter": [{"type": "page"}],
            })
        except CDPError:
            try:
                self.cdp.send("Target.setAutoAttach", {
                    "autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True,
                })
            except CDPError:
                pass
        for t in self._targets():
            if t.get("type") == "page":
                try:
                    self.attach(t["targetId"])
                except CDPError:
                    pass

    def _targets(self) -> list[dict]:
        try:
            return self.cdp.send("Target.getTargets").get("targetInfos", [])
        except CDPError:
            return []

    def attach(self, target_id: str) -> str | None:
        r = self.cdp.send("Target.attachToTarget", {"targetId": target_id, "flatten": True})
        sid = r.get("sessionId")
        if sid:
            with self._lock:
                self.sessions[sid] = target_id
            self.apply(sid)
        return sid

    def apply(self, sid: str) -> None:
        try:
            self.cdp.send("Emulation.setTimezoneOverride", {"timezoneId": self.timezone},
                          session_id=sid, timeout=6)
        except CDPError:
            pass
        try:
            self.cdp.send("Emulation.setLocaleOverride", {"locale": self.locale},
                          session_id=sid, timeout=6)
        except CDPError:
            pass

    def _on_event(self, method: str, params: dict) -> None:
        if method == "Target.attachedToTarget":
            sid = params.get("sessionId")
            info = params.get("targetInfo") or {}
            waiting = bool(params.get("waitingForDebugger"))
            if sid and info.get("type") == "page":
                with self._lock:
                    self.sessions[sid] = info.get("targetId", "")
                self.apply(sid)
            if sid and waiting:
                try:
                    self.cdp.send("Runtime.runIfWaitingForDebugger", session_id=sid, timeout=6)
                except CDPError:
                    pass
        elif method == "Target.detachedFromTarget":
            sid = params.get("sessionId")
            with self._lock:
                self.sessions.pop(sid, None)

    def loop(self) -> None:
        while not self._stop:
            time.sleep(3.0)
            with self._lock:
                sids = list(self.sessions.keys())
            for sid in sids:
                self.apply(sid)

    def start_loop(self) -> None:
        threading.Thread(target=self.loop, daemon=True).start()

    def stop(self) -> None:
        self._stop = True


# --------------------------------------------------------------------------- #
# 浏览器 / 内核
# --------------------------------------------------------------------------- #
def find_engine(cfg: dict) -> tuple[str, str]:
    """返回 (exe, mode) — mode ∈ {'fpchrome','chrome'}"""
    forced = (cfg.get("engine_path") or "").strip()
    if forced:
        p = Path(forced)
        if p.exists():
            return str(p), ("fpchrome" if cfg.get("engine") == "fpchrome" or "fingerprint" in p.name.lower() or
                            (p.parent / "FINGERPRINT").exists() else "chrome")
        warn(f"engine_path 不存在: {forced}")

    want = (cfg.get("engine") or "auto").lower()

    if want != "chrome":
        candidates = []
        for root in (HERE / "engines", HERE / "engines" / "chrome"):
            if root.exists():
                for exe in root.rglob("chrome.exe"):
                    candidates.append(exe)
        for c in candidates:
            return str(c), "fpchrome"

    if want == "fpchrome":
        warn("没找到 fingerprint-chromium，回落到系统 Chrome；先跑 下载内核.ps1 可拿到引擎级指纹")

    for p in (
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft/Edge/Application/msedge.exe",
    ):
        if p.exists():
            return str(p), "chrome"
    raise SystemExit("找不到任何 Chromium 内核，请在 config.json 里写 engine_path")


def build_args(exe: str, mode: str, cfg: dict, relay_url: str,
               locale: str, timezone: str, profile_dir: Path, seed: int) -> list[str]:
    args = [
        exe,
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-default-apps",
        "--disable-search-engine-choice-screen",
        "--disable-blink-features=AutomationControlled",
        f"--proxy-server={relay_url}",
        f"--lang={locale}",
        f"--accept-lang={locale},en",
        "--remote-debugging-port=0",
        # Restrict local target-name resolution while allowing the proxy hostname.
        # This is defense in depth, not a complete network or WebRTC isolation boundary.
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1, EXCLUDE "
        + (urlsplit(relay_url).hostname or "127.0.0.1"),
        f"--window-size={cfg.get('window_size', '1600,1000')}",
    ]
    if mode == "fpchrome":
        args += [
            f"--fingerprint={seed}",
            "--fingerprint-platform=windows",
            "--fingerprint-brand=Chrome",
            "--disable-non-proxied-udp",
            f"--timezone={timezone}",
        ]
    else:
        args += ["--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--disable-quic"]

    args += list(cfg.get("extra_args") or [])
    args.append("about:blank")
    return args


def wait_devtools(profile_dir: Path, proc: subprocess.Popen, timeout: float = 30.0) -> str:
    port_file = profile_dir / "DevToolsActivePort"
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit(
                "浏览器进程提前退出。常见原因：这个 profile 已经有一个窗口在跑，"
                "或者内核参数不被接受。"
            )
        if port_file.exists():
            try:
                content = port_file.read_text().splitlines()
                if content:
                    port = int(content[0].strip())
                    path = content[1].strip() if len(content) > 1 else "/devtools/browser"
                    base = f"ws://127.0.0.1:{port}"
                    return base + (path if path.startswith("/") else "/" + path)
            except Exception:
                pass
        time.sleep(0.2)
    raise SystemExit("等待 DevTools 端口超时")


# --------------------------------------------------------------------------- #
# 自测
# --------------------------------------------------------------------------- #
def selftest() -> int:
    import http.server
    import socketserver

    log("== 中继链路自测 ==")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"relay-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    target_port = srv.server_address[1]

    origin = Relay(require_auth=("u", "p")).start()
    front = Relay(upstream=ProxySpec(f"http://u:p@127.0.0.1:{origin.port}")).start()
    ok(f"内层(需鉴权) {origin.url} / 外层(注入凭据) {front.url}")

    import requests
    s = requests.Session()
    s.trust_env = False
    try:
        r = s.get(f"http://127.0.0.1:{target_port}/", timeout=8,
                  proxies={"http": front.url, "https": front.url})
        assert r.text == "relay-ok"
        ok("明文 HTTP 转发 + 凭据注入 正常")
    except Exception as e:
        warn(f"明文 HTTP 失败: {e}")
        return 1

    # CONNECT 路径：对明文目标做隧道，验证 200 + 数据透传
    try:
        c = socket.create_connection(("127.0.0.1", front.port), timeout=8)
        c.sendall(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
        head = _read_head(c, 4096)
        assert b" 200" in head.split(b"\r\n")[0], head
        c.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        data = b""
        while b"relay-ok" not in data:
            chunk = c.recv(4096)
            if not chunk:
                break
            data += chunk
        c.close()
        assert b"relay-ok" in data
        ok("CONNECT 隧道 + 凭据注入 正常（HTTPS 走的就是这条路径）")
    except Exception as e:
        warn(f"CONNECT 失败: {e}")
        return 1

    # 鉴权缺失应被拒绝
    try:
        direct = Relay(upstream=None).start()
        c = socket.create_connection(("127.0.0.1", origin.port), timeout=8)
        c.sendall(b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        resp = c.recv(4096)
        assert b"407" in resp
        c.close()
        ok("缺凭据被 407 拒绝（说明鉴权头确实生效）")
        direct.stop()
    except Exception as exc:
        warn(f"Authentication rejection self-test failed: {exc}")
        return 1

    srv.shutdown()
    srv.server_close()
    origin.stop()
    front.stop()
    log("\n自测通过。")
    return 0


def selftest_cdp(exe: str, timezone: str = "America/Los_Angeles", locale: str = "en-US") -> int:
    log("== CDP 时区/语言覆盖自测（无头 Chrome）==")
    tmp = Path(tempfile.mkdtemp(prefix="cc-cdp-"))
    proc = subprocess.Popen(
        [exe, f"--user-data-dir={tmp}", "--headless=new", "--no-first-run",
         "--no-default-browser-check", "--remote-debugging-port=0",
         f"--lang={locale}",
         f"--accept-lang={locale},en", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        ws = wait_devtools(tmp, proc, timeout=25)
        cdp = CDP(ws)
        al = Aligner(cdp, timezone, locale)
        al.install()
        time.sleep(0.4)
        target = cdp.send("Target.createTarget", {"url": "about:blank"})["targetId"]
        time.sleep(0.6)
        sid = None
        for s, t in al.sessions.items():
            if t == target:
                sid = s
        if not sid:
            sid = al.attach(target)
        cdp.send("Page.navigate", {"url": "data:text/html,<title>t</title>ok"}, session_id=sid)
        time.sleep(0.8)
        expr = ("JSON.stringify({tz:Intl.DateTimeFormat().resolvedOptions().timeZone,"
                "locale:Intl.DateTimeFormat().resolvedOptions().locale,"
                "nav:navigator.language,languages:navigator.languages})")
        r = cdp.send("Runtime.evaluate", {"expression": expr, "returnByValue": True},
                     session_id=sid)
        val = r.get("result", {}).get("value")
        log(f"  页面内读到: {val}")
        good = (timezone in str(val)) and ("en-US" in str(val))
        if good:
            ok("导航之后时区和 locale 覆盖生效")
        else:
            warn(f"覆盖未按预期生效（期望 {timezone} / {locale}）")
        cdp.close()
        return 0 if good else 1
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 常驻中继 / 探测
# --------------------------------------------------------------------------- #
RELAY_FILE = HERE / "relay.json"


def _port_open(port: int, timeout: float = 1.0) -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def live_relay(cfg: dict) -> str | None:
    """如果常驻中继还活着，直接复用它，保证浏览器/CLI/桌面走同一个出口"""
    if not RELAY_FILE.exists():
        return None
    try:
        j = json.loads(RELAY_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None
    if j.get("proxy_key") != proxy_key(cfg.get("proxy") or ""):
        return None
    port = int(j.get("port") or 0)
    if port and _port_open(port):
        return f"http://127.0.0.1:{port}"
    return None


def open_proxy(cfg: dict, direct: bool = False) -> tuple[str, Relay | None]:
    """Use HTTP directly only without credentials; normalize SOCKS through the relay."""
    raw = "" if direct else (cfg.get("proxy") or "").strip()
    if not raw:
        if not direct:
            raise ValueError("Configure a proxy or explicitly request --direct")
        relay = Relay().start()
        return relay.url, relay
    spec = ProxySpec(raw)
    mode = str(cfg.get("relay") or "auto").lower()
    if mode not in ("auto", "always", "never"):
        raise ValueError("relay must be auto, always or never")
    needs_relay = bool(spec.user) or spec.scheme == "socks5"
    if mode == "never" and needs_relay:
        raise ValueError("SOCKS5 and authenticated proxies require relay=auto or always")
    live = live_relay(cfg)
    if live:
        return live, None
    if mode != "always" and not needs_relay:
        return raw, None
    relay = Relay(upstream=spec).start()
    return relay.url, relay


def cmd_status(cfg: dict) -> int:
    if not RELAY_FILE.exists():
        note("没有常驻中继（还没跑过 us-on.ps1）")
        return 1
    j = json.loads(RELAY_FILE.read_text(encoding="utf-8"))
    if j.get("proxy_key") != proxy_key(cfg.get("proxy") or ""):
        warn("Relay configuration differs from config.json; restore before restarting")
        return 1
    port = int(j.get("port") or 0)
    alive = _port_open(port)
    log(f"  端口   : {port}  {'活着' if alive else '已退出'}")
    log(f"  代理   : {j.get('proxy_display') or '<unknown>'}")
    log(f"  PID    : {j.get('pid')}")
    log(f"  启动于 : {datetime.fromtimestamp(j.get('started', 0)).isoformat(timespec='seconds')}")
    log(f"  地址   : http://127.0.0.1:{port}")
    return 0 if alive else 1


def cmd_relay_only(cfg: dict, port: int) -> int:
    """前台常驻：绑定固定端口，写 relay.json，供所有程序共用"""
    raw = (cfg.get("proxy") or "").strip()
    spec = ProxySpec(raw) if raw else None
    try:
        relay = Relay(upstream=spec, port=port).start()
    except OSError as e:
        warn(f"端口 {port} 绑定失败: {e}")
        return 2
    info = {
        "port": relay.port,
        "pid": os.getpid(),
        "proxy_key": proxy_key(raw),
        "proxy_display": redact_proxy(raw),
        "started": int(time.time()),
        "config": str(CONFIG_PATH),
    }
    temporary = RELAY_FILE.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(RELAY_FILE)
    log(f"RELAY_READY {relay.port} proxy={redact_proxy(raw)}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        relay.stop()
        try:
            RELAY_FILE.unlink()
        except OSError:
            pass
    return 0


def cmd_probe(cfg: dict) -> int:
    """给 PowerShell 用：输出一行 JSON"""
    live = live_relay(cfg)
    relay = None
    if live:
        proxy_url = live
    else:
        raw = (cfg.get("proxy") or "").strip()
        spec = ProxySpec(raw) if raw else None
        relay = Relay(upstream=spec).start()
        proxy_url = relay.url
    try:
        geo, extra = probe_exit(proxy_url)
        kind, why = ip_kind(geo) if geo.ip else ("unknown", "")
        payload = {
            "ip": geo.ip,
            "probe_ip": geo.probe_ip,
            "split": bool(extra.get("split")),
            "dual": bool(extra.get("dual")),
            "cc": geo.country_code,
            "country": geo.country,
            "city": geo.city,
            "timezone": geo.timezone,
            "asn": geo.asn,
            "org": geo.org,
            "kind": kind,
            "kind_why": why,
            "supported": (geo.country_code or "").upper() in SUPPORTED_CC,
            "locale": choose_locale(cfg, geo, not cfg.get("proxy"))[0],
            "skew": extra.get("skew"),
            "tz_sources": extra.get("tz_sources") or [],
            "traces": {k: {kk: vv for kk, vv in v.items() if kk != "_status"}
                       for k, v in (extra.get("traces") or {}).items()},
        }
        print(json.dumps(payload, ensure_ascii=False))
        return 0
    finally:
        if relay:
            relay.stop()


VERIFY_JS = r"""
(async () => {
  const r = {
    href: location.href,
    body: (document.body ? document.body.innerText : '').slice(0, 600),
    ua: navigator.userAgent,
    lang: navigator.language,
    langs: (navigator.languages || []).join(','),
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    locale: Intl.DateTimeFormat().resolvedOptions().locale,
    webdriver: navigator.webdriver,
    platform: navigator.platform,
    cores: navigator.hardwareConcurrency,
    tid: (navigator.userAgentData && navigator.userAgentData.brands)
         ? navigator.userAgentData.brands.map(b => b.brand + '/' + b.version).join(' ')
         : '',
  };
  r.webrtc = await new Promise(res => {
    const cand = [];
    try {
      const pc = new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
      pc.onicecandidate = e => {
        if (e.candidate && e.candidate.candidate) cand.push(e.candidate.candidate);
      };
      pc.createDataChannel('probe');
      pc.createOffer().then(o => pc.setLocalDescription(o)).catch(() => {});
      setTimeout(() => { try { pc.close(); } catch (e) {} res(cand); }, 5000);
    } catch (e) { res(['ERR:' + e.message]); }
  });
  return JSON.stringify(r);
})()
"""


def cmd_verify(cfg: dict) -> int:
    """无头实测：在 claude.ai 的真实页面上量时区 / 语言 / WebRTC，不依赖第三方检测站"""
    raw = (cfg.get("proxy") or "").strip()
    proxy_url, relay = open_proxy(cfg, direct=not raw)

    try:
        exe, mode = find_engine(cfg)
        geo, extra = probe_exit(proxy_url)
        tz, _ = choose_timezone(cfg, geo)
        loc, _ = choose_locale(cfg, geo, not raw)

        tmp = Path(tempfile.mkdtemp(prefix="cc-verify-"))
        seed = int(cfg.get("fingerprint_seed") or 1)
        args = build_args(exe, mode, cfg, proxy_url, loc, tz, tmp, seed)
        args.insert(1, "--headless=new")
        args[-1] = "about:blank"
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cdp = None
        try:
            ws = wait_devtools(tmp, proc, timeout=25)
            cdp = CDP(ws)
            al = Aligner(cdp, tz, loc)
            al.install()
            time.sleep(0.5)
            tid = cdp.send("Target.createTarget",
                           {"url": "https://claude.ai/cdn-cgi/trace"})["targetId"]
            time.sleep(7.0)
            sid = None
            for s, t in al.sessions.items():
                if t == tid:
                    sid = s
            if not sid:
                sid = al.attach(tid)
            r = cdp.send("Runtime.evaluate",
                         {"expression": VERIFY_JS, "awaitPromise": True,
                          "returnByValue": True}, session_id=sid, timeout=20)
            val = json.loads(r["result"]["value"])
        finally:
            if cdp:
                cdp.close()
            try:
                proc.terminate(); proc.wait(timeout=6)
            except Exception:
                pass
            shutil.rmtree(tmp, ignore_errors=True)
    finally:
        if relay:
            relay.stop()

    line("浏览器内实测（headless，用的是同一套启动参数）")
    trace = ""
    for raw_line in (val.get("body") or "").splitlines():
        if raw_line.startswith(("ip=", "loc=", "colo=", "warp=")):
            trace += raw_line + "  "
    note(f"URL      : {val.get('href')}")
    note(f"trace    : {trace or '取不到（claude.ai 没回来）'}")
    note(f"UA       : {val.get('ua')}")
    note(f"brands   : {val.get('tid')}")
    note(f"language : {val.get('lang')}  [{val.get('langs')}]")
    note(f"Intl     : tz={val.get('tz')}  locale={val.get('locale')}")
    note(f"webdriver: {val.get('webdriver')}   platform={val.get('platform')}  cores={val.get('cores')}")

    cands = val.get("webrtc") or []
    bad = []
    line("WebRTC")
    if not cands:
        ok("ICE 候选 0 个 —— 非代理 UDP 已禁用，页面拿不到你任何真实地址")
    else:
        bad = []
        for c in cands:
            note(c[:110])
            m = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", c)
            if m and any(not ip.startswith(("10.", "127.", "169.254.", "192.168.", "172.16."))
                         for ip in m):
                bad.append(c)
        if bad:
            warn(f"仍有 {len(bad)} 个候选带公网地址 —— 这个内核没吃 --force-webrtc-ip-handling-policy")
        else:
            ok("候选里没有公网地址（只有本地/占位候选）")

    line("结论")
    good = 0
    if val.get("tz") == tz:
        ok(f"时区已是出口时区 {tz}"); good += 1
    else:
        warn(f"时区 {val.get('tz')} != 期望 {tz}")
    if (val.get("locale") or "").startswith(loc.split("-")[0]):
        ok(f"Intl locale 已是 {val.get('locale')}"); good += 1
    else:
        warn(f"Intl locale {val.get('locale')} != 期望 {loc}")
    if (val.get("lang") or "").startswith(loc.split("-")[0]):
        ok(f"navigator.language 已是 {val.get('lang')}"); good += 1
    else:
        warn(f"navigator.language {val.get('lang')} != 期望 {loc}")
    if val.get("webdriver") is False:
        ok("navigator.webdriver = false"); good += 1
    if not bad:
        good += 1
    note(f"{good}/5 项通过；这个窗口拿去跑 cleanip 检测，浏览器环境那几栏才会跟着变")
    return 0 if good == 5 else 1


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def main() -> int:
    global CONFIG_PATH
    ap = argparse.ArgumentParser(description="Claude 安全窗口启动器")
    ap.add_argument("--config", default=str(CONFIG_PATH))
    ap.add_argument("--init", action="store_true", help="生成 config.json 模板")
    ap.add_argument("--dry-run", action="store_true", help="只做预检，不启动浏览器")
    ap.add_argument("--check", action="store_true", help="启动后顺手打开 cleanip 检测页")
    ap.add_argument("--direct", action="store_true", help="忽略代理，仅做环境隔离")
    ap.add_argument("--locale", default="")
    ap.add_argument("--timezone", default="")
    ap.add_argument("--profile", default="")
    ap.add_argument("--seed", type=int, default=0, help="临时换一个 fingerprint seed（新设备身份）")
    ap.add_argument("--url", action="append", default=None)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--selftest-cdp", action="store_true")
    ap.add_argument("--probe", action="store_true", help="只探测出口，输出 JSON")
    ap.add_argument("--relay-only", action="store_true", help="常驻中继（浏览器/CLI/桌面共用同一出口）")
    ap.add_argument("--port", type=int, default=0, help="中继端口，0=随机")
    ap.add_argument("--status", action="store_true", help="查看常驻中继状态")
    ap.add_argument("--engine", default="", help="chrome | fpchrome | auto（临时切换内核）")
    ap.add_argument("--verify", action="store_true",
                    help="用无头浏览器在 claude.ai 上实测时区/语言/WebRTC 是否干净")
    args = ap.parse_args()

    CONFIG_PATH = Path(args.config)
    PROFILE_ROOT.mkdir(parents=True, exist_ok=True)

    if args.selftest:
        return selftest()

    if args.selftest_cdp:
        exe, _mode = find_engine(load_cfg())
        return selftest_cdp(exe)

    cfg = load_cfg()
    if args.init or not CONFIG_PATH.exists():
        write_cfg(cfg)
        log(f"已写入配置模板: {CONFIG_PATH}")
        log("先把 proxy 填成你的住宅/ISP 代理，再启动。示例：")
        log('  "proxy": "http://user:pass@1.2.3.4:8080"')
        log('  "proxy": "socks5://user:pass@1.2.3.4:1080"')
        return 0

    if args.locale:
        cfg["locale"] = args.locale
    if args.timezone:
        cfg["timezone"] = args.timezone
    if args.engine:
        cfg["engine"] = args.engine
        if args.engine.lower() == "chrome":
            cfg["engine_path"] = ""
    if args.profile:
        cfg["profile"] = args.profile
    if args.seed:
        cfg["fingerprint_seed"] = args.seed
    if args.url:
        cfg["start_urls"] = args.url
    if args.check:
        cfg["open_check_page"] = True

    if args.status:
        return cmd_status(cfg)
    if args.direct:
        cfg["proxy"] = ""
    elif not (cfg.get("proxy") or "").strip():
        raise ValueError("Set proxy in config.json, or explicitly use --direct for direct access")
    else:
        ProxySpec(cfg["proxy"])

    if args.relay_only:
        return cmd_relay_only(cfg, args.port or int(cfg.get("relay_port") or 10800))
    if args.probe:
        return cmd_probe(cfg)
    if args.verify:
        return cmd_verify(cfg)

    state = load_state()
    direct = bool(args.direct) or not (cfg.get("proxy") or "").strip()

    log("")
    log("  Claude 安全窗口 · 启动器")
    log("  ------------------------------------------------------------")

    proxy_url, relay = open_proxy(cfg, direct=args.direct)
    note(f"Proxy: {redact_proxy(proxy_url)}")

    # 2) 预检
    geo = GeoInfo()
    extra = {"traces": {}, "skew": None}
    try:
        geo, extra = probe_exit(proxy_url)
    except Exception as e:
        warn(f"预检失败: {e}")

    _report_lines, verdict = build_report(geo, extra, cfg, direct)

    # 3) 身份固定：seed / profile
    seed = int(cfg.get("fingerprint_seed") or 0)
    if seed <= 0:
        seed = state.get("fingerprint_seed") or secrets.randbelow(2 ** 31 - 1) + 1
        cfg["fingerprint_seed"] = seed
        write_cfg(cfg)
        note(f"生成固定 fingerprint seed={seed}（之后每次都用它，别改）")
    else:
        note(f"fingerprint seed={seed}（固定身份）")

    profile_name = cfg.get("profile") or "claude"
    if not re.fullmatch(r"[A-Za-z0-9_-]+", profile_name):
        raise ValueError("profile must contain only letters, digits, underscores and hyphens")
    profile_dir = PROFILE_ROOT / profile_name
    profile_dir.mkdir(parents=True, exist_ok=True)

    # 4) 出口漂移预警
    prev = state.get("last_exit") or {}
    if prev.get("ip") and geo.ip and prev["ip"] != geo.ip:
        warn(f"出口 IP 变了：{prev['ip']} → {geo.ip}"
             f"（国家 {prev.get('cc','?')} → {geo.country_code or '?'}）")
        note("同一个账号频繁换 IP/国家是风控重点，尽量固定一条线路")
    if geo.ip:
        state["last_exit"] = {"ip": geo.ip, "cc": geo.country_code,
                             "tz": geo.timezone, "at": int(time.time())}
        save_state(state)

    # 5) 对齐参数
    timezone, tz_why = choose_timezone(cfg, geo)
    locale, loc_why = choose_locale(cfg, geo, direct)
    line("07 生效参数")
    note(f"timezone = {timezone}  ({tz_why})")
    note(f"locale   = {locale}  ({loc_why})")
    note(f"proxy    = {proxy_url}")

    try:
        LOG_PATH.write_text(
            "\n".join([
                f"time={datetime.now().isoformat(timespec='seconds')}",
                f"proxy={redact_proxy(cfg.get('proxy') or '')}",
                f"exit_ip={geo.ip} cc={geo.country_code} tz={geo.timezone}",
                f"asn={geo.asn} org={geo.org}",
                f"traces={json.dumps(extra['traces'], ensure_ascii=False)}",
                f"verdict={json.dumps(verdict, ensure_ascii=False)}",
                f"timezone_used={timezone} locale_used={locale} seed={seed}",
            ]), encoding="utf-8")
        note(f"预检报告已写入 {LOG_PATH.name}")
    except Exception:
        pass

    if args.dry_run:
        note("--dry-run：不启动浏览器。")
        if relay:
            relay.stop()
        return 0

    # 6) 启动
    try:
        exe, mode = find_engine(cfg)
    except SystemExit:
        if relay:
            relay.stop()
        raise
    note(f"内核: {Path(exe).name} ({mode})")
    if mode == "chrome":
        warn("当前是系统 Chrome：时区/语言只能靠 CDP 在渲染层覆盖，"
             "字体与 Canvas 等仍是你本机的真实值")
        note("想要引擎级字体/画布/WebRTC 一致性，跑一次 下载内核.ps1 换 fpchrome")

    try:
        (profile_dir / "DevToolsActivePort").unlink(missing_ok=True)
    except Exception:
        pass

    cmd = build_args(exe, mode, cfg, proxy_url, locale, timezone, profile_dir, seed)
    note("启动参数: " + " ".join(cmd[1:]))
    proc = subprocess.Popen(cmd)

    cdp = None
    aligner = None
    try:
        ws = wait_devtools(profile_dir, proc)
        cdp = CDP(ws)
        aligner = Aligner(cdp, timezone, locale)
        ver = cdp.send("Browser.getVersion")
        note(f"DevTools 已连接: {ver.get('product')}")
        aligner.install()
        aligner.start_loop()
        time.sleep(0.5)

        initial = {t["targetId"] for t in aligner._targets() if t.get("type") == "page"}
        urls = list(cfg.get("start_urls") or ["https://claude.ai/new"])
        if cfg.get("open_check_page"):
            urls.append("https://cleanip.io/claude")
        opened = 0
        for u in urls:
            try:
                cdp.send("Target.createTarget", {"url": u})
                opened += 1
            except CDPError as e:
                warn(f"打开 {u} 失败: {e}")

        # 只关掉启动时那一个空白页，避免误关还没提交导航的新标签
        time.sleep(1.0)
        if opened:
            for tid in initial:
                try:
                    cdp.send("Target.closeTarget", {"targetId": tid})
                except CDPError:
                    pass
    except SystemExit:
        raise
    except Exception as e:
        warn(f"CDP 对齐失败（浏览器仍在运行，但时区可能没盖住）: {e}")

    line("08 已启动")
    note("窗口已经打开。关闭它只结束浏览器；常驻中继还在，Claude Code 继续可用")
    note("登录/注册全程只用这个窗口，别用平时的浏览器，也别中途换代理")
    note("第一次登录后不要清 profile，指纹和登录态一起构成同一个'设备'")

    try:
        proc.wait()
    except KeyboardInterrupt:
        pass
    finally:
        if aligner:
            aligner.stop()
        if cdp:
            cdp.close()
        if relay:
            relay.stop()
            log("\n中继已关闭，本次会话结束。")
        else:
            log("\n浏览器已关闭；常驻中继仍在运行（一键还原用 us-off.ps1）")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(2)
