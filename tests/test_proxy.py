"""Offline protocol regression tests. All sockets bind to loopback only."""
import base64
import contextlib
import http.server
import socket
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import claude_clean as cc


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.closed = False

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, count):
        # Fragment every response: real TCP need not preserve message boundaries.
        count = min(count, 1)
        data = self.incoming[:count]
        del self.incoming[:count]
        return bytes(data)

    def settimeout(self, value):
        self.timeout = value

    def close(self):
        self.closed = True


OK_IPV4 = b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50'


class Socks5Tests(unittest.TestCase):
    def connect(self, response, url='socks5://127.0.0.1:1080', host='example.com'):
        sock = FakeSocket(response)
        with patch.object(cc.socket, 'create_connection', return_value=sock):
            result = cc.ProxySpec(url).connect_tunnel(host, 443)
        self.assertIs(result, sock)
        self.assertIsNone(sock.timeout)
        return sock

    def test_no_auth_and_remote_domain_resolution(self):
        sock = self.connect(b'\x05\x00' + OK_IPV4)
        self.assertEqual(sock.sent, b'\x05\x01\x00\x05\x01\x00\x03\x0bexample.com\x01\xbb')

    def test_password_auth_and_url_decoding(self):
        sock = self.connect(b'\x05\x02\x01\x00' + OK_IPV4,
                            'socks5h://test%40user:p%3Ass@127.0.0.1:1080')
        self.assertTrue(sock.sent.startswith(b'\x05\x02\x00\x02\x01\x09test@user\x04p:ss'))

    def test_server_may_choose_no_auth_even_when_credentials_exist(self):
        sock = self.connect(b'\x05\x00' + OK_IPV4, 'socks5://test:sample@127.0.0.1')
        self.assertTrue(sock.sent.startswith(b'\x05\x02\x00\x02\x05\x01'))
        self.assertNotIn(b'sample', sock.sent)

    def test_ipv4_and_ipv6_destinations(self):
        for host, atyp in [('192.0.2.1', 1), ('2001:db8::1', 4)]:
            with self.subTest(host=host):
                sock = self.connect(b'\x05\x00' + OK_IPV4, host=host)
                self.assertEqual(sock.sent[6], atyp)

    def test_all_reply_address_types(self):
        for address in [b'\x01' + b'\x00'*4, b'\x04' + b'\x00'*16, b'\x03\x03abc']:
            with self.subTest(address=address):
                self.connect(b'\x05\x00\x05\x00\x00' + address + b'\x00\x50')

    def test_invalid_responses_close_connection(self):
        cases = [b'\x05\xff', b'\x04\x00', b'\x05\x01', b'\x05',
                 b'\x05\x02',  # not offered when no credentials
                 b'\x05\x00\x05\x01\x00\x01',
                 b'\x05\x00\x04\x00\x00\x01',
                 b'\x05\x00\x05\x00\x01\x01',
                 b'\x05\x00\x05\x00\x00\x09',
                 b'\x05\x00\x05\x00\x00\x03\x00',
                 b'\x05\x00\x05\x00\x00\x01\x00']
        for response in cases:
            with self.subTest(response=response):
                sock = FakeSocket(response)
                with patch.object(cc.socket, 'create_connection', return_value=sock):
                    with self.assertRaises(RuntimeError):
                        cc.ProxySpec('socks5://127.0.0.1').connect_tunnel('example.com', 443)
                self.assertTrue(sock.closed)

    def test_auth_failures_and_invalid_lengths(self):
        cases = [('test', 'sample', b'\x01\x01'), ('test', 'sample', b'\x02\x00'),
                 ('x'*256, 'sample', b''), ('test', '', b'')]
        for username, password, response in cases:
            with self.subTest(username_length=len(username), response=response):
                sock = FakeSocket(b'\x05\x02' + response)
                with patch.object(cc.socket, 'create_connection', return_value=sock):
                    with self.assertRaises((RuntimeError, ValueError)):
                        cc.ProxySpec(f'socks5://{username}:{password}@127.0.0.1').connect_tunnel('example.com', 443)
                self.assertTrue(sock.closed)

    def test_reject_unsupported_proxy_schemes(self):
        for url in ['https://127.0.0.1', 'socks4://127.0.0.1', 'http://', 'http://localhost/path']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                cc.ProxySpec(url)

    def test_redaction(self):
        raw = 'http://testuser:sample-secret@127.0.0.1:8080'
        self.assertEqual(cc.redact_proxy(raw), 'http://127.0.0.1:8080 (auth)')
        self.assertNotIn('sample-secret', cc.proxy_key(raw))

    def test_never_mode_rejects_passwords_and_socks(self):
        for url in ['http://test:sample@127.0.0.1:8080', 'socks5h://127.0.0.1:1080']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                cc.open_proxy({'proxy': url, 'relay': 'never'})

    def test_invalid_config_never_falls_back_to_direct(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / 'config.json'
            config.write_text('{invalid', encoding='utf-8')
            with patch.object(cc, 'CONFIG_PATH', config), self.assertRaises(ValueError):
                cc.load_cfg()

    def test_http_connect_preserves_immediate_tunnel_data(self):
        sock = FakeSocket(b'HTTP/1.1 200 OK\r\n\r\nhello')
        with patch.object(cc.socket, 'create_connection', return_value=sock):
            connection = cc.ProxySpec('http://127.0.0.1').connect_tunnel('example.com', 443)
        self.assertEqual(bytes(connection.incoming), b'hello')


@contextlib.contextmanager
def server(handler):
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
    instance = Server(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


class RelayIntegrationTests(unittest.TestCase):
    def test_http_origin_never_receives_proxy_credentials(self):
        seen = []

        class Origin(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, dict(self.headers)))
                body = b'origin-ok'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        with server(Origin) as origin:
            upstream = cc.Relay(require_auth=('testuser', 'testpass')).start()
            front = cc.Relay(cc.ProxySpec(f'http://testuser:testpass@127.0.0.1:{upstream.port}')).start()
            try:
                import requests
                session = requests.Session()
                session.trust_env = False
                response = session.get(f'http://127.0.0.1:{origin.server_address[1]}/hello?q=1',
                                       proxies={'http': front.url}, timeout=3)
                self.assertEqual(response.text, 'origin-ok')
                self.assertEqual(seen[0][0], '/hello?q=1')
                self.assertNotIn('proxy-authorization', {key.lower() for key in seen[0][1]})
                session.close()
            finally:
                front.stop()
                upstream.stop()

    def test_socks_tcp_tunnel_and_payload_in_connect_packet(self):
        observed = []

        class Socks(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                sock.settimeout(3)
                self.server.error = None
                try:
                    version, count = cc._read_exact(sock, 2)
                    methods = cc._read_exact(sock, count)
                    if version != 5 or 0 not in methods:
                        raise AssertionError('Invalid SOCKS greeting')
                    sock.sendall(b'\x05\x00')
                    header = cc._read_exact(sock, 4)
                    if header != b'\x05\x01\x00\x03':
                        raise AssertionError('Expected a remotely resolved hostname')
                    size = cc._read_exact(sock, 1)[0]
                    observed.append((cc._read_exact(sock, size), cc._read_exact(sock, 2)))
                    sock.sendall(OK_IPV4)
                    data = cc._read_exact(sock, 4)
                    sock.sendall(data.upper())
                except BaseException as exc:
                    self.server.error = exc

        with server(Socks) as upstream:
            relay = cc.Relay(cc.ProxySpec(f'socks5://127.0.0.1:{upstream.server_address[1]}')).start()
            try:
                with socket.create_connection(('127.0.0.1', relay.port), timeout=3) as client:
                    client.sendall(b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\nping')
                    self.assertIn(b' 200 ', cc._read_head(client, 8192, exact=True))
                    self.assertEqual(cc._read_exact(client, 4), b'PING')
                self.assertEqual(observed, [(b'example.com', b'\x01\xbb')])
                self.assertIsNone(upstream.error)
            finally:
                relay.stop()


if __name__ == '__main__':
    unittest.main()
