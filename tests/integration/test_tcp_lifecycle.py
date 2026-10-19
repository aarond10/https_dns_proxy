"""Exercise real TCP clients and shutdown against a local TLS DoH server."""

import argparse
import http.server
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest


def query(identifier):
    return struct.pack("!6H", identifier, 0x0100, 1, 0, 0, 0) + (
        b"\x07example\x04test\x00\x00\x01\x00\x01"
    )


def answer(request):
    # A valid DNS response with EDNS padding, large enough to exercise framing.
    question = request[12:]
    padding = 4096 - 12 - len(question) - 15
    return (
        struct.pack("!6H", struct.unpack("!H", request[:2])[0], 0x8180, 1, 0, 0, 1)
        + question
        + b"\x00"
        + struct.pack("!HHIH", 41, 4096, 0, padding + 4)
        + struct.pack("!HH", 12, padding)
        + bytes(padding)
    )


def receive_exact(client, length):
    data = bytearray()
    while len(data) < length:
        part = client.recv(length - len(data))
        if not part:
            raise AssertionError("TCP stream ended in the middle of a frame")
        data.extend(part)
    return bytes(data)


def receive_frame(client):
    length = struct.unpack("!H", receive_exact(client, 2))[0]
    return receive_exact(client, length)


class LocalDohServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, context):
        super().__init__(("127.0.0.1", 0), DohHandler)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.received = threading.Event()
        self.release = threading.Event()
        self.release.set()


class DohHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        request = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.received.set()
        if not self.server.release.wait(15):
            return
        response = answer(request)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/dns-message")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass  # The shutdown-deadline tests deliberately cancel the transfer.

    def log_message(self, *args):
        pass


class TcpLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = tempfile.TemporaryDirectory(prefix="hdp-tcp-lifecycle-")
        cls.root = Path(cls.files.name)
        cls.cert = cls.root / "cert.pem"
        key = cls.root / "key.pem"
        subprocess.run([
            OPTIONS.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cls.cert), "-days", "1",
            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(cls.cert, key)

    @classmethod
    def tearDownClass(cls):
        cls.files.cleanup()

    def setUp(self):
        self.server = LocalDohServer(self.context)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()
        self.clients = []
        self.process = None
        self.log = tempfile.TemporaryFile(mode="w+b")
        self.memory_log = self.root / (self.id().rsplit(".", 1)[-1] + ".valgrind")

    def tearDown(self):
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        for client in self.clients:
            client.close()
        self.server.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join()
        self.log.seek(0)
        output = self.log.read().decode(errors="replace")
        self.log.close()
        if self.process is not None:
            memory_output = self.memory_log.read_text() if self.memory_log.exists() else ""
            self.assertEqual(self.process.returncode, 0, output + memory_output)

    def start_proxy(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        command = [str(OPTIONS.binary), "-a", "127.0.0.1", "-p", str(self.port),
                   "-r", f"https://127.0.0.1:{self.server.server_port}/dns-query",
                   "-C", str(self.cert), "-x", "-4", "-vvv"]
        if OPTIONS.valgrind:
            command = [OPTIONS.valgrind, "--error-exitcode=99", "--leak-check=full",
                       "--show-leak-kinds=definite,indirect",
                       "--errors-for-leak-kinds=definite,indirect",
                       f"--log-file={self.memory_log}"] + command
        environment = os.environ.copy()
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy",
                     "https_proxy", "all_proxy"):
            environment.pop(name, None)
        environment["NO_PROXY"] = "127.0.0.1"
        self.process = subprocess.Popen(command, stdout=self.log, stderr=self.log,
                                        env=environment)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.fail("Proxy exited during startup")
            try:
                return self.connect()
            except ConnectionRefusedError:
                time.sleep(0.02)
        self.fail("Proxy did not start listening")

    def connect(self):
        client = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        self.clients.append(client)
        return client

    def stop_proxy(self):
        start = time.monotonic()
        self.process.send_signal(signal.SIGINT)
        self.process.wait(timeout=7)
        return time.monotonic() - start

    def test_idle_shutdown_does_not_wait_for_deadline(self):
        self.start_proxy()
        self.assertLess(self.stop_proxy(), 2)

    def test_shutdown_delivers_response_that_finishes_within_grace(self):
        self.server.release.clear()
        client = self.start_proxy()
        request = query(123)
        client.sendall(struct.pack("!H", len(request)) + request)
        self.assertTrue(self.server.received.wait(10))
        self.process.send_signal(signal.SIGINT)
        # Keep the upstream response pending until the proxy is draining.
        # This must fail if tcp_stop() immediately drops every connection.
        release = threading.Timer(0.2, self.server.release.set)
        release.start()
        try:
            self.assertEqual(receive_frame(client), answer(request))
        finally:
            release.cancel()
            release.join()
        self.assertEqual(client.recv(1), b"")
        self.process.wait(timeout=2)

    def check_shutdown_deadline(self, tcp):
        self.server.release.clear()
        client = self.start_proxy()
        request = query(456)
        if tcp:
            client.sendall(struct.pack("!H", len(request)) + request)
        else:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.clients.append(udp)
            udp.sendto(request, ("127.0.0.1", self.port))
        self.assertTrue(self.server.received.wait(10))
        elapsed = self.stop_proxy()
        self.assertGreater(elapsed, 4)
        self.assertLess(elapsed, 6.5)

    def test_shutdown_bounds_outstanding_tcp_fetch(self):
        self.check_shutdown_deadline(tcp=True)

    def test_shutdown_bounds_outstanding_udp_fetch(self):
        self.check_shutdown_deadline(tcp=False)

    def test_slow_reader_does_not_stall_another_client(self):
        slow = self.start_proxy()
        slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        requests = [query(identifier) for identifier in range(24)]
        slow.sendall(b"".join(struct.pack("!H", len(req)) + req for req in requests))
        self.assertTrue(self.server.received.wait(10))
        time.sleep(0.2)  # Let responses accumulate while this client does not read.
        fast = self.connect()
        request = query(1000)
        start = time.monotonic()
        fast.sendall(struct.pack("!H", len(request)) + request)
        self.assertEqual(receive_frame(fast), answer(request))
        self.assertLess(time.monotonic() - start, 2)
        slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 131072)
        responses = [receive_frame(slow) for _ in requests]
        self.assertEqual(sorted(responses), sorted(answer(req) for req in requests))
        self.assertLess(self.stop_proxy(), 2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--openssl", required=True)
    parser.add_argument("--valgrind")
    OPTIONS = parser.parse_args()
    unittest.main(argv=[__file__], verbosity=2)
