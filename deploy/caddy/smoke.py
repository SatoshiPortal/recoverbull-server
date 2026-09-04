#!/usr/bin/env python3
"""Bounded localhost smoke test for the supported Caddy deployment."""

import argparse
import gzip
import http.client
import json
import os
import urllib.parse
import socket
import subprocess
import sys
import threading
import time
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Backend(BaseHTTPRequestHandler):
    calls = {}
    post_calls = 0

    def do_GET(self):  # noqa: N802 - stdlib handler API
        Backend.calls[self.path.split("?", 1)[0]] = Backend.calls.get(self.path.split("?", 1)[0], 0) + 1
        route = self.path.split("?", 1)[0]
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if route == "/attempts" and query.get("status") == ["404"]:
            body, status, headers = b"upstream-not-found", 404, {}
        elif route == "/attempts" and query.get("status") == ["500"]:
            body, status, headers = b"upstream-failure", 500, {}
        elif route == "/attempts" and query.get("status") == ["503"]:
            body, status, headers = b"upstream-pressure", 503, {"Retry-After": "9"}
        elif route == "/attempts":
            body, status = gzip.compress(b'{"snapshot":true}', mtime=0), 200
            headers = {"Cache-Control": "public, max-age=30", "ETag": '"snapshot-v1"', "Content-Encoding": "gzip"}
        elif route == "/backend-429":
            body, status, headers = b"axum-lockout", 429, {"Retry-After": "7"}
        elif route == "/backend-404":
            body, status, headers = b"upstream-not-found", 404, {}
        elif route == "/backend-500":
            body, status, headers = b"upstream-failure", 500, {}
        elif route == "/backend-503":
            body, status, headers = b"upstream-pressure", 503, {"Retry-After": "9"}
        else:
            body, status, headers = b"uncached-route", 200, {}
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            # Caddy may close the upstream after enforcing the request limit.
            pass

    def do_POST(self):  # noqa: N802 - stdlib handler API
        Backend.post_calls += 1
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        body = b"posted"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            # Caddy may close the upstream after enforcing the request limit.
            pass

    def log_message(self, *_args):
        pass


def request(path, headers=None, method="GET", body=None):
    conn = http.client.HTTPConnection("127.0.0.1", 3000, timeout=3)
    conn.request(method, path, body=body, headers=headers or {})
    response = conn.getresponse()
    result = response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
    conn.close()
    return result


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def port_is_free(port):
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Caddy binary to validate and run")
    args = parser.parse_args()
    binary = args.binary.resolve()
    root = Path(__file__).resolve().parent
    config = root / "Caddyfile"
    assert_true(binary.is_file() and os.access(binary, os.X_OK), f"not executable: {binary}")
    assert_true(port_is_free(3000) and port_is_free(3001), "ports 3000 and 3001 must be free before smoke")

    subprocess.run([str(binary), "adapt", "--config", str(config), "--adapter", "caddyfile", "--validate"], check=True, timeout=10, stdout=subprocess.DEVNULL)
    subprocess.run([str(binary), "validate", "--config", str(config), "--adapter", "caddyfile"], check=True, timeout=10, stdout=subprocess.DEVNULL)
    modules = subprocess.run([str(binary), "list-modules"], check=True, timeout=10, text=True, capture_output=True).stdout
    for module in ("http.handlers.cache", "storages.cache.otter", "http.handlers.rate_limit"):
        assert_true(module in modules, f"missing Caddy module: {module}")
    build_info = subprocess.run([str(binary), "build-info"], check=True, timeout=10, text=True, capture_output=True).stdout
    for pin in (
        "go\tgo1.26.7",
        "github.com/caddyserver/caddy/v2\tv2.11.4",
        "github.com/caddyserver/cache-handler\tv0.16.0",
        "github.com/darkweak/storages/otter/caddy\tv0.0.15",
        "github.com/mholt/caddy-ratelimit\tv0.1.1-0.20260612195517-5625512f24f6",
        "github.com/go-chi/chi/v5\tv5.3.0",
        "github.com/klauspost/compress\tv1.18.7",
        "go.opentelemetry.io/otel\tv1.44.0",
        "go.opentelemetry.io/otel/metric\tv1.44.0",
        "go.opentelemetry.io/otel/trace\tv1.44.0",
        "golang.org/x/net\tv0.58.0",
        "golang.org/x/text\tv0.41.0",
        "google.golang.org/grpc\tv1.82.1",
    ):
        assert_true(pin in build_info, f"build-info missing pin: {pin}")

    backend = ThreadingHTTPServer(("127.0.0.1", 3001), Backend)
    backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
    backend_thread.start()
    caddy = None
    diagnostic_log = None
    passed = False
    try:
        descriptor, diagnostic_log = tempfile.mkstemp(prefix="recoverbull-caddy-smoke-", suffix=".log")
        log_file = os.fdopen(descriptor, "w")
        caddy = subprocess.Popen([str(binary), "run", "--config", str(config), "--adapter", "caddyfile"], stdout=log_file, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 10
        while True:
            try:
                status, _, _ = request("/health")
                if status == 200:
                    break
            except (ConnectionError, OSError):
                pass
            assert_true(time.monotonic() < deadline, "Caddy did not start within 10 seconds")
            time.sleep(0.05)

        for route, expected_status, expected_body in (("/attempts?status=404", 404, b"upstream-not-found"), ("/attempts?status=500", 500, b"upstream-failure"), ("/attempts?status=503", 503, b"upstream-pressure")):
            got, got_headers, got_body = request(route)
            again, _, again_body = request(route)
            assert_true((got, again, got_body, again_body) == (expected_status, expected_status, expected_body, expected_body), f"upstream {route} was changed or cached: {(got, again, got_body, again_body)!r}")
            assert_true(got_headers.get("cache-control") == "no-store", f"upstream {route} lacked no-store")

        attempts_before = Backend.calls.get("/attempts", 0)
        status, first_headers, first_body = request("/attempts?first=1", {"Host": "first.example"})
        status2, second_headers, second_body = request("/attempts?second=2", {"Host": "second.example"})
        assert_true((status, status2) == (200, 200) and first_body == second_body, "attempts responses differ")
        cache_status = (first_headers.get("cache-status", "") + " " + second_headers.get("cache-status", "")).lower()
        assert_true("miss" in cache_status and "hit" in cache_status, "attempts did not report cache miss and hit")
        assert_true(first_headers.get("etag") == '"snapshot-v1"' and second_headers.get("etag") == '"snapshot-v1"', "ETag was not preserved")
        assert_true(Backend.calls.get("/attempts", 0) - attempts_before == 1, "host/query normalization caused a second backend call")
        gzip_bytes = first_body
        assert_true(first_headers.get("content-encoding") == "gzip" and gzip.decompress(gzip_bytes) == b'{"snapshot":true}', "attempts was not deterministic gzip")
        assert_true(second_body == gzip_bytes, "cache hit changed gzip bytes")
        attempts_after_hit = Backend.calls.get("/attempts", 0)
        status304, headers304, body304 = request("/attempts", {"If-None-Match": '"snapshot-v1"'})
        assert_true(status304 == 304 and not body304 and headers304.get("etag") == '"snapshot-v1"' and Backend.calls.get("/attempts", 0) == attempts_after_hit, "conditional attempts request was not a backend-free 304")

        status, headers, body = request("/uncached?x=1", {"Host": "one.example"})
        status2, _, body2 = request("/uncached?x=2", {"Host": "two.example"})
        assert_true((status, status2, body, body2) == (200, 200, b"uncached-route", b"uncached-route"), f"non-attempts route failed: {(status, status2, body, body2)!r}")
        assert_true("cache-status" not in headers and Backend.calls.get("/uncached") == 2, "route outside /attempts was cached")
        status, _, body = request("/uncached", {"Content-Type": "application/octet-stream"}, method="POST", body=b"small")
        assert_true(status == 200 and body == b"posted" and Backend.post_calls == 1, "small non-cache POST did not reach backend")
        status, _, _ = request("/uncached", {"Content-Type": "application/octet-stream"}, method="POST", body=b"x" * 2048)
        assert_true(status == 413, f"oversized body was not rejected: status={status}")

        status, headers, body = request("/backend-429")
        assert_true((status, body, headers.get("retry-after")) == (429, b"axum-lockout", "7"), "Axum 429 was adapted by Caddy")

        # The first zone admits 20 events per second; the 21st must exercise
        # Caddy's internal 429 and the local handle_errors adapter.
        edge = [request(f"/attempts?edge={i}") for i in range(21)]
        status, headers, body = edge[-1]
        assert_true(status == 503 and headers.get("retry-after") and json.loads(body) == {"error": "Service unavailable"}, "edge pressure was not JSON 503 with Retry-After")
        passed = True
        print("Caddy smoke passed: config, build-info, gzip cache, normalization, body limit, status contract, and edge pressure")
    finally:
        backend.shutdown()
        backend.server_close()
        if caddy is not None:
            caddy.terminate()
            try:
                caddy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                caddy.kill()
                caddy.wait(timeout=2)
        if diagnostic_log is not None:
            log_file.close()
            if passed:
                Path(diagnostic_log).unlink(missing_ok=True)
            else:
                print(f"Caddy diagnostics retained at {diagnostic_log}", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, subprocess.CalledProcessError, TimeoutError) as error:
        print(f"Caddy smoke failed: {error}", file=sys.stderr)
        raise SystemExit(1)
