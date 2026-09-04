#!/usr/bin/env python3
"""Bounded localhost smoke test for the nginx deployment example."""

import argparse
import gzip
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Backend(BaseHTTPRequestHandler):
    calls = {}
    calls_lock = threading.Lock()
    slow_body_started = threading.Event()
    protocol_version = "HTTP/1.1"

    @classmethod
    def record(cls, method, route):
        with cls.calls_lock:
            key = (method, route)
            cls.calls[key] = cls.calls.get(key, 0) + 1

    @classmethod
    def count(cls, method, route):
        with cls.calls_lock:
            return cls.calls.get((method, route), 0)

    def respond(self, status, body=b"", headers=None, include_body=True):
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def do_GET(self):  # noqa: N802 - stdlib handler API
        parsed = urllib.parse.urlsplit(self.path)
        route = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        Backend.record("GET", route)
        if route == "/attempts" and query.get("status") == ["404"]:
            self.respond(404, b"upstream-not-found")
        elif route == "/attempts" and query.get("status") == ["500"]:
            self.respond(500, b"upstream-failure")
        elif route == "/attempts" and query.get("status") == ["503"]:
            self.respond(503, b"upstream-pressure", {"Retry-After": "9"})
        elif route == "/attempts":
            if query.get("slow") == ["1"]:
                time.sleep(0.5)
            body = gzip.compress(b'{"snapshot":true}', mtime=0)
            self.respond(
                200,
                body,
                {
                    "Cache-Control": "public, max-age=30",
                    "Content-Encoding": "gzip",
                    "ETag": '"snapshot-v1"',
                },
            )
        elif route == "/backend-429":
            self.respond(429, b"axum-lockout", {"Retry-After": "7"})
        elif route == "/backend-503":
            self.respond(503, b"axum-pressure", {"Retry-After": "9"})
        else:
            self.respond(200, b"uncached-route")

    def do_HEAD(self):  # noqa: N802 - stdlib handler API
        route = urllib.parse.urlsplit(self.path).path
        Backend.record("HEAD", route)
        self.respond(405, b"method-not-allowed", include_body=False)

    def do_POST(self):  # noqa: N802 - stdlib handler API
        route = urllib.parse.urlsplit(self.path).path
        Backend.record("POST", route)
        if route == "/slow-body":
            # Reaching the handler before the declared body is complete proves
            # nginx is streaming rather than buffering the request body.
            Backend.slow_body_started.set()
            self.close_connection = True
            self.respond(200, b"streamed")
            return
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        if route == "/attempts":
            self.respond(405, b"method-not-allowed")
        else:
            self.respond(200, b"posted")

    def log_message(self, *_args):
        pass


# The nginx example now expects a PROXY-protocol header (Tor supplies it via
# HiddenServiceExportCircuitID). The source address becomes the per-circuit
# key for limit_req/limit_conn; distinct sources therefore get independent
# budgets, which the isolation test below exercises.
DEFAULT_SOURCE = "10.200.0.1"


class _ProxyConnection(http.client.HTTPConnection):
    def __init__(self, *args, source=DEFAULT_SOURCE, **kwargs):
        super().__init__(*args, **kwargs)
        self._source = source

    def connect(self):
        super().connect()
        self.sock.sendall(
            f"PROXY TCP4 {self._source} 127.0.0.1 40000 3000\r\n".encode()
        )


def request(path, headers=None, method="GET", body=None, timeout=40, source=DEFAULT_SOURCE):
    connection = _ProxyConnection("127.0.0.1", 3000, timeout=timeout, source=source)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    result = (
        response.status,
        {name.lower(): value for name, value in response.getheaders()},
        response.read(),
    )
    connection.close()
    return result


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def assert_request_body_is_streamed():
    Backend.slow_body_started.clear()
    with socket.create_connection(("127.0.0.1", 3000), timeout=5) as connection:
        connection.sendall(
            b"PROXY TCP4 10.200.0.1 127.0.0.1 40000 3000\r\n"
            b"POST /slow-body HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 1024\r\n"
            b"Connection: close\r\n\r\n"
            b"x"
        )
        assert_true(
            Backend.slow_body_started.wait(timeout=5),
            "nginx buffered an incomplete request body instead of streaming it",
        )


def port_is_free(port):
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def render_config(source, root):
    cache = root / "cache"
    proxy_temp = root / "proxy_temp"
    cache.mkdir()
    proxy_temp.mkdir()
    include = source.read_text(encoding="utf-8")
    include = include.replace("/var/cache/nginx/recoverbull", str(cache))
    include = include.replace(
        "error_log /var/log/nginx/recoverbull-error.log crit;",
        "error_log stderr crit;",
    )
    indented = "\n".join(f"    {line}" for line in include.splitlines())
    config = root / "nginx.conf"
    config.write_text(
        "daemon off;\n"
        "master_process off;\n"
        f"pid {root / 'nginx.pid'};\n"
        "error_log stderr notice;\n"
        "events { worker_connections 256; }\n"
        "http {\n"
        f"    proxy_temp_path {proxy_temp};\n"
        f"{indented}\n"
        "}\n",
        encoding="utf-8",
    )
    return config


def assert_statuses_are_not_cached():
    for route, expected_status, expected_body in (
        ("/attempts?status=404", 404, b"upstream-not-found"),
        ("/attempts?status=500", 500, b"upstream-failure"),
        ("/attempts?status=503", 503, b"upstream-pressure"),
    ):
        before = Backend.count("GET", "/attempts")
        first = request(route)
        second = request(route)
        assert_true(
            (first[0], second[0], first[2], second[2])
            == (expected_status, expected_status, expected_body, expected_body),
            f"upstream response changed for {route}: {first!r} {second!r}",
        )
        assert_true(
            Backend.count("GET", "/attempts") - before == 2,
            f"upstream {expected_status} was cached",
        )
        if expected_status == 503:
            assert_true(first[1].get("retry-after") == "9", "upstream 503 changed")


def assert_method_scope():
    for index in range(25):
        status, _, body = request(
            f"/attempts?post={index}",
            {"Content-Type": "application/octet-stream"},
            method="POST",
            body=b"small",
        )
        assert_true(
            (status, body) == (405, b"method-not-allowed"),
            "non-GET /attempts was edge-limited or cached",
        )
    status, _, _ = request("/attempts", method="HEAD")
    assert_true(status == 405, "HEAD was converted to a cached GET")


def assert_single_flight_cache():
    time.sleep(2)
    before = Backend.count("GET", "/attempts")
    barrier = threading.Barrier(17)
    results = []
    result_lock = threading.Lock()

    def poll(index):
        barrier.wait()
        result = request(
            f"/attempts?slow=1&variant={index}",
            {"Host": f"variant-{index}.example"},
        )
        with result_lock:
            results.append(result)

    threads = [threading.Thread(target=poll, args=(index,)) for index in range(16)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=40)
        assert_true(not thread.is_alive(), "concurrent cache request did not finish")

    assert_true(len(results) == 16, "a concurrent cache request failed")
    assert_true(all(result[0] == 200 for result in results), "cache burst changed status")
    assert_true(
        len({result[2] for result in results}) == 1,
        "cache burst returned divergent bodies",
    )
    assert_true(
        Backend.count("GET", "/attempts") - before == 1,
        "Host/query variants or cache-lock expiry caused multiple upstream builds",
    )
    body = results[0][2]
    headers = results[0][1]
    assert_true(
        headers.get("content-encoding") == "gzip"
        and gzip.decompress(body) == b'{"snapshot":true}',
        "cached /attempts was not the upstream deterministic gzip",
    )

    cached_calls = Backend.count("GET", "/attempts")
    status, headers, body = request(
        "/attempts", {"If-None-Match": '"snapshot-v1"'}
    )
    assert_true(
        status == 304
        and not body
        and headers.get("etag") == '"snapshot-v1"'
        and Backend.count("GET", "/attempts") == cached_calls,
        "conditional cache hit was not a backend-free 304",
    )

    status, _, _ = request("/attempts", method="HEAD")
    assert_true(status == 405, "cached GET representation answered HEAD")


def assert_other_routes_and_pressure():
    before = Backend.count("GET", "/uncached")
    first = request("/uncached?x=1", {"Host": "one.example"})
    second = request("/uncached?x=2", {"Host": "two.example"})
    assert_true(
        (first[0], second[0], first[2], second[2])
        == (200, 200, b"uncached-route", b"uncached-route"),
        "non-attempts route failed",
    )
    assert_true(
        Backend.count("GET", "/uncached") - before == 2,
        "route outside /attempts was cached",
    )
    status, _, body = request(
        "/uncached",
        {"Content-Type": "application/octet-stream"},
        method="POST",
        body=b"small",
    )
    assert_true((status, body) == (200, b"posted"), "small POST did not reach Axum")
    status, _, _ = request(
        "/uncached",
        {"Content-Type": "application/octet-stream"},
        method="POST",
        body=b"x" * 2048,
    )
    assert_true(status == 413, "oversized body was not rejected")

    status, headers, body = request("/backend-429")
    assert_true(
        (status, body, headers.get("retry-after")) == (429, b"axum-lockout", "7"),
        "Axum targeted 429 was adapted by nginx",
    )
    status, headers, body = request("/backend-503")
    assert_true(
        (status, body, headers.get("retry-after")) == (503, b"axum-pressure", "9"),
        "Axum shared-pressure 503 was intercepted by nginx",
    )

    pressure = None
    for index in range(60):
        result = request(f"/attempts?edge={index}")
        if result[0] == 503:
            pressure = result
            break
    assert_true(pressure is not None, "nginx GET /attempts bucket did not reject a burst")
    status, headers, body = pressure
    assert_true(
        status == 503
        and headers.get("retry-after") == "1"
        and json.loads(body) == {"error": "Service unavailable"},
        "nginx edge pressure was not JSON 503 with Retry-After",
    )


def assert_per_circuit_isolation():
    # AUD-09 fix: with the PROXY header carrying a per-circuit source address,
    # limit_req/limit_conn count per circuit. A burst that trips a shared
    # bucket for one source must all succeed when spread across circuits, and a
    # single circuit flooding must still be limited to its own bucket.
    time.sleep(2)  # let earlier per-default-source buckets refill
    count = 40
    results = []
    result_lock = threading.Lock()
    barrier = threading.Barrier(count)

    def poll(index):
        barrier.wait()
        status = request(
            f"/attempts?circuit={index}",
            {"Host": f"c{index}.example"},
            source=f"10.50.{(index >> 8) & 255}.{(index & 255) or 1}",
        )[0]
        with result_lock:
            results.append(status)

    threads = [threading.Thread(target=poll, args=(index,)) for index in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=40)
        assert_true(not thread.is_alive(), "per-circuit request did not finish")
    assert_true(
        all(status == 200 for status in results),
        f"distinct per-circuit sources must not share a bucket: {sorted(set(results))}",
    )

    flood = [request(f"/attempts?flood={k}", source="10.99.99.99")[0] for k in range(60)]
    assert_true(
        503 in flood,
        "a single circuit flooding must still trip its own limit_req bucket",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="nginx binary to validate and run")
    arguments = parser.parse_args()
    binary = arguments.binary.resolve()
    root = Path(__file__).resolve().parent
    source = root / "recoverbull.conf"
    assert_true(
        binary.is_file() and os.access(binary, os.X_OK), f"not executable: {binary}"
    )
    assert_true(
        port_is_free(3000) and port_is_free(3001),
        "ports 3000 and 3001 must be free before smoke",
    )
    version = subprocess.run(
        [str(binary), "-V"], check=True, capture_output=True, text=True, timeout=10
    )
    assert_true("nginx version:" in version.stderr, "nginx -V returned no version")

    with tempfile.TemporaryDirectory(prefix="recoverbull-nginx-smoke-") as directory:
        temporary_root = Path(directory)
        config = render_config(source, temporary_root)
        command = [str(binary), "-p", f"{temporary_root}/", "-c", str(config)]
        subprocess.run(
            [*command, "-t"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )

        backend = ThreadingHTTPServer(("127.0.0.1", 3001), Backend)
        backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
        backend_thread.start()
        nginx = None
        log_file = None
        log_path = temporary_root / "nginx.log"
        passed = False
        try:
            log_file = log_path.open("w", encoding="utf-8")
            nginx = subprocess.Popen(
                command, stdout=log_file, stderr=subprocess.STDOUT, text=True
            )
            deadline = time.monotonic() + 10
            while True:
                try:
                    if request("/health", timeout=1)[0] == 200:
                        break
                except (ConnectionError, OSError):
                    pass
                assert_true(time.monotonic() < deadline, "nginx did not start")
                time.sleep(0.05)

            assert_request_body_is_streamed()
            assert_method_scope()
            assert_statuses_are_not_cached()
            assert_single_flight_cache()
            assert_other_routes_and_pressure()
            assert_per_circuit_isolation()
            passed = True
            print(
                "nginx smoke passed: syntax, methods, cache single-flight, "
                "normalization, gzip/304, body streaming/limit, status contract, "
                "and per-circuit rate-limit isolation"
            )
        finally:
            backend.shutdown()
            backend.server_close()
            if nginx is not None:
                nginx.terminate()
                try:
                    nginx.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    nginx.kill()
                    nginx.wait(timeout=2)
            if log_file is not None:
                log_file.close()
            if not passed and log_path.exists():
                print("nginx diagnostics:", file=sys.stderr)
                print(log_path.read_text(encoding="utf-8"), file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, subprocess.CalledProcessError) as error:
        print(f"nginx smoke failed: {error}", file=sys.stderr)
        raise SystemExit(1)
