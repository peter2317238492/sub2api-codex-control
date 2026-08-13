#!/usr/bin/env python3
"""Allowlisted bearer proxy and Unix relay for private Alertmanager."""

from __future__ import annotations

import argparse
import hmac
import http.client
import os
import select
import socket
import socketserver
import stat
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from common import open_parent, read_secret_file, require_parent_stable

LISTEN_PORT = 19093
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
ALLOWED = {("POST", "/api/v2/alerts"), ("GET", "/metrics"), ("GET", "/-/ready")}


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path, socket_identity: tuple[int, int]) -> None:
        super().__init__("localhost", timeout=5)
        self.socket_path = socket_path
        self.socket_identity = socket_identity

    def connect(self) -> None:
        before = validate_socket(self.socket_path)
        if before != self.socket_identity:
            raise OSError("relay socket identity changed")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.socket_path))
        after = validate_socket(self.socket_path)
        if after != before:
            self.sock.close()
            raise OSError("relay socket identity changed during connect")


def validate_socket(socket_path: Path) -> tuple[int, int]:
    absolute, parent_fd, parent_identity = open_parent(socket_path)
    try:
        metadata = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("relay socket identity, owner, link count, or mode is invalid")
        require_parent_stable(parent_fd, absolute.parent, parent_identity)
        return metadata.st_dev, metadata.st_ino
    finally:
        os.close(parent_fd)


class ProxyHandler(BaseHTTPRequestHandler):
    bearer = ""
    socket_path = Path("/bridge/alertmanager.sock")

    def do_GET(self) -> None:
        self._proxy()

    def do_POST(self) -> None:
        self._proxy()

    def do_DELETE(self) -> None:
        self._respond(405, b"")

    def do_PUT(self) -> None:
        self._respond(405, b"")

    def _proxy(self) -> None:
        if (self.command, self.path) not in ALLOWED:
            self._respond(404, b"")
            return
        if not hmac.compare_digest(
            self.headers.get("Authorization", ""), f"Bearer {self.bearer}"
        ):
            self._respond(401, b"")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._respond(400, b"")
            return
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._respond(413, b"")
            return
        body = self.rfile.read(length) if length else None
        headers = {}
        if body is not None:
            content_type = self.headers.get("Content-Type", "")
            if content_type != "application/json":
                self._respond(415, b"")
                return
            headers["Content-Type"] = content_type
        try:
            socket_identity = validate_socket(self.socket_path)
        except (OSError, ValueError):
            self._respond(502, b"")
            return
        connection = UnixHTTPConnection(self.socket_path, socket_identity)
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            upstream = connection.getresponse()
            payload = upstream.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                self._respond(502, b"")
                return
            self._respond(
                upstream.status,
                payload,
                upstream.getheader("Content-Type", "application/octet-stream"),
            )
        except OSError:
            self._respond(502, b"")
        finally:
            connection.close()

    def _respond(
        self,
        status_code: int,
        payload: bytes,
        content_type: str = "text/plain; charset=utf-8",
    ) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


def run_proxy(socket_path: Path, bearer_path: Path) -> None:
    bearer = read_secret_file(bearer_path).strip().decode("ascii")
    if len(bearer) != 64:
        raise ValueError("proxy bearer must be 64 ASCII bytes")
    deadline = time.monotonic() + 60
    while True:
        try:
            validate_socket(socket_path)
            break
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)
    ProxyHandler.bearer = bearer
    ProxyHandler.socket_path = socket_path
    ThreadingHTTPServer(("127.0.0.1", LISTEN_PORT), ProxyHandler).serve_forever()


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        with socket.create_connection(("127.0.0.1", 9093), timeout=5) as upstream:
            sockets = [self.request, upstream]
            while sockets:
                readable, _, _ = select.select(sockets, [], [], 6)
                if not readable:
                    return
                for source in readable:
                    payload = source.recv(65536)
                    if not payload:
                        return
                    target = upstream if source is self.request else self.request
                    target.sendall(payload)


def run_relay(socket_path: Path) -> None:
    absolute, parent_fd, parent_identity = open_parent(socket_path)
    previous_directory_fd = -1
    try:
        try:
            existing = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if (
                not stat.S_ISSOCK(existing.st_mode)
                or existing.st_uid != os.geteuid()
                or existing.st_nlink != 1
            ):
                raise ValueError("refusing to replace relay path")
            os.unlink(absolute.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        require_parent_stable(parent_fd, absolute.parent, parent_identity)
        previous_directory_fd = os.open(
            ".",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
        )
        old_umask = os.umask(0o177)
        try:
            os.fchdir(parent_fd)
            server = socketserver.ThreadingUnixStreamServer(absolute.name, RelayHandler)
        finally:
            os.umask(old_umask)
            os.fchdir(previous_directory_fd)
        os.chmod(absolute.name, 0o600, dir_fd=parent_fd, follow_symlinks=False)
        created = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISSOCK(created.st_mode) or created.st_nlink != 1:
            raise ValueError("relay did not create the expected socket")
        socket_identity = (created.st_dev, created.st_ino)
        require_parent_stable(parent_fd, absolute.parent, parent_identity)
        try:
            server.serve_forever()
        finally:
            server.server_close()
            try:
                current = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != socket_identity:
                    raise ValueError("refusing to remove replaced relay socket")
                os.unlink(absolute.name, dir_fd=parent_fd)
                require_parent_stable(parent_fd, absolute.parent, parent_identity)
                os.fsync(parent_fd)
            except FileNotFoundError:
                pass
    finally:
        if previous_directory_fd >= 0:
            os.close(previous_directory_fd)
        os.close(parent_fd)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    proxy = subparsers.add_parser("proxy")
    proxy.add_argument("--socket", type=Path, required=True)
    proxy.add_argument("--bearer-file", type=Path, required=True)
    relay = subparsers.add_parser("relay")
    relay.add_argument("--socket", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.command == "proxy":
        run_proxy(arguments.socket, arguments.bearer_file)
    else:
        run_relay(arguments.socket)


if __name__ == "__main__":
    main()
