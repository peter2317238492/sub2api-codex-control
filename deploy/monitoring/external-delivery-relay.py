#!/usr/bin/env python3
"""Fail-closed HTTPS relay for Alertmanager external operator delivery."""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import socket
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, List, Optional, Tuple
from urllib.parse import urlsplit

from common import read_secret_file

LISTEN_ADDRESS = "0.0.0.0"  # Container-private network only; Compose publishes no port.
LISTEN_PORT = 19095
MAX_BODY_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
TIMEOUT_SECONDS = 10


def _load_config(path: Path) -> Tuple[str, str, int, str]:
    try:
        value = json.loads(read_secret_file(path, maximum=4096).decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid external delivery config") from error
    if not isinstance(value, dict) or set(value) != {
        "format_version",
        "receiver_id",
        "webhook_url",
    }:
        raise ValueError("external delivery config does not match the exact schema")
    parsed = urlsplit(value["webhook_url"])
    if parsed.scheme != "https" or parsed.hostname is None:
        raise ValueError("external delivery requires HTTPS")
    return value["receiver_id"], parsed.hostname, parsed.port or 443, parsed.path


def public_addresses(hostname: str, port: int) -> List[Tuple[Any, ...]]:
    addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError("external receiver did not resolve")
    accepted = []
    for family, socket_type, protocol, canonical_name, sockaddr in addresses:
        address = ipaddress.ip_address(sockaddr[0])
        if not address.is_global:
            raise ValueError("external receiver resolved to a non-public address")
        accepted.append((family, socket_type, protocol, canonical_name, sockaddr))
    return accepted


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, port: int, addresses: List[Tuple[Any, ...]]) -> None:
        super().__init__(
            hostname,
            port,
            timeout=TIMEOUT_SECONDS,
            context=ssl.create_default_context(),
        )
        self.addresses = addresses

    def connect(self) -> None:
        last_error: Optional[OSError] = None
        raw_socket: Optional[socket.socket] = None
        for family, socket_type, protocol, _, sockaddr in self.addresses:
            try:
                raw_socket = socket.socket(family, socket_type, protocol)
                raw_socket.settimeout(self.timeout)
                raw_socket.connect(sockaddr)
                break
            except OSError as error:
                last_error = error
                if raw_socket is not None:
                    raw_socket.close()
                raw_socket = None
        if raw_socket is None:
            raise last_error or OSError("external receiver connection failed")
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


class RelayHandler(BaseHTTPRequestHandler):
    hostname = ""
    port = 443
    path = "/"
    bearer = ""

    def do_POST(self) -> None:
        if self.path != "/v1/alerts":
            self._respond(404, b"not found\n")
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            self._respond(400, b"invalid request\n")
            return
        if (
            length < 1
            or length > MAX_BODY_BYTES
            or self.headers.get("Content-Type", "") != "application/json"
        ):
            self._respond(413, b"invalid request\n")
            return
        body = self.rfile.read(length)
        try:
            addresses = public_addresses(self.hostname, self.port)
            connection = PinnedHTTPSConnection(self.hostname, self.port, addresses)
            connection.request(
                "POST",
                self.path,
                body=body,
                headers={
                    "Authorization": f"Bearer {self.bearer}",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "User-Agent": "codex-control-alert-delivery/1",
                },
            )
            response = connection.getresponse()
            response_payload = response.read(MAX_RESPONSE_BYTES + 1)
            connection.close()
            if len(response_payload) > MAX_RESPONSE_BYTES or not 200 <= response.status < 300:
                raise OSError("external receiver rejected the notification")
        except (OSError, ssl.SSLError, ValueError):
            self._respond(502, b"external delivery failed\n")
            return
        self._respond(200, b"accepted\n")

    def _respond(self, status_code: int, payload: bytes) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--delivery-config", type=Path, required=True)
    parser.add_argument("--bearer-file", type=Path, required=True)
    arguments = parser.parse_args()
    _, hostname, port, path = _load_config(arguments.delivery_config)
    bearer = read_secret_file(arguments.bearer_file).strip().decode("ascii")
    if len(bearer) != 64:
        raise ValueError("external delivery bearer must be 64 ASCII bytes")
    public_addresses(hostname, port)
    RelayHandler.hostname = hostname
    RelayHandler.port = port
    RelayHandler.path = path
    RelayHandler.bearer = bearer
    ThreadingHTTPServer((LISTEN_ADDRESS, LISTEN_PORT), RelayHandler).serve_forever()


if __name__ == "__main__":
    main()
