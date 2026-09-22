"""Bounded JSON framing for an audited supervisor and a disposable guest.

This is a transport, not a VM launcher or an isolation guarantee. It never
opens TCP, maps host directories, or executes a sample.
"""
from __future__ import annotations

import json
import base64
import hashlib
import re
import socket
import struct
from pathlib import Path
from typing import Any

MAX_FRAME_BYTES = 8 * 1024 * 1024


def _read_exact(connection, length: int) -> bytes:
    parts = bytearray()
    while len(parts) < length:
        block = connection.recv(min(65536, length - len(parts)))
        if not block:
            raise ValueError("Truncated guest-channel frame")
        parts.extend(block)
    return bytes(parts)


def send_frame(connection, value: dict[str, Any], *, maximum: int = MAX_FRAME_BYTES) -> None:
    if not isinstance(value, dict):
        raise ValueError("Guest-channel frame must be an object")
    data = json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if not 1 <= len(data) <= maximum:
        raise ValueError("Guest-channel frame exceeds limit")
    connection.sendall(struct.pack("!I", len(data)) + data)


def receive_frame(connection, *, maximum: int = MAX_FRAME_BYTES) -> dict[str, Any]:
    length = struct.unpack("!I", _read_exact(connection, 4))[0]
    if not 1 <= length <= maximum:
        raise ValueError("Guest-channel frame exceeds limit")
    def unique_keys(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate guest-channel JSON key")
            value[key] = item
        return value
    def invalid_constant(value):
        raise ValueError("Non-finite guest-channel JSON number")
    value = json.loads(_read_exact(connection, length), object_pairs_hook=unique_keys,
                       parse_constant=invalid_constant)
    if not isinstance(value, dict):
        raise ValueError("Guest-channel frame must be an object")
    return value


def request_guest(uds_path: str | Path, request: dict[str, Any], *, port: int = 4050,
                  timeout: int = 60) -> dict[str, Any]:
    """Firecracker host-initiated vsock transport; caller owns VM lifecycle."""
    if type(port) is not int or not 1 <= port <= 65535 or type(timeout) is not int or not 1 <= timeout <= 330:
        raise ValueError("Invalid guest-channel port or timeout")
    if not hasattr(socket, "AF_UNIX"):
        raise RuntimeError("Supervisor guest transport requires AF_UNIX")
    path = Path(uds_path)
    if not path.is_absolute():
        raise ValueError("Supervisor UDS path must be absolute")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(str(path))
        connection.sendall(f"CONNECT {port}\n".encode("ascii"))
        acknowledgment = bytearray()
        while len(acknowledgment) < 64:
            byte = _read_exact(connection, 1)
            acknowledgment.extend(byte)
            if byte == b"\n":
                break
        if not re.fullmatch(rb"OK [0-9]+\n", acknowledgment):
            raise ValueError("Invalid Firecracker vsock acknowledgment")
        send_frame(connection, request)
        return receive_frame(connection)


def decode_guest_response(response: dict[str, Any], *, run_id: str, sample_sha256: str) -> dict[str, bytes]:
    """Validate guest response before a reviewed supervisor writes any artifacts."""
    from .sandbox import ARTIFACT_NAMES, TERMINAL_STATUSES
    required = {"schema", "run_id", "status", "sample_sha256", "exit_code", "artifacts"}
    if (not isinstance(response, dict) or set(response) != required
            or response["schema"] != "vulntools/guest-response/v1"
            or response["run_id"] != run_id or response["sample_sha256"] != sample_sha256
            or response["status"] not in TERMINAL_STATUSES
            or type(response["exit_code"]) is not int):
        raise ValueError("Guest response is invalid or not bound to this run/sample")
    if not isinstance(response["artifacts"], list) or len(response["artifacts"]) != len(ARTIFACT_NAMES):
        raise ValueError("Guest response must provide all four allow-listed artifacts")
    output, total = {}, 0
    for item in response["artifacts"]:
        if (not isinstance(item, dict) or set(item) != {"name", "sha256", "content_base64"}
                or not isinstance(item["name"], str) or item["name"] not in ARTIFACT_NAMES
                or item["name"] in output or not isinstance(item["content_base64"], str)):
            raise ValueError("Unexpected or duplicate guest artifact")
        data = base64.b64decode(item["content_base64"], validate=True)
        total += len(data)
        if total > 4 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("Guest artifact exceeds limit or has wrong digest")
        output[item["name"]] = data
    runtime = json.loads(output["result.json"])
    if (not isinstance(runtime, dict) or runtime.get("run_id") != run_id
            or runtime.get("sample_sha256") != sample_sha256
            or type(runtime.get("exit_code")) is not int or runtime["exit_code"] != response["exit_code"]
            or runtime.get("status") != response["status"]):
        raise ValueError("Guest runtime artifact does not match response")
    lines = output["events.jsonl"].splitlines()
    if not lines:
        raise ValueError("Guest response has no monitoring events")
    for line in lines:
        event = json.loads(line)
        if not isinstance(event, dict) or event.get("run_id") != run_id or not event.get("type") or not event.get("timestamp"):
            raise ValueError("Guest event is missing fields or belongs to another run")
    return output
