"""The oracle's PPSSPP back end: PPSSPP's WebSocket debugger API (PPSSPP has no GDB stub).

`ws://HOST:PORT/debugger`, subprotocol `debugger.ppsspp.org`, JSON events (`Core/Debugger/
WebSocket/*.cpp` in PPSSPP's tree documents each): `version` first, then `cpu.status`,
`cpu.stepping` (stop; PPSSPP answers with a `cpu.stepping` event carrying `pc`), `cpu.resume`,
`cpu.breakpoint.add` and `.remove`, `memory.read` (`base64`). A request carries a `ticket` the
answer repeats; an `error` event says what went wrong. The WebSocket client is the few lines of
RFC 6455 a client needs (text frames, masked; ping, close), the standard library only.

PPSSPP's debugger is off until you turn it on ("Allow remote debugger", `RemoteDebuggerOnStartup`),
and while its web server runs PPSSPP reports your local address and port to report.ppsspp.org every
nine minutes, with no setting to stop it (docs/PSP.md). The suite does not start PPSSPP or change
that setting; this back end only connects to one you started.

Checked against an in-process stand-in (test_oracle_ppsspp.py); the events are as PPSSPP's source
describes them, not yet run against PPSSPP itself.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import time

from rea_suite.oracle import EmulatorTarget, Stop, TargetError, host_port

SUBPROTOCOL = "debugger.ppsspp.org"
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"  # RFC 6455's, for Sec-WebSocket-Accept
READ_CHUNK = 1 << 20
MAX_MESSAGE = 64 << 20


class WebSocket:
    """A WebSocket client connection carrying text messages."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = bytearray()

    @classmethod
    def open(cls, host: str, port: int, path: str, protocol: str, timeout: float) -> WebSocket:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            raise TargetError(f"ppsspp: {host}:{port}: {exc}") from None
        key = base64.b64encode(os.urandom(16)).decode()
        name = f"[{host}]" if ":" in host else host
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {name}:{port}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: {protocol}\r\n\r\n"
        )
        sock.sendall(request.encode())
        ws = cls(sock)
        while b"\r\n\r\n" not in ws.buf:
            ws._more(time.monotonic() + timeout)
            if len(ws.buf) > 16384:
                raise TargetError("ppsspp: the handshake's answer is too long")
        head, _, rest = bytes(ws.buf).partition(b"\r\n\r\n")
        ws.buf = bytearray(rest)
        lines = head.decode("latin-1").split("\r\n")
        if len(lines[0].split()) < 2 or lines[0].split()[1] != "101":
            raise TargetError(f"ppsspp: not a WebSocket: {lines[0][:80]!r}")
        headers = {
            k.strip().lower(): v.strip() for k, _, v in (h.partition(":") for h in lines[1:])
        }
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        if headers.get("sec-websocket-accept") != accept:
            raise TargetError("ppsspp: the handshake's Sec-WebSocket-Accept is wrong")
        return ws

    def _more(self, deadline: float | None) -> bool:
        if deadline is None:
            self.sock.settimeout(None)
        else:
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            self.sock.settimeout(left)
        try:
            data = self.sock.recv(65536)
        except TimeoutError:
            return False
        except OSError as exc:
            raise TargetError(f"ppsspp: {exc}") from None
        if not data:
            raise TargetError("ppsspp: the connection closed")
        self.buf += data
        return True

    def _frame(self, opcode: int, payload: bytes) -> None:
        head = bytearray((0x80 | opcode,))
        n = len(payload)
        if n < 126:
            head.append(0x80 | n)
        elif n < 1 << 16:
            head += bytes((0x80 | 126,)) + struct.pack(">H", n)
        else:
            head += bytes((0x80 | 127,)) + struct.pack(">Q", n)
        mask = os.urandom(4)
        head += mask
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(head) + body)

    def send(self, text: str) -> None:
        self._frame(0x1, text.encode())

    def _take(self, n: int, deadline: float | None) -> bytes | None:
        while len(self.buf) < n:
            if not self._more(deadline):
                return None
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def receive(self, deadline: float | None) -> str | None:
        """The next text message; None when the deadline passed first."""
        parts: list[bytes] = []
        while True:
            head = self._take(2, deadline)
            if head is None:
                return None
            fin, opcode, n = head[0] & 0x80, head[0] & 0x0F, head[1] & 0x7F
            masked = head[1] & 0x80
            if n == 126:
                n = struct.unpack(">H", self._take(2, None) or b"\0\0")[0]
            elif n == 127:
                n = struct.unpack(">Q", self._take(8, None) or b"\0" * 8)[0]
            if n > MAX_MESSAGE:
                raise TargetError(f"ppsspp: a {n}-byte frame")
            mask = self._take(4, None) if masked else None
            payload = self._take(n, None) or b""
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:
                raise TargetError("ppsspp: the debugger closed the connection")
            if opcode == 0x9:
                self._frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            parts.append(payload)
            if fin:
                return b"".join(parts).decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self._frame(0x8, struct.pack(">H", 1000))
        except OSError:
            pass
        self.sock.close()


class PpssppTarget(EmulatorTarget):
    """PPSSPP's WebSocket debugger as an EmulatorTarget."""

    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.producer = f"ppsspp {host}:{port}"
        self.ws: WebSocket | None = None
        self.ticket = 0
        self.breakpoints: set[int] = set()

    @classmethod
    def from_url(cls, url: str, timeout: float = 10.0) -> PpssppTarget:
        host, port = host_port(url)
        return cls(host, port, timeout)

    def _ws(self) -> WebSocket:
        if self.ws is None:
            raise TargetError("ppsspp: not connected")
        return self.ws

    def _next(self, deadline: float | None) -> dict | None:
        text = self._ws().receive(deadline)
        if text is None:
            return None
        try:
            message = json.loads(text)
        except json.JSONDecodeError:
            raise TargetError("ppsspp: a message that is not JSON") from None
        return message if isinstance(message, dict) else {}

    def ask(self, event: str, **params) -> dict:
        """A request and its answer (matched by ticket)."""
        self.ticket += 1
        ticket = str(self.ticket)
        self._ws().send(json.dumps({"event": event, "ticket": ticket, **params}))
        deadline = time.monotonic() + self.timeout
        while True:
            message = self._next(deadline)
            if message is None:
                raise TargetError(f"ppsspp: no answer to {event}")
            if message.get("ticket") != ticket:
                continue  # another event: a log line, a stepping event
            if message.get("event") == "error":
                raise TargetError(f"ppsspp: {event}: {str(message.get('message'))[:200]}")
            return message

    def _stepping(self, deadline: float | None) -> dict | None:
        while True:
            message = self._next(deadline)
            if message is None:
                return None
            if message.get("event") == "cpu.stepping":
                return message

    def connect(self) -> Stop:
        self.ws = WebSocket.open(self.host, self.port, "/debugger", SUBPROTOCOL, self.timeout)
        self.ask("version", name="rea-suite oracle", version="1")
        status = self.ask("cpu.status")
        if status.get("stepping"):
            return Stop("stepping", int(status.get("pc", 0)))
        self._ws().send(json.dumps({"event": "cpu.stepping"}))
        message = self._stepping(time.monotonic() + self.timeout)
        if message is None:
            raise TargetError("ppsspp: the CPU did not stop (is a game running?)")
        return Stop("stepping", int(message.get("pc", 0)))

    def set_breakpoint(self, address: int, hardware: bool = False) -> None:
        self.ask("cpu.breakpoint.add", address=address, enabled=True)
        self.breakpoints.add(address)

    def clear_breakpoint(self, address: int, hardware: bool = False) -> None:
        self.ask("cpu.breakpoint.remove", address=address)
        self.breakpoints.discard(address)

    def resume(self, timeout: float | None) -> Stop:
        ws = self._ws()
        ws.send(json.dumps({"event": "cpu.resume"}))
        deadline = None if timeout is None else time.monotonic() + timeout
        message = self._stepping(deadline)
        reason = "break"
        if message is None:
            ws.send(json.dumps({"event": "cpu.stepping"}))
            message = self._stepping(time.monotonic() + self.timeout)
            if message is None:
                raise TargetError("ppsspp: the CPU did not stop when asked")
            reason = "timeout"
        pc = int(message.get("pc", 0))
        if reason == "break" and pc not in self.breakpoints:
            reason = "stepping"
        return Stop(reason, pc, str(message.get("reason", ""))[:80])

    def read(self, address: int, length: int) -> bytes:
        out = bytearray()
        while len(out) < length:
            size = min(READ_CHUNK, length - len(out))
            answer = self.ask("memory.read", address=address + len(out), size=size)
            try:
                data = base64.b64decode(answer.get("base64", ""), validate=True)
            except ValueError:
                raise TargetError("ppsspp: memory.read: not base64") from None
            if not data:
                raise TargetError(f"ppsspp: memory at {address + len(out):#x}: nothing read")
            out += data[:size]
        return bytes(out)

    def close(self) -> None:
        ws = self.ws
        if ws is None:
            return
        try:
            for address in sorted(self.breakpoints):
                try:
                    self.clear_breakpoint(address)
                except TargetError:
                    pass
            ws.send(json.dumps({"event": "cpu.resume"}))
        except OSError:
            pass
        finally:
            ws.close()
            self.ws = None
