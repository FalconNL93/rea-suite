"""The oracle's GDB back end: GDB's remote serial protocol (RSP) over TCP, in pure Python.

Every emulator with a GDB stub speaks it: xemu (QEMU's stub, `-gdb tcp:HOST:PORT`), Dolphin
(`-C Dolphin.General.GDBPort=N`), DuckStation and PCSX-Redux (PlayStation, MIPS R3000), melonDS (ARM)
and others. The oracle needs little of it: `qSupported` (the packet size, and `QStartNoAckMode`
where offered), `?` (where it stopped), `m` (memory), `Z0`/`Z1` and `z0`/`z1` (software and hardware
breakpoints), `c` and `s` (continue, step), a 0x03 byte (stop now), `p` and `g` (the PC) and `D`
(detach, leaving the emulator running).

Where the PC is differs by CPU: ARCHES holds, per architecture, its register number, size and byte
order, where it sits in a `g` answer, and the breakpoint kind `Z0` takes. A stop reply's `T`
registers give the PC when the stub sends it (Dolphin does: register 40h); otherwise `p`, then `g`.

The protocol: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Protocol.html. Checked
against an in-process stand-in stub (test_oracle_gdb.py) and, by reading their source, Dolphin's
`Source/Core/Core/PowerPC/GDBStub.cpp` (no no-ack mode, `g` gives only r0-r31) and DuckStation's
`src/core/gdb_server.cpp` (PC is register 37, an execute breakpoint stops with `S05`).
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from rea_suite.oracle import EmulatorTarget, Stop, TargetError, host_port


@dataclass(frozen=True)
class Arch:
    """What the back end needs to know about a CPU."""

    name: str
    pc: int  # the PC's register number
    size: int  # its size in bytes
    endian: str  # its byte order on the wire: the target's own
    g_offset: int  # where it starts in a `g` answer, in bytes
    kind: int  # the breakpoint kind for Z0/Z1 (the instruction's length)


ARCHES = {
    # i386: eax..edi (0-7), eip 8 (GDB's i386 layout; QEMU's for a 32-bit guest, xemu's)
    "x86": Arch("x86", 8, 4, "little", 8 * 4, 1),
    # x86-64: rax..r15 (0-15), rip 16
    "x86-64": Arch("x86-64", 16, 8, "little", 16 * 8, 1),
    # PowerPC 750 / Gekko / Broadway: r0-r31 (4 bytes), f0-f31 (8 bytes), pc 64 (Dolphin)
    "ppc": Arch("ppc", 64, 4, "big", 32 * 4 + 32 * 8, 4),
    # MIPS R3000: r0-r31, sr, lo, hi, bad, cause, pc 37 (DuckStation, PCSX-Redux)
    "mips": Arch("mips", 37, 4, "little", 37 * 4, 4),
    # ARM (ARM7TDMI, ARM946E-S): r0-r15, pc is r15 (melonDS). A Thumb breakpoint would be kind 2.
    "arm": Arch("arm", 15, 4, "little", 15 * 4, 4),
}
ALIASES = {
    "i386": "x86", "xemu": "x86", "xbox": "x86", "amd64": "x86-64", "x86_64": "x86-64",
    "powerpc": "ppc", "gekko": "ppc", "broadway": "ppc", "750": "ppc", "ppc750": "ppc",
    "dolphin": "ppc", "r3000": "mips", "mips1": "mips", "ps1": "mips", "psx": "mips",
    "arm7": "arm", "arm9": "arm", "armv4t": "arm", "armv5te": "arm",
}  # fmt: skip


def arch(name: str | None) -> Arch:
    if not name:
        raise ValueError(f"--arch: a GDB target needs one of {', '.join(ARCHES)}")
    key = ALIASES.get(name.lower(), name.lower())
    if key not in ARCHES:
        raise ValueError(f"--arch {name!r}: one of {', '.join(ARCHES)} (or {', '.join(ALIASES)})")
    return ARCHES[key]


# --- packets ----------------------------------------------------------------------------------------

ESCAPED = b"#$}*"
INTERRUPT = b"\x03"


def checksum(data: bytes) -> bytes:
    return f"{sum(data) & 0xFF:02x}".encode()


def frame(payload: bytes) -> bytes:
    """$payload#cs, with # $ } * escaped."""
    body = bytearray()
    for b in payload:
        if b in ESCAPED:
            body += bytes((0x7D, b ^ 0x20))
        else:
            body.append(b)
    return b"$" + bytes(body) + b"#" + checksum(bytes(body))


def unpack(body: bytes) -> bytes:
    """A packet's body as sent: escapes undone, run lengths (X*N: N - 29 more of X) expanded."""
    out = bytearray()
    i = 0
    while i < len(body):
        b = body[i]
        if b == 0x7D and i + 1 < len(body):
            out.append(body[i + 1] ^ 0x20)
            i += 2
        elif b == 0x2A and out and i + 1 < len(body):
            out += bytes((out[-1],)) * (body[i + 1] - 29)
            i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out)


class Connection:
    """One RSP connection: packets out, packets in, acknowledgments until no-ack mode."""

    def __init__(self, sock: socket.socket, timeout: float):
        self.sock = sock
        self.timeout = timeout
        self.ack = True
        self.buf = bytearray()

    def _fill(self, deadline: float | None) -> bool:
        """More bytes; False when the deadline passed first."""
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
            raise TargetError(f"gdb: {exc}") from None
        if not data:
            raise TargetError("gdb: the stub closed the connection")
        self.buf += data
        return True

    def send(self, payload: bytes) -> None:
        packet = frame(payload)
        for _ in range(3):
            self.sock.sendall(packet)
            if not self.ack:
                return
            deadline = time.monotonic() + self.timeout
            while True:
                while self.buf[:1] not in (b"+", b"-") and self.buf:
                    if self.buf[:1] == b"$":  # a packet before the ack; the ack was lost
                        return
                    del self.buf[:1]
                if self.buf:
                    break
                if not self._fill(deadline):
                    raise TargetError(f"gdb: no acknowledgment for {payload[:20]!r}")
            sign = self.buf[:1]
            del self.buf[:1]
            if sign == b"+":
                return
        raise TargetError(f"gdb: the stub refused {payload[:20]!r} three times")

    def receive(self, timeout: float | None = -1.0) -> bytes | None:
        """The next packet's body; None when `timeout` seconds passed first (None: no limit)."""
        wait = self.timeout if timeout is not None and timeout < 0 else timeout
        deadline = None if wait is None else time.monotonic() + wait
        while True:
            start = self.buf.find(b"$")
            if start >= 0:
                end = self.buf.find(b"#", start)
                if end >= 0 and len(self.buf) >= end + 3:
                    body = bytes(self.buf[start + 1 : end])
                    sent = bytes(self.buf[end + 1 : end + 3]).lower()
                    del self.buf[: end + 3]
                    if self.ack:
                        good = sent == checksum(body)
                        self.sock.sendall(b"+" if good else b"-")
                        if not good:
                            continue
                    return unpack(body)
            elif self.buf:
                self.buf.clear()  # acks and noise between packets
            if not self._fill(deadline):
                return None

    def ask(self, payload: bytes) -> bytes:
        self.send(payload)
        reply = self.receive()
        if reply is None:
            raise TargetError(f"gdb: no answer to {payload[:20]!r}")
        return reply


# --- the target -------------------------------------------------------------------------------------


def stop_reply(reply: bytes, arch_: Arch) -> Stop:
    """A stop reply: S/T (a signal, T with registers and reasons), W/X (the program ended)."""
    kind = reply[:1]
    if kind in (b"W", b"X"):
        return Stop("exited", None, reply.decode("ascii", "replace"))
    if kind not in (b"S", b"T") or len(reply) < 3:
        raise TargetError(f"gdb: not a stop reply: {reply[:40]!r}")
    signal = int(reply[1:3], 16)
    pc = None
    reason = ""
    if kind == b"T":
        for pair in reply[3:].split(b";"):
            key, sep, value = pair.partition(b":")
            if not sep:
                continue
            try:
                number = int(key, 16)
            except ValueError:
                reason = reason or key.decode("ascii", "replace")
                continue
            if number == arch_.pc:
                pc = int.from_bytes(bytes.fromhex(value.decode()), arch_.endian)
    return Stop("signal", pc, f"signal {signal}" + (f" {reason}" if reason else ""))


class GdbTarget(EmulatorTarget):
    """An emulator's GDB stub as an EmulatorTarget."""

    def __init__(self, host: str, port: int, arch_: Arch, timeout: float = 10.0):
        self.host, self.port, self.arch = host, port, arch_
        self.timeout = timeout
        self.producer = f"gdb {arch_.name} {host}:{port}"
        self.conn: Connection | None = None
        self.breakpoints: set[tuple[int, bool]] = set()
        self.packet_size = 4096
        self.pc: int | None = None

    @classmethod
    def from_url(cls, url: str, arch_name: str | None, timeout: float = 10.0) -> GdbTarget:
        host, port = host_port(url)
        return cls(host, port, arch(arch_name), timeout)

    # -- plumbing

    def _conn(self) -> Connection:
        if self.conn is None:
            raise TargetError("gdb: not connected")
        return self.conn

    def _ok(self, payload: bytes, what: str) -> None:
        reply = self._conn().ask(payload)
        if reply == b"":
            raise TargetError(f"gdb: the stub does not support {what}")
        if reply != b"OK":
            raise TargetError(f"gdb: {what}: {reply[:40].decode('ascii', 'replace')}")

    def _read_pc(self) -> int | None:
        conn = self._conn()
        reply = conn.ask(f"p{self.arch.pc:x}".encode())
        if reply and not reply.startswith(b"E"):
            try:
                return int.from_bytes(bytes.fromhex(reply[: self.arch.size * 2].decode()),
                                      self.arch.endian)  # fmt: skip
            except ValueError:
                pass
        reply = conn.ask(b"g")
        start, end = self.arch.g_offset * 2, (self.arch.g_offset + self.arch.size) * 2
        if len(reply) >= end and not reply.startswith(b"E"):
            try:
                return int.from_bytes(bytes.fromhex(reply[start:end].decode()), self.arch.endian)
            except ValueError:
                pass
        return None

    def _stopped(self, reply: bytes) -> Stop:
        stop = stop_reply(reply, self.arch)
        if stop.reason != "exited" and stop.pc is None:
            stop.pc = self._read_pc()
        self.pc = stop.pc
        if stop.reason == "signal" and any(a == stop.pc for a, _ in self.breakpoints):
            stop.reason = "break"
        return stop

    def _wait_stop(self, timeout: float | None) -> Stop:
        conn = self._conn()
        while True:
            reply = conn.receive(timeout)
            if reply is None:  # time is up: stop it
                conn.sock.sendall(INTERRUPT)
                reply = conn.receive()
                if reply is None:
                    raise TargetError("gdb: the stub did not stop when asked")
                while reply.startswith(b"O") and reply != b"OK":
                    reply = conn.receive()
                    if reply is None:
                        raise TargetError("gdb: the stub did not stop when asked")
                stop = self._stopped(reply)
                if stop.reason != "exited" and stop.reason != "break":
                    stop.reason = "timeout"
                return stop
            if reply.startswith(b"O") and reply != b"OK":
                continue  # the program's console output
            return self._stopped(reply)

    # -- the interface

    def connect(self) -> Stop:
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as exc:
            raise TargetError(f"gdb: {self.host}:{self.port}: {exc}") from None
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.conn = Connection(sock, self.timeout)
        features = self.conn.ask(b"qSupported:swbreak+;hwbreak+").split(b";")
        for feature in features:
            if feature.startswith(b"PacketSize="):
                try:
                    self.packet_size = max(64, int(feature[11:], 16))
                except ValueError:
                    pass
        if b"QStartNoAckMode+" in features and self.conn.ask(b"QStartNoAckMode") == b"OK":
            self.conn.ack = False
        reply = self.conn.ask(b"?")
        stop = self._stopped(reply)
        if stop.reason == "exited":
            raise TargetError(f"gdb: the program has ended ({stop.detail})")
        return stop

    def set_breakpoint(self, address: int, hardware: bool = False) -> None:
        z = b"1" if hardware else b"0"
        self._ok(b"Z" + z + f",{address:x},{self.arch.kind}".encode(),
                 f"{'hardware' if hardware else 'software'} breakpoints (Z{z.decode()})")  # fmt: skip
        self.breakpoints.add((address, hardware))

    def clear_breakpoint(self, address: int, hardware: bool = False) -> None:
        z = b"1" if hardware else b"0"
        self._ok(b"z" + z + f",{address:x},{self.arch.kind}".encode(), f"z{z.decode()}")
        self.breakpoints.discard((address, hardware))

    def resume(self, timeout: float | None) -> Stop:
        conn = self._conn()
        here = [bp for bp in self.breakpoints if bp[0] == self.pc]
        if here:  # step over the breakpoint the CPU stands on, as GDB does, then put it back
            for bp in here:
                self.clear_breakpoint(*bp)
            conn.send(b"s")
            stop = self._wait_stop(self.timeout)
            for bp in here:
                self.set_breakpoint(*bp)
            if stop.reason == "exited":
                return stop
            if stop.pc is not None and any(a == stop.pc for a, _ in self.breakpoints):
                stop.reason = "break"
                return stop
        conn.send(b"c")
        return self._wait_stop(timeout)

    def read(self, address: int, length: int) -> bytes:
        conn = self._conn()
        chunk = max(16, min(0x800, (self.packet_size - 8) // 2))
        out = bytearray()
        while len(out) < length:
            size = min(chunk, length - len(out))
            at = address + len(out)
            reply = conn.ask(f"m{at:x},{size:x}".encode())
            if reply == b"" or (reply.startswith(b"E") and len(reply) == 3):
                why = reply.decode("ascii", "replace") or "no answer"
                raise TargetError(f"gdb: memory at {at:#x} ({why})")
            try:
                data = bytes.fromhex(reply.decode("ascii"))
            except ValueError:
                raise TargetError(f"gdb: memory at {at:#x}: not hex") from None
            if not data:
                raise TargetError(f"gdb: memory at {at:#x}: nothing read")
            out += data[:size]
        return bytes(out)

    def close(self) -> None:
        conn = self.conn
        if conn is None:
            return
        try:
            for bp in sorted(self.breakpoints):
                try:
                    self.clear_breakpoint(*bp)
                except TargetError:
                    pass
            reply = conn.ask(b"D")
            if reply != b"OK":  # no detach (Dolphin): let it run on
                conn.send(b"c")
        except TargetError:
            pass
        finally:
            conn.sock.close()
            self.conn = None
