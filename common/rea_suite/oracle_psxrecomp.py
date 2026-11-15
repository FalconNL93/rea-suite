"""The oracle's PSXRecomp back end: a PSXRecomp runtime's debug server (docs/PS1.md).

`psxrecomp://HOST:PORT`, one JSON object a line over TCP, a connection per command (as the
runtime's own clients do): `ping`, `frame` (the guest's frame counter), `read_ram` (hex),
`set_snapshot` (slot 0-3, an address: 128 bytes the runtime records at the end of every frame),
`read_frame_ram` (up to 128 bytes of a recorded frame), `get_snapshots`.

The server has no breakpoints and no pause: upstream removed pause, step and run_to_frame, and a
host pause stops the server too (it is pumped by the game's main thread). So the target runs
freely: `frame=N` sync points are read from the frame history, which holds the last 36,000 frames,
four regions of at most 128 bytes each; `t=` and `start` read live RAM. `resume` waits a moment and
reports the frame counter. A Release build's server is off unless `PSX_DEBUG_SERVER=1`, and a
connection to it then hangs: every command has a timeout.

Checked against an in-process stand-in (test_oracle_psxrecomp.py) and, on 2026-11-15, against Duke
Nukem: Time to Kill's PSXRecomp build (docs/PORT-TOOLS.md, "The oracle").
"""

from __future__ import annotations

import json
import socket
import time

from rea_suite.oracle import EmulatorTarget, Region, Stop, TargetError, host_port

SLOTS = 4
SNAPSHOT_SIZE = 128
POLL = 0.2  # seconds a resume waits before it reports the frame counter


class PsxRecompTarget(EmulatorTarget):
    frames = True

    def __init__(self, host: str, port: int, timeout: float):
        self.host, self.port, self.timeout = host, port, timeout
        self.producer = f"psxrecomp {host}:{port}"
        self.slots: list[int] = []  # the snapshot slots this target set

    @classmethod
    def from_url(cls, url: str, timeout: float) -> PsxRecompTarget:
        host, port = host_port(url)
        return cls(host, port, timeout)

    def command(self, request: dict, timeout: float | None = None) -> dict:
        try:
            with socket.create_connection(
                (self.host, self.port), timeout=timeout or self.timeout
            ) as sock:
                sock.sendall((json.dumps(request) + "\n").encode())
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = sock.recv(1 << 20)
                    if not chunk:
                        break
                    buf += chunk
        except TimeoutError:
            raise TargetError(
                f"psxrecomp: no answer to {request['cmd']} in {timeout or self.timeout} s"
            ) from None
        except OSError as exc:
            raise TargetError(f"psxrecomp: {self.host}:{self.port}: {exc}") from None
        try:
            answer = json.loads(buf.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TargetError(f"psxrecomp: {request['cmd']}: not a JSON answer") from None
        if not answer.get("ok"):
            raise TargetError(f"psxrecomp: {request['cmd']}: {answer.get('error', answer)}")
        return answer

    def frame(self) -> int:
        return int(self.command({"cmd": "frame"})["frame"])

    def connect(self) -> Stop:
        self.command({"cmd": "ping"})
        return Stop("signal", None, "running", frame=self.frame())

    def set_breakpoint(self, address: int, hardware: bool = False) -> None:
        raise TargetError(
            "psxrecomp: the debug server has no breakpoints: use frame=N or t= triggers"
        )

    def clear_breakpoint(self, address: int, hardware: bool = False) -> None:
        return None

    def resume(self, timeout: float | None) -> Stop:
        time.sleep(min(POLL, timeout) if timeout is not None else POLL)
        try:
            return Stop("timeout", None, frame=self.frame())
        except TargetError as exc:
            if "Connection refused" in str(exc):
                return Stop("exited", None, "the debug server is gone")
            raise

    def read(self, address: int, length: int) -> bytes:
        answer = self.command(
            {"cmd": "read_ram", "addr": f"0x{address:08X}", "len": length}, max(self.timeout, 30)
        )
        data = bytes.fromhex(answer["hex"])
        if len(data) != length:
            raise TargetError(
                f"psxrecomp: read_ram gave {len(data)} of {length} bytes at {address:#x}"
            )
        return data

    def watch(self, regions: list[Region]) -> None:
        if len(regions) > SLOTS:
            raise TargetError(
                f"psxrecomp: the frame history records {SLOTS} regions, not {len(regions)}"
            )
        for slot, region in enumerate(regions):
            if region.length > SNAPSHOT_SIZE:
                raise TargetError(
                    f"psxrecomp: region {region.name} is {region.length} bytes; the frame history keeps {SNAPSHOT_SIZE}"
                )
            self.command(
                {"cmd": "set_snapshot", "slot": slot, "addr": f"0x{region.address.value:08X}"}
            )
            self.slots.append(slot)

    def read_at_frame(self, frame: int, address: int, length: int) -> bytes:
        request = {
            "cmd": "read_frame_ram",
            "frame": frame,
            "addr": f"0x{address:08X}",
            "len": length,
        }
        try:
            answer = self.command(request)
        except TargetError as exc:
            if "not in buffer" in str(exc) and self.frame() > frame + 1:
                raise TargetError(
                    f"psxrecomp: frame {frame} has passed but is not in the frame history: a build "
                    "with PSX_NO_DEBUG_TOOLS (a Release build) records none; use t= triggers"
                ) from None
            raise
        return bytes.fromhex(answer["hex"])

    def close(self) -> None:
        for slot in self.slots:
            try:
                self.command({"cmd": "set_snapshot", "slot": slot, "addr": "0x0"})
            except TargetError:
                break
        self.slots.clear()
