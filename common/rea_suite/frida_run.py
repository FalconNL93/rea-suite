"""Run a Frida script against a process and log what it sends, one JSON object a line.

  rea-suite frida <script.js> --pid N|--name NAME|--spawn PROGRAM [ARG...] [options]

The script is loaded, then its `configure` RPC export (when it has one) gets the config (--config
FILE or --config-json TEXT); a spawned process resumes only after both succeeded, so nothing
runs unobserved. Each message becomes {"t": seconds since the start, ...payload}; script errors
become {"kind": "script-error", ...}. It ends after --seconds, when the process ends or on
Ctrl+C; a spawned process keeps running unless --kill. Scripts for it are in common/frida/
(observer.js, write-guard.js; docs/PORT-TOOLS.md).

Exit 0: ran; 1: the script failed (an error, or configure refused); 2: no such process or Frida
could not attach.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path

import frida


class Log:
    def __init__(self, path: Path | None, quiet: bool):
        self.start = time.monotonic()
        self.file = path.open("a", encoding="utf-8") if path else None
        self.quiet = quiet
        self.failed = False
        self.lock = threading.Lock()

    def write(self, record: dict) -> None:
        line = json.dumps({"t": round(time.monotonic() - self.start, 3), **record})
        with self.lock:
            if self.file:
                self.file.write(line + "\n")
                self.file.flush()
            if not self.quiet:
                print(line, flush=True)

    def message(self, message: dict, data: bytes | None) -> None:
        if message.get("type") == "send":
            payload = message.get("payload")
            record = payload if isinstance(payload, dict) else {"payload": payload}
            if data:
                record = {**record, "data": data.hex()}
            self.write(record)
        elif message.get("type") == "error":
            self.failed = True
            self.write(
                {
                    "kind": "script-error",
                    "description": message.get("description"),
                    "stack": message.get("stack"),
                }
            )
        else:
            self.write({"kind": "frida", "message": message})


def device_of(args) -> frida.core.Device:
    if args.host:
        return frida.get_device_manager().add_remote_device(args.host)
    if args.usb:
        return frida.get_usb_device(timeout=5)
    return frida.get_local_device()


def load_config(args) -> dict | None:
    if args.config:
        return json.loads((args.caller_cwd / args.config).read_text())
    if args.config_json:
        return json.loads(args.config_json)
    return None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rea-suite frida",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    p.add_argument("script", type=Path)
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--pid", type=int)
    target.add_argument("--name", help="attach to the process with this name")
    target.add_argument("--spawn", nargs=argparse.REMAINDER, metavar="PROGRAM", help="start it")
    p.add_argument("--config", type=Path, help="JSON file passed to the script's configure()")
    p.add_argument("--config-json", help="the same as text")
    p.add_argument("--log", type=Path, help="append the JSON lines to this file too")
    p.add_argument("--seconds", type=float, help="stop after this long")
    p.add_argument("--cwd", type=Path, help="working directory of a spawned process")
    p.add_argument("--kill", action="store_true", help="end a spawned process at the end")
    p.add_argument("--quiet", action="store_true", help="no lines on stdout (with --log)")
    p.add_argument("--usb", action="store_true", help="a USB device (Android)")
    p.add_argument("--host", help="a remote frida-server, host:port")
    args = p.parse_args(argv)
    cwd = args.caller_cwd
    source = (cwd / args.script).read_text(encoding="utf-8")
    config = load_config(args)
    log = Log(cwd / args.log if args.log else None, args.quiet)
    ended = threading.Event()
    try:
        device = device_of(args)
        spawned = None
        if args.spawn:
            program = [
                str(cwd / args.spawn[0]) if (cwd / args.spawn[0]).exists() else args.spawn[0]
            ]
            options = {"cwd": str(cwd / args.cwd)} if args.cwd else {}
            spawned = device.spawn(program + args.spawn[1:], **options)
            pid = spawned
        elif args.name:
            pid = device.get_process(args.name).pid
        else:
            pid = args.pid
        session = device.attach(pid)
    except (frida.ProcessNotFoundError, frida.ServerNotRunningError, frida.ExecutableNotFoundError,
            frida.InvalidArgumentError, frida.NotSupportedError, frida.PermissionDeniedError,
            frida.TransportError, frida.TimedOutError) as exc:  # fmt: skip
        print(f"frida: {exc}", file=sys.stderr)
        return 2
    session.on(
        "detached",
        lambda reason, crash: (log.write({"kind": "detached", "reason": reason}), ended.set()),
    )
    script = session.create_script(source, name=args.script.stem)
    script.on("message", log.message)
    log.write(
        {"kind": "start", "pid": pid, "spawned": spawned is not None, "frida": frida.__version__}
    )
    try:
        script.load()
        if config is not None and not script.exports_sync.configure(config):
            raise frida.InvalidOperationError("configure returned false")
    except (frida.InvalidOperationError, frida.core.RPCException) as exc:
        log.write({"kind": "script-error", "description": str(exc)})
        if spawned is not None:
            device.kill(spawned)  # it never ran: do not leave it suspended
        return 1
    if spawned is not None:
        device.resume(spawned)
    try:
        ended.wait(args.seconds)
    except KeyboardInterrupt:
        pass
    if not ended.is_set():
        try:
            if "report" in script.list_exports_sync():
                script.exports_sync.report()
            time.sleep(0.2)  # let the last messages arrive
            script.unload()
            session.detach()
        except frida.InvalidOperationError:
            pass
    if args.kill and spawned is not None:
        try:
            device.kill(spawned)
        except frida.ProcessNotFoundError:
            pass
    log.write({"kind": "end"})
    return 1 if log.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
