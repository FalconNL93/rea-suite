"""One external program run with a wall-clock limit: on a timeout or an interruption the program
and every child it started are stopped, first asked (SIGTERM, so Java's shutdown hooks release a
Ghidra project's lock), then killed after a grace period. Windows ends the tree with taskkill."""

from __future__ import annotations

import os
import signal
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import IO

GRACE_SECONDS = 10


def _stop(child: subprocess.Popen, grace: float) -> None:
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(child.pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if child.poll() is None:
            child.kill()
        return
    for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, None)):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            return
        try:
            child.wait(timeout=wait)
            # the leader is gone; a child that ignored SIGTERM still holds the group
            if sig == signal.SIGTERM:
                os.killpg(child.pid, signal.SIGKILL)
            return
        except subprocess.TimeoutExpired:
            continue
        except ProcessLookupError:
            return


def run(
    command: Sequence[str],
    cwd: Path,
    log: IO,
    timeout: float,
    env: Mapping[str, str] | None = None,
    grace: float = GRACE_SECONDS,
) -> int:
    """Runs the command into the log; raises TimeoutExpired past the limit (after stopping it),
    CalledProcessError on a non-zero exit."""
    with subprocess.Popen(
        list(command),
        cwd=cwd,
        stdout=log,
        stderr=subprocess.STDOUT,
        env=dict(env) if env is not None else None,
        start_new_session=os.name != "nt",
    ) as child:
        try:
            code = child.wait(timeout=timeout)
        except BaseException:
            if child.poll() is None:
                _stop(child, grace)
                child.wait()
            raise
    if code:
        raise subprocess.CalledProcessError(code, list(command))
    return code
