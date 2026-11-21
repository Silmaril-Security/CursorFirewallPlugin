"""Serialize QA across repositories using the preprovisioned MacStadium host lock."""
import contextlib
import fcntl
import os
import platform
import stat
import subprocess
import time
from pathlib import Path


class PhysicalHostUnavailable(RuntimeError):
    pass


@contextlib.contextmanager
def physical_lease():
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise PhysicalHostUnavailable("A physical MacStadium Apple silicon runner is required")
    model = subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.model"], text=True).strip()
    if model.startswith("Virtual"):
        raise PhysicalHostUnavailable("A physical Mac is required")
    parent = Path("/Users/Shared/silmaril-release-qa")
    try:
        directory = parent.lstat()
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid or directory.st_mode & 0o022:
            raise PhysicalHostUnavailable("Untrusted MacStadium lease directory")
        fd = os.open(parent / "physical.lock", os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise PhysicalHostUnavailable("MacStadium lease is not provisioned") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_nlink != 1 or info.st_mode & 0o002:
            raise PhysicalHostUnavailable("Untrusted MacStadium lease file")
        until = time.monotonic() + 300
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= until:
                    raise PhysicalHostUnavailable("The MacStadium host is in use")
                time.sleep(2)
        yield
    finally:
        os.close(fd)
