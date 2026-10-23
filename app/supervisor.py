"""Keeps the server running as a background service (used by the Windows installer).

Starts `python -m app.main` and restarts it if it stops. On Windows the child is put in a Job Object, so stopping
the supervisor (e.g. Stop-ScheduledTask) also stops the server.

    pythonw -m app.supervisor
"""
import logging
import os
import subprocess
import sys
import time
from logging.handlers import RotatingFileHandler

from . import config

log = logging.getLogger("supervisor")


def _job_kill_on_close():
    """Windows: a job object that kills its processes when this process exits."""
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("ReadOperationCount", "WriteOperationCount",
                                                      "OtherOperationCount", "ReadTransferCount",
                                                      "WriteTransferCount", "OtherTransferCount")]

    class BASIC_LIMIT(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class EXTENDED_LIMIT(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BASIC_LIMIT), ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    job = k32.CreateJobObjectW(None, None)
    if not job:
        return None
    info = EXTENDED_LIMIT()
    info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    k32.SetInformationJobObject(wintypes.HANDLE(job), 9, ctypes.byref(info), ctypes.sizeof(info))
    return k32, job


def _assign(job, proc):
    if not job:
        return
    import ctypes
    from ctypes import wintypes
    k32, handle = job
    k32.AssignProcessToJobObject(wintypes.HANDLE(handle), wintypes.HANDLE(int(proc._handle)))


def _python():
    exe = sys.executable
    if os.name == "nt" and exe.lower().endswith("pythonw.exe"):
        console = exe[:-len("pythonw.exe")] + "python.exe"
        if os.path.isfile(console):
            return console
    return exe


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        handlers=[RotatingFileHandler(os.path.join(config.LOG_DIR, "service.log"),
                                                      maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")])
    job = _job_kill_on_close()
    with open(os.path.join(config.DATA_DIR, "service.pid"), "w") as fh:
        fh.write(str(os.getpid()))
    flags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
    backoff = 5
    while True:
        started = time.time()
        console = os.path.join(config.LOG_DIR, "console.log")
        if os.path.isfile(console) and os.path.getsize(console) > 5 * 1024 * 1024:
            os.replace(console, console + ".1")
        out = open(console, "ab")
        log.info("starting server")
        env = dict(os.environ, NO_CONSOLE_LOG="1", PYTHONUNBUFFERED="1")
        proc = subprocess.Popen([_python(), "-m", "app.main"], cwd=config.ROOT_DIR, stdout=out, env=env,
                                stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, creationflags=flags)
        _assign(job, proc)
        code = proc.wait()
        out.close()
        backoff = 5 if time.time() - started > 120 else min(backoff * 2, 60)
        log.warning("server exited with code %s; restarting in %ss", code, backoff)
        time.sleep(backoff)


if __name__ == "__main__":
    main()
