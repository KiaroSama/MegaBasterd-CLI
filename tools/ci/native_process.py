# SPDX-License-Identifier: GPL-3.0-or-later
"""Native ownership for CI children; no production/runtime dependency."""
import ctypes
import os
from pathlib import Path
import signal
import sys


class WindowsJob:
    def __init__(self, memory_mib):
        from ctypes import wintypes as w

        class Limits(ctypes.Structure):
            _fields_ = [("user", ctypes.c_int64), ("kernel", ctypes.c_int64),
                        ("flags", w.DWORD), ("min_ws", ctypes.c_size_t),
                        ("max_ws", ctypes.c_size_t), ("active", w.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", w.DWORD),
                        ("scheduling", w.DWORD)]

        class Extended(ctypes.Structure):
            _fields_ = [("limits", Limits), ("io", ctypes.c_uint64 * 6),
                        ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                        ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]

        class Accounting(ctypes.Structure):
            _fields_ = [("user", ctypes.c_int64), ("kernel", ctypes.c_int64),
                        ("period_user", ctypes.c_int64), ("period_kernel", ctypes.c_int64),
                        ("faults", w.DWORD), ("total", w.DWORD),
                        ("active", w.DWORD), ("terminated", w.DWORD)]

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        declarations = {
            "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            "QueryInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                            w.DWORD, ctypes.c_void_p], w.BOOL),
            "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
            "OpenProcess": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
            "CloseHandle": ([w.HANDLE], w.BOOL),
        }
        for name, (args, result) in declarations.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = args, result
        self.extended, self.accounting = Extended, Accounting
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError("CI Job Object creation failed")
        info = Extended()
        info.limits.flags = 0x2000 | 0x200  # KILL_ON_JOB_CLOSE + JOB_MEMORY, no breakaway.
        info.job_memory = memory_mib * 1024 * 1024
        try:
            self._check(self.api.SetInformationJobObject(
                self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)))
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _check(result):
        if not result:
            raise OSError("CI Job Object operation failed")

    def assign(self, pid):
        # Guardian waits on its input gate until assignment succeeds; target cannot race assignment.
        process = self.api.OpenProcess(0x0100 | 0x0001, False, pid)
        if not process:
            raise OSError("CI guardian process handle is unavailable")
        try:
            self._check(self.api.AssignProcessToJobObject(self.handle, process))
        finally:
            self._check(self.api.CloseHandle(process))

    def sample(self):
        accounting, extended = self.accounting(), self.extended()
        for kind, data in [(1, accounting), (9, extended)]:
            self._check(self.api.QueryInformationJobObject(
                self.handle, kind, ctypes.byref(data), ctypes.sizeof(data), None))
        return {"processes": accounting.active,
                "cpu": (accounting.user + accounting.kernel) / 10_000_000,
                "memory": extended.peak_job}

    def stop(self):
        self._check(self.api.TerminateJobObject(self.handle, 125))

    def close(self):
        if self.handle:
            handle, self.handle = self.handle, None
            self._check(self.api.CloseHandle(handle))


class UnixTree:
    def __init__(self, pid):
        self.pid = pid
        self.root_stamp = None
        self.reap_adopted = False
        self.owned = {}
        self.cpu_seen = {}
        self.apple = None
        if sys.platform == "darwin":
            self.apple = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            self.apple.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self.apple.proc_listallpids.restype = ctypes.c_int
            self.apple.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                               ctypes.c_void_p, ctypes.c_int]
            self.apple.proc_pidinfo.restype = ctypes.c_int
        elif sys.platform != "linux":
            raise OSError("CI process ownership supports only native Linux/macOS/Windows")
        self.sample()

    @staticmethod
    def _linux():
        ticks = os.sysconf("SC_CLK_TCK")
        pages = os.sysconf("SC_PAGE_SIZE")
        result = {}
        for directory in Path("/proc").iterdir():
            if not directory.name.isdecimal():
                continue
            try:
                text = (directory / "stat").read_bytes()
                data = text[text.rindex(b")") + 2:].split()
                result[int(directory.name)] = (
                    int(data[1]), int(data[3]), int(data[19]), data[0].decode("ascii"),
                    (int(data[11]) + int(data[12])) / ticks, int(data[21]) * pages)
            except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError):
                continue
        return result

    def _macos(self):
        class Bsd(ctypes.Structure):
            _fields_ = [("prefix", ctypes.c_uint32 * 12), ("comm", ctypes.c_char * 16),
                        ("name", ctypes.c_char * 32), ("tail", ctypes.c_uint32 * 6),
                        ("start_sec", ctypes.c_uint64), ("start_us", ctypes.c_uint64)]

        class Task(ctypes.Structure):
            _fields_ = [("wide", ctypes.c_uint64 * 6), ("narrow", ctypes.c_int32 * 12)]

        # Native process list is bounded; saturation is an explicit failure, never missing coverage.
        pids = (ctypes.c_int * 32768)()
        count = self.apple.proc_listallpids(pids, ctypes.sizeof(pids))
        if count <= 0 or count >= len(pids):
            raise OSError("CI native process enumeration failed or saturated")
        result = {}
        for pid in pids[:count]:
            if pid <= 0:
                continue
            bsd, task = Bsd(), Task()
            if self.apple.proc_pidinfo(pid, 3, 0, ctypes.byref(bsd), ctypes.sizeof(bsd)) != ctypes.sizeof(bsd):
                if pid == self.pid or pid in self.owned:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        continue
                    raise OSError("CI cannot inspect an owned native process identity")
                continue
            try:
                session = os.getsid(pid)
            except (ProcessLookupError, PermissionError):
                continue
            size = self.apple.proc_pidinfo(pid, 4, 0, ctypes.byref(task), ctypes.sizeof(task))
            cpu = (task.wide[2] + task.wide[3]) / 1_000_000_000 if size == ctypes.sizeof(task) else 0
            memory = task.wide[1] if size == ctypes.sizeof(task) else 0
            result[pid] = (bsd.prefix[4], session, (bsd.start_sec, bsd.start_us),
                           "Z" if bsd.prefix[1] == 5 else "R", cpu, memory)
        return result

    def members(self):
        snapshot = self._macos() if self.apple else self._linux()
        if self.root_stamp is None and self.pid in snapshot:
            self.root_stamp = snapshot[self.pid][2]
        root_matches = self.pid not in snapshot or snapshot[self.pid][2] == self.root_stamp
        # Keep observed ancestry even when a child starts another session. A never-observed
        # double-fork/setsid escape cannot be guaranteed by POSIX polling; not a sandbox.
        known = {pid for pid, stamp in self.owned.items()
                 if pid in snapshot and snapshot[pid][2] == stamp}
        if self.reap_adopted:
            known.update(pid for pid, data in snapshot.items() if data[0] == os.getpid())
        for _ in range(len(snapshot) + 1):
            found = {pid for pid, data in snapshot.items()
                     if (root_matches and (pid == self.pid or data[1] == self.pid)) or data[0] in known}
            updated = known | found
            if updated == known:
                break
            known = updated
        for pid in known:
            self.owned[pid] = snapshot[pid][2]
            key = (pid, snapshot[pid][2])
            self.cpu_seen[key] = max(self.cpu_seen.get(key, 0), snapshot[pid][4])
        return {pid: snapshot[pid] for pid in known}

    def sample(self):
        members = self.members()
        return {"processes": len(members), "cpu": sum(self.cpu_seen.values()),
                "memory": sum(data[5] for data in members.values()),
                "zombies": sum(data[3] == "Z" for data in members.values())}

    def stop(self):
        members = self.members()
        # Identity is checked again before signaling; never kill a reused PID by name.
        for pid, data in sorted(members.items(), key=lambda item: item[0] == self.pid):
            if self.reap_adopted and pid != self.pid:
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
            current = self._macos() if self.apple else self._linux()
            if pid in current and current[pid][2] == data[2] and current[pid][3] != "Z":
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def close(self):
        pass


def enable_linux_subreaper():
    if sys.platform != "linux":
        return False
    api = ctypes.CDLL(None, use_errno=True)
    api.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    api.prctl.restype = ctypes.c_int
    if api.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError("CI Linux child-subreaper initialization failed")
    return True


def available_memory():
    if os.name == "nt":
        class Memory(ctypes.Structure):
            _fields_ = [("length", ctypes.c_uint32), ("load", ctypes.c_uint32),
                        ("wide", ctypes.c_uint64 * 7)]
        data = Memory()
        data.length = ctypes.sizeof(data)
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.GlobalMemoryStatusEx.argtypes = [ctypes.c_void_p]
        api.GlobalMemoryStatusEx.restype = ctypes.c_int
        if not api.GlobalMemoryStatusEx(ctypes.byref(data)):
            raise OSError("CI memory budget discovery failed")
        return data.wide[1]
    if sys.platform == "linux":
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    # macOS physical RAM is conservative for worker selection; runtime RSS is monitored separately.
    if sys.platform == "darwin":
        value, length = ctypes.c_uint64(), ctypes.c_size_t(8)
        api = ctypes.CDLL(None, use_errno=True)
        api.sysctlbyname.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_size_t]
        api.sysctlbyname.restype = ctypes.c_int
        if api.sysctlbyname(b"hw.memsize", ctypes.byref(value), ctypes.byref(length), None, 0) != 0:
            raise OSError("CI memory budget discovery failed")
        return value.value // 2
    raise OSError("CI memory budget is unavailable")
