#
# This file is part of udmp-parser project
#
# Released under MIT License, by 0vercl0k - 2023
#
# With contribution from:
# * hugsy - (github.com/hugsy)
#

import pathlib
import ctypes
from ctypes import wintypes
import time
from typing import Optional


def get_process_id(process_name: str):
    kernel32 = ctypes.WinDLL("kernel32")
    CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
    Process32First = kernel32.Process32First
    Process32Next = kernel32.Process32Next
    CloseHandle = kernel32.CloseHandle

    TH32CS_SNAPPROCESS = 0x00000002
    MAX_PATH = 260

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", wintypes.LPVOID),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.CHAR * MAX_PATH),
        ]

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == -1:
        return None

    pe32 = PROCESSENTRY32()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if Process32First(snapshot, ctypes.byref(pe32)) == 0:
        CloseHandle(snapshot)
        return None

    res = None
    while True:
        process_name_str = pe32.szExeFile.decode("utf-8").lower()
        if process_name.lower() == process_name_str:
            res = pe32.th32ProcessID
            break

        if Process32Next(snapshot, ctypes.byref(pe32)) == 0:
            break

    CloseHandle(snapshot)
    return res


def generate_minidump(process_id: int, dump_file_path: pathlib.Path) -> bool:
    kernel32 = ctypes.WinDLL("kernel32")
    dbghelp = ctypes.WinDLL("dbghelp")

    # Constants
    INVALID_HANDLE_VALUE = -1
    CREATE_ALWAYS = 2
    PROCESS_ALL_ACCESS = 0x1F0FFF
    GENERIC_WRITE = 0x40000000
    FILE_ATTRIBUTE_NORMAL = 0x80

    MiniDumpNormal = 0x00000000
    MiniDumpWithDataSegs = 0x00000001
    MiniDumpWithFullMemory = 0x00000002
    MiniDumpWithHandleData = 0x00000004
    MiniDumpScanMemory = 0x00000010
    MiniDumpWithFullMemoryInfo = 0x00000800

    class MINIDUMP_EXCEPTION_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("ThreadId", ctypes.c_ulong),
            ("ExceptionPointers", ctypes.POINTER(ctypes.c_void_p)),
            ("ClientPointers", ctypes.c_ulong),
        ]

    class MINIDUMP_CALLBACK_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("CallbackRoutine", ctypes.c_void_p),
            ("CallbackParam", ctypes.c_void_p),
        ]

    class MINIDUMP_USER_STREAM(ctypes.Structure):
        _fields_ = [
            ("Type", ctypes.c_ulong),
            ("BufferSize", ctypes.c_ulong),
            ("Buffer", ctypes.POINTER(ctypes.c_void_p)),
        ]

    class MINIDUMP_USER_STREAM_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("UserStreamCount", ctypes.c_ulong),
            ("UserStreamArray", ctypes.POINTER(MINIDUMP_USER_STREAM)),
            ("Reserved0", ctypes.c_ulong),
            ("Reserved1", ctypes.c_void_p),
        ]

    MiniDumpWriteDump = dbghelp.MiniDumpWriteDump
    MiniDumpWriteDump.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(MINIDUMP_EXCEPTION_INFORMATION),
        ctypes.POINTER(MINIDUMP_USER_STREAM_INFORMATION),
        ctypes.POINTER(MINIDUMP_CALLBACK_INFORMATION),
    ]
    MiniDumpWriteDump.restype = ctypes.c_bool

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)

    if not hProcess:
        return False

    bSuccess = False
    hFile = kernel32.CreateFileW(
        str(dump_file_path.absolute()),
        GENERIC_WRITE,
        0,
        None,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )

    if hFile != INVALID_HANDLE_VALUE:
        flags = (
            MiniDumpWithFullMemory
            | MiniDumpWithDataSegs
            | MiniDumpScanMemory
            | MiniDumpWithHandleData
            | MiniDumpWithFullMemoryInfo
        )
        bSuccess = MiniDumpWriteDump(
            hProcess,
            process_id,
            hFile,
            flags,
            None,
            None,
            None,
        )

        kernel32.CloseHandle(hFile)

    kernel32.CloseHandle(hProcess)
    return bSuccess


def generate_minidump_from_process_name(
    process_name: str = "explorer.exe", output_dir: pathlib.Path = pathlib.Path(".")
) -> Optional[tuple[int, pathlib.Path]]:
    process_id = get_process_id(process_name)
    if not process_id or not isinstance(process_id, int):
        return None

    dump_file_path = output_dir / f"minidump-{process_name}-{int(time.time())}.dmp"

    if not generate_minidump(process_id, dump_file_path):
        return None

    print(f"Minidump generated successfully: PID={process_id} -> {dump_file_path}")
    return (process_id, dump_file_path)
