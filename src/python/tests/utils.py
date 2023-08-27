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
from typing import Optional, Tuple

import udmp_parser


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


def generate_minidump_from_process_name(
    process_name: str = "explorer.exe", output_dir: pathlib.Path = pathlib.Path(".")
) -> Optional[Tuple[int, pathlib.Path]]:
    process_id = get_process_id(process_name)
    if not process_id or not isinstance(process_id, int):
        return None

    dump_file_path = output_dir / f"minidump-{process_name}-{int(time.time())}.dmp"

    if not udmp_parser.utils.generate_minidump(process_id, dump_file_path):
        return None

    print(f"Minidump generated successfully: PID={process_id} -> {dump_file_path}")
    return (process_id, dump_file_path)
