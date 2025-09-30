#
# This file is part of udmp-parser project
#
# Released under MIT License, by 0vercl0k - 2023
#
# With contribution from:
# * hugsy - (github.com/hugsy)
#

import lief
import pathlib
import platform
import pytest
import subprocess
import tempfile
import time
import unittest

# format: on
import udmp_parser  # type: ignore
from .utils import generate_minidump_from_process_name  # type: ignore

# format: off

TARGET_PROCESS_NAME: str = "winver.exe"
TARGET_PROCESS_PATH: pathlib.Path = pathlib.Path(
    f"C:/Windows/System32/{TARGET_PROCESS_NAME}"
)


@pytest.mark.skipif(
    platform.system().lower() != "windows", reason="Tests only for Windows"
)
class TestParserBasic(unittest.TestCase):
    def setUp(self):
        # TODO switch to LFS to store minidump test cases (x86, x64, wow64, etc.)
        self.process = subprocess.Popen(
            [
                TARGET_PROCESS_PATH,
            ]
        )
        time.sleep(1)
        self.tempdir = tempfile.TemporaryDirectory(prefix="minidump_")
        self.tempdir_path = pathlib.Path(self.tempdir.name)
        res = generate_minidump_from_process_name(
            TARGET_PROCESS_NAME, self.tempdir_path
        )
        assert res
        _, self.minidump_file = res
        assert self.minidump_file.exists()

    def tearDown(self) -> None:
        self.process.kill()
        return super().tearDown()

    def test_version(self):
        assert udmp_parser.version.major == 0
        assert udmp_parser.version.minor == 7
        assert udmp_parser.version.release == ""

    def test_parser_basic(self):
        parser = udmp_parser.UserDumpParser()
        assert parser.ForegroundThreadId() is None
        assert len(parser.Threads()) == 0
        assert len(parser.Memory()) == 0
        assert parser.Parse(self.minidump_file)
        assert len(parser.Threads())
        assert len(parser.Memory())
        assert len(parser.Modules())

    def test_threads(self):
        parser = udmp_parser.UserDumpParser()
        assert parser.Parse(self.minidump_file)
        threads = parser.Threads()
        assert len(threads)

        for _, thread in threads.items():
            assert thread.ThreadId, "invalid ThreadId field"
            assert thread.Teb, "invalid Teb field"
            assert not isinstance(
                thread.Context, udmp_parser.UnknownContext
            ), "invalid Context field"
            if isinstance(thread.Context, udmp_parser.Context32):
                assert thread.Context.Esp
                assert thread.Context.Eip
            elif isinstance(thread.Context, udmp_parser.Context64):
                assert thread.Context.Rsp
                assert thread.Context.Rip
            else:
                assert False, "invalid Context field"

    def test_modules(self):
        parser = udmp_parser.UserDumpParser()
        assert parser.Parse(self.minidump_file)
        modules = parser.Modules()
        assert len(modules)

        ntdll_modules = [
            mod
            for _, mod in modules.items()
            if mod.ModuleName.lower().endswith("ntdll.dll")
        ]
        kernel32_modules = [
            mod
            for _, mod in modules.items()
            if mod.ModuleName.lower().endswith("kernel32.dll")
        ]

        assert len(ntdll_modules) >= 1
        assert len(kernel32_modules) >= 1

        for mod in ntdll_modules + kernel32_modules:
            assert mod.BaseOfImage > 0, f"Invalid BaseOfImage for '{mod}'"
            assert mod.SizeOfImage > 0, f"Invalid SizeOfImage for '{mod}'"
            module_raw = parser.ReadMemory(mod.BaseOfImage, mod.SizeOfImage)
            img = lief.PE.parse(module_raw)
            assert img
            assert img.header.numberof_sections
            assert img.optional_header.sizeof_code
            assert img.optional_header.imagebase

    def test_memory(self):
        parser = udmp_parser.UserDumpParser()
        assert parser.Parse(self.minidump_file)
        memory_regions = parser.Memory()
        assert len(memory_regions)

    def test_memory_inexistent(self):
        """This ensures that `ReadMemory` returns `None` when trying to
        read a segment of memory that isn't described in the dump file."""
        parser = udmp_parser.UserDumpParser()
        assert parser.Parse(self.minidump_file)
        assert parser.ReadMemory(0xDEADBEEF_BAADC0DE, 0x10) is None

    def test_memory_empty(self):
        """This ensures that `ReadMemory` returns an empty array (and not `None`)
        when trying to read into a memory region that has no data associated."""
        parser = udmp_parser.UserDumpParser()
        assert parser.Parse(self.minidump_file)
        mem = parser.Memory()
        empty_regions = list(filter(lambda m: m.DataSize == 0, mem.values()))
        assert len(empty_regions) > 0
        empty_region = empty_regions[0]
        assert len(parser.ReadMemory(empty_region.BaseAddress, 0x10)) == 0

    def test_utils(self):
        assert udmp_parser.utils.TypeToString(0x2_0000) == "MEM_PRIVATE"
        assert udmp_parser.utils.TypeToString(0x4_0000) == "MEM_MAPPED"
        assert udmp_parser.utils.TypeToString(0x100_0000) == "MEM_IMAGE"
        assert udmp_parser.utils.TypeToString(0x41414141) == ""

        assert udmp_parser.utils.StateToString(0x1000) == "MEM_COMMIT"
        assert udmp_parser.utils.StateToString(0x2000) == "MEM_RESERVE"
        assert udmp_parser.utils.StateToString(0x10000) == "MEM_FREE"
        assert udmp_parser.utils.StateToString(0x41414141) == ""

        assert udmp_parser.utils.ProtectionToString(0x01) == "PAGE_NOACCESS"
        assert udmp_parser.utils.ProtectionToString(0x02) == "PAGE_READONLY"
        assert udmp_parser.utils.ProtectionToString(0x04) == "PAGE_READWRITE"
        assert udmp_parser.utils.ProtectionToString(0x08) == "PAGE_WRITECOPY"
        assert udmp_parser.utils.ProtectionToString(0x10) == "PAGE_EXECUTE"
        assert udmp_parser.utils.ProtectionToString(
            0x20) == "PAGE_EXECUTE_READ"
        assert udmp_parser.utils.ProtectionToString(
            0x40) == "PAGE_EXECUTE_READWRITE"
        assert udmp_parser.utils.ProtectionToString(
            0x80) == "PAGE_EXECUTE_WRITECOPY"
        assert (
            udmp_parser.utils.ProtectionToString(
                0x18) == "PAGE_WRITECOPY,PAGE_EXECUTE"
        )
        assert (
            udmp_parser.utils.ProtectionToString(0x19)
            == "PAGE_NOACCESS,PAGE_WRITECOPY,PAGE_EXECUTE"
        )
        assert (
            udmp_parser.utils.ProtectionToString(0x44_0000 | 0x19)
            == "PAGE_NOACCESS,PAGE_WRITECOPY,PAGE_EXECUTE,0x440000"
        )
