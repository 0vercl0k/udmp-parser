import os
from typing import Union, Optional, overload
from enum import Enum, IntEnum
import udmp_parser


class ProcessorArch(IntEnum):
    X86 = 0
    ARM = 5
    IA64 = 6
    AMD64 = 9
    Unknown = 0xFFFF


class Arch(IntEnum):
    X86 = 0
    X64 = 1


kWOW64_SIZE_OF_80387_REGISTERS: int = 80


class FloatingSaveArea32:
    ControlWord: int
    StatusWord: int
    TagWord: int
    ErrorOffset: int
    ErrorSelector: int
    DataOffset: int
    DataSelector: int
    RegisterArea: bytearray  # size =kWOW64_SIZE_OF_80387_REGISTERS
    Cr0NpxState: int


class Context32:
    ContextFlags: int
    Dr0: int
    Dr1: int
    Dr2: int
    Dr3: int
    Dr6: int
    Dr7: int
    FloatSave: FloatingSaveArea32
    SegGs: int
    SegFs: int
    SegEs: int
    SegDs: int
    Edi: int
    Esi: int
    Ebx: int
    Edx: int
    Ecx: int
    Eax: int
    Ebp: int
    Eip: int
    SegCs: int
    EFlags: int
    Esp: int
    SegSs: int
    ExtendedRegisters: bytearray  # size =kWOW64_MAXIMUM_SUPPORTED_EXTENSION


class uint128_t:
    Low: int
    High: int


class Context64:
    P1Home: int
    P2Home: int
    P3Home: int
    P4Home: int
    P5Home: int
    P6Home: int
    ContextFlags: int
    MxCsr: int
    SegCs: int
    SegDs: int
    SegEs: int
    SegFs: int
    SegGs: int
    SegSs: int
    EFlags: int
    Dr0: int
    Dr1: int
    Dr2: int
    Dr3: int
    Dr6: int
    Dr7: int
    Rax: int
    Rcx: int
    Rdx: int
    Rbx: int
    Rsp: int
    Rbp: int
    Rsi: int
    Rdi: int
    R8: int
    R9: int
    R10: int
    R11: int
    R12: int
    R13: int
    R14: int
    R15: int
    Rip: int
    ControlWord: int
    StatusWord: int
    TagWord: int
    Reserved1: int
    ErrorOpcode: int
    ErrorOffset: int
    ErrorSelector: int
    Reserved2: int
    DataOffset: int
    DataSelector: int
    Reserved3: int
    MxCsr2: int
    MxCsr_Mask: int
    FloatRegisters: list[uint128_t]  # size =8
    Xmm0: uint128_t
    Xmm1: uint128_t
    Xmm2: uint128_t
    Xmm3: uint128_t
    Xmm4: uint128_t
    Xmm5: uint128_t
    Xmm6: uint128_t
    Xmm7: uint128_t
    Xmm8: uint128_t
    Xmm9: uint128_t
    Xmm10: uint128_t
    Xmm11: uint128_t
    Xmm12: uint128_t
    Xmm13: uint128_t
    Xmm14: uint128_t
    Xmm15: uint128_t
    Padding: bytearray  # size =0x60
    VectorRegister: list[uint128_t]  # size =26
    VectorControl: int
    DebugControl: int
    LastBranchToRip: int
    LastBranchFromRip: int
    LastExceptionToRip: int
    LastExceptionFromRip: int


class Directory:
    StreamType: StreamType = StreamType.Unused
    LocationDescriptor32_t: int


class FileMap:
    def InBounds(self, arg0: int, arg1: int, /) -> bool: ...
    def MapFile(self, arg: str, /) -> bool: ...
    def ViewBase(self) -> int: ...
    def __init__(self) -> None: ...


class FixedFileInfo:
    Signature: int = 0
    StrucVersion: int = 0
    FileVersionMS: int = 0
    FileVersionLS: int = 0
    ProductVersionMS: int = 0
    ProductVersionLS: int = 0
    FileFlagsMask: int = 0
    FileFlags: int = 0
    FileOS: int = 0
    FileType: int = 0
    FileSubtype: int = 0
    FileDateMS: int = 0
    FileDateLS: int = 0


class Header:
    Signature: int
    Version: int
    ImplementationVersion: int
    NumberOfStreams: int
    StreamDirectoryRva: int
    CheckSum: int
    Reserved: int
    TimeDateStamp: int
    Flags: int
    ExpectedSignature: int
    ValidFlagsMask: int

    def LooksGood(self) -> bool: ...

    def __init__(*args, **kwargs):
        """
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...


class LocationDescriptor32:
    DataSize: int
    Rva: int

    def __init__(*args, **kwargs):
        """
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...


class LocationDescriptor64:
    DataSize: int
    Rva: int

    def __init__(*args, **kwargs):
        """
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...


class MemBlock:
    BaseAddress: int
    AllocationBase: int
    AllocationProtect: int
    RegionSize: int
    State: int
    Protect: int
    Type: int
    Data: int
    DataSize: int

    def __init__(self, arg: udmp_parser.MemoryInfo, /) -> None: ...
    def __str__(self) -> str: ...


class Memory64ListStreamHdr:
    StartOfMemoryRange: int
    DataSize: int


class MemoryDescriptor:
    ThreadId: int
    SuspendCount: int
    PriorityClass: int
    Priority: int
    Teb: int
    Stack: MemoryDescriptor
    ThreadContext: LocationDescriptor32


class ThreadEntry:
    ThreadId: int
    SuspendCount: int
    PriorityClass: int
    Priority: int
    Teb: int
    Stack: MemoryDescriptor
    ThreadContext: LocationDescriptor32


class Thread_t:
    ThreadId: int
    SuspendCount: int
    PriorityClass: int
    Priority: int
    Teb: int
    Context: Union[UnknownContext, Context32, Context64]


class MemoryDescriptor64:
    StartOfMemoryRange: int
    DataSize: int


class MemoryInfoListStream:
    SizeOfHeader: int
    SizeOfEntry: int
    NumberOfEntries: int


class MemoryInfo:
    BaseAddress: int
    AllocationBase: int
    AllocationProtect: int
    __alignment1: int
    RegionSize: int
    State: int
    Protect: int
    Type: int
    __alignment2: int


class Module:
    BaseAddress: int
    AllocationBase: int
    AllocationProtect: int
    RegionSize: int
    State: int
    Protect: int
    Type: int
    DataSize: int

    @property
    def Data(self) -> int: ...
    def __str__(self) -> str: ...


class StreamType(IntEnum):
    Unused = 0
    ThreadList = 3
    ModuleList = 4
    Exception = 6
    SystemInfo = 7
    Memory64List = 9
    MemoryInfoList = 16


class SystemInfoStream:
    ProcessorArchitecture: ProcessorArch
    ProcessorLevel: int
    ProcessorRevision: int
    NumberOfProcessors: int
    ProductType: int
    MajorVersion: int
    MinorVersion: int
    BuildNumber: int
    PlatformId: int
    CSDVersionRva: int
    SuiteMask: int
    Reserved2: int


class ExceptionRecord:
    ExceptionCode: int
    ExceptionFlags: int
    ExceptionRecord: int
    ExceptionAddress: int
    NumberParameters: int
    __unusedAlignment: int
    ExceptionInformation: list[int]  # size=kEXCEPTION_MAXIMUM_PARAMETERS


class ExceptionStream:
    ThreadId: int
    __alignment: int
    ExceptionRecord: ExceptionRecord
    ThreadContext: LocationDescriptor32


class UnknownContext:
    def __init__(*args, **kwargs):
        """
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...


class UserDumpParser:
    def ForegroundThreadId(self) -> Optional[int]: ...

    def GetMemoryBlock(self, arg: int, /) -> udmp_parser.MemBlock:
        """
        Access a specific MemoryBlock
        """
        ...

    def Memory(self) -> dict[int, udmp_parser.MemBlock]: ...

    def Modules(self) -> dict[int, udmp_parser.Modules]:
        """
        Get the minidump modules
        """
        ...

    def Parse(self, arg: os.PathLike, /) -> bool:
        """
        Parse the minidump given in argument.
        """
        ...

    def ReadMemory(self, arg0: int, arg1: int, /) -> Optional[list[int]]:
        """
        Read bytes from memory
        """
        ...

    def Threads(self) -> dict[int, udmp_parser.Thread]:
        """
        Get the minidump threads
        """
        ...

    def __init__(self) -> None: ...


class version:
    def __init__(*args, **kwargs):
        """
        Initialize self.  See help(type(self)) for accurate signature.
        """
        ...
    major: int

    minor: int

    release: str
