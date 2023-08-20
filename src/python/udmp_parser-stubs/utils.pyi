import os

def ProtectionToString(arg: int, /) -> str:
    """
    Get a string representation of the memory protection
    """
    ...

def StateToString(arg: int, /) -> str:
    """
    Get a string representation of the memory state
    """
    ...

def TypeToString(arg: int, /) -> str:
    """
    Get a string representation of the memory type
    """
    ...

def generate_minidump(TargetPid: int, MiniDumpFilePath: os.PathLike) -> int:
    """
    Generate a minidump for the target ProcessId, write it to the given path. Returns 0 on success, non-zero on error.
    """
    ...

def generate_minidump_from_command_line() -> int:
    """
    Generate a minidump for the target ProcessId, write it to the given path. Returns 0 on success, non-zero on error.
    """
    ...
