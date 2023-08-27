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


def generate_minidump(TargetPid: int, MiniDumpFilePath: os.PathLike) -> bool:
    """
    Generate a minidump for TargetPid and save it to the given path. Returns true on success.
    """
    ...


def generate_minidump_from_command_line() -> bool:
    """
    Generate a minidump for the target TargetPid, write it to the given path. Returns true on success.
    """
    ...
