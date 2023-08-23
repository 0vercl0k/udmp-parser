# udmp-parser: A Cross-Platform C++ parser library for Windows user minidumps

![Build status](https://github.com/0vercl0k/udmp-parser/workflows/Builds/badge.svg)
[![Downloads](https://static.pepy.tech/badge/udmp-parser/month)](https://pepy.tech/project/udmp-parser)

This is a cross-platform (Windows / Linux / OSX / x86 / x64) C++ library that parses Windows user [minidump](https://docs.microsoft.com/en-us/windows/win32/debug/minidump-files) dumps (`.dump /m` and **not** `.dump /f` in WinDbg usermode).

![parser](pics/parser.gif)

The library supports Intel 32-bit / 64-bit dumps and provides read access to things like:

- The thread list and their context records,
- The virtual memory,
- The loaded modules.

Compiled binaries are available in the [releases](https://github.com/0vercl0k/udmp-parser/releases) section.

## Parser

The `parser` application is a small utility to show-case how to use the library and demonstrate its features. You can use it to dump memory, list the loaded modules, dump thread contexts, dump a memory map various, etc.

![parser-usage](pics/parser-usage.gif)

Here are the options supported:
```
parser.exe [-a] [-mods] [-mem] [-t [<TID>|main] [-h] [-dump <addr>] <dump path>

Examples:
  Show all:
    parser.exe -a user.dmp
  Show loaded modules:
    parser.exe -mods user.dmp
  Show memory map:
    parser.exe -mem user.dmp
  Show all threads:
    parser.exe -t user.dmp
  Show thread w/ specific TID:
    parser.exe -t 1337 user.dmp
  Show foreground thread:
    parser.exe -t main user.dmp
  Show a memory page at a specific address:
    parser.exe -dump 0x7ff00 user.dmp
```

## Building

You can build it yourself using the appropriate build script for your platform in the [build](build/) directory. It builds on Linux, Windows, OSX with the [Microsoft](https://visualstudio.microsoft.com/vs/features/cplusplus/), the [LLVM Clang](https://clang.llvm.org/) and [GNU](https://gcc.gnu.org/) compilers.

Here is an example on Windows:

```
udmp-parser>cd src\build
udmp-parser\src\build>build-release.bat
udmp-parser\src\build>cmake .. -GNinja
-- The C compiler identification is MSVC 19.29.30139.0
-- The CXX compiler identification is MSVC 19.29.30139.0
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/VC/Tools/MSVC/14.29.30133/bin/Hostx64/x64/cl.exe - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/VC/Tools/MSVC/14.29.30133/bin/Hostx64/x64/cl.exe - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Configuring done
-- Generating done
-- Build files have been written to: C:/work/codes/udmp-parser/src/build
udmp-parser\src\build>cmake --build . --config RelWithDebInfo
[1/2] Building CXX object parser\CMakeFiles\parser.dir\parser.cc.obj
cl : Command line warning D9025 : overriding '/W3' with '/W4'
[2/2] Linking CXX executable parser\parser.exe
```

And here is another example on Linux:

```
~/udmp-parser$ cd src/build
~/udmp-parser/src/build$ chmod u+x build-release.sh
~/udmp-parser/src/build$ ./build-release.sh
-- The C compiler identification is GNU 9.3.0
-- The CXX compiler identification is GNU 9.3.0
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Detecting C compile features
-- Detecting C compile features - done
-- Check for working CXX compiler: /usr/bin/c++
-- Check for working CXX compiler: /usr/bin/c++ -- works
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Configuring done
-- Generating done
-- Build files have been written to: ~/udmp-parser/src/build
[2/2] Linking CXX executable parser/parser
```

## Python bindings

### From PyPI

The easiest way is simply to:

```
pip install udmp_parser
```

### Using PIP

To install the package
```
cd src/python
pip install .
```

To create a wheel pacakge
```
cd src/python
pip wheel .
```


### Usage

The Python API was built around the C++ code so the names were preserved. Everything lives within the module `udmp_parser`.
Note: For convenience, a simple [pure Python script](src/python/tests/utils.py) was added to generate minidumps ready to use:

```python
$ python -i src/python/tests/utils.py
>>> pid, dmppath = generate_minidump_from_process_name("winver.exe")
Minidump generated successfully: PID=3232 -> minidump-winver.exe-1687024880.dmp
>>> pid
3232
>>> dmppath
WindowsPath('minidump-winver.exe-1687024880.dmp'))
```

Parsing a minidump object is as simple as:

```python
>>> import udmp_parser
>>> udmp_parser.version.major, udmp_parser.version.minor, udmp_parser.version.release
(0, 4, '')
>>> dmp = udmp_parser.UserDumpParser()
>>> dmp.Parse(pathlib.Path("C:/temp/rundll32.dmp"))
True
```

Feature-wise, here are some examples of usage:

#### Threads

Get a hashmap of threads (as `{TID: ThreadObject}`), access their information:

```python
>>> threads = dmp.Threads()
>>> len(threads)
14
>>> threads
{5292: Thread(Id=0x14ac, SuspendCount=0x1, Teb=0x2e8000),
 5300: Thread(Id=0x14b4, SuspendCount=0x1, Teb=0x2e5000),
 5316: Thread(Id=0x14c4, SuspendCount=0x1, Teb=0x2df000),
 3136: Thread(Id=0xc40, SuspendCount=0x1, Teb=0x2ee000),
 4204: Thread(Id=0x106c, SuspendCount=0x1, Teb=0x309000),
 5328: Thread(Id=0x14d0, SuspendCount=0x1, Teb=0x2e2000),
 1952: Thread(Id=0x7a0, SuspendCount=0x1, Teb=0x2f7000),
 3888: Thread(Id=0xf30, SuspendCount=0x1, Teb=0x2eb000),
 1760: Thread(Id=0x6e0, SuspendCount=0x1, Teb=0x2f4000),
 792: Thread(Id=0x318, SuspendCount=0x1, Teb=0x300000),
 1972: Thread(Id=0x7b4, SuspendCount=0x1, Teb=0x2fa000),
 1228: Thread(Id=0x4cc, SuspendCount=0x1, Teb=0x2fd000),
 516: Thread(Id=0x204, SuspendCount=0x1, Teb=0x303000),
 2416: Thread(Id=0x970, SuspendCount=0x1, Teb=0x306000)}
```

And access invidual thread, including their register context:

```python
>>> thread = threads[5292]
>>> print(f"RIP={thread.Context.Rip:#x} RBP={thread.Context.Rbp:#x} RSP={thread.Context.Rsp:#x}")
RIP=0x7ffc264b0ad4 RBP=0x404fecc RSP=0x7de628
```


#### Modules

Get a hashmap of modules (as `{address: ModuleObject}`), access their information:

```python
>>> modules = dmp.Modules()
>>> modules
{1572864: Module_t(BaseOfImage=0x180000, SizeOfImage=0x3000, ModuleName=C:\Windows\SysWOW64\sfc.dll),
 10813440: Module_t(BaseOfImage=0xa50000, SizeOfImage=0x14000, ModuleName=C:\Windows\SysWOW64\rundll32.exe),
 1929052160: Module_t(BaseOfImage=0x72fb0000, SizeOfImage=0x11000, ModuleName=C:\Windows\SysWOW64\wkscli.dll),
 1929183232: Module_t(BaseOfImage=0x72fd0000, SizeOfImage=0x52000, ModuleName=C:\Windows\SysWOW64\mswsock.dll),
 1929576448: Module_t(BaseOfImage=0x73030000, SizeOfImage=0xf000, ModuleName=C:\Windows\SysWOW64\browcli.dll),
 1929641984: Module_t(BaseOfImage=0x73040000, SizeOfImage=0xa000, ModuleName=C:\Windows\SysWOW64\davhlpr.dll),
 1929707520: Module_t(BaseOfImage=0x73050000, SizeOfImage=0x19000, ModuleName=C:\Windows\SysWOW64\davclnt.dll),
 1929838592: Module_t(BaseOfImage=0x73070000, SizeOfImage=0x18000, ModuleName=C:\Windows\SysWOW64\ntlanman.dll),
 [...]
 140720922427392: Module_t(BaseOfImage=0x7ffc24980000, SizeOfImage=0x83000, ModuleName=C:\Windows\System32\wow64win.dll),
 140720923017216: Module_t(BaseOfImage=0x7ffc24a10000, SizeOfImage=0x59000, ModuleName=C:\Windows\System32\wow64.dll),
 140720950280192: Module_t(BaseOfImage=0x7ffc26410000, SizeOfImage=0x1f8000, ModuleName=C:\Windows\System32\ntdll.dll)}
```

Access directly module info:

```python
>>> ntdll_modules = [mod for addr, mod in dmp.Modules().items() if mod.ModuleName.lower().endswith("ntdll.dll")]
>>> len(ntdll_modules)
2
>>> for ntdll in ntdll_modules:
  print(f"{ntdll.ModuleName=} {ntdll.BaseOfImage=:#x} {ntdll.SizeOfImage=:#x}")

ntdll.ModuleName='C:\\Windows\\SysWOW64\\ntdll.dll' ntdll.BaseOfImage=0x77430000 ntdll.SizeOfImage=0x1a4000
ntdll.ModuleName='C:\\Windows\\System32\\ntdll.dll' ntdll.BaseOfImage=0x7ffc26410000 ntdll.SizeOfImage=0x1f8000
```

A convenience function under `udmp_parser.UserDumpParser.ReadMemory()` can be used to directly read memory from the dump. The signature of the function is as follow: `def ReadMemory(Address: int, Size: int) -> list[int]`. So to dump for instance the `wow64` module, it would go as follow:

```python
>>> wow64 = [mod for addr, mod in dmp.Modules().items() if mod.ModuleName.lower() == r"c:\windows\system32\wow64.dll"][0]
>>> print(str(wow64))
Module_t(BaseOfImage=0x7ffc24a10000, SizeOfImage=0x59000, ModuleName=C:\Windows\System32\wow64.dll)
>>> wow64_module = bytearray(dmp.ReadMemory(wow64.BaseOfImage, wow64.SizeOfImage))
>>> assert wow64_module[:2] == b'MZ'
>>> import hexdump
>>> hexdump.hexdump(wow64_module[:128])
00000000: 4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00  MZ..............
00000010: B8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  ........@.......
00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000030: 00 00 00 00 00 00 00 00  00 00 00 00 E8 00 00 00  ................
00000040: 0E 1F BA 0E 00 B4 09 CD  21 B8 01 4C CD 21 54 68  ........!..L.!Th
00000050: 69 73 20 70 72 6F 67 72  61 6D 20 63 61 6E 6E 6F  is program canno
00000060: 74 20 62 65 20 72 75 6E  20 69 6E 20 44 4F 53 20  t be run in DOS
00000070: 6D 6F 64 65 2E 0D 0D 0A  24 00 00 00 00 00 00 00  mode....$.......
```


#### Memory

The memory blocks can also be enumerated in a hashmap `{address: MemoryBlock}`.

```python
>>> memory = dmp.Memory()
>>> len(memory)
0x260
>>> memory
[...]
 0x7ffc26410000: [MemBlock_t(BaseAddress=0x7ffc26410000, AllocationBase=0x7ffc26410000, AllocationProtect=0x80, RegionSize=0x1000)],
 0x7ffc26411000: [MemBlock_t(BaseAddress=0x7ffc26411000, AllocationBase=0x7ffc26410000, AllocationProtect=0x80, RegionSize=0x11c000)],
 0x7ffc2652d000: [MemBlock_t(BaseAddress=0x7ffc2652d000, AllocationBase=0x7ffc26410000, AllocationProtect=0x80, RegionSize=0x49000)],
 0x7ffc26576000: [MemBlock_t(BaseAddress=0x7ffc26576000, AllocationBase=0x7ffc26410000, AllocationProtect=0x80, RegionSize=0x1000)],
 0x7ffc26577000: [MemBlock_t(BaseAddress=0x7ffc26577000, AllocationBase=0x7ffc26410000, AllocationProtect=0x80, RegionSize=0x2000)],
 0x7ffc26579000: [MemBlock_t(BaseAddress=0x7ffc26579000, AllocationBase=0x7ffc26410000, AllocationProtect=0x80, RegionSize=0x9000)],
 0x7ffc26582000: [MemBlock_t(BaseAddress=0x7ffc26582000, AllocationBase=0x7ffc26410000, AllocationProtect=0x80, RegionSize=0x86000)],
 0x7ffc26608000: [MemBlock_t(BaseAddress=0x7ffc26608000, AllocationBase=0x0, AllocationProtect=0x0, RegionSize=0x3d99e8000)]}
```

To facilitate the parsing in a human-friendly manner, some helper functions are provided:
 * `udmp_parser.utils.TypeToString`: convert the region type to its meaning (from MSDN)
 * `udmp_parser.utils.StateToString`: convert the region state to its meaning (from MSDN)
 * `udmp_parser.utils.ProtectionToString`: convert the region protection to its meaning (from MSDN)

This allows to search and filter in a more comprehensible way:


```python
# Collect only executable memory regions
>>> exec_regions = [region for _, region in dmp.Memory().items() if "PAGE_EXECUTE_READ" in udmp_parser.utils.ProtectionToString(region.Protect)]

# Pick any, disassemble code using capstone
>>> exec_region = exec_regions[-1]
>>> mem = dmp.ReadMemory(exec_region.BaseAddress, 0x100)
>>> for insn in cs.disasm(bytearray(mem), exec_region.BaseAddress):
  print(f"{insn=}")

insn=<CsInsn 0x7ffc26582000 [cc]: int3 >
insn=<CsInsn 0x7ffc26582001 [cc]: int3 >
insn=<CsInsn 0x7ffc26582002 [cc]: int3 >
insn=<CsInsn 0x7ffc26582003 [cc]: int3 >
insn=<CsInsn 0x7ffc26582004 [cc]: int3 >
insn=<CsInsn 0x7ffc26582005 [cc]: int3 >
insn=<CsInsn 0x7ffc26582006 [cc]: int3 >
insn=<CsInsn 0x7ffc26582007 [cc]: int3 >
insn=<CsInsn 0x7ffc26582008 [cc]: int3 >
insn=<CsInsn 0x7ffc26582009 [cc]: int3 >
insn=<CsInsn 0x7ffc2658200a [cc]: int3 >
insn=<CsInsn 0x7ffc2658200b [cc]: int3 >
insn=<CsInsn 0x7ffc2658200c [cc]: int3 >
insn=<CsInsn 0x7ffc2658200d [cc]: int3 >
insn=<CsInsn 0x7ffc2658200e [cc]: int3 >
insn=<CsInsn 0x7ffc2658200f [cc]: int3 >
insn=<CsInsn 0x7ffc26582010 [48895c2410]: mov qword ptr [rsp + 0x10], rbx>
insn=<CsInsn 0x7ffc26582015 [4889742418]: mov qword ptr [rsp + 0x18], rsi>
insn=<CsInsn 0x7ffc2658201a [57]: push rdi>
insn=<CsInsn 0x7ffc2658201b [4156]: push r14>
insn=<CsInsn 0x7ffc2658201d [4157]: push r15>
[...]
```

# Authors

* Axel '[@0vercl0k](https://twitter.com/0vercl0k)' Souchet

# Contributors

[ ![contributors-img](https://contrib.rocks/image?repo=0vercl0k/udmp-parser) ](https://github.com/0vercl0k/udmp-parser/graphs/contributors)
