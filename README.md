# udmp-parser: A Windows user minidump C++ parser library.

![Build status](https://github.com/0vercl0k/udmp-parser/workflows/Builds/badge.svg)

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

# Authors

* Axel '[@0vercl0k](https://twitter.com/0vercl0k)' Souchet
