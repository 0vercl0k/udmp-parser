set ARCH=x64
if %1 == "x86" set ARCH=Win32
cmake .. -GNinja -A %ARCH%
cmake --build . --config RelWithDebInfo
