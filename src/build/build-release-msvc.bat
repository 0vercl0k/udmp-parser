set ARCH=x64
if "%1"=="win32" set ARCH=Win32
cmake .. -A %ARCH%
cmake --build . --config RelWithDebInfo
