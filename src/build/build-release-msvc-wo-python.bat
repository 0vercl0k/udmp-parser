set ARCH=x64
if "%1"=="win32" set ARCH=Win32
cmake .. -A %ARCH% -DBUILD_PYTHON_BINDING=OFF
cmake --build . --config RelWithDebInfo
