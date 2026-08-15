@echo off
REM ============================================================
REM  Aegis kernel build  (driver .sys + user-mode service .exe)
REM  VS2022 BuildTools + standalone WDK 10.0.28000.0
REM ============================================================
setlocal ENABLEEXTENSIONS
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "OUT=%ROOT%\build"

set "WDK=C:\Program Files (x86)\Windows Kits\10"
set "WDKVER=10.0.28000.0"
set "VS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
set "TOOLS=%VS%\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64"
set "VCINC=%VS%\VC\Tools\MSVC\14.44.35207\include"
set "VCLIB=%VS%\VC\Tools\MSVC\14.44.35207\lib\x64"

if not exist "%OUT%" mkdir "%OUT%"

REM ---------------- minifilter driver (.sys) ----------------
REM Compile AGAINST the WDK first, falling back to the SDK shared tree
REM for base headers (ntdef/ntstatus) that the WDK no longer ships.
set "SDK=C:\Program Files (x86)\Windows Kits\10"
set "SDKV=10.0.26100.0"
set "INCLUDE=%WDK%\Include\%WDKVER%\km;%WDK%\Include\%WDKVER%\shared;%SDK%\Include\%SDKV%\shared;%SDK%\Include\%SDKV%\ucrt;%VCINC%"
set "LIB=%WDK%\Lib\%WDKVER%\km\x64;%VCLIB%"

echo [*] Compiling aegis_kernel.c (kernel mode, WDK %WDKVER% + SDK %SDKV% shared, x64)...
"%TOOLS%\cl.exe" /nologo /c /GS- /kernel /W3 /Zl /Oy- ^
  /I"%WDK%\Include\%WDKVER%\km" ^
  /I"%WDK%\Include\%WDKVER%\shared" ^
  /I"%SDK%\Include\%SDKV%\shared" ^
  /I"%SDK%\Include\%SDKV%\ucrt" ^
  /I"%VCINC%" ^
  /I"%ROOT%\src" ^
  /D_AMD64_=1 /D_WIN64 /DSTD_CALL ^
  /Fo"%OUT%\aegis_kernel.obj" ^
  "%ROOT%\src\driver\aegis_kernel.c"
if errorlevel 1 goto :fail

echo [*] Linking aegis_kernel.sys (native /DRIVER, no manifest)...
"%TOOLS%\link.exe" /nologo /DRIVER /INTEGRITYCHECK /SUBSYSTEM:NATIVE ^
  /MACHINE:X64 /NODEFAULTLIB /ENTRY:DriverEntry ^
  /OUT:"%OUT%\aegis_kernel.sys" ^
  "%OUT%\aegis_kernel.obj" ^
  "%WDK%\Lib\%WDKVER%\km\x64\fltMgr.lib" ^
  "%WDK%\Lib\%WDKVER%\km\x64\ntoskrnl.lib" ^
  "%WDK%\Lib\%WDKVER%\km\x64\BufferOverflowK.lib"
if errorlevel 1 goto :fail

REM ---------------- usermode service (.exe) ----------------
REM Built directly with cl/link: SDK + WDK user-mode (um) includes.
echo [*] Compiling aegis_kernel_svc.c (user mode, x64)...
"%TOOLS%\cl.exe" /nologo /c /O2 /W3 /GS- /D_WIN64 /D_AMD64_=1 ^
  /I"%SDK%\Include\%SDKV%\um" ^
  /I"%SDK%\Include\%SDKV%\shared" ^
  /I"%SDK%\Include\%SDKV%\ucrt" ^
  /I"%WDK%\Include\%WDKVER%\um" ^
  /I"%WDK%\Include\%WDKVER%\shared" ^
  /I"%VCINC%" ^
  /I"%ROOT%\src" ^
  /Fo"%OUT%\aegis_kernel_svc.obj" ^
  "%ROOT%\src\svc\svc.c"
if errorlevel 1 goto :fail

echo [*] Linking aegis_kernel_svc.exe ...
"%TOOLS%\link.exe" /nologo /SUBSYSTEM:CONSOLE /MACHINE:X64 ^
  /OUT:"%OUT%\aegis_kernel_svc.exe" ^
  "%OUT%\aegis_kernel_svc.obj" ^
  fltLib.lib psapi.lib user32.lib advapi32.lib ws2_32.lib shell32.lib ^
  /LIBPATH:"%SDK%\Lib\%SDKV%\um\x64" ^
  /LIBPATH:"%SDK%\Lib\%SDKV%\ucrt\x64" ^
  /LIBPATH:"%WDK%\Lib\%WDKVER%\um\x64"
if errorlevel 1 goto :fail

REM ---------------- verify ----------------
echo.
echo [*] Artifacts:
if exist "%OUT%\aegis_kernel.sys" echo     OK  build\aegis_kernel.sys
if exist "%OUT%\aegis_kernel_svc.exe" echo     OK  build\aegis_kernel_svc.exe
goto :eof

:fail
echo [!] Build failed.
exit /b 1
