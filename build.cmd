@echo off
rem build.cmd -- build aegis_kernel.sys + aegis_kernel_svc.exe
rem Run from a "Developer Command Prompt for VS" (WDK props on PATH).
setlocal
set ROOT=%~dp0
set OUT=%ROOT%build
if not exist "%OUT%" mkdir "%OUT%"

echo [*] Building minifilter (kmdf/umdf: kernel mode)...
msbuild "%ROOT%src\driver\aegis_kernel.vcxproj" /p:Configuration=Release /p:Platform=x64 /p:OutDir="%OUT%\"
if errorlevel 1 goto :fail

echo [*] Building usermode service...
msbuild "%ROOT%src\svc\svc.vcxproj" /p:Configuration=Release /p:Platform=x64 /p:OutDir="%OUT%\"
if errorlevel 1 goto :fail

echo [+] Done. Outputs in %OUT%
dir "%OUT%\aegis_kernel.sys" "%OUT%\aegis_kernel_svc.exe"
goto :eof

:fail
echo [!] Build failed.
exit /b 1
