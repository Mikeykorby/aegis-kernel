@echo off
REM =============================================================================
REM sign.cmd — TEST-SIGN the Aegis kernel driver. No paid certificate needed.
REM
REM This creates a self-signed certificate and uses it to test-sign the .sys so
REM it loads on YOUR machine in Test Signing mode. (A Microsoft WHQL/HLK cert is
REM only required to load on locked-down, Secure-Boot customer PCs — that costs
REM money and is NOT part of this repo.)
REM
REM USAGE (run from "Developer Command Prompt for VS" with the WDK):
REM   1) bcdedit /set testsigning on      <-- once, then reboot
REM   2) sign.cmd  build\Release\aegis_kernel.sys
REM =============================================================================
setlocal
if "%1"=="" (
  echo Usage: sign.cmd ^<path-to-aegis_kernel.sys^>
  exit /b 1
)
set SYS=%1
set CERT=aegis_test
set PFX=aegis_test.pfx

REM Make a self-signed test cert (valid 10 years) in the local machine store.
certutil -f -p "" -sc "%CERT%" nofile >nul 2>&1
makecert -r -pe -ss My -n "CN=Aegis Test Signing" -eku 1.3.6.1.5.5.7.3.3 ^
  -cy end -a sha256 -sky signature -b 01/01/2026 -e 01/01/2036 ^
  "%CERT%.cer" >nul 2>&1 || goto :nocert
echo [+] Test certificate ready.

REM Sign the driver with the test cert (driver signing policy = 7, page hash on).
signtool sign /v /fd sha256 /s My /n "Aegis Test Signing" ^
  /t http://timestamp.digicert.com /ac "%CERT%.cer" "%SYS%" || goto :signfail
echo [+] Signed: %SYS%
echo.
echo Next:  copy "%SYS%" %%windir%%\system32\drivers\
echo         sc create aegis_kernel type= filesys binPath= "%%windir%%\system32\drivers\aegis_kernel.sys"
echo         sc start aegis_kernel
goto :done

:nocert
echo [!] makecert not available. Install the WDK / SDK "makecert" or use New-SelfSignedCertificate in PowerShell.
exit /b 1
:signfail
echo [!] Signing failed. Is the WDK's signtool on PATH?
exit /b 1
:done
endlocal
