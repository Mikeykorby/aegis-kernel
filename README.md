# Aegis Kernel Driver (aegis_kernel.sys)

Kernel-mode companion for **Aegis AV**. Provides:

- A **file system minifilter** (`aegis_kernel.sys`) that monitors file
  create/cleanup/close and reports suspicious paths (script/executable writes
  to startup / temp / User directories) to a usermode agent over a
  communication port.
- A tiny **usermode service** (`aegis_kernel_svc.exe`) that connects to the
  port, receives events, and forwards them to the Aegis engine over the
  existing local API.

The Aegis desktop app probes for this driver via `engine/kernel_probe.py`
(`driver_present`). Until this project is built and the `.sys` is dropped into
the app's `driver/` folder, the Kernel page reports `driver_present = false`
and only offers "Enable Test Signing" (no auto-install).

## Requirements (build machine)
- Windows 10+ x64
- Visual Studio 2022 (Desktop development with C++)
- Windows Driver Kit (WDK) 10/11
- Run **from a "Developer Command Prompt for VS"** so `msbuild` + WDK props are on PATH.

## Build
```
build.cmd            # builds both the minifilter .sys and the usermode svc
```
Outputs:
- `build/aegis_kernel.sys`
- `build/aegis_kernel.inf`
- `build/aegis_kernel_svc.exe`

## Install (test machine, admin + test signing on)
```
bcdedit /set testsigning on   # reboot
sc create aegis_kernel type= kernel binPath= C:\path\to\aegis_kernel.sys
sc start aegis_kernel
aegis_kernel_svc.exe          # usermode listener
```
The Aegis app's Kernel page "Enable Test Signing" button automates the
`bcdedit` step; the service install is handled by the app's updater once a
signed `.sys` ships.

## Test-signing note
The `.sys` produced here is **test-signed** and will only load with test
signing enabled (or on a machine enrolled in WHQL/Attestation signing). For a
production build, submit through Windows Hardware Compatibility Program (WHCP)
to get a Microsoft-cross-signed / Attestation-signed binary that loads with
Secure Boot on.

## Source layout
```
src/
  driver/
    aegis_kernel.c        minifilter entry + callbacks
    aegis_kernel.h        shared struct/IOCTL/port definitions
    aegis_kernel.inf      installer
  svc/
    svc.c                 usermode listener -> Aegis engine
```
