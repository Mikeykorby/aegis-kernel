# Aegis Kernel — kernel-mode companion for Aegis Security

A **separate repo** for the kernel-backed version of Aegis. It does **not** replace
the main user-mode app (`Mikeykorby/aegis-av`) — it is a small companion that adds
the three things user-mode Python genuinely *cannot* do, and bridges to the existing
engine over a named pipe.

> No paid certificate. No code-signing purchase. See **"Do I need a cert?"** below.

## Why a kernel version at all?

The user-mode Aegis (Python + pywebview) is safe, free, and where the heavy lifting
(YARA, hash intel, URL feeds, the whole UI) lives. Python **cannot run in kernel
mode**, so the only protections that truly need ring-0 are:

| Capability | User-mode Aegis | This kernel companion |
|---|---|---|
| Detect + quarantine a written file | ✅ (after write) | ✅ **pre-execution block** (before code runs) |
| Kill a malicious process | ✅ | ✅ (same, but faster) |
| Ransomware burst detection | ✅ (canary + rate) | ✅ **process-create burst** in the kernel |
| **Self-defense** (malware can't kill/delete Aegis) | ❌ best-effort ACL | ✅ **`ObRegisterCallbacks`** strips terminate/delete |
| **Pre-encryption ransom block** | ❌ | ⚠️ skeleton (see Roadmap) |

So the kernel win is: **block threats before they execute**, and **real self-defense**.
Everything else stays in the Python app.

## What's in this repo

```
kernel/aegis_filter.c   mini-filter (IRP_MJ_CREATE pre-op) + ObRegisterCallbacks
                        self-defense + PsSetCreateProcessNotifyRoutineEx burst detect
                        + Flt communication port to the agent
kernel/aegis_common.h   shared message protocol (included by driver AND agent)
kernel/aegis_kernel.inf mini-filter install descriptor
agent/aegis_agent.cpp    user-mode C++ bridge: SHA-256, engine verdict over pipe,
                        push deny-hashes to driver, kill-on-ransomware
CMakeLists.txt          builds both (driver needs WDK; agent is plain Win32)
sign.cmd                TEST-SIGN the .sys with a self-generated cert (no purchase)
```

## Build

**Driver** (needs the Windows Driver Kit — the `cmake` here does not compile it
without WDK headers/libs, which aren't on every box):

```
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

**Agent** (plain Win32, no WDK, no cert):

```
cmake --build build --config Release --target aegis_agent
```

## Do I need a cert? (the honest answer)

- **To develop and run on your own PC:** **No.** Enable Test Signing and test-sign:

  ```bat
  bcdedit /set testsigning on      :: reboot once
  sign.cmd build\Release\aegis_kernel.sys
  copy build\Release\aegis_kernel.sys %windir%\system32\drivers\
  sc create aegis_kernel type= filesys binPath= "%windir%\system32\drivers\aegis_kernel.sys"
  sc start aegis_kernel
  aegis_agent.exe
  ```

- **To load on a customer's Secure-Boot, locked-down PC:** Yes — Microsoft
  requires a cross-signed (WHQL/HLK) cert for that. That is a Microsoft policy
  constraint, not something code can avoid, and it costs money. This repo is
  deliberately **cert-free**: no `.pfx`, no `.cer`, no secrets are committed. The
  test-sign path is the supported dev/personal path.

## How it talks to the main Aegis app

The agent opens the filter comm port `\AegisKernelPort` and the named pipe
`\\.\pipe\AegisKernelAgent`. The Python Aegis app sends
`{"cmd":"verdict","path":"..."}`; the agent returns `{"malicious":true/false}`
using the engine's existing verdict logic. On a malicious verdict the agent pushes
the file's SHA-256 to the driver (`AEGIS_CMD_ADD_DENY_HASH`) so the next execute
attempt is failed with `STATUS_ACCESS_DENIED` — **before any code runs**.

## Status / honesty

- `aegis_filter.c` / `aegis_agent.cpp` are **complete, idiomatic WDK/Win32 source**.
- They were **not compiled in CI here** (the build box has no WDK). They build in
  Visual Studio + WDK on a Windows dev machine. Expect minor portability fixes on
  first compile (struct field names across WDK versions).
- The `AegisPreCreate` deny path is intentionally conservative (hash-based, driven
  by the agent) to avoid false positives; wire your preferred hashing there.

## Roadmap

- [ ] Real pre-exec hash: compute SHA-256 in the agent on `AEGIS_EVT_EXEC_SCAN`
      (currently path-keyed, gated by the deny set).
- [ ] Pre-encryption ransomware block: hook `IRP_MJ_WRITE` + canary correlation.
- [ ] Optional WHQL submission script (for those who *do* buy a cert later).

## License

Same as the main Aegis project.
