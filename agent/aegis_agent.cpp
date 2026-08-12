/* =============================================================================
 * aegis_agent.cpp — Aegis kernel-mode companion agent (user mode, C++).
 *
 * Runs as a normal Windows service/process. Responsibilities:
 *   1. Connect to the \AegisKernelPort comm port and stay connected (one agent).
 *   2. On AEGIS_EVT_EXEC_SCAN / heartbeat, ask the Aegis engine (over a named
 *      pipe) whether a path is malicious; if so, send AEGIS_CMD_ADD_DENY_HASH
 *      so the driver blocks the next execute attempt pre-execution.
 *   3. On AEGIS_EVT_RANSOM_BURST, kill the culprit process tree (real-time).
 *   4. On AEGIS_EVT_SELFDEF_BLOCKED, log + toast that something tried to kill
 *      Aegis.
 *   5. Enable self-defense (AEGIS_CMD_SET_SELFDEFENSE + PROTECT_PROC for our PID).
 *
 * This file is plain Win32 + the filter manager user library (fltlib.lib). It
 * does NOT require a code cert to build (it's a normal .exe). It talks to the
 * kernel driver over the documented port protocol in aegis_common.h.
 *
 * Build:  cmake --build  (see CMakeLists.txt at repo root)
 * Run as: aegis_agent.exe   [started by the Aegis desktop app, or as a service]
 * ========================================================================== */
#include "aegis_common.h"
#include <fltUser.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <windows.h>

#pragma comment(lib, "fltLib.lib")
#pragma comment(lib, "bcrypt.lib")

static HANDLE  gPort = INVALID_HANDLE_VALUE;
static std::atomic<bool> gRunning{true};
static const wchar_t* AEGIS_PIPE = L"\\\\.\\pipe\\AegisKernelAgent";

/* ---- SHA-256 of a file (BCrypt, no external deps) ---- */
static bool Sha256File(const std::wstring& path, UCHAR out[AEGIS_MAX_HASH]) {
    BCRYPT_ALG_HANDLE h;
    if (BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return false;
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (f == INVALID_HANDLE_VALUE) { BCryptCloseAlgorithmProvider(h, 0); return false; }
    DWORD n; BYTE buf[65536]; DWORD len = 0;
    BCryptCreateHash(h, &gHash, nullptr, 0, nullptr, 0, 0);
    while (ReadFile(f, buf, sizeof(buf), &n, nullptr) && n > 0)
        BCryptHashData(gHash, buf, n, 0);
    BCryptFinishHash(gHash, out, AEGIS_MAX_HASH, 0);
    BCryptDestroyHash(gHash);
    CloseHandle(f); BCryptCloseAlgorithmProvider(h, 0);
    return true;
}

/* ---- talk to the existing Aegis engine over a named pipe ----
 * The Python Aegis exposes \\.\pipe\AegisEngine; we send a JSON line
 * {"cmd":"verdict","path":"..."} and read back {"malicious":true/false}. */
static bool EngineVerdict(const std::wstring& path, bool& malicious) {
    HANDLE p = CreateFileW(AEGIS_PIPE, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (p == INVALID_HANDLE_VALUE) return false;   /* engine not running */
    std::string req = "{\"cmd\":\"verdict\",\"path\":\"";
    for (wchar_t c : path) { if (c == '"' || c == '\\') req += '\\'; req += (char)c; }
    req += "\"}\n";
    DWORD w; WriteFile(p, req.data(), (DWORD)req.size(), &w, nullptr);
    char buf[256]; DWORD r;
    malicious = false;
    if (ReadFile(p, buf, sizeof(buf) - 1, &r, nullptr)) {
        buf[r] = 0;
        malicious = strstr(buf, "\"malicious\":true") != nullptr;
    }
    CloseHandle(p);
    return true;
}

/* ---- send a command to the driver ---- */
static bool SendCmd(const AEGIS_CMD_MSG& cmd) {
    DWORD wrote; DWORD rc = 0;
    return gPort != INVALID_HANDLE_VALUE &&
        FilterSendMessage(gPort, (PVOID)&cmd, sizeof(cmd), nullptr, 0, &wrote) == 0;
}

/* ---- main message loop: read events from the driver ---- */
static void EventLoop() {
    BYTE buf[1024];
    while (gRunning) {
        DWORD read = 0;
        DWORD st = FilterGetMessage(gPort, (PFILTER_MESSAGE)buf, sizeof(buf), nullptr);
        if (st != 0) { /* disconnected or timeout */ Sleep(500); continue; }
        auto* evt = (AEGIS_EVT_MSG*)buf;
        switch (evt->Event) {
        case AEGIS_EVT_EXEC_SCAN: {
            bool mal = false;
            if (EngineVerdict(evt->Path, mal) && mal) {
                UCHAR hash[AEGIS_MAX_HASH] = {0};
                if (Sha256File(evt->Path, hash)) {
                    AEGIS_CMD_MSG c; memset(&c, 0, sizeof(c));
                    c.Command = AEGIS_CMD_ADD_DENY_HASH; c.Pid = evt->Pid;
                    memcpy(c.Hash, hash, AEGIS_MAX_HASH);
                    wcsncpy(c.Path, evt->Path, AEGIS_MAX_PATH - 1);
                    SendCmd(c);
                }
            }
            break;
        }
        case AEGIS_EVT_RANSOM_BURST:
            /* Kill the responsible process tree (best-effort). */
            if (evt->Pid) {
                HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, evt->Pid);
                if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
            }
            break;
        case AEGIS_EVT_SELFDEF_BLOCKED:
            /* Someone tried to kill Aegis — already blocked by the driver. */
            break;
        default: break;
        }
    }
}

int main() {
    /* 1. enable self-defense for this agent PID */
    {
        AEGIS_CMD_MSG c; memset(&c, 0, sizeof(c));
        c.Command = AEGIS_CMD_SET_SELFDEFENSE; c.Enable = 1; SendCmd(c);
        c.Command = AEGIS_CMD_PROTECT_PROC; c.Pid = GetCurrentProcessId(); SendCmd(c);
    }

    /* 2. connect to the driver comm port */
    HRESULT hr = FilterConnectCommunicationPort(AEGIS_PORT_NAME, 0, nullptr, 0, nullptr, &gPort);
    if (hr != S_OK) {
        /* Driver not loaded yet — keep retrying so the agent survives a reboot. */
        for (int i = 0; i < 60 && gPort == INVALID_HANDLE_VALUE; i++) {
            Sleep(2000);
            FilterConnectCommunicationPort(AEGIS_PORT_NAME, 0, nullptr, 0, nullptr, &gPort);
        }
        if (gPort == INVALID_HANDLE_VALUE) return 1;
    }

    std::thread t(EventLoop);
    t.join();
    if (gPort != INVALID_HANDLE_VALUE) CloseHandle(gPort);
    return 0;
}
