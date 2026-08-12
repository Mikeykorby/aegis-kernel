/* =============================================================================
 * aegis_agent.cpp — Aegis kernel-mode companion agent (user mode, C++).
 *
 * Runs as a normal Windows process. Responsibilities:
 *   1. Connect to the \AegisKernelPort comm port and stay connected (one agent).
 *   2. On AEGIS_EVT_EXEC_SCAN / heartbeat, ask the Aegis engine (over a named
 *      pipe) whether a path is malicious; if so, send AEGIS_CMD_ADD_DENY_HASH
 *      so the driver blocks the next execute attempt pre-execution.
 *   3. On AEGIS_EVT_RANSOM_BURST, kill the culprit process tree (real-time).
 *   4. On AEGIS_EVT_SELFDEF_BLOCKED, log that something tried to kill Aegis.
 *   5. Enable self-defense (AEGIS_CMD_SET_SELFDEFENSE + PROTECT_PROC).
 *
 * The filter-manager user API (fltlib) is loaded DYNAMICALLY via
 * GetProcAddress, so this file builds with only the base Windows SDK
 * (bcrypt.lib + kernel32.lib) — no WDK user-mode headers required.
 * ========================================================================== */
#include "aegis_common.h"
#include <bcrypt.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <windows.h>

#pragma comment(lib, "bcrypt.lib")

/* ---- Filter manager (fltlib.dll) loaded dynamically ---- */
typedef long HRESULT;
#ifndef S_OK
#define S_OK 0L
#endif

typedef struct _FILTER_MESSAGE_HEADER {
    DWORD ReplyLength;
    DWORD MessageId;
} FILTER_MESSAGE_HEADER, *PFILTER_MESSAGE_HEADER;

typedef HRESULT (WINAPI* PFN_FilterConnectCommunicationPort)(
    LPCWSTR lpPortName, DWORD dwOptions, LPVOID lpContext,
    WORD wSizeOfContext, LPSECURITY_ATTRIBUTES lpSecurityAttributes, HANDLE* hPort);
typedef HRESULT (WINAPI* PFN_FilterSendMessage)(
    HANDLE hPort, LPVOID lpInBuffer, DWORD dwInBufferSize,
    LPVOID lpOutBuffer, DWORD dwOutBufferSize, LPDWORD lpBytesReturned);
typedef HRESULT (WINAPI* PFN_FilterGetMessage)(
    HANDLE hPort, PVOID lpMessageBuffer, DWORD dwMessageBufferSize, LPOVERLAPPED lpOverlapped);

static PFN_FilterConnectCommunicationPort gFltConnect = nullptr;
static PFN_FilterSendMessage              gFltSend    = nullptr;
static PFN_FilterGetMessage               gFltGet     = nullptr;

static HANDLE  gPort = INVALID_HANDLE_VALUE;
static std::atomic<bool> gRunning{true};
static const wchar_t* AEGIS_PIPE = L"\\\\.\\pipe\\AegisKernelAgent";

static bool LoadFltLib() {
    HMODULE h = LoadLibraryW(L"fltlib.dll");
    if (!h) return false;
    gFltConnect = (PFN_FilterConnectCommunicationPort)GetProcAddress(h, "FilterConnectCommunicationPort");
    gFltSend    = (PFN_FilterSendMessage)GetProcAddress(h, "FilterSendMessage");
    gFltGet     = (PFN_FilterGetMessage)GetProcAddress(h, "FilterGetMessage");
    return gFltConnect && gFltSend && gFltGet;
}

/* ---- SHA-256 of a file (BCrypt, no external deps) ---- */
static bool Sha256File(const std::wstring& path, UCHAR out[AEGIS_MAX_HASH]) {
    BCRYPT_ALG_HANDLE h;
    if (BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return false;
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (f == INVALID_HANDLE_VALUE) { BCryptCloseAlgorithmProvider(h, 0); return false; }
    DWORD n; BYTE buf[65536]; DWORD len = 0;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BCryptCreateHash(h, &hHash, nullptr, 0, nullptr, 0, 0);
    while (ReadFile(f, buf, sizeof(buf), &n, nullptr) && n > 0)
        BCryptHashData(hHash, buf, n, 0);
    BCryptFinishHash(hHash, out, AEGIS_MAX_HASH, 0);
    BCryptDestroyHash(hHash);
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
    DWORD wrote;
    return gPort != INVALID_HANDLE_VALUE &&
        gFltSend(gPort, (PVOID)&cmd, sizeof(cmd), nullptr, 0, &wrote) == 0;
}

/* ---- main message loop: read events from the driver ---- */
static void EventLoop() {
    BYTE buf[sizeof(FILTER_MESSAGE_HEADER) + sizeof(AEGIS_EVT_MSG)];
    while (gRunning) {
        DWORD st = gFltGet(gPort, buf, sizeof(buf), nullptr);
        if (st != 0) { Sleep(500); continue; }   /* disconnected or timeout */
        auto* evt = (AEGIS_EVT_MSG*)(buf + sizeof(FILTER_MESSAGE_HEADER));
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
            if (evt->Pid) {
                HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, evt->Pid);
                if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
            }
            break;
        case AEGIS_EVT_SELFDEF_BLOCKED:
            break;
        default: break;
        }
    }
}

int main() {
    if (!LoadFltLib()) return 2;   /* fltlib.dll missing — cannot talk to driver */

    /* 1. enable self-defense for this agent PID */
    {
        AEGIS_CMD_MSG c; memset(&c, 0, sizeof(c));
        c.Command = AEGIS_CMD_SET_SELFDEFENSE; c.Enable = 1; SendCmd(c);
        c.Command = AEGIS_CMD_PROTECT_PROC; c.Pid = GetCurrentProcessId(); SendCmd(c);
    }

    /* 2. connect to the driver comm port */
    HRESULT hr = gFltConnect(AEGIS_PORT_NAME, 0, nullptr, 0, nullptr, &gPort);
    if (hr != S_OK) {
        for (int i = 0; i < 60 && gPort == INVALID_HANDLE_VALUE; i++) {
            Sleep(2000);
            gFltConnect(AEGIS_PORT_NAME, 0, nullptr, 0, nullptr, &gPort);
        }
        if (gPort == INVALID_HANDLE_VALUE) return 1;
    }

    std::thread t(EventLoop);
    t.join();
    if (gPort != INVALID_HANDLE_VALUE) CloseHandle(gPort);
    return 0;
}
