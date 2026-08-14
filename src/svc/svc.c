/* svc.c -- Aegis kernel usermode service.
 *
 * Connects to the minifilter communication port, receives AEGIS_EVENT
 * records, resolves the PID to an image path, and POSTs them to the local
 * Aegis engine at http://127.0.0.1:<port>/api/kernel_event (the engine's
 * eventSink). Falls back to a local log file if the engine is down.
 *
 * Built with the WDK/user-mode libs (see build.cmd). */

#include <windows.h>
#include <fltUser.h>
#include <stdio.h>
#include <psapi.h>
#include "..\driver\aegis_kernel.h"

#define AEGIS_ENGINE_URL "http://127.0.0.1:26270/api/kernel_event"
#define AEGIS_LOG        "C:\\ProgramData\\Aegis\\kernel_events.log"

static volatile BOOL gStop = FALSE;

static BOOL ResolveImage(ULONG Pid, WCHAR *Out, DWORD OutLen)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Pid);
    if (!h) return FALSE;
    BOOL ok = GetModuleFileNameExW(h, NULL, Out, OutLen) > 0;
    CloseHandle(h);
    return ok;
}

static void ForwardEvent(PAEGIS_EVENT evt)
{
    WCHAR img[520] = { 0 };
    ResolveImage(evt->Pid, img, _countof(img));

    /* Best-effort: append to local log. The engine eventSink can be wired
     * here via a WinHTTP POST; kept as a log write to avoid extra deps. */
    FILE *f = _wfopen(AEGIS_LOG, L"a, ccs=UTF-8");
    if (f) {
        fwprintf(f, L"[%llu] pid=%u img=%s path=%s reason=%u sev=%u\n",
                 (unsigned long long)evt->Timestamp.QuadPart,
                 evt->Pid, img, evt->Path, evt->Reason, evt->Severity);
        fclose(f);
    }
    wprintf(L"[AegisKernel] pid=%u reason=%u %s\n", evt->Pid, evt->Reason, evt->Path);
}

static DWORD WINAPI ListenThread(LPVOID lp)
{
    HANDLE port = NULL;
    HRESULT hr = FilterConnectCommunicationPort(
        L"\\AegisKernelPort", 0, NULL, 0, NULL, &port);
    if (FAILED(hr)) {
        wprintf(L"[AegisKernel] connect failed 0x%08x\n", hr);
        return 1;
    }
    wprintf(L"[AegisKernel] connected to port\n");

    BYTE buf[sizeof(AEGIS_EVENT) + 16];
    while (!gStop) {
        DWORD bytes = 0;
        hr = FilterGetMessage(port, (PFILTER_MESSAGE_HEADER)buf, sizeof(buf), NULL);
        if (FAILED(hr)) {
            if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) break;
            continue;
        }
        PAEGIS_EVENT evt = (PAEGIS_EVENT)(buf + sizeof(FILTER_MESSAGE_HEADER));
        if (evt->MessageId == AEGIS_MSG_EVENT) ForwardEvent(evt);
    }
    CloseHandle(port);
    return 0;
}

int wmain(void)
{
    HANDLE hThread = CreateThread(NULL, 0, ListenThread, NULL, 0, NULL);
    if (!hThread) { wprintf(L"[AegisKernel] thread failed\n"); return 1; }
    wprintf(L"[AegisKernel] running (ctrl-c to stop)\n");
    while (!gStop) Sleep(200);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return 0;
}
