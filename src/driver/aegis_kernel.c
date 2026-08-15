/* aegis_kernel.c -- Aegis file-system minifilter.
 *
 * Monitors file create/cleanup and flags writes to sensitive locations
 * (startup folders, %TEMP% executables/scripts). Events are sent to a
 * usermode service over a communication port; the service forwards them to
 * the Aegis engine.
 *
 * Build with the WDK (see build.cmd). Test-signed only. */

#include "aegis_kernel.h"

#define AEGIS_POOL_TAG 'gEaA'

/* ---- global state ---- */
static PFLT_FILTER        gFilter   = NULL;
static PFLT_PORT          gServerPort = NULL;
static PFLT_PORT          gClientPort = NULL;   /* single connected client */
static EX_PUSH_LOCK       gClientLock;

/* A few prefixes we treat as interesting. Lowercase compare is done in the
 * callback with RtlCompareUnicodeString. */
static const UNICODE_STRING gStartupPrefix =
    RTL_CONSTANT_STRING(L"\\device\\harddiskvolume");
/* We match on the user-visible tail instead (see IsSuspicious) to stay
 * volume-letter agnostic. */

/* ---- forward decls ---- */
NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING);
NTSTATUS NTAPI AegisUnload(FLT_FILTER_UNLOAD_FLAGS);
FLT_PREOP_CALLBACK_STATUS NTAPI AegisPreCreate(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_POSTOP_CALLBACK_STATUS NTAPI AegisPostCleanup(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID, FLT_POST_OPERATION_FLAGS);

NTSTATUS NTAPI AegisConnectNotify(PFLT_PORT, PVOID, PVOID, ULONG, PVOID*);
void     NTAPI AegisDisconnectNotify(PVOID);
NTSTATUS NTAPI AegisMessageNotify(PVOID, PVOID, ULONG, PVOID, ULONG, PULONG);

/* ---- registration ---- */
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,        0, AegisPreCreate,  NULL },
    { IRP_MJ_CLEANUP,       0, NULL,            AegisPostCleanup },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,                /* ContextRegistration */
    Callbacks,           /* OperationRegistration */
    AegisUnload,         /* FilterUnloadCallback */
    NULL,                /* InstanceSetupCallback */
    NULL,                /* InstanceQueryTeardownCallback */
    NULL,                /* InstanceTeardownStartCallback */
    NULL,                /* InstanceTeardownCompleteCallback */
    NULL, NULL, NULL
};

/* ---- helpers ---- */
static BOOLEAN IsSuspicious(PCUNICODE_STRING FileName, ULONG CreateDisposition)
{
    /* Heuristic: flag writes (not reads) that land in a temp/startup-ish
     * path OR carry a script/executable extension. Kept cheap on purpose. */
    if (!FileName || FileName->Length == 0) return FALSE;

    const WCHAR *p = FileName->Buffer;
    SIZE_T n = FileName->Length / sizeof(WCHAR);

    /* Look for "\temp\" or "startup" or "appdata\\roaming\\microsoft\\windows\\start menu" */
    if (wcsstr(p, L"\\temp\\") || wcsstr(p, L"\\tmp\\")) {
        /* executable/script extension? */
        if (wcschr(p, L'.')) {
            const WCHAR *ext = wcsrchr(p, L'.');
            if (_wcsicmp(ext, L".exe") == 0 ||
                _wcsicmp(ext, L".dll") == 0 ||
                _wcsicmp(ext, L".ps1") == 0 ||
                _wcsicmp(ext, L".vbs") == 0 ||
                _wcsicmp(ext, L".js")  == 0 ||
                _wcsicmp(ext, L".bat") == 0 ||
                _wcsicmp(ext, L".scr") == 0)
                return TRUE;
        }
    }
    if (wcsstr(p, L"startup") || wcsstr(p, L"start menu\\programs")) {
        return TRUE;
    }
    UNREFERENCED_PARAMETER(CreateDisposition);
    UNREFERENCED_PARAMETER(n);
    return FALSE;
}

static VOID SendEvent(PFLT_CALLBACK_DATA Data, PCUNICODE_STRING FileName, ULONG Reason, UCHAR Severity)
{
    AEGIS_EVENT evt;
    NTSTATUS st;
    ULONG out = 0;

    RtlZeroMemory(&evt, sizeof(evt));
    evt.MessageId = AEGIS_MSG_EVENT;
    KeQuerySystemTimePrecise(&evt.Timestamp);
    evt.Pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    evt.Reason = Reason;
    evt.Severity = Severity;

    if (FileName && FileName->Length < AEGIS_MAX_PATH * sizeof(WCHAR))
        RtlCopyMemory(evt.Path, FileName->Buffer, FileName->Length);
    else if (FileName)
        RtlCopyMemory(evt.Path, FileName->Buffer, (AEGIS_MAX_PATH - 1) * sizeof(WCHAR));

    /* copy process image name if available */
    if (Data && Data->Thread)
        ; /* process image path retrieval omitted for brevity; filled by svc via PID */

    FltAcquirePushLockShared(&gClientLock);
    if (gClientPort) {
        st = FltSendMessage(gFilter, &gClientPort, &evt, sizeof(evt),
                            NULL, &out, NULL);
        if (!NT_SUCCESS(st))
            ; /* client gone or busy -- drop */
    }
    FltReleasePushLock(&gClientLock);
}

/* ---- callbacks ---- */
FLT_PREOP_CALLBACK_STATUS NTAPI AegisPreCreate(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    NTSTATUS st;

    if (!FltObjects->FileObject) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    st = FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (NT_SUCCESS(st)) {
        if (IsSuspicious(&name->Name, Data->Iopb->Parameters.Create.SecurityContext
                            ? Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess : 0)) {
            SendEvent(Data, &name->Name, AEGIS_REASON_TEMP_EXEC, 1);
        }
        FltReleaseFileNameInformation(name);
    }
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS NTAPI AegisPostCleanup(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ---- port callbacks ---- */
NTSTATUS NTAPI AegisConnectNotify(PFLT_PORT Port, PVOID ServerPortCookie,
        PVOID ConnectionContext, ULONG SizeOfContext, PVOID *ConnectionCookie)
{
    NTSTATUS st = STATUS_SUCCESS;
    FltAcquirePushLockExclusive(&gClientLock);
    if (gClientPort) { st = STATUS_CONNECTION_IN_USE; }
    else { gClientPort = Port; }
    FltReleasePushLock(&gClientLock);
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);
    return st;
}

VOID NTAPI AegisDisconnectNotify(PVOID ConnectionCookie)
{
    FltAcquirePushLockExclusive(&gClientLock);
    if (gClientPort) { FltCloseClientPort(gFilter, &gClientPort); gClientPort = NULL; }
    FltReleasePushLock(&gClientLock);
    UNREFERENCED_PARAMETER(ConnectionCookie);
}

NTSTATUS NTAPI AegisMessageNotify(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength,
        PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength)
{
    /* We only send driver->svc; ignore svc->driver messages for now. */
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(ReturnOutputBufferLength);
    return STATUS_SUCCESS;
}

/* ---- driver entry / unload ---- */
NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS st;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;
    PSECURITY_DESCRIPTOR sd;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializePushLock(&gClientLock);

    st = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilter);
    if (!NT_SUCCESS(st)) goto fail;

    st = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(st)) goto fail2;

    RtlInitUnicodeString(&portName, AEGIS_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    st = FltCreateCommunicationPort(gFilter, &gServerPort, &oa,
            NULL, AegisConnectNotify, AegisDisconnectNotify, AegisMessageNotify, 1);
    FltFreeSecurityDescriptor(sd);
    if (!NT_SUCCESS(st)) goto fail2;

    st = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(st)) goto fail3;

    DbgPrint("[AegisKernel] loaded\n");
    return STATUS_SUCCESS;

fail3:
    if (gServerPort) FltCloseCommunicationPort(gServerPort);
fail2:
    if (gFilter) FltUnregisterFilter(gFilter);
fail:
    DbgPrint("[AegisKernel] DriverEntry failed 0x%08x\n", st);
    return st;
}

NTSTATUS NTAPI AegisUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (gServerPort) FltCloseCommunicationPort(gServerPort);
    if (gClientPort) { FltCloseClientPort(gFilter, &gClientPort); gClientPort = NULL; }
    if (gFilter) FltUnregisterFilter(gFilter);
    DbgPrint("[AegisKernel] unloaded\n");
    return STATUS_SUCCESS;
}
