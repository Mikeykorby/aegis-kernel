/* aegis_kernel.h -- shared definitions between the minifilter and the
 * usermode service. Keep this header IDENTICAL in both src/driver and
 * src/svc so the IOCTL codes and port name match. */
#ifndef AEGIS_KERNEL_H
#define AEGIS_KERNEL_H

#include <fltKernel.h>

/* Communication port name (used by FltCreateCommunicationPort and the
 * usermode FilterConnectCommunicationPort). */
#define AEGIS_PORT_NAME          L"\\AegisKernelPort"

/* IOCTL / message types exchanged over the port. */
#define AEGIS_MSG_EVENT          0x1001   /* driver -> svc event */
#define AEGIS_MSG_ACK            0x1002   /* svc -> driver ack     */

/* Max path we are willing to copy into an event record. */
#define AEGIS_MAX_PATH           520

/* An event the driver sends to usermode. */
#pragma warning(push)
#pragma warning(disable:4200) /* zero-length array is intentional */
typedef struct _AEGIS_EVENT {
    ULONG MessageId;                 /* AEGIS_MSG_EVENT */
    LARGE_INTEGER Timestamp;         /* kernel ticks */
    ULONG  Pid;                      /* originating process id */
    WCHAR  ProcessImage[AEGIS_MAX_PATH];
    WCHAR  Path[AEGIS_MAX_PATH];     /* file path involved */
    ULONG  Reason;                   /* see AEGIS_REASON_* */
    UCHAR  Severity;                 /* 0=info 1=warn 2=alert */
    UCHAR  _pad[3];
} AEGIS_EVENT, *PAEGIS_EVENT;
#pragma warning(pop)

/* Why the driver flagged a path. */
#define AEGIS_REASON_NONE         0
#define AEGIS_REASON_STARTUP_WRITE 1   /* write under a startup/run location */
#define AEGIS_REASON_TEMP_EXEC     2   /* executable/script written to %TEMP% */
#define AEGIS_REASON_SUSPICIOUS_EXT 3  /* double-extension / script-in-temp   */

#endif /* AEGIS_KERNEL_H */
