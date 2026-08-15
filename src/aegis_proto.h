/* aegis_proto.h -- shared protocol between the minifilter (kernel) and the
 * usermode service. NO kernel headers here so it compiles in user mode too.
 * Keep the message layout identical to src/driver/aegis_kernel.h. */
#ifndef AEGIS_PROTO_H
#define AEGIS_PROTO_H

/* Communication port name (FltCreateCommunicationPort / FilterConnect...). */
#define AEGIS_PORT_NAME          L"\\AegisKernelPort"

/* IOCTL / message types exchanged over the port. */
#define AEGIS_MSG_EVENT          0x1001   /* driver -> svc event */
#define AEGIS_MSG_ACK            0x1002   /* svc -> driver ack     */

#define AEGIS_MAX_PATH           520

#pragma warning(push)
#pragma warning(disable:4200)
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

#define AEGIS_REASON_NONE         0
#define AEGIS_REASON_STARTUP_WRITE 1
#define AEGIS_REASON_TEMP_EXEC     2
#define AEGIS_REASON_SUSPICIOUS_EXT 3

#endif /* AEGIS_PROTO_H */
