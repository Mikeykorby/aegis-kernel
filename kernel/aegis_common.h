/* =============================================================================
 * aegis-kernel — shared definitions between the kernel driver and the agent.
 *
 * This header is included by BOTH:
 *   - kernel/aegis_filter.c  (the mini-filter + object-callback driver)
 *   - agent/aegis_agent.cpp  (the user-mode C++ bridge)
 *
 * It defines the communication-port message protocol. Keep it in sync with
 * both sides. No kernel-only types live here so the agent can include it.
 *
 * BUILD / SIGNING NOTE (read this):
 *   The driver (.sys) cannot load on a Secure-Boot PC without a Microsoft
 *   cross-signed (WHQL/HLK) certificate. That cert costs money and is NOT
 *   required to develop or to run this driver on your own machine:
 *     - enable Test Signing:   bcdedit /set testsigning on   (needs reboot)
 *     - the build script test-signs the .sys with a self-generated cert
 *   On a locked-down customer PC you WOULD need the paid cert. That is a
 *   Microsoft policy constraint, not something code can avoid.
 * ========================================================================== */
#ifndef AEGIS_COMMON_H
#define AEGIS_COMMON_H

#ifdef _KERNEL_MODE
#include <fltKernel.h>
#include <wdm.h>
#else
#include <windows.h>
#include <stdint.h>
#endif

/* Friendly name of the filter + the comm-port endpoint. */
#define AEGIS_FILTER_NAME      L"aegis-kernel"
#define AEGIS_PORT_NAME         L"\\AegisKernelPort"

/* Max bytes of a file path we ferry to user mode for a pre-exec decision. */
#define AEGIS_MAX_PATH         520
#define AEGIS_MAX_HASH         32   /* SHA-256 = 32 bytes */

/* ---- Message types sent AGENT -> DRIVER (commands) ---- */
enum AEGIS_CMD {
    AEGIS_CMD_ADD_DENY_HASH = 1,   /* deny execution of a file with this SHA-256 */
    AEGIS_CMD_CLEAR_DENY,         /* clear the deny set */
    AEGIS_CMD_SET_SELFDEFENSE,     /* enable/disable self-defense for a process */
    AEGIS_CMD_PROTECT_PROC,        /* protect a PID from termination/deletion */
    AEGIS_CMD_UNPROTECT_PROC,
    AEGIS_CMD_QUERY_VERSION
};

/* ---- Message types sent DRIVER -> AGENT (events) ---- */
enum AEGIS_EVT {
    AEGIS_EVT_EXEC_BLOCKED = 1,    /* a pre-exec deny fired */
    AEGIS_EVT_EXEC_SCAN,           /* a pre-exec open needs a verdict (agent scans) */
    AEGIS_EVT_RANSOM_BURST,        /* process-creation burst detected */
    AEGIS_EVT_SELFDEF_BLOCKED,     /* someone tried to kill/delete the protected proc */
    AEGIS_EVT_HEARTBEAT
};

#ifdef _KERNEL_MODE
/* Kernel-side message wrappers use FltSendMessage; the body is one of these. */
#pragma warning(disable:4200)  /* allow flexible array member */
#endif

/* Command envelope (agent -> driver). */
typedef struct _AEGIS_CMD_MSG {
    ULONG  Command;                       /* AEGIS_CMD */
    ULONG  Pid;                           /* relevant process id */
    UCHAR  Hash[AEGIS_MAX_HASH];          /* for ADD_DENY_HASH */
    WCHAR  Path[AEGIS_MAX_PATH];          /* optional context path */
    ULONG  Enable;                        /* 0/1 for toggle commands */
} AEGIS_CMD_MSG, *PAEGIS_CMD_MSG;

/* Event envelope (driver -> agent). */
typedef struct _AEGIS_EVT_MSG {
    ULONG  Event;                         /* AEGIS_EVT */
    ULONG  Pid;                           /* subject / target process */
    WCHAR  Path[AEGIS_MAX_PATH];          /* path that triggered (if any) */
    LARGE_INTEGER When;                   /* kernel tick / timestamp */
} AEGIS_EVT_MSG, *PAEGIS_EVT_MSG;

/* Version handshake so the agent refuses to talk to a mismatched driver. */
#define AEGIS_PROTO_VERSION 1

#endif /* AEGIS_COMMON_H */
