/*
 * Copyright 2017, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 *
 * @TAG(DATA61_BSD)
 */


/* This header was generated by kernel/tools/syscall_header_gen.py.
 *
 * To add a system call number, edit kernel/include/api/syscall.xml
 *
 */
#ifndef __LIBSEL4_SYSCALL_H
#define __LIBSEL4_SYSCALL_H

#include <autoconf.h>

typedef enum {
    seL4_SysCall = -1,
    seL4_SysReplyRecv = -2,
    seL4_SysSend = -3,
    seL4_SysNBSend = -4,
    seL4_SysRecv = -5,
    seL4_SysReply = -6,
    seL4_SysYield = -7,
    seL4_SysNBRecv = -8,
#if defined CONFIG_PRINTING
    seL4_SysDebugPutChar = -9,
    seL4_SysDebugDumpScheduler = -10,
#endif /* defined CONFIG_PRINTING */
#if defined CONFIG_DEBUG_BUILD
    seL4_SysDebugHalt = -11,
    seL4_SysDebugCapIdentify = -12,
    seL4_SysDebugSnapshot = -13,
    seL4_SysDebugNameThread = -14,
#endif /* defined CONFIG_DEBUG_BUILD */
#if defined CONFIG_DEBUG_BUILD && CONFIG_MAX_NUM_NODES > 1
    seL4_SysDebugSendIPI = -15,
#endif /* defined CONFIG_DEBUG_BUILD && CONFIG_MAX_NUM_NODES > 1 */
#if defined CONFIG_DANGEROUS_CODE_INJECTION
    seL4_SysDebugRun = -16,
#endif /* defined CONFIG_DANGEROUS_CODE_INJECTION */
#if defined CONFIG_ENABLE_BENCHMARKS
    seL4_SysBenchmarkFlushCaches = -17,
    seL4_SysBenchmarkResetLog = -18,
    seL4_SysBenchmarkFinalizeLog = -19,
    seL4_SysBenchmarkSetLogBuffer = -20,
    seL4_SysBenchmarkNullSyscall = -21,
#endif /* defined CONFIG_ENABLE_BENCHMARKS */
#if defined CONFIG_BENCHMARK_TRACK_UTILISATION
    seL4_SysBenchmarkGetThreadUtilisation = -22,
    seL4_SysBenchmarkResetThreadUtilisation = -23,
#endif /* defined CONFIG_BENCHMARK_TRACK_UTILISATION */
#if defined CONFIG_KERNEL_X86_DANGEROUS_MSR
    seL4_SysX86DangerousWRMSR = -24,
    seL4_SysX86DangerousRDMSR = -25,
#endif /* defined CONFIG_KERNEL_X86_DANGEROUS_MSR */
#if defined CONFIG_VTX
    seL4_SysVMEnter = -26,
#endif /* defined CONFIG_VTX */
#if defined CONFIG_SET_TLS_BASE_SELF
    seL4_SysSetTLSBase = -27,
#endif /* defined CONFIG_SET_TLS_BASE_SELF */
    SEL4_FORCE_LONG_ENUM(seL4_Syscall_ID)
} seL4_Syscall_ID;

#endif /* __ARCH_API_SYSCALL_H */
