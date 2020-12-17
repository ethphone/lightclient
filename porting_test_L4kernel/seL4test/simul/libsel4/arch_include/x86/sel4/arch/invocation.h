/*
 * Copyright 2017, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */

/* This header was generated by kernel/tools/invocation_header_gen.py.
 *
 * To add an invocation call number, edit libsel4/include/interfaces/sel4.xml.
 *
 */
#ifndef __LIBSEL4_ARCH_INVOCATION_H
#define __LIBSEL4_ARCH_INVOCATION_H
enum arch_invocation_label {
    X86PageDirectoryMap = nSeL4ArchInvocationLabels,
    X86PageDirectoryUnmap,
#if defined(CONFIG_ARCH_IA32)
    X86PageDirectoryGetStatusBits,
#endif
    X86PageTableMap,
    X86PageTableUnmap,
#if defined(CONFIG_IOMMU)
    X86IOPageTableMap,
#endif
#if defined(CONFIG_IOMMU)
    X86IOPageTableUnmap,
#endif
    X86PageMap,
    X86PageUnmap,
#if defined(CONFIG_IOMMU)
    X86PageMapIO,
#endif
    X86PageGetAddress,
#if defined(CONFIG_VTX)
    X86PageMapEPT,
#endif
    X86ASIDControlMakePool,
    X86ASIDPoolAssign,
    X86IOPortControlIssue,
    X86IOPortIn8,
    X86IOPortIn16,
    X86IOPortIn32,
    X86IOPortOut8,
    X86IOPortOut16,
    X86IOPortOut32,
    X86IRQIssueIRQHandlerIOAPIC,
    X86IRQIssueIRQHandlerMSI,
#if defined(CONFIG_VTX)
    TCBSetEPTRoot,
#endif
#if defined(CONFIG_VTX)
    X86VCPUSetTCB,
#endif
#if defined(CONFIG_VTX)
    X86VCPUReadVMCS,
#endif
#if defined(CONFIG_VTX)
    X86VCPUWriteVMCS,
#endif
#if defined(CONFIG_VTX)
    X86VCPUEnableIOPort,
#endif
#if defined(CONFIG_VTX)
    X86VCPUDisableIOPort,
#endif
#if defined(CONFIG_VTX)
    X86VCPUWriteRegisters,
#endif
#if defined(CONFIG_VTX)
    X86EPTPDPTMap,
#endif
#if defined(CONFIG_VTX)
    X86EPTPDPTUnmap,
#endif
#if defined(CONFIG_VTX)
    X86EPTPDMap,
#endif
#if defined(CONFIG_VTX)
    X86EPTPDUnmap,
#endif
#if defined(CONFIG_VTX)
    X86EPTPTMap,
#endif
#if defined(CONFIG_VTX)
    X86EPTPTUnmap,
#endif
    nArchInvocationLabels
};

#endif /* __LIBSEL4_ARCH_INVOCATION_H */