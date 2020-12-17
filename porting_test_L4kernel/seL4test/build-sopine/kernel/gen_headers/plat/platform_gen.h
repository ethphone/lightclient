/*
 * Copyright 2019, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */

#ifndef __ARM_PLAT_H
#define __ARM_PLAT_H

#include <autoconf.h>

#define TIMER_CLOCK_HZ 24000000llu
#define CLK_MAGIC 
#define CLK_SHIFT 
#define TIMER_PRECISION 0

enum IRQConstants {
    maxIRQ                      = 181
} platform_interrupt_t;

#define IRQ_CNODE_SLOT_BITS (8)

#include <arch/machine/gic_v3.h>
#include <drivers/timer/arm_generic.h>

/* #undef CONFIGURE_SMMU */
#if (defined(CONFIGURE_SMMU) && defined(CONFIG_ARM_SMMU))
#include CONFIGURE_SMMU
#endif

#ifdef CONFIG_KERNEL_MCS
static inline CONST time_t getKernelWcetUs(void)
{
    return ;
}
#endif

#endif /* !__ARM_PLAT_H */
