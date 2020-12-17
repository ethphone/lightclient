/*
 * Copyright 2019, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */

#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include <utils/util.h>

#include <platsupport/timer.h>
#include <platsupport/plat/timer.h>

#define TIOCP_CFG_SOFTRESET BIT(0)

#define TIER_MATCHENABLE BIT(0)
#define TIER_OVERFLOWENABLE BIT(1)
#define TIER_COMPAREENABLE BIT(2)

#define TCLR_STARTTIMER BIT(0)
#define TCLR_AUTORELOAD BIT(1)
#define TCLR_PRESCALER BIT(5)
#define TCLR_COMPAREENABLE BIT(6)

#define TISR_MAT_IT_FLAG BIT(0)
#define TISR_OVF_IT_FLAG BIT(1)
#define TISR_TCAR_IT_FLAG BIT(2)

#define TISR_IRQ_CLEAR (TISR_TCAR_IT_FLAG | TISR_OVF_IT_FLAG | TISR_MAT_IT_FLAG)

static void dmt_reset(dmt_t *dmt)
{
    /* stop */
    dmt->hw->tclr = 0;
    dmt->hw->cfg = TIOCP_CFG_SOFTRESET;
    while (dmt->hw->cfg & TIOCP_CFG_SOFTRESET);
    dmt->hw->tier = TIER_OVERFLOWENABLE;
}

int dmt_stop(dmt_t *dmt)
{
    if (dmt == NULL) {
        return EINVAL;
    }

    dmt->hw->tclr = dmt->hw->tclr & ~TCLR_STARTTIMER;
    return 0;
}

int dmt_start(dmt_t *dmt)
{
    if (dmt == NULL) {
        return EINVAL;
    }
    dmt->hw->tclr = dmt->hw->tclr | TCLR_STARTTIMER;
    return 0;
}

int dmt_set_timeout(dmt_t *dmt, uint64_t ns, bool periodic)
{
    if (dmt == NULL) {
        return EINVAL;
    }
    dmt->hw->tclr = 0;      /* stop */

    /* XXX handle prescaler */
    uint32_t tclrFlags = periodic ? TCLR_AUTORELOAD : 0;

    uint64_t ticks = freq_ns_and_hz_to_cycles(ns, 24000000llu);
    if (ticks < 2) {
        return ETIME;
    }
    /* TODO: add functionality for 64 bit timeouts
     */
    if (ticks > UINT32_MAX) {
        ZF_LOGE("Timeout too far in future");
        return ETIME;
    }

    /* reload value */
    dmt->hw->tldr = 0xffffffff - (ticks);

    /* counter */
    dmt->hw->tcrr = 0xffffffff - (ticks);

    /* ack any pending irqs */
    dmt->hw->tisr = TISR_IRQ_CLEAR;
    dmt->hw->tclr = TCLR_STARTTIMER | tclrFlags;
    return 0;
}

int dmt_start_ticking_timer(dmt_t *dmt)
{
    if (dmt == NULL) {
        return EINVAL;
    }
    /* stop */
    dmt->hw->tclr = 0;

    /* reset */
    dmt->hw->cfg = TIOCP_CFG_SOFTRESET;
    while (dmt->hw->cfg & TIOCP_CFG_SOFTRESET);

    /* reload value */
    dmt->hw->tldr = 0x0;

    /* use overflow mode */
    dmt->hw->tier = TIER_OVERFLOWENABLE;

    /* counter */
    dmt->hw->tcrr = 0x0;

    /* ack any pending irqs */
    dmt->hw->tisr = TISR_IRQ_CLEAR;

    /* start with auto reload */
    dmt->hw->tclr = TCLR_STARTTIMER | TCLR_AUTORELOAD;
    return 0;
}

void dmt_handle_irq(dmt_t *dmt)
{
    if (dmt == NULL) {
        ZF_LOGE("DMT is NULL");
        return;
    }
    /* ack any pending irqs */
    dmt->hw->tisr = TISR_IRQ_CLEAR;
}

bool dmt_pending_overflow(dmt_t *dmt)
{
    return dmt->hw->tisr & TISR_OVF_IT_FLAG;
}

uint32_t dmt_get_time(dmt_t *dmt)
{
    return dmt->hw->tcrr;
}

int dmt_init(dmt_t *dmt, dmt_config_t config)
{
    if (dmt == NULL) {
        return EINVAL;
    }
    if (config.id < DMTIMER2 || config.id >= NTIMERS) {
        ZF_LOGE("Invalid timer id");
        return EINVAL;
    }

    dmt->hw = (struct dmt_map *)config.vaddr;
    // XXX support config->prescaler.

    dmt_reset(dmt);
    return 0;
}
