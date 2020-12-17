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
#include <utils/frequency.h>

#define USER_MODE BIT(1)
#define UNMASKED_INT BIT(2)
#define TCLR_STARTTIMER BIT(0)
#define TISR_IRQ_CLEAR BIT(0)

//debug method
static void print_regs(rk_t *rk){
    printf("load_count0          >> 0x%08x\n", rk->hw->load_count0);
    printf("load_count1          >> 0x%08x\n", rk->hw->load_count1);
    printf("current_cnt_lowbits  >> 0x%08x\n", rk->hw->current_value0);
    printf("current_cnt_highbits >> 0x%08x\n", rk->hw->current_value1);
    printf("load_count2          >> 0x%08x\n", rk->hw->load_count2);
    printf("load_count3          >> 0x%08x\n", rk->hw->load_count3);
    printf("interrupt_status     >> 0x%08x\n", rk->hw->interrupt_status);
    printf("control_register     >> 0x%08x\n", rk->hw->control_register);
}

int rk_stop(rk_t *rk)
{
    if (rk == NULL) {
        return EINVAL;
    }

    rk->hw->control_register = 0;
    return 0;
}

uint64_t rk_get_time(rk_t *rk)
{
    if (rk == NULL){
        return EINVAL;
    }
    uint32_t val1 = rk->hw->current_value1;
    uint32_t val2 = rk->hw->current_value0;
    if (val1 != rk->hw->current_value1){
         val1 = rk->hw->current_value1;
         val2 = rk->hw->current_value0;
    }

    uint64_t time = 0;
    time = val1;
    time <<= 32;
    time |= val2;
    return ((uint64_t)((time) * NS_IN_S)/24000000ull); 
}

int rk_start(rk_t *rk, enum ttype type)
{
    if (rk == NULL) {
        return EINVAL;
    }
    rk->hw->control_register = 0;   

    //set timer to count up monotonically
    if (type == TIMER_RK){
        rk->hw->load_count0  = 0xffffffff;
        rk->hw->load_count1  = 0xffffffff;
    }

    rk->hw->control_register |= UNMASKED_INT | TCLR_STARTTIMER;
    return 0;
}

int rk_set_timeout(rk_t *rk, uint64_t ns, bool periodic)
{  
    if (rk == NULL) {
        return EINVAL;
    }
    /* disable timer */
    rk->hw->control_register = 0;      

    /* timer mode */
    uint32_t tclrFlags = periodic ? 0 : USER_MODE;

    /* load timer count */
    uint64_t ticks = freq_ns_and_hz_to_cycles(ns, 24000000ull);
    rk->hw->load_count0  = (uint32_t)(ticks & 0xffffffff);
    rk->hw->load_count1  = (ticks >> 32);

    /* enable timer with configs */
    rk->hw->control_register |= TCLR_STARTTIMER | UNMASKED_INT | tclrFlags;
    return 0;
}

void rk_handle_irq(rk_t *rk)
{
    if (rk == NULL) {
        ZF_LOGE("rk is NULL");
        return;
    }
    /* ack any pending irqs */
    rk->hw->interrupt_status = 1;  
}

bool rk_pending_match(rk_t *rk)
{
    return rk->hw->interrupt_status & TISR_IRQ_CLEAR;
}

int rk_init(rk_t *rk, rk_config_t config)
{
    if (rk == NULL) {
        return EINVAL;
    }
    if (config.id < RKTIMER0 || config.id >= NTIMERS) {
        ZF_LOGE("Invalid timer id");
        return EINVAL;
    }
    rk->hw = (struct rk_map *)config.vaddr;
    return 0;
}
