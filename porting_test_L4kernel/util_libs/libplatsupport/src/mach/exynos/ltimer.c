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
/* Implementation of a logical timer for omap platforms
 *
 * We use two GPTS: one for the time and relative timeouts, the other
 * for absolute timeouts.
 */
#include <platsupport/timer.h>
#include <platsupport/ltimer.h>
#include <platsupport/mach/pwm.h>
#include <platsupport/pmem.h>
#include <utils/util.h>

#include "../../ltimer.h"

static ps_irq_t irqs[] = {
    {
        .type = PS_INTERRUPT,
        .irq.number = PWM_T4_INTERRUPT
    },
    {
        .type = PS_INTERRUPT,
        .irq.number = PWM_T0_INTERRUPT
    },
};

static pmem_region_t pmems[] = {
    {
        .type = PMEM_TYPE_DEVICE,
        .base_addr = PWM_TIMER_PADDR,
        .length = PAGE_SIZE_4K
    }
};

#define N_IRQS ARRAY_SIZE(irqs)
#define N_PMEMS ARRAY_SIZE(pmems)

typedef struct {
    pwm_t pwm;
    void *vaddr;
    irq_id_t timer_irq_ids[N_IRQS];
    timer_callback_data_t callback_datas[N_IRQS];
    ltimer_callback_fn_t user_callback;
    void *user_callback_token;
    ps_io_ops_t ops;
} pwm_ltimer_t;

 size_t get_num_irqs(void *data)
{
    return N_IRQS;
}

static int get_nth_irq(void *data, size_t n, ps_irq_t *irq)
{
    assert(n < N_IRQS);

    *irq = irqs[n];
    return 0;
}

static size_t get_num_pmems(void *data)
{
    return N_PMEMS;
}

static int get_nth_pmem(void *data, size_t n, pmem_region_t *paddr)
{
    assert(n < N_PMEMS);
    *paddr = pmems[n];
    return 0;
}

static int handle_irq(void *data, ps_irq_t *irq)
{
    assert(data != NULL);
    pwm_ltimer_t *pwm_ltimer = data;
    pwm_handle_irq(&pwm_ltimer->pwm, irq->irq.number);
    /* This assumes that the T0 is for keeping track of the timestamp, and T4 is used for timeouts
     * TODO Refactor pwm_handle_irq and remove this assumption */
    ltimer_event_t event = irq->irq.number == PWM_T0_INTERRUPT ? LTIMER_OVERFLOW_EVENT : LTIMER_TIMEOUT_EVENT;
    if (pwm_ltimer->user_callback) {
        pwm_ltimer->user_callback(pwm_ltimer->user_callback_token, event);
    }
    return 0;
}

static int get_time(void *data, uint64_t *time)
{
    assert(data != NULL);
    assert(time != NULL);

    pwm_ltimer_t *pwm_ltimer = data;
    *time = pwm_get_time(&pwm_ltimer->pwm);
    return 0;
}

static int get_resolution(void *data, uint64_t *resolution)
{
    return ENOSYS;
}

static int set_timeout(void *data, uint64_t ns, timeout_type_t type)
{
    assert(data != NULL);
    pwm_ltimer_t *pwm_ltimer = data;

    switch (type) {
    case TIMEOUT_ABSOLUTE: {
        uint64_t time = pwm_get_time(&pwm_ltimer->pwm);
        if (time >= ns) {
            return ETIME;
        }
        return pwm_set_timeout(&pwm_ltimer->pwm, ns - time, false);
    }
    case TIMEOUT_RELATIVE:
        return pwm_set_timeout(&pwm_ltimer->pwm, ns, false);
    case TIMEOUT_PERIODIC:
        return pwm_set_timeout(&pwm_ltimer->pwm, ns, true);
    }

    return EINVAL;
}

static int reset(void *data)
{
    assert(data != NULL);
    pwm_ltimer_t *pwm_ltimer = data;
    pwm_stop(&pwm_ltimer->pwm);
    pwm_start(&pwm_ltimer->pwm);
    return 0;
}

static void destroy(void *data)
{
    assert(data);
    pwm_ltimer_t *pwm_ltimer = data;
    if (pwm_ltimer->vaddr) {
        pwm_stop(&pwm_ltimer->pwm);
        ps_pmem_unmap(&pwm_ltimer->ops, pmems[0], pwm_ltimer->vaddr);
    }

    for (int i = 0; i < N_IRQS; i++) {
        if (pwm_ltimer->timer_irq_ids[i] > PS_INVALID_IRQ_ID) {
            int error = ps_irq_unregister(&pwm_ltimer->ops.irq_ops, pwm_ltimer->timer_irq_ids[i]);
            ZF_LOGF_IF(error, "Failed to unregister IRQ");
        }
    }

    ps_free(&pwm_ltimer->ops.malloc_ops, sizeof(pwm_ltimer), pwm_ltimer);
}

static int create_ltimer(ltimer_t *ltimer, ps_io_ops_t ops)
{
    assert(ltimer != NULL);
    ltimer->get_time = get_time;
    ltimer->get_resolution = get_resolution;
    ltimer->set_timeout = set_timeout;
    ltimer->reset = reset;
    ltimer->destroy = destroy;

    int error = ps_calloc(&ops.malloc_ops, 1, sizeof(pwm_ltimer_t), &ltimer->data);
    if (error) {
        return error;
    }
    assert(ltimer->data != NULL);

    /* initialise the IRQ IDs */
    pwm_ltimer_t *pwm_ltimer = ltimer->data;
    for (int i = 0; i < N_IRQS; i++) {
        pwm_ltimer->timer_irq_ids[i] = PS_INVALID_IRQ_ID;
    }

    return 0;
}

static int init_ltimer(ltimer_t *ltimer)
{
    assert(ltimer != NULL);
    pwm_ltimer_t *pwm_ltimer = ltimer->data;

    /* setup pwm */
    pwm_config_t config = {
        .vaddr = pwm_ltimer->vaddr,
    };

    pwm_init(&pwm_ltimer->pwm, config);
    pwm_start(&pwm_ltimer->pwm);
    return 0;
}

int ltimer_default_init(ltimer_t *ltimer, ps_io_ops_t ops, ltimer_callback_fn_t callback, void *callback_token)
{

    int error = ltimer_default_describe(ltimer, ops);
    if (error) {
        return error;
    }

    error = create_ltimer(ltimer, ops);
    if (error) {
        return error;
    }

    pwm_ltimer_t *pwm_ltimer = ltimer->data;
    pwm_ltimer->ops = ops;
    pwm_ltimer->user_callback = callback;
    pwm_ltimer->user_callback_token = callback_token;
    pwm_ltimer->vaddr = ps_pmem_map(&ops, pmems[0], false, PS_MEM_NORMAL);
    if (pwm_ltimer->vaddr == NULL) {
        destroy(ltimer->data);
        return ENOMEM;
    }

    /* register the IRQs that we need */
    for (int i = 0; i < N_IRQS; i++) {
        pwm_ltimer->callback_datas[i].ltimer = ltimer;
        pwm_ltimer->callback_datas[i].irq = &irqs[i];
        pwm_ltimer->callback_datas[i].irq_handler = handle_irq;
        pwm_ltimer->timer_irq_ids[i] = ps_irq_register(&ops.irq_ops, irqs[i], handle_irq_wrapper,
                                                       &pwm_ltimer->callback_datas[i]);
        if (pwm_ltimer->timer_irq_ids[i] < 0) {
            destroy(ltimer->data);
            return EIO;
        }
    }

    init_ltimer(ltimer);
    if (error) {
        destroy(ltimer->data);
        return error;
    }

    /* success! */
    return 0;
}

int ltimer_default_describe(ltimer_t *ltimer, ps_io_ops_t ops)
{
    if (ltimer == NULL) {
        ZF_LOGE("Timer is NULL!");
        return EINVAL;
    }

    ltimer->get_num_irqs = get_num_irqs;
    ltimer->get_nth_irq = get_nth_irq;
    ltimer->get_num_pmems = get_num_pmems;
    ltimer->get_nth_pmem = get_nth_pmem;
    return 0;
}
