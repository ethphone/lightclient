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

#pragma once

#include <stdint.h>
#include <platsupport/io.h>
#include <platsupport/plat/tmu.h>
#include <utils/temperature.h>
#include <utils/zf_log.h>

/* Interface for a temperature sensor driver */

typedef struct ps_tmu ps_tmu_t;

struct ps_tmu {
    void* priv;

    /* Operations for the temperature sensor */
    temperature_t (*get_temperature)(ps_tmu_t* tmu);
    uint32_t (*get_raw_temperature)(ps_tmu_t* tmu);
};

/*
 * Initialize a temperature sensor driver
 * @param[in]   id      the id of the temperature sensor
 * @param[in]   ops     a structure containing OS specific operations for memory access
 * @param[out]  dev     temperature sensor driver to populate
 * @return              -1 on error, otherwise returns 0
 */
int ps_tmu_init(enum tmu_id id, ps_io_ops_t* ops, ps_tmu_t* dev);

/*
 * Read the current temperature sensor value, converting to millikelvins
 * @param[in]   d   The device to read data from
 * @return          The current temperature in millikelvin
 */
static inline temperature_t ps_tmu_get_temperature(ps_tmu_t* d)
{
    if (!d || !d->get_temperature) {
        ZF_LOGF("TMU driver not initialized");
    }
    return d->get_temperature(d);
}

/*
 * Read the raw value from the temperature sensor
 * @param[in]   d   The device to read data from
 * @return          The raw temperature sensor value
 */
static inline uint32_t ps_tmu_get_raw_temperature(ps_tmu_t *d)
{
    if (!d || !d->get_raw_temperature) {
        ZF_LOGF("TMU driver not initialized");
    }
    return d->get_raw_temperature(d);
}

/*
 * Read the current temperature sensor value, converting to millicelsius
 * @param[in]   d   The device to read data from
 * @return          The current temperature in millicelsius
 */
static inline millicelcius_t ps_tmu_get_temperature_millicelsius(ps_tmu_t* d)
{
    return millikelvin_to_millicelcius(ps_tmu_get_temperature(d));
}

/*
 * Read the current temperature sensor value, converting to degrees celsius
 * @param[in]   d   The device to read data from
 * @return          The current temperature in degrees celsius
 */
static inline celcius_t ps_tmu_get_temperature_celsius(ps_tmu_t* d)
{
    return ps_tmu_get_temperature_millicelsius(d) / MILLICELCIUS_IN_CELCIUS;
}

