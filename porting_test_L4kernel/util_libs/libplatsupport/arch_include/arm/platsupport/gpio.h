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

#pragma once

struct gpio_sys;
typedef struct gpio_sys gpio_sys_t;
typedef int gpio_id_t;

#include <stdbool.h>
#include <utils/util.h>
#include <platsupport/io.h>

#define GPIOID(port, pin)             ((port) * 32 + (pin))
#define GPIOID_PORT(gpio)             ((gpio) / 32)
#define GPIOID_PIN(gpio)              ((gpio) % 32)

typedef struct gpio gpio_t;
struct gpio {
/// GPIO port identifier
    gpio_id_t id;
/// GPIO subsystem handle
    gpio_sys_t *gpio_sys;
};

typedef enum gpio_dir {
/// Input direction
    GPIO_DIR_IN,
    /* Output direction:
     * DEFAULT_LOW will ensure that the pin stays low even while the driver is
     * initializing the pin.
     * DEFAULT_HIGH will ensure that the pin stays high even while the driver is
     * initializing the pin.
     */
    GPIO_DIR_OUT_DEFAULT_LOW,
    GPIO_DIR_OUT = GPIO_DIR_OUT_DEFAULT_LOW,
    GPIO_DIR_OUT_DEFAULT_HIGH,

/// Input direction with IRQ on low logic level
    GPIO_DIR_IRQ_LOW,
/// Input direction with IRQ on high logic level
    GPIO_DIR_IRQ_HIGH,
/// Input direction with IRQ on falling edge
    GPIO_DIR_IRQ_FALL,
/// Input direction with IRQ on rising edge
    GPIO_DIR_IRQ_RISE,
/// Input direction with IRQ on both rising and falling edges
    GPIO_DIR_IRQ_EDGE
} gpio_dir_t;

enum gpio_level {
    /* GPIO input/output levels */
    GPIO_LEVEL_LOW,
    GPIO_LEVEL_HIGH
};

struct gpio_sys {
    /** Initialize a GPIO pin.
     * @param   gpio_sys        Initialized gpio driver instance.
     * @param   id              ID of the pin to initialize a handle to.
     * @param   gpio_dir        Configure the pin for input/output/IRQ.
     *                          Use GPIO_DIR_OUT_DEFAULT_HIGH and
     *                          GPIO_DIR_OUT_DEFAULT_LOW to set the pin's
     *                          default logic level. Can be useful for things
     *                          like GPIO pins used as SPI chipselects where
     *                          you want to ensure that a pin stays in a certain
     *                          logic level even while this initialization
     *                          function is running.
     * @param   gpio[out]       Pointer to a gpio_t structure to be initialised.
     * @return 0 on success. Non-zero on error.
     */
    int (*init)(gpio_sys_t *gpio_sys, gpio_id_t id, enum gpio_dir dir, gpio_t *gpio);

    /**
     * Set a GPIO's output level. The pin must be configured for output
     * for this to work.
     * @param   gpio    Initialised GPIO pin instance.
     * @param   level   The output level to set for the pin.
     * @return 0 on success. Non-zero on error.
     */
    int (*set_level)(gpio_t *gpio, enum gpio_level level);

    /**
     * Read a pin's input level. The pin must be configured for input for
     * this to work.
     * @param   gpio    Initialised GPIO pin instance.
     * @return GPIO_LEVEL_LOW or GPIO_LEVEL_HIGH depending on the input level.
     *         Negative integer on error.
     */
    int (*read_level)(gpio_t *gpio);

    /**
     * Read and manipulate the status of a pending IRQ.
     * @param   gpio    Initialised GPIO pin instance.
     * @param   clear   Flag indicating whether or not the pending IRQ
     *                  should be cleared.
     * @return 0 (none) or 1 (pending) depending on the status of the IRQ.
     *         Negative integer on error.
     */
    int (*pending_status)(gpio_t *gpio, bool clear);

    /**
     * Enable or disable the IRQ signal from the pin.
     * @param   gpio    Initialised GPIO pin instance.
     * @param   enable  Flag indicating whether or not the IRQ signal
     *                  should be enabled.
     * @return 0 on success. Non-zero on error.
     */
    int (*irq_enable_disable)(gpio_t *gpio, bool enable);

/// platform specific private data
    void *priv;
};

static inline bool gpio_sys_valid(const gpio_sys_t *gpio_sys)
{
    return gpio_sys != NULL && gpio_sys->priv != NULL;
}

static inline bool gpio_instance_valid(const gpio_t *gpio)
{
    if (!gpio) {
        ZF_LOGE("Handle to GPIO not supplied!");
        return false;
    }
    if (!gpio->gpio_sys) {
        ZF_LOGE("GPIO pin's parent controller handle invalid!");
        return false;
    }
    return true;
}

/**
 * Initialise the GPIO subsystem and provide a handle for access
 * @param[in]  io_ops   io operations for device initialisation
 * @param[out] gpio_sys A gpio handle structure to initialise
 * @return              0 on success, errno value otherwise
 */
int gpio_sys_init(ps_io_ops_t *io_ops, gpio_sys_t *gpio_sys);

/**
 * Clear a GPIO pin
 * @param[in] a handle to a GPIO
 * @return    0 on success, otherwise errno value
 */
static inline int gpio_clr(gpio_t *gpio)
{
    if (!gpio_instance_valid(gpio)) {
        return -EINVAL;
    }
    if (!gpio->gpio_sys->set_level) {
        ZF_LOGE("Unimplemented");
        return -ENOSYS;
    }
    return gpio->gpio_sys->set_level(gpio, GPIO_LEVEL_LOW);
}

/**
 * Return the state of a GPIO pin
 * @param[in] a handle to a GPIO
 * @return    the value of the pin, otherwise errno value
 */
static inline int gpio_get(gpio_t *gpio)
{
    if (!gpio_instance_valid(gpio)) {
        return -EINVAL;
    }
    if (!gpio->gpio_sys->read_level) {
        ZF_LOGE("Unimplemented");
        return -ENOSYS;
    }
    return gpio->gpio_sys->read_level(gpio);
}

/**
 * Set a GPIO pin
 * @param[in] a handle to a GPIO
 * @return    0 on success, otherwise errno value
 */
static inline int gpio_set(gpio_t *gpio)
{
    if (!gpio_instance_valid(gpio)) {
        return -EINVAL;
    }
    if (!gpio->gpio_sys->set_level) {
        ZF_LOGE("Unimplemented");
        return -ENOSYS;
    }
    return gpio->gpio_sys->set_level(gpio, GPIO_LEVEL_HIGH);
}

/**
 * Check if an IRQ is pending for this GPIO
 * @param[in]  a handle to a GPIO
 * @return     errno value on error
 *             0 if an IRQ is not pending
 *             1 if an IRQ is pending
 */
static inline int gpio_is_pending(gpio_t *gpio)
{
    if (!gpio_instance_valid(gpio)) {
        return -EINVAL;
    }
    if (!gpio->gpio_sys->pending_status) {
        ZF_LOGE("Unimplemented");
        return -ENOSYS;
    }
    return gpio->gpio_sys->pending_status(gpio, false);
}

/**
 * Clear pending IRQs for this GPIO
 * @param[in] a handle to a GPIO
 * @return    0 on success, errno value on error
 */
static inline int gpio_pending_clear(gpio_t *gpio)
{
    if (!gpio_instance_valid(gpio)) {
        return -EINVAL;
    }
    if (!gpio->gpio_sys->pending_status) {
        ZF_LOGE("Unimplemented");
        return -ENOSYS;
    }
    int ret = gpio->gpio_sys->pending_status(gpio, true);
    if (ret < 0) {
        return ret;
    }
    return 0;
}

/**
 * Enable the IRQ signal from the pin.
 * @param[in] gpio Handle to the pin to manipulate
 * @return 0 for success, errno value on error.
 */
static inline int gpio_irq_enable(gpio_t *gpio)
{
    if (!gpio_instance_valid(gpio)) {
        return -EINVAL;
    }
    if (!gpio->gpio_sys->irq_enable_disable) {
        ZF_LOGE("Unimplemented");
        return -ENOSYS;
    }
    return gpio->gpio_sys->irq_enable_disable(gpio, true);
}

/**
 * Disable the IRQ signal from the pin.
 * @param[in] gpio Handle to the pin to manipulate
 * @return 0 for success, errno value on error.
 */
static inline int gpio_irq_disable(gpio_t *gpio)
{
    if (!gpio_instance_valid(gpio)) {
        return -EINVAL;
    }
    if (!gpio->gpio_sys->irq_enable_disable) {
        ZF_LOGE("Unimplemented");
        return -ENOSYS;
    }
    return gpio->gpio_sys->irq_enable_disable(gpio, false);
}

/**
 * Acquire a handle to a GPIO pin
 * @param[in]  gpio_sys  a handle to an initialised GPIO subsystem\
 * @param[in]  id        A pin identifier obtained from the macro
 *                       GPIOID(port, pin)
 * @param[in]  dir       The direction of the pin
 * @param[out] gpio      a GPIO handle to initialise
 * @return               0 on success
 */
static inline int gpio_new(gpio_sys_t *gpio_sys, gpio_id_t id, enum gpio_dir dir, gpio_t *gpio)
{
    if (!gpio_sys) {
        ZF_LOGE("Handle to GPIO controller not supplied!");
        return -EINVAL;
    }

    if (!gpio_sys->init) {
        ZF_LOGE("Unimplemented");
        return -ENOSYS;
    }

    if (!gpio) {
        ZF_LOGE("Handle to output pin structure not supplied!");
        return -EINVAL;
    }

    return gpio_sys->init(gpio_sys, id, dir, gpio);
}
