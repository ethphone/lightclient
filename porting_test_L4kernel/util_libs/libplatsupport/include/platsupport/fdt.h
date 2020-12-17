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

#include <libfdt.h>
#include <platsupport/irq.h>
#include <platsupport/io.h>
#include <platsupport/pmem.h>

/* We make an assumption that the size of the address/size cells are no larger than 2
 * RISCV does have 128 bits but there are no platforms that use that bit length (yet) */
#define READ_CELL32(addr) fdt32_ld(addr)
#define READ_CELL64(addr) fdt64_ld(addr)
#define READ_CELL(size, addr, offset) (size == 2 ? READ_CELL64(addr + (offset * sizeof(uint32_t))) : \
                                                   READ_CELL32(addr + (offset * sizeof(uint32_t))))

/*
 * Type of the callback function that is called for each device register instance
 * during a call to ps_fdt_walk_registers.
 *
 * @param pmem Description of the device register instance.
 * @param curr_num A number indicating the current register instance that we are currently at.
 * @param num_regs The total number of register instances that the device that we are walking through has.
 *
 * @return 0 on success, otherwise an error code
 */
typedef int (*reg_walk_cb_fn_t)(pmem_region_t pmem, unsigned curr_num, size_t num_regs, void *token);

/*
 * Type of the callback function that is called for each device interrupt
 * instance during a call to ps_fdt_walk_irqs.
 *
 * @param irq Description of the device interrupt instance.
 * @param curr_num A number indicating the current interrupt instance that we are currently at.
 * @param num_irqs The total number of interrupt instances that the device that we are walking through has.
 *
 * @return 0 on success, otherwise an error code
 */
typedef int (*irq_walk_cb_fn_t)(ps_irq_t irq, unsigned curr_num, size_t num_irqs, void *token);

/* An internal private struct used by the utility functions in this library. */
typedef struct ps_fdt_cookie ps_fdt_cookie_t;

/*
 * Given a devicetree path, this function will return a cookie that can be used in
 * the other functions in this library.
 *
 * @param io_fdt An initialised IO FDT interface.
 * @param malloc_ops An initialised malloc interface.
 * @param path Devicetree path to the device for which you want to use the utility functions on.
 * @param ret_cookie Storage that will have the pointer to the corresponding cookie written to.
 *
 * @returns 0 on success, otherwise -EINVAL, -ENOMEM, or one of the error codes in libfdt
 */
int ps_fdt_read_path(ps_io_fdt_t *io_fdt, ps_malloc_ops_t *malloc_ops, char *path, ps_fdt_cookie_t **ret_cookie);

/*
 * Cleans up a cookie that was initialised by ps_fdt_read_path.
 *
 * @param malloc_ops An initialised malloc interface.
 * @param cookie A pointer to a initialised cookie.
 *
 * @returns 0 on success, otherwise -EINVAL
 */
int ps_fdt_cleanup_cookie(ps_malloc_ops_t *malloc_ops, ps_fdt_cookie_t *cookie);

/*
 * Walks the registers property of the device node (if any) corresponding to the
 * cookie passed in and calls a callback function at each register instance of
 * the field.
 *
 * @param io_fdt An initialised IO FDT interface.
 * @param cookie A pointer to a initialised cookie.
 * @param callback Pointer to a callback function that is called at each register instance of the property.
 * @param token Pointer to be passed into the callback function when it is called.
 *
 * @returns 0 on success, otherwise:
 *  - one of the error codes in libfdt
 *  - -EINVAL
 *  - the error returned by the callback function
 */

int ps_fdt_walk_registers(ps_io_fdt_t *io_fdt, ps_fdt_cookie_t *cookie, reg_walk_cb_fn_t callback, void *token);

/*
 * Walks the interrupts/interrupts-extended field of the device node (if any)
 * corresponding to the cookie passed in and calls a callback function at each
 * interrupt instance of the field. Note that depending on the interrupt parser
 * modules available, this function may fail to parse the interrupt property.
 *
 * The modules can checked by looking inside the libplatsupport/src/arch/arm/irqchip/ folder.
 *
 * @param io_fdt An initialised IO FDT interface.
 * @param cookie A pointer to a initialised cookie.
 * @param callback Pointer to a callback function that is called at each interrupt instance of the property.
 * @param token Pointer to be passed into the callback function when it is called.
 *
 * @returns 0 on success, otherwise:
 *  - one of the error codes in libfdt
 *  - -EINVAL or -ENOENT for no suitable interrupt parsing module
 *  - the error returned by the callback function
 */
int ps_fdt_walk_irqs(ps_io_fdt_t *io_fdt, ps_fdt_cookie_t *cookie, irq_walk_cb_fn_t callback, void *token);
