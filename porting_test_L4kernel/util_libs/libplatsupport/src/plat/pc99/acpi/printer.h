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

#include <autoconf.h>
#include <platsupport/gen_config.h>
#include <utils/attribute.h>
#include "regions.h"

#ifdef CONFIG_LIB_SEL4_ACPI_DEBUG

/************************
 **** Debug features ****
 ************************/

// pretty print a table. table type is auto detected
void
acpi_print_table(const void* start);

// print the raw table in hex and ASCII
void
acpi_print_table_raw(const void* start, int length);

void
acpi_print_regions(const RegionList_t* rl);

#else
static inline void
acpi_print_table(const void* start UNUSED) {}

static inline void
acpi_print_table_raw(const void* start UNUSED, int length UNUSED) {}

static inline void
acpi_print_regions(const RegionList_t* rl UNUSED) {}
#endif
