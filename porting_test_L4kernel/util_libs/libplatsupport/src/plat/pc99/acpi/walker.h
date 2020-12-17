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

#include <stdbool.h>

#include <platsupport/plat/acpi/regions.h>
#include <platsupport/plat/acpi/acpi.h>

#include "regions.h"
/*
 * Find the address of "sig" between the given addresses.
 * sig_len provides the length of sig to allow a sig that
 * is not NULL terminated.
 * -- In general, use this to find the RSDT pointer
 */
void*
acpi_sig_search(acpi_t* acpi, const char* sig, int sig_len, void* start, void* end);

/*
 * walk the tables and report table locations and sizes
 * Returns -1 if unable to parse RSDP, 0 on success
 */
int
acpi_parse_tables(acpi_t *acpi);

/*
 * Parse the acpi table given its paddr.
 * Returns a dynamically allocated copy of the table
 * header. Returns NULL if unable to parse the table.
 */
acpi_header_t*
acpi_parse_table(acpi_t *acpi, void *table_paddr);
