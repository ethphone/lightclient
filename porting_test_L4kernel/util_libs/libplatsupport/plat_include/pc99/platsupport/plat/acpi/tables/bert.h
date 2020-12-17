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

#pragma pack(push,1)

/* Boot error region */
typedef struct acpi_bert_ber {
    uint32_t block_status;
    uint32_t data_offset;
    uint32_t data_length;
    uint32_t error_severity;
    /* first of many error data structures */
    /* Not implemented. See table 18-289 of ACPI book */
// acpi_bert_ged_t ged;
} acpi_bert_ber;

typedef struct acpi_bert {
    acpi_header_t header;
    uint32_t      ber_length;
    uint64_t       ber;
} acpi_bert_t;

#pragma pack(pop)
