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

/*
 * This section is imcomplete. See page 638 of the ACPI book v50
 */

typedef struct acpi_hest_entry_hdr {
    uint16_t type;
    uint16_t src_id;
} acpi_hest_entry_hdr_t;

/* Hardware Error Source Table */
typedef struct acpi_hest {
    acpi_header_t header;
    uint32_t      entry_count;
    /* First item in array */
//    acpi_hest_entry_hdr entry[];
} acpi_hest_t;

#pragma pack(pop)
