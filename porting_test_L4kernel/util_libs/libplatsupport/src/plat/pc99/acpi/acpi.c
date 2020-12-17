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

#include <platsupport/plat/acpi/acpi.h>
#include <stdlib.h>
#include <string.h>
#include <utils/util.h>
#include <assert.h>

#include "walker.h"
#include "acpi.h"


// sum bytes at the given location
uint8_t
acpi_calc_checksum(const char* start, int length)
{
    uint8_t checksum = 0;
    while (length-- > 0) {
        checksum += *start++;
    }
    return checksum;
}

size_t
acpi_table_length(const void* tbl)
{
    const char* table = (const char*)tbl;
    size_t length;

    if (HAS_GENERIC_HEADER(table)) {
        length = ((acpi_header_t*)table)->length;
    } else if (ACPI_TABLE_TEST(table, FACS)) {
        length =  ((acpi_facs_t*)table)->length;
    } else if (ACPI_TABLE_TEST(table, RSDP)) {
        length = ((acpi_rsdp_t*)table)->length;
        if (length == 0) {
            /* some platforms do not initliase length of rsdp */
            length = sizeof(acpi_rsdp_t);
        }
    } else {
        length = 0xffffffff;
    }

    return length;
}

/*
 * Split an available memory region and return the index of the
 * new region
 * force_ptr is a flag that forces the use of the Root pointer
 * region. If insufficient memory is available in an alternate
 * region, the root pointer region will be used
 */
static int
split_available(RegionList_t* dst, size_t size, int force_ptr)
{
    /* default: no region found */
    int index = -1;
    ZF_LOGD("Region 0/%d: size = %zu/%zu\n", dst->region_count, dst->regions[0].size, size);
    /* Find region to split */
    if (!force_ptr) { /* first preference if permitted */
        index = find_space(dst, size, ACPI_AVAILABLE);
    }
    if (index < 0) { /* resort to BIOS PTR if no space found */
        index = find_space(dst, size, ACPI_AVAILABLE_PTR);
    }

    ZF_LOGD("found index %d\n", index);

    /* split the region */
    if (index >= 0) {
        index = split_region(dst, index, size);
    }

    return index;
}

static int
create_copy_region(const Region_t* src, RegionList_t* dlist,
                   int parent, int force_ptr)
{
    int index = split_available(dlist, src->size, force_ptr);
    if (index >= 0) {
        Region_t* dst = &dlist->regions[index];
        dst->type = src->type;
        dst->parent = parent;
        memcpy(dst->start, src->start, src->size);
        return index;
    } else {
        ZF_LOGD("err: could not split region\n");
        /* Error */
        return -1;
    }
}

/*
 * copy table and return relative address ready for linking
 * "table_index" is the table to be copied (index into slist)
 * "parent" is the index of the parent table (index into dlist)
 */
static void*
_acpi_copy_tables(const RegionList_t* slist, RegionList_t* dlist,
                  int table_index, int parent)
{
    int index;
    const Region_t *src;

    ZF_LOGD("ti %d, pi %d\n", table_index, parent);

    /* hold the index of the newly created dlist region */
    index = -1;

    /* table specific generation */
    src = &slist->regions[table_index];
    ZF_LOGD("copy -> %s\n", acpi_sig_str(src->type));
    switch (src->type) {
    case ACPI_RSDP:
        /* Split region */
        index = create_copy_region(src, dlist, parent, 1);
        if (index >= 0) {
            Region_t* dst = &dlist->regions[index];
            acpi_rsdp_t *dst_tbl = (acpi_rsdp_t*)dst->start;

            int child;
            dst_tbl->rsdt_address = 0;
            dst_tbl->xsdt_address = 0;

            /* find and copy RSDT */
            child = find_region(slist, 0, ACPI_RSDT);
            if (child >= 0) {
                void* p = _acpi_copy_tables(slist, dlist,
                                            child, index);
                /* This downcast is correct as an RSDP is defined as being in the bottom 4G of memory */
                dst_tbl->rsdt_address = (uint32_t)(uintptr_t)p;
                ZF_LOGD("Got address %p\n", p);
            } else {
                ZF_LOGD("err: unable to find rsdt\n");
            }

            /* find and copy XSDT */
            child = find_region(slist, 0, ACPI_XSDT);
            if (child >= 0) {
                /* PRE: RSDT must be found in dlist */
                void* p = _acpi_copy_tables(slist, dlist,
                                            child, index);
                dst_tbl->xsdt_address = (uint64_t)(uintptr_t)p;
                ZF_LOGD("Got address %p\n", p);
            } else {
                ZF_LOGD("err: unable to find xsdt\n");
            }

            /* recompute checksums */
            dst_tbl->checksum -=
                acpi_calc_checksum(dst->start, 20);
            dst_tbl->extended_checksum -=
                acpi_calc_checksum(dst->start, dst->size);
        } else {
            ZF_LOGD("err: unable to copy region\n");
        }
        break;

    case ACPI_RSDT: {
        /* find and copy sub tables and find RSDT size*/
        int hdr_size = sizeof(acpi_rsdt_t);
        int sub_size = 0;
        int child[MAX_REGIONS];
        int children = 0;

        for (int i = 0; i < slist->region_count; i++) {
            if (slist->regions[i].parent == table_index) {
                child[children++] = i;
                sub_size += sizeof(uint32_t);
            }
        }

        /* generate table */
        index = split_available(dlist, sub_size + hdr_size, 0);
        if (index >= 0) {
            acpi_rsdt_t *dst_tbl;
            uint32_t *subtables;
            Region_t* dst = &dlist->regions[index];
            dst->type = src->type;
            dst->parent = parent;

            /* copy header */
            dst_tbl = (acpi_rsdt_t*)dst->start;
            memcpy(dst->start, src->start, hdr_size);

            /* copy subtable */
            subtables = acpi_rsdt_first(dst_tbl);
            for (int i = 0; i < children; i++) {
                void* p;
                p = _acpi_copy_tables(slist, dlist, child[i], index);
                ZF_LOGD("Got address %p\n", p);
                if (p == NULL) {
                    /*
                     * we tolerate a little wasted space to recover
                     * from an abnormal event
                     */
                    sub_size -= sizeof(uint32_t);
                } else {
                    *subtables++ = (uint32_t)(uintptr_t)p;
                }
            }

            /* update length */
            dst->size = hdr_size + sub_size;
            dst_tbl->header.length = dst->size;

            /* update checksum */
            dst_tbl->header.checksum -=
                acpi_calc_checksum(dst->start, dst->size);
        }

        /* done */
        break;
    }

    case ACPI_XSDT: {
        /* create XSDT based on RSDT */
        int rsdt_index, entries, sub_size, hdr_size;
        acpi_rsdt_t *rsdt;

        rsdt_index = find_region(dlist, 0, ACPI_RSDT);
        assert(rsdt_index >= 0);

        rsdt = dlist->regions[rsdt_index].start;

        /* calculate sizes */
        entries = acpi_rsdt_entry_count(rsdt);
        ZF_LOGD("Found rsdt with %d entries\n", entries);
        sub_size = entries * sizeof(uint64_t);
        hdr_size = sizeof(acpi_xsdt_t);

        /* create tables */
        index = split_available(dlist, sub_size + hdr_size, 0);
        if (index >= 0) {
            acpi_xsdt_t *xsdt;
            uint32_t *rentry;
            uint64_t *xentry;
            Region_t* dst = &dlist->regions[index];
            dst->type = src->type;
            dst->parent = parent;

            /* copy header */
            memcpy(dst->start, src->start, hdr_size);

            /* copy entries */
            xsdt = (acpi_xsdt_t*)dst->start;
            rentry = acpi_rsdt_first(rsdt);
            xentry = acpi_xsdt_first(xsdt);
            while (entries-- > 0) {
                *xentry++ = (uint32_t)(*rentry++);
            }

            /* update checksum */
            xsdt->header.length = hdr_size + sub_size;
            xsdt->header.checksum -=
                acpi_calc_checksum(dst->start, dst->size);
        }
        break;
    }

    /* end points: simple table copy */
    case ACPI_MADT:
        index = create_copy_region(src, dlist, parent, 0);
        break;

        /* unknown table */
    default:
        index = -1;
        break;
    }

    /* Error */
    if (index >= 0) {
        return dlist->regions[index].start - dlist->offset;
    } else {
        return NULL;
    }
}

int
acpi_copy_tables(const RegionList_t* slist, RegionList_t* dlist)
{
    int i;
    for (i = 0; i < slist->region_count; i++) {
        if (slist->regions[i].parent != NOPARENT) {
            continue;
        }
        if (slist->regions[i].type >= ACPI_NTYPES) {
            continue;
        }

        if (_acpi_copy_tables(slist, dlist, i, NOPARENT) == NULL) {
            return !0;
        }
    }

    return 0;
}

/* only need to parse the tables once */
static acpi_t *acpi_singleton = NULL;

acpi_t *
create_acpi(ps_io_mapper_t io_mapper)
{
    acpi_t *acpi = (acpi_t *) malloc(sizeof(acpi_t));
    if (acpi == NULL) {
        ZF_LOGE("Failed to allocate memory of size %zu\n", sizeof(acpi));
        assert(acpi != NULL);
        return NULL;
    }

    acpi->regions = (RegionList_t *) malloc(sizeof(RegionList_t));

    if (acpi->regions == NULL) {
        ZF_LOGE("Failed to allocate memory of size %zu\n", sizeof(acpi));
        assert(acpi->regions != NULL);
        free(acpi);
        return NULL;
    }

    acpi->io_mapper = io_mapper;

    return acpi;
}

acpi_t *
acpi_init_with_rsdp(ps_io_mapper_t io_mapper, acpi_rsdp_t rsdp)
{
    if (acpi_singleton != NULL) {
        /* acpi already initialised */
        return acpi_singleton;
    }

    acpi_t *acpi = create_acpi(io_mapper);
    if(acpi == NULL) {
        ZF_LOGE("Failed to create acpi object");
        return NULL;
    }
    acpi->rsdp = rsdp;

    ZF_LOGV("Parsing ACPI tables\n");
    int error = acpi_parse_tables(acpi);
    if(error) {
        ZF_LOGE("Failed to parse acpi tables\n");
        free(acpi->regions);
        free(acpi);
        return NULL;
    }

    acpi_singleton = acpi;
    return acpi;
}

acpi_t *
acpi_init(ps_io_mapper_t io_mapper)
{
    if (acpi_singleton != NULL) {
        /* acpi already initialised */
        return acpi_singleton;
    }

    acpi_t *acpi = create_acpi(io_mapper);
    if(acpi == NULL) {
        ZF_LOGE("Failed to create acpi object");
        return NULL;
    }

    acpi_rsdp_t *rsdp_paddr;
    rsdp_paddr = acpi_sig_search(acpi, ACPI_SIG_RSDP, strlen(ACPI_SIG_RSDP),
                                 (void *) BIOS_PADDR_START, (void *) BIOS_PADDR_END);
    if (rsdp_paddr == NULL) {
        ZF_LOGW("Failed to find rsdp\n");
        return NULL;
    }

    acpi_rsdp_t *rsdp = (acpi_rsdp_t *) acpi_parse_table(acpi, rsdp_paddr);
    if (rsdp == NULL) {
        ZF_LOGE("Failed to parse rsdp\n");
        return NULL;
    }
    /* Copy rsdp object into acpi struct */
    memcpy(&(acpi->rsdp), rsdp, sizeof(acpi_rsdp_t));

    /*rsdp was dynamically allocated. No longer require the memory*/
    free(rsdp);

    ZF_LOGV("Parsing ACPI tables\n");
    int error = acpi_parse_tables(acpi);
    if(error) {
        ZF_LOGE("Failed to parse acpi tables\n");
        free(acpi->regions);
        free(acpi);
        return NULL;
    }

    acpi_singleton = acpi;
    return acpi;
}
