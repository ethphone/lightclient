/*
 * Copyright 2020, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */

#include <ethdrivers/tx2.h>
#include <ethdrivers/raw.h>
#include <ethdrivers/helpers.h>
#include <string.h>
#include <utils/util.h>
#include <stdio.h>
#include "uboot/tx2_configs.h"
#include "tx2.h"
#include "io.h"

static void free_desc_ring(struct tx2_eth_data *dev, ps_dma_man_t *dma_man)
{
    if (dev->rx_ring != NULL) {
        dma_unpin_free(dma_man, (void *)dev->rx_ring, sizeof(struct eqos_desc) * dev->rx_size);
        dev->rx_ring = NULL;
    }

    if (dev->tx_ring != NULL) {
        dma_unpin_free(dma_man, (void *)dev->tx_ring, sizeof(struct eqos_desc) * dev->tx_size);
        dev->tx_ring = NULL;
    }

    if (dev->rx_cookies != NULL) {
        free(dev->rx_cookies);
        dev->rx_cookies = NULL;
    }

    if (dev->tx_cookies != NULL) {
        free(dev->tx_cookies);
        dev->tx_cookies = NULL;
    }

    if (dev->tx_lengths != NULL) {
        free(dev->tx_lengths);
        dev->tx_lengths = NULL;
    }
}

static int initialize_desc_ring(struct tx2_eth_data *dev, ps_dma_man_t *dma_man, struct eth_driver *eth_driver)
{
    dma_addr_t rx_ring = dma_alloc_pin(dma_man, ALIGN_UP(sizeof(struct eqos_desc) * dev->rx_size, ARCH_DMA_MINALIGN), 0,
                                       ARCH_DMA_MINALIGN);
    if (!rx_ring.phys) {
        LOG_ERROR("Failed to allocate rx_ring");
        return -1;
    }
    dev->rx_ring = rx_ring.virt;
    dev->rx_ring_phys = rx_ring.phys;

    dma_addr_t tx_ring = dma_alloc_pin(dma_man, ALIGN_UP(sizeof(struct eqos_desc) * dev->tx_size, ARCH_DMA_MINALIGN), 0,
                                       ARCH_DMA_MINALIGN);
    if (!tx_ring.phys) {
        LOG_ERROR("Failed to allocate tx_ring");
        free_desc_ring(dev, dma_man);
        return -1;
    }
    dev->tx_ring = tx_ring.virt;
    dev->tx_ring_phys = tx_ring.phys;

    ps_dma_cache_clean_invalidate(dma_man, rx_ring.virt, sizeof(struct eqos_desc) * dev->rx_size);
    ps_dma_cache_clean_invalidate(dma_man, tx_ring.virt, sizeof(struct eqos_desc) * dev->tx_size);

    dev->rx_cookies = malloc(sizeof(void *) * dev->rx_size);
    dev->tx_cookies = malloc(sizeof(void *) * dev->tx_size);
    dev->tx_lengths = malloc(sizeof(unsigned int) * dev->tx_size);

    if (dev->rx_cookies == NULL || dev->tx_cookies == NULL || dev->tx_lengths == NULL) {

        if (dev->rx_cookies != NULL) {
            free(dev->rx_cookies);
        }

        if (dev->tx_cookies != NULL) {
            free(dev->tx_cookies);
        }

        if (dev->tx_lengths != NULL) {
            free(dev->tx_lengths);
        }

        LOG_ERROR("Failed to malloc");
        free_desc_ring(dev, dma_man);
        return -1;
    }

    /* Remaining needs to be 2 less than size as we cannot actually enqueue size many descriptors,
     * since then the head and tail pointers would be equal, indicating empty. */
    dev->rx_remain = dev->rx_size - 1;
    dev->tx_remain = dev->tx_size - 1;

    dev->rdt = dev->rdh = dev->tdt = dev->tdh = 0;

    /* zero both rings */
    memset((void *)dev->tx_ring, 0, sizeof(struct eqos_desc) * dev->tx_size);
    memset((void *)dev->rx_ring, 0, sizeof(struct eqos_desc) * dev->tx_size);

    __sync_synchronize();

    return 0;
}

static void fill_rx_bufs(struct eth_driver *driver)
{
    struct tx2_eth_data *dev = (struct tx2_eth_data *)driver->eth_data;
    __sync_synchronize();
    while (dev->rx_remain > 0) {

        void *cookie = NULL;
        /* request a buffer */
        uintptr_t phys = driver->i_cb.allocate_rx_buf(driver->cb_cookie, EQOS_MAX_PACKET_SIZE, &cookie);
        if (!phys) {
            break;
        }

        dev->rx_cookies[dev->rdt] = cookie;
        dev->rx_ring[dev->rdt].des0 = phys;
        dev->rx_ring[dev->rdt].des1 = 0;
        dev->rx_ring[dev->rdt].des2 = 0;
        __sync_synchronize();
        dev->rx_ring[dev->rdt].des3 = EQOS_DESC3_OWN | EQOS_DESC3_BUF1V | DWCEQOS_DMA_RDES3_INTE;

        dev->rdt = (dev->rdt + 1) % dev->rx_size;
        dev->rx_remain--;
    }

    __sync_synchronize();
    ack_rx(dev);

}

static void complete_rx(struct eth_driver *eth_driver)
{
    struct tx2_eth_data *dev = (struct tx2_eth_data *)eth_driver->eth_data;
    unsigned int rdt = dev->rdt;

    while (dev->rdh != rdt) {
        unsigned int status = dev->rx_ring[dev->rdh].des3;

        /* Ensure no memory references get ordered before we checked the descriptor was written back */
        __sync_synchronize();
        if (status & EQOS_DESC3_OWN) {
            /* not complete yet */
            break;
        }

        /* TBD: Need to handle multiple buffers for single frame? */
        void *cookie = dev->rx_cookies[dev->rdh];
        unsigned int len = status & 0x7fff;

        dev->rx_remain++;
        /* update rdh */
        dev->rdh = (dev->rdh + 1) % dev->rx_size;

        /* Give the buffers back */
        eth_driver->i_cb.rx_complete(eth_driver->cb_cookie, 1, &cookie, &len);
    }
}

static void complete_tx(struct eth_driver *driver)
{
    struct tx2_eth_data *dev = (struct tx2_eth_data *)driver->eth_data;
    volatile struct eqos_desc *tx_desc;

    while (dev->tdh != dev->tdt) {
        uint32_t i;
        for (i = 0; i < dev->tx_lengths[dev->tdh]; i++) {
            uint32_t ring_pos = (i + dev->tdh) % dev->tx_size;
            tx_desc = &dev->tx_ring[ring_pos];
            if ((tx_desc->des3 & EQOS_DESC3_OWN)) {
                /* not all parts complete */
                return;
            }
        }

        /* do not let memory loads happen before our checking of the descriptor write back */
        __sync_synchronize();

        /* increase TX Descriptor head */
        void *cookie = dev->tx_cookies[dev->tdh];
        dev->tx_remain += dev->tx_lengths[dev->tdh];
        dev->tdh = (dev->tdh + dev->tx_lengths[dev->tdh]) % dev->tx_size;

        /* give the buffer back */
        driver->i_cb.tx_complete(driver->cb_cookie, cookie);
    }
}

static void handle_irq(struct eth_driver *driver, int irq)
{
    struct tx2_eth_data *eth_data = (struct tx2_eth_data *)driver->eth_data;
    uint32_t val = eqos_handle_irq(eth_data, irq);

    if (val == TXIRQ) {
        complete_tx(driver);
    }

    if (val == RXIRQ) {
        complete_rx(driver);
        fill_rx_bufs(driver);
        eqos_dma_enable_rxirq(eth_data);
    }

    if (val == -1) {
        ZF_LOGF("Something went wrong");
    }
}

static void print_state(struct eth_driver *eth_driver)
{
    ZF_LOGF("print_state not implemented\n");
}

static void low_level_init(struct eth_driver *driver, uint8_t *mac, int *mtu)
{
    ZF_LOGF("low_level_init not implemented\n");
}

static int raw_tx(struct eth_driver *driver, unsigned int num, uintptr_t *phys,
                  unsigned int *len, void *cookie)
{
    assert(num == 1);
    struct tx2_eth_data *dev = (struct tx2_eth_data *)driver->eth_data;
    struct eth_device *enet = dev->eth_dev;
    int err;
    /* Ensure we have room */
    if (dev->tx_remain < num) {
        /* try and complete some */
        complete_tx(driver);
        if (dev->tx_remain < num) {
            ZF_LOGF("Raw TX failed");
            return ETHIF_TX_FAILED;
        }
    }
    __sync_synchronize();

    uint32_t i;
    for (i = 0; i < num; i++) {
        dev->tx_cookies[dev->tdt] = cookie;
        dev->tx_lengths[dev->tdt] = num;
        err = eqos_send(dev, (void *)phys[i], len[i]);
        if (err == -ETIMEDOUT) {
            ZF_LOGF("send timed out");
        }
    }

    dev->tx_remain -= num;

    return ETHIF_TX_ENQUEUED;
}

static void raw_poll(struct eth_driver *driver)
{
    complete_rx(driver);
    complete_tx(driver);
    fill_rx_bufs(driver);
}

static void get_mac(struct eth_driver *driver, uint8_t *mac)
{
    memcpy(mac, TX2_DEFAULT_MAC, 6);
}

static struct raw_iface_funcs iface_fns = {
    .raw_handleIRQ = handle_irq,
    .print_state = print_state,
    .low_level_init = low_level_init,
    .raw_tx = raw_tx,
    .raw_poll = raw_poll,
    .get_mac = get_mac
};

int ethif_tx2_init(struct eth_driver *eth_driver, ps_io_ops_t io_ops, void *config)
{
    int err;
    struct arm_eth_plat_config *plat_config = (struct arm_eth_plat_config *)config;
    struct tx2_eth_data *eth_data = NULL;
    void *eth_dev;

    if (config == NULL) {
        LOG_ERROR("Cannot get platform info; Passed in Config Pointer NULL");
        goto error;
    }

    eth_data = (struct tx2_eth_data *)malloc(sizeof(struct tx2_eth_data));
    if (eth_data == NULL) {
        LOG_ERROR("Failed to allocate eth data struct");
        goto error;
    }

    uintptr_t base_addr = (uintptr_t)plat_config->buffer_addr;

    eth_data->tx_size = EQOS_DESCRIPTORS_TX;
    eth_data->rx_size = EQOS_DESCRIPTORS_RX;
    eth_driver->dma_alignment = ARCH_DMA_MINALIGN;
    eth_driver->eth_data = eth_data;
    eth_driver->i_fn = iface_fns;

    /* Initialize Descriptors */
    err = initialize_desc_ring(eth_data, &io_ops.dma_manager, eth_driver);
    if (err) {
        LOG_ERROR("Failed to allocate descriptor rings");
        goto error;
    }

    eth_dev = (struct eth_device *)tx2_initialise(base_addr, &io_ops);
    if (NULL == eth_dev) {
        LOG_ERROR("Failed to initialize tx2 Ethernet Device");
        goto error;
    }
    eth_data->eth_dev = eth_dev;

    fill_rx_bufs(eth_driver);

    err = eqos_start(eth_data);
    if (err) {
        goto error;
    }
    return 0;
error:
    if (eth_data != NULL) {
        free(eth_data);
    }
    free_desc_ring(eth_data, &io_ops.dma_manager);
    return -1;
}
