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
#include <platsupport/io.h>

#include "uboot/tx2_configs.h"

void eqos_dma_enable_rxirq(struct tx2_eth_data *dev);

void eqos_stop(struct tx2_eth_data *dev);

int eqos_start(struct tx2_eth_data *dev);

int eqos_send(struct tx2_eth_data *dev, void *packet, int length);

int eqos_handle_irq(struct tx2_eth_data *dev, int irq);

int eqos_recv(struct tx2_eth_data *dev, uintptr_t packetp);

void *tx2_initialise(uintptr_t base_addr, ps_io_ops_t *io_ops);

void ack_rx(struct tx2_eth_data *dev);