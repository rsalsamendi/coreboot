/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2017 Intel Corp.
 * (Written by Bora Guvendik <bora.guvendik@intel.com> for Intel Corp.)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */


/* PCI IRQ assignment */
#include "pci_irqs.asl"

/* eMMC, SD Card */
#include "scs.asl"

/* PCR access */
#include "pcr.asl"

/* GPIO controller */
#include "gpio.asl"
