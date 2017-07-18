/*
 * Copyright (c) 2017 Mellanox Technologies.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _RDMA_H
#define _RDMA_H

enum rdma_dev_cap {
	RDMA_DEV_RESIZE_MAX_WR			= (1 << 0),
	RDMA_DEV_BAD_PKEY_CNTR			= (1 << 1),
	RDMA_DEV_BAD_QKEY_CNTR			= (1 << 2),
	RDMA_DEV_RAW_MULTI			= (1 << 3),
	RDMA_DEV_AUTO_PATH_MIG			= (1 << 4),
	RDMA_DEV_CHANGE_PHY_PORT		= (1 << 5),
	RDMA_DEV_UD_AV_PORT_ENFORCE		= (1 << 6),
	RDMA_DEV_CURR_QP_STATE_MOD		= (1 << 7),
	RDMA_DEV_SHUTDOWN_PORT			= (1 << 8),
	/* Not in use, former INIT_TYPE		= (1 << 9),*/
	RDMA_DEV_PORT_ACTIVE_EVENT		= (1 << 10),
	RDMA_DEV_SYS_IMAGE_GUID			= (1 << 11),
	RDMA_DEV_RC_RNR_NAK_GEN			= (1 << 12),
	RDMA_DEV_SRQ_RESIZE			= (1 << 13),
	RDMA_DEV_N_NOTIFY_CQ			= (1 << 14),

	/*
	 * This device supports a per-device lkey or stag that can be
	 * used without performing a memory registration for the local
	 * memory.  Note that ULPs should never check this flag, but
	 * instead of use the local_dma_lkey flag in the ib_pd structure,
	 * which will always contain a usable lkey.
	 */
	RDMA_DEV_LOCAL_DMA_LKEY			= (1 << 15),
	/* Reserved, old SEND_W_INV		= (1 << 16),*/
	RDMA_DEV_MEM_WINDOW			= (1 << 17),
	/*
	 * Devices should set RDMA_DEV_UD_IP_SUM if they support
	 * insertion of UDP and TCP checksum on outgoing UD IPoIB
	 * messages and can verify the validity of checksum for
	 * incoming messages.  Setting this flag implies that the
	 * IPoIB driver may set NETIF_F_IP_CSUM for datagram mode.
	 */
	RDMA_DEV_UD_IP_CSUM			= (1 << 18),
	RDMA_DEV_UD_TSO				= (1 << 19),
	RDMA_DEV_XRC				= (1 << 20),

	/*
	 * This device supports the IB "base memory management extension",
	 * which includes support for fast registrations (IB_WR_REG_MR,
	 * IB_WR_LOCAL_INV and IB_WR_SEND_WITH_INV verbs).  This flag should
	 * also be set by any iWarp device which must support FRs to comply
	 * to the iWarp verbs spec.  iWarp devices also support the
	 * IB_WR_RDMA_READ_WITH_INV verb for RDMA READs that invalidate the
	 * stag.
	 */
	RDMA_DEV_MEM_MGT_EXTENSIONS		= (1 << 21),
	RDMA_DEV_BLOCK_MULTICAST_LOOPBACK	= (1 << 22),
	RDMA_DEV_MEM_WINDOW_TYPE_2A		= (1 << 23),
	RDMA_DEV_MEM_WINDOW_TYPE_2B		= (1 << 24),
	RDMA_DEV_RC_IP_CSUM			= (1 << 25),
	/* Deprecated. Please use IB_RAW_PACKET_CAP_IP_CSUM. */
	RDMA_DEV_RAW_IP_CSUM			= (1 << 26),
	/*
	 * Devices should set RDMA_DEV_CROSS_CHANNEL if they
	 * support execution of WQEs that involve synchronization
	 * of I/O operations with single completion queue managed
	 * by hardware.
	 */
	RDMA_DEV_CROSS_CHANNEL			= (1 << 27),
	RDMA_DEV_MANAGED_FLOW_STEERING		= (1 << 29),
	RDMA_DEV_SIGNATURE_HANDOVER		= (1 << 30),
	RDMA_DEV_ON_DEMAND_PAGING		= (1ULL << 31),
	RDMA_DEV_SG_GAPS_REG			= (1ULL << 32),
	RDMA_DEV_VIRTUAL_FUNCTION		= (1ULL << 33),
	/* Deprecated. Please use IB_RAW_PACKET_CAP_SCATTER_FCS. */
	RDMA_DEV_RAW_SCATTER_FCS		= (1ULL << 34),
	RDMA_DEV_RDMA_NETDEV_OPA_VNIC		= (1ULL << 35),
};

enum rdma_node_type {
	/* IB values map to NodeInfo:NodeType. */
	RDMA_NODE_IB_CA		= 1,
	RDMA_NODE_RNIC		= 4,
	RDMA_NODE_USNIC_UDP	= 6,
};

/*
 * This capability flags are taken from
 * InfiniBandTM Architecture Specification Volume 1, Revision 1.3
 * 14.2.5.6 PORTINFO - CapabilityMask
 *
 */
enum rdma_port_cap {
	RDMA_PORT_SM				= 1 <<  1,
	RDMA_PORT_NOTICE			= 1 <<  2,
	RDMA_PORT_TRAP				= 1 <<  3,
	RDMA_PORT_OPT_IPD			= 1 <<  4,
	RDMA_PORT_AUTO_MIGR			= 1 <<  5,
	RDMA_PORT_SL_MAP			= 1 <<  6,
	RDMA_PORT_MKEY_NVRAM			= 1 <<  7,
	RDMA_PORT_PKEY_NVRAM			= 1 <<  8,
	RDMA_PORT_LED_INFO			= 1 <<  9,
	RDMA_PORT_SM_DISABLED			= 1 << 10,
	RDMA_PORT_SYS_IMAGE_GUID		= 1 << 11,
	RDMA_PORT_PKEY_SW_EXT_PORT_TRAP		= 1 << 12,
	RDMA_PORT_EXTENDED_SPEEDS		= 1 << 14,
	RDMA_PORT_CM				= 1 << 16,
	RDMA_PORT_SNMP_TUNNEL			= 1 << 17,
	RDMA_PORT_REINIT			= 1 << 18,
	RDMA_PORT_DEVICE_MGMT			= 1 << 19,
	RDMA_PORT_VENDOR_CLASS			= 1 << 20,
	RDMA_PORT_DR_NOTICE			= 1 << 21,
	RDMA_PORT_CAP_MASK_NOTICE		= 1 << 22,
	RDMA_PORT_BOOT_MGMT			= 1 << 23,
	RDMA_PORT_LINK_LATENCY			= 1 << 24,
	RDMA_PORT_CLIENT_REG			= 1 << 25,
	RDMA_PORT_IP_BASED_GIDS			= 1 << 26,
};

enum rdma_link_state {
	RDMA_LINK_STATE_NOP,
	RDMA_LINK_STATE_DOWN,
	RDMA_LINK_STATE_INIT,
	RDMA_LINK_STATE_ARMED,
	RDMA_LINK_STATE_ACTIVE,
	RDMA_LINK_STATE_ACTIVE_DEFER,
};
};
#endif /* _RDMA_H */
