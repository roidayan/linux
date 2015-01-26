/*
 * Copyright (c) 2015 Mellanox Technologies Ltd.  All rights reserved.
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

#ifndef IB_VERBS_EXP_H
#define IB_VERBS_EXP_H

#include <rdma/ib_verbs.h>


enum ib_exp_device_cap_flags2 {
	IB_EXP_DEVICE_DC_TRANSPORT		= 1 << 0,
	IB_EXP_DEVICE_QPG			= 1 << 1,
	IB_EXP_DEVICE_UD_RSS			= 1 << 2,
	IB_EXP_DEVICE_UD_TSS			= 1 << 3,
	IB_EXP_DEVICE_EXT_ATOMICS		= 1 << 4,
	IB_EXP_DEVICE_NOP			= 1 << 5,
	IB_EXP_DEVICE_UMR			= 1 << 6,
	IB_EXP_DEVICE_ODP			= 1 << 7,
	IB_EXP_DEVICE_ROCE_MODE_1_5		= 1 << 8,
	IB_EXP_DEVICE_ROCE_MODE_2		= 1 << 9,
	IB_EXP_DEVICE_MEM_WINDOW		= IB_DEVICE_MEM_WINDOW,
	IB_EXP_DEVICE_MEM_MGT_EXTENSIONS	= IB_DEVICE_MEM_MGT_EXTENSIONS,
	/* Jumping to 23 as of next capability in include/rdma/ib_verbs.h */
	/*
	 * Devices can set either IB_DEVICE_MEM_WINDOW_TYPE_2A or
	 * IB_DEVICE_MEM_WINDOW_TYPE_2B if it supports type 2A or type 2B
	 * memory windows. It can set neither to indicate it doesn't support
	 * type 2 windows at all.
	 */
	IB_EXP_DEVICE_MEM_WINDOW_TYPE_2A	= IB_DEVICE_MEM_WINDOW_TYPE_2A,
	IB_EXP_DEVICE_MEM_WINDOW_TYPE_2B	= IB_DEVICE_MEM_WINDOW_TYPE_2B,
	IB_EXP_DEVICE_CROSS_CHANNEL		= IB_DEVICE_CROSS_CHANNEL,
	IB_EXP_DEVICE_MANAGED_FLOW_STEERING	= IB_DEVICE_MANAGED_FLOW_STEERING,
	IB_EXP_DEVICE_MR_ALLOCATE		= IB_DEVICE_MR_ALLOCATE,
	IB_EXP_DEVICE_SHARED_MR			= IB_DEVICE_SHARED_MR,
	IB_EXP_DEVICE_MASK =	IB_EXP_DEVICE_MEM_WINDOW |
				IB_EXP_DEVICE_MEM_MGT_EXTENSIONS |
				IB_EXP_DEVICE_MEM_WINDOW_TYPE_2A |
				IB_EXP_DEVICE_MEM_WINDOW_TYPE_2B |
				IB_EXP_DEVICE_MR_ALLOCATE |
				IB_EXP_DEVICE_SHARED_MR |
				IB_EXP_DEVICE_CROSS_CHANNEL |
				IB_EXP_DEVICE_MANAGED_FLOW_STEERING
};

struct ib_exp_umr_caps {
	u32                max_reg_descriptors;
	u32                max_send_wqe_inline_klms;
	u32                max_umr_recursion_depth;
	u32                max_umr_stride_dimenson;
};


struct ib_exp_odp_caps {
	uint64_t	general_odp_caps;
	struct {
		uint32_t	rc_odp_caps;
		uint32_t	uc_odp_caps;
		uint32_t	ud_odp_caps;
		uint32_t	dc_odp_caps;
		uint32_t	xrc_odp_caps;
		uint32_t	raw_eth_odp_caps;
	} per_transport_caps;
};

enum ib_exp_device_attr_comp_mask {
	IB_EXP_DEVICE_ATTR_WITH_TIMESTAMP_MASK	= 1ULL << 1,
	IB_EXP_DEVICE_ATTR_WITH_HCA_CORE_CLOCK	= 1ULL << 2,
	IB_EXP_DEVICE_ATTR_CAP_FLAGS2		= 1ULL << 3,
	IB_EXP_DEVICE_ATTR_DC_REQ_RD		= 1ULL << 4,
	IB_EXP_DEVICE_ATTR_DC_RES_RD		= 1ULL << 5,
	IB_EXP_DEVICE_ATTR_INLINE_RECV_SZ	= 1ULL << 6,
	IB_EXP_DEVICE_ATTR_RSS_TBL_SZ		= 1ULL << 7,
	IB_EXP_DEVICE_ATTR_EXT_ATOMIC_ARGS	= 1ULL << 8,
	IB_EXP_DEVICE_ATTR_UMR                  = 1ULL << 9,
	IB_EXP_DEVICE_ATTR_ODP			= 1ULL << 10,
	IB_EXP_DEVICE_ATTR_MAX_DCT		= 1ULL << 11,
};

struct ib_exp_device_attr {
	struct ib_device_attr	base;
	/* Use IB_EXP_DEVICE_ATTR_... for exp_comp_mask */
	uint32_t		exp_comp_mask;
	uint64_t		device_cap_flags2;
	uint32_t		dc_rd_req;
	uint32_t		dc_rd_res;
	uint32_t		inline_recv_sz;
	uint32_t		max_rss_tbl_sz;
	/*
	 * This field is a bit mask for the supported atomic argument sizes.
	 * A bit set signifies an argument of size of 2 ^ bit_nubmer bytes is
	 * supported.
	 */
	u64			atomic_arg_sizes;
	u32			max_fa_bit_boudary;
	u32			log_max_atomic_inline_arg;
	struct ib_exp_umr_caps  umr_caps;
	struct ib_exp_odp_caps	odp_caps;
	uint32_t		max_dct;
};

struct ib_exp_qp_init_attr {
	void                  (*event_handler)(struct ib_event *, void *);
	void		       *qp_context;
	struct ib_cq	       *send_cq;
	struct ib_cq	       *recv_cq;
	struct ib_srq	       *srq;
	struct ib_xrcd	       *xrcd;     /* XRC TGT QPs only */
	struct ib_qp_cap	cap;
	union {
		struct ib_qp *qpg_parent; /* see qpg_type */
		struct ib_qpg_init_attrib parent_attrib;
	};
	enum ib_sig_type	sq_sig_type;
	enum ib_qp_type		qp_type;
	enum ib_qp_create_flags	create_flags;
	enum ib_qpg_type	qpg_type;
	u8			port_num; /* special QP types only */
	u32			max_inl_recv;
};


int ib_exp_query_device(struct ib_device *device,
			struct ib_exp_device_attr *device_attr);


enum ib_exp_mr_rereg_flags {
	IB_EXP_MR_REREG_TRANS		= IB_MR_REREG_TRANS,
	IB_EXP_MR_REREG_PD		= IB_MR_REREG_PD,
	IB_EXP_MR_REREG_ACCESS		= IB_MR_REREG_ACCESS,
	IB_EXP_MR_REREG_SUPPORTED	= ((IB_EXP_MR_REREG_ACCESS << 1) - 1)
};


#endif /* IB_VERBS_EXP_H */
