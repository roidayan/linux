/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
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

#include <linux/if_vlan.h>
#include <linux/etherdevice.h>
#include <linux/timecounter.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/qp.h>
#include <linux/mlx5/cq.h>
#include <linux/mlx5/port.h>
#include <linux/mlx5/vport.h>
#include <linux/mlx5/transobj.h>
#include "wq.h"
#include "mlx5_core.h"

#define MLX5E_MAX_NUM_TC	8

#define MLX5E_PARAMS_MINIMUM_LOG_SQ_SIZE                0x6
#define MLX5E_PARAMS_DEFAULT_LOG_SQ_SIZE                0xa
#define MLX5E_PARAMS_MAXIMUM_LOG_SQ_SIZE                0xd

#define MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE                0x1
#define MLX5E_PARAMS_DEFAULT_LOG_RQ_SIZE                0xa
#define MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE                0xd

#define MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE_MPW            0x1
#define MLX5E_PARAMS_DEFAULT_LOG_RQ_SIZE_MPW            0x4
#define MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE_MPW            0x6

#define MLX5_MPWRQ_LOG_NUM_STRIDES		10
#define MLX5_MPWRQ_LOG_STRIDE_SIZE		7
#define MLX5_MPWRQ_NUM_STRIDES			BIT(MLX5_MPWRQ_LOG_NUM_STRIDES)
#define MLX5_MPWRQ_STRIDE_SIZE			BIT(MLX5_MPWRQ_LOG_STRIDE_SIZE)
#define MLX5_MPWRQ_LOG_WQE_SZ			(MLX5_MPWRQ_LOG_NUM_STRIDES +\
						 MLX5_MPWRQ_LOG_STRIDE_SIZE)
#define MLX5_MPWRQ_WQE_PAGE_ORDER	(MLX5_MPWRQ_LOG_WQE_SZ >= PAGE_SHIFT ? \
					 MLX5_MPWRQ_LOG_WQE_SZ - PAGE_SHIFT : 0)
#define MLX5_MPWRQ_WQE_NUM_PAGES		BIT(MLX5_MPWRQ_WQE_PAGE_ORDER)
#define MLX5_CHANNEL_MAX_NUM_PAGES (MLX5_MPWRQ_WQE_NUM_PAGES * \
				    BIT(MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE_MPW))
#define MLX5_UMR_ALIGN				(2048)
#define MLX5_MPWRQ_SMALL_PACKET_THRESHOLD	(128)

#define MLX5E_PARAMS_DEFAULT_LRO_WQE_SZ                 (64 * 1024)
#define MLX5E_PARAMS_DEFAULT_RX_CQ_MODERATION_USEC      0x10
#define MLX5E_PARAMS_DEFAULT_RX_CQ_MODERATION_USEC_FROM_CQE 0x3
#define MLX5E_PARAMS_DEFAULT_RX_CQ_MODERATION_PKTS      0x20
#define MLX5E_PARAMS_DEFAULT_TX_CQ_MODERATION_USEC      0x10
#define MLX5E_PARAMS_DEFAULT_TX_CQ_MODERATION_PKTS      0x20
#define MLX5E_PARAMS_DEFAULT_MIN_RX_WQES                0x80
#define MLX5E_PARAMS_DEFAULT_MIN_RX_WQES_MPW            0x2

#define MLX5E_LOG_INDIR_RQT_SIZE       0x7
#define MLX5E_INDIR_RQT_SIZE           BIT(MLX5E_LOG_INDIR_RQT_SIZE)
#define MLX5E_MAX_NUM_CHANNELS         (MLX5E_INDIR_RQT_SIZE >> 1)
#define MLX5E_TX_CQ_POLL_BUDGET        128
#define MLX5E_UPDATE_STATS_INTERVAL    200 /* msecs */
#define MLX5E_SQ_BF_BUDGET             16

#define MLX5E_NUM_MAIN_GROUPS 9
#define MLX5E_NET_IP_ALIGN 2

static inline u16 mlx5_min_rx_wqes(int wq_type, u32 wq_size)
{
	switch (wq_type) {
	case MLX5_WQ_TYPE_LINKED_LIST:
		return min_t(u16, MLX5E_PARAMS_DEFAULT_MIN_RX_WQES,
			     wq_size / 2);
	case MLX5_WQ_TYPE_LINKED_LIST_STRIDING_RQ:
		return min_t(u16, MLX5E_PARAMS_DEFAULT_MIN_RX_WQES_MPW,
			     wq_size / 2);
	default:
		BUG_ON(true);
		return -EINVAL;
	}
}

static inline int mlx5_min_log_rq_size(int wq_type)
{
	switch (wq_type) {
	case MLX5_WQ_TYPE_LINKED_LIST:
		return MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE;
	case MLX5_WQ_TYPE_LINKED_LIST_STRIDING_RQ:
		return MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE_MPW;
	default:
		BUG_ON(true);
		return -EINVAL;
	}
}

static inline int mlx5_max_log_rq_size(int wq_type)
{
	switch (wq_type) {
	case MLX5_WQ_TYPE_LINKED_LIST:
		return MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE;
	case MLX5_WQ_TYPE_LINKED_LIST_STRIDING_RQ:
		return MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE_MPW;
	default:
		BUG_ON(true);
		return -EINVAL;
	}
}

struct mlx5e_tx_wqe {
	struct mlx5_wqe_ctrl_seg ctrl;
	struct mlx5_wqe_eth_seg  eth;
};

struct mlx5e_rx_wqe {
	struct mlx5_wqe_srq_next_seg  next;
	struct mlx5_wqe_data_seg      data;
};

struct mlx5e_umr_wqe {
	struct mlx5_wqe_ctrl_seg       ctrl;
	struct mlx5_wqe_umr_ctrl_seg   uctrl;
	struct mlx5_mkey_seg           mkc;
	struct mlx5_wqe_data_seg       data;
};

#ifdef CONFIG_MLX5_CORE_EN_DCB
#define MLX5E_MAX_BW_ALLOC 100 /* Max percentage of BW allocation */
#define MLX5E_MIN_BW_ALLOC 1   /* Min percentage of BW allocation */
#endif

static const char vport_strings[][ETH_GSTRING_LEN] = {
	/* vport statistics */
	"rx_packets",
	"rx_bytes",
	"tx_packets",
	"tx_bytes",
	"rx_error_packets",
	"rx_error_bytes",
	"tx_error_packets",
	"tx_error_bytes",
	"rx_unicast_packets",
	"rx_unicast_bytes",
	"tx_unicast_packets",
	"tx_unicast_bytes",
	"rx_multicast_packets",
	"rx_multicast_bytes",
	"tx_multicast_packets",
	"tx_multicast_bytes",
	"rx_broadcast_packets",
	"rx_broadcast_bytes",
	"tx_broadcast_packets",
	"tx_broadcast_bytes",

	/* SW counters */
	"tso_packets",
	"tso_bytes",
	"lro_packets",
	"lro_bytes",
	"rx_csum_good",
	"rx_csum_none",
	"rx_csum_sw",
	"tx_csum_offload",
	"tx_queue_stopped",
	"tx_queue_wake",
	"tx_queue_dropped",
	"rx_wqe_err",
	"rx_frag_mpwqe",
	"rx_cqe_compress",
};

struct mlx5e_vport_stats {
	/* HW counters */
	u64 rx_packets;
	u64 rx_bytes;
	u64 tx_packets;
	u64 tx_bytes;
	u64 rx_error_packets;
	u64 rx_error_bytes;
	u64 tx_error_packets;
	u64 tx_error_bytes;
	u64 rx_unicast_packets;
	u64 rx_unicast_bytes;
	u64 tx_unicast_packets;
	u64 tx_unicast_bytes;
	u64 rx_multicast_packets;
	u64 rx_multicast_bytes;
	u64 tx_multicast_packets;
	u64 tx_multicast_bytes;
	u64 rx_broadcast_packets;
	u64 rx_broadcast_bytes;
	u64 tx_broadcast_packets;
	u64 tx_broadcast_bytes;

	/* SW counters */
	u64 tso_packets;
	u64 tso_bytes;
	u64 lro_packets;
	u64 lro_bytes;
	u64 rx_csum_good;
	u64 rx_csum_none;
	u64 rx_csum_sw;
	u64 tx_csum_offload;
	u64 tx_queue_stopped;
	u64 tx_queue_wake;
	u64 tx_queue_dropped;
	u64 rx_wqe_err;
	u64 rx_frag_mpwqe;
	u64 rx_cqe_compress;

#define NUM_VPORT_COUNTERS     34
};

static const char pport_strings[][ETH_GSTRING_LEN] = {
	/* IEEE802.3 counters */
	"frames_tx",
	"frames_rx",
	"check_seq_err",
	"alignment_err",
	"octets_tx",
	"octets_received",
	"multicast_xmitted",
	"broadcast_xmitted",
	"multicast_rx",
	"broadcast_rx",
	"in_range_len_errors",
	"out_of_range_len",
	"too_long_errors",
	"symbol_err",
	"mac_control_tx",
	"mac_control_rx",
	"unsupported_op_rx",
	"pause_ctrl_rx",
	"pause_ctrl_tx",

	/* RFC2863 counters */
	"in_octets",
	"in_ucast_pkts",
	"in_discards",
	"in_errors",
	"in_unknown_protos",
	"out_octets",
	"out_ucast_pkts",
	"out_discards",
	"out_errors",
	"in_multicast_pkts",
	"in_broadcast_pkts",
	"out_multicast_pkts",
	"out_broadcast_pkts",

	/* RFC2819 counters */
	"drop_events",
	"octets",
	"pkts",
	"broadcast_pkts",
	"multicast_pkts",
	"crc_align_errors",
	"undersize_pkts",
	"oversize_pkts",
	"fragments",
	"jabbers",
	"collisions",
	"p64octets",
	"p65to127octets",
	"p128to255octets",
	"p256to511octets",
	"p512to1023octets",
	"p1024to1518octets",
	"p1519to2047octets",
	"p2048to4095octets",
	"p4096to8191octets",
	"p8192to10239octets",
};

#define NUM_IEEE_802_3_COUNTERS		19
#define NUM_RFC_2863_COUNTERS		13
#define NUM_RFC_2819_COUNTERS		21
#define NUM_PPORT_COUNTERS		(NUM_IEEE_802_3_COUNTERS + \
					 NUM_RFC_2863_COUNTERS + \
					 NUM_RFC_2819_COUNTERS)

struct mlx5e_pport_stats {
	__be64 IEEE_802_3_counters[NUM_IEEE_802_3_COUNTERS];
	__be64 RFC_2863_counters[NUM_RFC_2863_COUNTERS];
	__be64 RFC_2819_counters[NUM_RFC_2819_COUNTERS];
};

static const char qcounter_stats_strings[][ETH_GSTRING_LEN] = {
	"out_of_rx_buffer",
};

struct mlx5e_qcounter_stats {
	u32 out_of_rx_buffer;
#define NUM_Q_COUNTERS 1
};

static const char rq_stats_strings[][ETH_GSTRING_LEN] = {
	"packets",
	"csum_none",
	"csum_sw",
	"lro_packets",
	"lro_bytes",
	"wqe_err",
	"frag_mpwqe",
	"cqe_compress",
};

struct mlx5e_rq_stats {
	u64 packets;
	u64 csum_none;
	u64 csum_sw;
	u64 lro_packets;
	u64 lro_bytes;
	u64 wqe_err;
	u64 frag_mpwqe;
	u64 cqe_compress;
#define NUM_RQ_STATS 8
};

static const char sq_stats_strings[][ETH_GSTRING_LEN] = {
	"packets",
	"tso_packets",
	"tso_bytes",
	"nop",
	"csum_offload_none",
	"stopped",
	"wake",
	"dropped",
};

struct mlx5e_sq_stats {
	u64 packets;
	u64 tso_packets;
	u64 tso_bytes;
	u64 nop;
	u64 csum_offload_none;
	u64 stopped;
	u64 wake;
	u64 dropped;
#define NUM_SQ_STATS 8
};

struct mlx5e_stats {
	struct mlx5e_vport_stats   vport;
	struct mlx5e_pport_stats   pport;
	struct mlx5e_qcounter_stats qcnt;
};

struct mlx5e_params {
	u8  log_sq_size;
	u8  rq_wq_type;
	u8  log_rq_size;
	u16 num_channels;
	u8  num_tc;
	u8  rx_cq_period_mode;
	u16 rx_cq_moderation_usec;
	u16 rx_cq_moderation_pkts;
	u16 tx_cq_moderation_usec;
	u16 tx_cq_moderation_pkts;
	u16 min_rx_wqes;
	bool lro_en;
	u32 lro_wqe_sz;
	u16 tx_max_inline;
	u8  rss_hfunc;
	u8  toeplitz_hash_key[40];
	u32 indirection_rqt[MLX5E_INDIR_RQT_SIZE];
#ifdef CONFIG_MLX5_CORE_EN_DCB
	struct ieee_ets ets;
#endif
};

struct mlx5e_tstamp {
	rwlock_t                   lock;
	struct cyclecounter        cycles;
	struct timecounter         clock;
	struct hwtstamp_config     hwtstamp_config;
	u32                        nominal_c_mult;
	unsigned long              overflow_period;
	struct delayed_work        overflow_work;
	struct mlx5_core_dev      *mdev;
	struct ptp_clock          *ptp;
	struct ptp_clock_info      ptp_info;
};

enum {
	MLX5E_RQ_STATE_POST_WQES_ENABLE,
	MLX5E_RQ_STATE_UMR_WQE_IN_PROGRESS,
};

struct mlx5e_cq {
	/* data path - accessed per cqe */
	struct mlx5_cqwq           wq;

	/* data path - accessed per napi poll */
	struct napi_struct        *napi;
	struct mlx5_core_cq        mcq;
	struct mlx5e_channel      *channel;
	struct mlx5e_priv         *priv;

	/* control */
	struct mlx5_wq_ctrl        wq_ctrl;
} ____cacheline_aligned_in_smp;

struct mlx5e_dma_info {
	struct page	*page;
	dma_addr_t	addr;
};

struct mlx5e_rq {
	/* data path */
	struct mlx5_wq_ll      wq;
	u32                    wqe_sz;
	struct sk_buff       **skb;
	struct mlx5e_mpw_info *wqe_info;
	__be32                 mkey_be;
	__be32                 umr_mkey_be;

	struct device         *pdev;
	struct net_device     *netdev;
	struct mlx5e_tstamp   *tstamp;
	struct mlx5e_rq_stats  stats;
	struct mlx5e_cq        cq;
	void (*handle_rx_cqe)(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe);
	int (*alloc_wqe)(struct mlx5e_rq *rq, struct mlx5e_rx_wqe *wqe,
			 u16 ix);

	unsigned long          state;
	int                    ix;

	/* control */
	struct mlx5_wq_ctrl    wq_ctrl;
	u8                     wq_type;
	u32                    rqn;
	struct mlx5e_channel  *channel;
	struct mlx5e_priv     *priv;
} ____cacheline_aligned_in_smp;

struct mlx5e_mpw_info {
	union {
		struct mlx5e_dma_info          dma_info;
		struct {
			__be64                *mtt;
			dma_addr_t             mtt_addr;
			struct mlx5e_dma_info *umr_dma_info;
		};
	};
	u16 consumed_strides;

	void (*complete_wqe)(struct mlx5e_rq *rq,
			     struct mlx5_cqe64 *cqe,
			     struct mlx5e_mpw_info *wi,
			     struct sk_buff *skb);
	void (*free_wqe)(struct mlx5e_rq *rq, struct mlx5e_mpw_info *wi);
};

struct mlx5e_tx_wqe_info {
	u32 num_bytes;
	u8  num_wqebbs;
	u8  num_dma;
};

enum mlx5e_dma_map_type {
	MLX5E_DMA_MAP_SINGLE,
	MLX5E_DMA_MAP_PAGE
};

struct mlx5e_sq_dma {
	dma_addr_t              addr;
	u32                     size;
	enum mlx5e_dma_map_type type;
};

enum {
	MLX5E_SQ_STATE_WAKE_TXQ_ENABLE,
};

struct mlx5e_ico_wqe_info {
	u8  opcode;
	u8  num_wqebbs;
};

struct mlx5e_sq {
	/* data path */

	/* dirtied @completion */
	u16                        cc;
	u32                        dma_fifo_cc;

	/* dirtied @xmit */
	u16                        pc ____cacheline_aligned_in_smp;
	u32                        dma_fifo_pc;
	u16                        bf_offset;
	u16                        prev_cc;
	u8                         bf_budget;
	struct mlx5e_sq_stats      stats;

	struct mlx5e_cq            cq;

	/* pointers to per packet info: write@xmit, read@completion */
	struct sk_buff           **skb;
	struct mlx5e_sq_dma       *dma_fifo;
	struct mlx5e_tx_wqe_info  *wqe_info;

	/* read only */
	struct mlx5_wq_cyc         wq;
	u32                        dma_fifo_mask;
	void __iomem              *uar_map;
	void __iomem              *uar_bf_map;
	struct netdev_queue       *txq;
	u32                        sqn;
	u16                        bf_buf_size;
	u16                        max_inline;
	u16                        edge;
	struct device             *pdev;
	struct mlx5e_tstamp       *tstamp;
	__be32                     mkey_be;
	unsigned long              state;

	/* control path */
	struct mlx5_wq_ctrl        wq_ctrl;
	struct mlx5_uar            uar;
	struct mlx5e_channel      *channel;
	int                        tc;
	struct mlx5e_ico_wqe_info *ico_wqe_info;
} ____cacheline_aligned_in_smp;

static inline bool mlx5e_sq_has_room_for(struct mlx5e_sq *sq, u16 n)
{
	return (((sq->wq.sz_m1 & (sq->cc - sq->pc)) >= n) ||
		(sq->cc  == sq->pc));
}

enum channel_flags {
	MLX5E_CHANNEL_NAPI_SCHED = 1,
};

struct mlx5e_channel {
	/* data path */
	struct mlx5e_rq            rq;
	struct mlx5e_sq            sq[MLX5E_MAX_NUM_TC];
	struct mlx5e_sq            icosq;   /* internal control operations */
	struct napi_struct         napi;
	struct device             *pdev;
	struct net_device         *netdev;
	__be32                     mkey_be;
	u8                         num_tc;
	unsigned long              flags;

	/* control */
	struct mlx5e_priv         *priv;
	int                        ix;
	int                        cpu;
};

enum mlx5e_traffic_types {
	MLX5E_TT_IPV4_TCP,
	MLX5E_TT_IPV6_TCP,
	MLX5E_TT_IPV4_UDP,
	MLX5E_TT_IPV6_UDP,
	MLX5E_TT_IPV4_IPSEC_AH,
	MLX5E_TT_IPV6_IPSEC_AH,
	MLX5E_TT_IPV4_IPSEC_ESP,
	MLX5E_TT_IPV6_IPSEC_ESP,
	MLX5E_TT_IPV4,
	MLX5E_TT_IPV6,
	MLX5E_TT_ANY,
	MLX5E_NUM_TT,
	MLX5E_NUM_INDIR_TIRS = MLX5E_TT_ANY,
};

enum mlx5e_tir_type {
	MLX5E_INDIR_TIR,
	MLX5E_DIRECT_TIR,
};

struct mlx5e_l2_rule {
	u8  addr[ETH_ALEN + 2];
	struct mlx5_flow_rule *rule;
};

struct mlx5e_flow_table {
	int num_groups;
	struct mlx5_flow_table		*t;
	struct mlx5_flow_group		**g;
};

#define MLX5E_L2_ADDR_HASH_SIZE BIT(BITS_PER_BYTE)

struct mlx5e_l2_table {
	struct mlx5e_flow_table    ft;
	struct hlist_head          netdev_uc[MLX5E_L2_ADDR_HASH_SIZE];
	struct hlist_head          netdev_mc[MLX5E_L2_ADDR_HASH_SIZE];
	struct mlx5e_l2_rule	   broadcast;
	struct mlx5e_l2_rule	   allmulti;
	struct mlx5e_l2_rule	   promisc;
	bool                       broadcast_enabled;
	bool                       allmulti_enabled;
	bool                       promisc_enabled;
};

struct mlx5e_tuple {
	__be16 etype;
	u8     ip_proto;
	union {
		__be32 src_ipv4;
		struct in6_addr src_ipv6;
	};
	union {
		__be32 dst_ipv4;
		struct in6_addr dst_ipv6;
	};
	__be16 src_port;
	__be16 dst_port;
};

struct mlx5e_arfs_rule {
	struct mlx5e_priv	*priv;
	struct work_struct      arfs_work;
	struct mlx5_flow_rule   *rule;
	struct hlist_node	hlist;
	struct list_head	list;
	/* RX queue index */
	int			rxq_index;
	/* Flow ID passed to ndo_rx_flow_steer */
	int			flow_id;
	/* Filter ID returned by ndo_rx_flow_steer */
	int			filter_id;
	struct mlx5e_tuple	tuple;
};

#define MLX5E_ARFS_HASH_SHIFT BITS_PER_BYTE
#define MLX5E_ARFS_HASH_SIZE BIT(BITS_PER_BYTE)
struct mlx5e_arfs_table {
	struct mlx5e_flow_table  ft;
	struct mlx5_flow_rule    *default_rule;
	struct hlist_head	 rules_hash[MLX5E_ARFS_HASH_SIZE];
};

enum  mlx5e_arfs_type {
	MLX5E_ARFS_IPV4_TCP,
	MLX5E_ARFS_IPV6_TCP,
	MLX5E_ARFS_IPV4_UDP,
	MLX5E_ARFS_IPV6_UDP,
	MLX5E_ARFS_NUM_TYPES,
};

struct mlx5e_arfs {
	struct mlx5e_arfs_table		arfs_tables[MLX5E_ARFS_NUM_TYPES];
	/* Protect aRFS rules list */
	spinlock_t			arfs_lock;
	struct list_head		rules;
	int				last_filter_id;
	struct workqueue_struct		*workqueue;
};

enum {
	MLX5E_STATE_ASYNC_EVENTS_ENABLE,
	MLX5E_STATE_OPENED,
	MLX5E_STATE_DESTROYING,
};

struct mlx5e_vlan_db {
	unsigned long active_vlans[BITS_TO_LONGS(VLAN_N_VID)];
	struct mlx5_flow_rule	*active_vlans_rule[VLAN_N_VID];
	struct mlx5_flow_rule	*untagged_rule;
	struct mlx5_flow_rule	*any_vlan_rule;
	bool          filter_disabled;
};

/* L3/L4 traffic type classifier */
struct mlx5e_ttc {
	struct mlx5e_flow_table  ft;
	struct mlx5_flow_rule	 *rules[MLX5E_NUM_TT];
};

struct mlx5e_flow_steering {
	struct mlx5_flow_namespace	*ns;
	struct mlx5e_flow_table		vlan;
	struct mlx5e_l2_table		l2;
	struct mlx5e_ttc		ttc;
	struct mlx5e_arfs		arfs;
};

struct mlx5e_direct_tir {
	u32              tirn;
	u32              rqtn;
};

struct mlx5e_priv {
	/* priv data path fields - start */
	struct mlx5e_sq            **txq_to_sq_map;
	int channeltc_to_txq_map[MLX5E_MAX_NUM_CHANNELS][MLX5E_MAX_NUM_TC];
	/* priv data path fields - end */

	unsigned long              state;
	struct mutex               state_lock; /* Protects Interface state */
	struct mlx5_uar            cq_uar;
	u32                        pdn;
	u32                        tdn;
	u32                        mkey;
	struct mlx5_core_mkey      umr_mr;
	struct mlx5e_rq            drop_rq;

	struct mlx5e_channel     **channel;
	u32                        tisn[MLX5E_MAX_NUM_TC];
	u32                        indir_rqtn;
	u32                        indir_tirn[MLX5E_NUM_INDIR_TIRS];
	struct mlx5e_direct_tir    direct_tir[MLX5E_MAX_NUM_CHANNELS];

	struct mlx5e_flow_steering fs;
	struct mlx5e_vlan_db       vlan;

	struct mlx5e_params        params;
	struct work_struct         update_carrier_work;
	struct work_struct         set_rx_mode_work;
	struct delayed_work        update_stats_work;

	struct mlx5_core_dev      *mdev;
	struct net_device         *netdev;
	struct mlx5e_stats         stats;
	struct mlx5e_tstamp        tstamp;
	bool q_count_valid;
	u16 counter_set_id;

	struct kobject *ecn_root_kobj;
	struct mlx5_ecn_ctx ecn_ctx[MLX5_CONG_PROTOCOL_NUM];
	struct mlx5_ecn_enable_ctx ecn_enable_ctx[MLX5_CONG_PROTOCOL_NUM][8];
};

enum mlx5e_link_mode {
	MLX5E_1000BASE_CX_SGMII	 = 0,
	MLX5E_1000BASE_KX	 = 1,
	MLX5E_10GBASE_CX4	 = 2,
	MLX5E_10GBASE_KX4	 = 3,
	MLX5E_10GBASE_KR	 = 4,
	MLX5E_20GBASE_KR2	 = 5,
	MLX5E_40GBASE_CR4	 = 6,
	MLX5E_40GBASE_KR4	 = 7,
	MLX5E_56GBASE_R4	 = 8,
	MLX5E_10GBASE_CR	 = 12,
	MLX5E_10GBASE_SR	 = 13,
	MLX5E_10GBASE_ER	 = 14,
	MLX5E_40GBASE_SR4	 = 15,
	MLX5E_40GBASE_LR4	 = 16,
	MLX5E_100GBASE_CR4	 = 20,
	MLX5E_100GBASE_SR4	 = 21,
	MLX5E_100GBASE_KR4	 = 22,
	MLX5E_100GBASE_LR4	 = 23,
	MLX5E_100BASE_TX	 = 24,
	MLX5E_100BASE_T		 = 25,
	MLX5E_10GBASE_T		 = 26,
	MLX5E_25GBASE_CR	 = 27,
	MLX5E_25GBASE_KR	 = 28,
	MLX5E_25GBASE_SR	 = 29,
	MLX5E_50GBASE_CR2	 = 30,
	MLX5E_50GBASE_KR2	 = 31,
	MLX5E_LINK_MODES_NUMBER,
};

#define MLX5E_PROT_MASK(link_mode) (1 << link_mode)

void mlx5e_send_nop(struct mlx5e_sq *sq, bool notify_hw);
u16 mlx5e_select_queue(struct net_device *dev, struct sk_buff *skb,
		       void *accel_priv, select_queue_fallback_t fallback);
netdev_tx_t mlx5e_xmit(struct sk_buff *skb, struct net_device *dev);

void mlx5e_completion_event(struct mlx5_core_cq *mcq);
void mlx5e_cq_error_event(struct mlx5_core_cq *mcq, enum mlx5_event event);
int mlx5e_napi_poll(struct napi_struct *napi, int budget);
bool mlx5e_poll_tx_cq(struct mlx5e_cq *cq);
int mlx5e_poll_rx_cq(struct mlx5e_cq *cq, int budget);

void mlx5e_handle_rx_cqe(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe);
void mlx5e_handle_rx_cqe_mpwrq(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe);
bool mlx5e_post_rx_wqes(struct mlx5e_rq *rq);
int mlx5e_alloc_rx_wqe(struct mlx5e_rq *rq, struct mlx5e_rx_wqe *wqe, u16 ix);
int mlx5e_alloc_rx_mpwqe(struct mlx5e_rq *rq, struct mlx5e_rx_wqe *wqe, u16 ix);
void mlx5e_post_rx_fragmented_mpwqe(struct mlx5e_rq *rq);
void mlx5e_complete_rx_linear_mpwqe(struct mlx5e_rq *rq,
				    struct mlx5_cqe64 *cqe,
				    struct mlx5e_mpw_info *wi,
				    struct sk_buff *skb);
void mlx5e_complete_rx_fragmented_mpwqe(struct mlx5e_rq *rq,
					struct mlx5_cqe64 *cqe,
					struct mlx5e_mpw_info *wi,
					struct sk_buff *skb);
void mlx5e_free_rx_linear_mpwqe(struct mlx5e_rq *rq,
				struct mlx5e_mpw_info *wi);
void mlx5e_free_rx_fragmented_mpwqe(struct mlx5e_rq *rq,
				    struct mlx5e_mpw_info *wi);
struct mlx5_cqe64 *mlx5e_get_cqe(struct mlx5e_cq *cq);

void mlx5e_update_stats(struct mlx5e_priv *priv);

int mlx5e_create_flow_tables(struct mlx5e_priv *priv);
void mlx5e_destroy_flow_tables(struct mlx5e_priv *priv);
void mlx5e_init_l2_addr(struct mlx5e_priv *priv);
void mlx5e_set_rx_mode_work(struct work_struct *work);

void mlx5e_fill_hwstamp(struct mlx5e_tstamp *clock, u64 timestamp,
			struct skb_shared_hwtstamps *hwts);
void mlx5e_timestamp_init(struct mlx5e_priv *priv);
void mlx5e_timestamp_cleanup(struct mlx5e_priv *priv);
int mlx5e_hwstamp_set(struct net_device *dev, struct ifreq *ifr);
int mlx5e_hwstamp_get(struct net_device *dev, struct ifreq *ifr);

int mlx5e_vlan_rx_add_vid(struct net_device *dev, __always_unused __be16 proto,
			  u16 vid);
int mlx5e_vlan_rx_kill_vid(struct net_device *dev, __always_unused __be16 proto,
			   u16 vid);
void mlx5e_enable_vlan_filter(struct mlx5e_priv *priv);
void mlx5e_disable_vlan_filter(struct mlx5e_priv *priv);

int mlx5e_redirect_rqt(struct mlx5e_priv *priv, enum mlx5e_tir_type type,
		       int ix);
void mlx5e_build_tir_ctx_hash(void *tirc, struct mlx5e_priv *priv);

int mlx5e_open_locked(struct net_device *netdev);
int mlx5e_close_locked(struct net_device *netdev);
void mlx5e_build_default_indir_rqt(u32 *indirection_rqt, int len,
				   int num_channels);
int mlx5e_sysfs_create(struct net_device *dev);
void mlx5e_sysfs_remove(struct net_device *dev);

#if CONFIG_RFS_ACCEL
int mlx5e_enable_arfs(struct mlx5e_priv *priv);
int mlx5e_disable_arfs(struct mlx5e_priv *priv);
int mlx5e_rx_flow_steer(struct net_device *dev, const struct sk_buff *skb,
			u16 rxq_index, u32 flow_id);
#endif

static inline void mlx5e_tx_notify_hw(struct mlx5e_sq *sq,
				      struct mlx5_wqe_ctrl_seg *ctrl, int bf_sz)
{
	u16 ofst = MLX5_BF_OFFSET + sq->bf_offset;

	/* ensure wqe is visible to device before updating doorbell record */
	dma_wmb();

	*sq->wq.db = cpu_to_be32(sq->pc);

	/* ensure doorbell record is visible to device before ringing the
	 * doorbell
	 */
	wmb();

	if (bf_sz) {
		__iowrite64_copy(sq->uar_bf_map + ofst, ctrl, bf_sz);

		/* flush the write-combining mapped buffer */
		wmb();

	} else {
		mlx5_write64((__be32 *)ctrl, sq->uar_map + ofst, NULL);
	}

	sq->bf_offset ^= sq->bf_buf_size;
}

static inline void mlx5e_cq_arm(struct mlx5e_cq *cq)
{
	struct mlx5_core_cq *mcq;

	mcq = &cq->mcq;
	mlx5_cq_arm(mcq, MLX5_CQ_DB_REQ_NOT, mcq->uar->map, NULL, cq->wq.cc);
}

static inline int mlx5e_get_max_num_channels(struct mlx5_core_dev *mdev)
{
	return min_t(int, mdev->priv.eq_table.num_comp_vectors,
		     MLX5E_MAX_NUM_CHANNELS);
}

static inline int mlx5e_get_mtt_octw(int npages)
{
	return ALIGN(npages, 8) / 2;
}

extern const struct ethtool_ops mlx5e_ethtool_ops;
#ifdef CONFIG_MLX5_CORE_EN_DCB
extern const struct dcbnl_rtnl_ops mlx5e_dcbnl_ops;
int mlx5e_dcbnl_ieee_setets_core(struct mlx5e_priv *priv, struct ieee_ets *ets);
#endif

u16 mlx5e_get_max_inline_cap(struct mlx5_core_dev *mdev);
