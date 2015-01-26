#ifndef _MLX4_STATS_
#define _MLX4_STATS_

#ifdef MLX4_EN_PERF_STAT
#define NUM_PERF_STATS			NUM_PERF_COUNTERS
#else
#define NUM_PERF_STATS			0
#endif

#define NUM_PRIORITIES	9
#define NUM_PRIORITY_STATS 2

struct mlx4_en_pkt_stats {
	unsigned long rx_packets;
	unsigned long rx_bytes;
	unsigned long rx_multicast_packets;
	unsigned long rx_broadcast_packets;
	unsigned long rx_errors;
	unsigned long rx_dropped;
	unsigned long rx_length_errors;
	unsigned long rx_over_errors;
	unsigned long rx_crc_errors;
	unsigned long rx_jabbers;
	unsigned long rx_in_range_length_error;
	unsigned long rx_out_range_length_error;
	unsigned long rx_lt_64_bytes_packets;
	unsigned long rx_127_bytes_packets;
	unsigned long rx_255_bytes_packets;
	unsigned long rx_511_bytes_packets;
	unsigned long rx_1023_bytes_packets;
	unsigned long rx_1518_bytes_packets;
	unsigned long rx_1522_bytes_packets;
	unsigned long rx_1548_bytes_packets;
	unsigned long rx_gt_1548_bytes_packets;
	unsigned long tx_packets;
	unsigned long tx_bytes;
	unsigned long tx_multicast_packets;
	unsigned long tx_broadcast_packets;
	unsigned long tx_errors;
	unsigned long tx_dropped;
	unsigned long tx_lt_64_bytes_packets;
	unsigned long tx_127_bytes_packets;
	unsigned long tx_255_bytes_packets;
	unsigned long tx_511_bytes_packets;
	unsigned long tx_1023_bytes_packets;
	unsigned long tx_1518_bytes_packets;
	unsigned long tx_1522_bytes_packets;
	unsigned long tx_1548_bytes_packets;
	unsigned long tx_gt_1548_bytes_packets;
	unsigned long rx_prio[NUM_PRIORITIES][NUM_PRIORITY_STATS];
	unsigned long tx_prio[NUM_PRIORITIES][NUM_PRIORITY_STATS];
#define NUM_PKT_STATS		72
};

struct mlx4_en_port_stats {
	unsigned long tx_tso_packets;
	unsigned long xmit_more;
	unsigned long tx_queue_stopped;
	unsigned long tx_wake_queue;
	unsigned long tx_timeout;
	unsigned long rx_alloc_failed;
	unsigned long rx_chksum_good;
	unsigned long rx_chksum_none;
	unsigned long rx_chksum_complete;
	unsigned long tx_chksum_offload;
#define NUM_PORT_STATS		10
};

struct mlx4_en_perf_stats {
	u32 tx_poll;
	u64 tx_pktsz_avg;
	u32 inflight_avg;
	u16 tx_coal_avg;
	u16 rx_coal_avg;
	u32 napi_quota;
#define NUM_PERF_COUNTERS		6
};

#define NUM_ALL_STATS	(NUM_PKT_STATS + \
			 NUM_PORT_STATS + NUM_PERF_STATS)
#endif
