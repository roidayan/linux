/*
 * Copyright (c) 2007-2014 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef FLOW_H
#define FLOW_H 1

#include <linux/cache.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/flex_array.h>
#include <net/inet_ecn.h>
#include <net/sw_flow.h>

struct sk_buff;

/* Used to memset ovs_key_ipv4_tunnel padding. */
#define OVS_TUNNEL_KEY_SIZE					\
	(offsetof(struct sw_flow_key_ipv4_tunnel, tp_dst) +		\
	 FIELD_SIZEOF(struct sw_flow_key_ipv4_tunnel, tp_dst))

struct ovs_tunnel_info {
	struct sw_flow_key_ipv4_tunnel tunnel;
	const void *options;
	u8 options_len;
};

/* Store options at the end of the array if they are less than the
 * maximum size. This allows us to get the benefits of variable length
 * matching for small options.
 */
#define TUN_METADATA_OFFSET(opt_len) \
	(FIELD_SIZEOF(struct sw_flow_key, tun_opts) - opt_len)
#define TUN_METADATA_OPTS(flow_key, opt_len) \
	((void *)((flow_key)->tun_opts + TUN_METADATA_OFFSET(opt_len)))

static inline void __ovs_flow_tun_info_init(struct ovs_tunnel_info *tun_info,
					    __be32 saddr, __be32 daddr,
					    u8 tos, u8 ttl,
					    __be16 tp_src,
					    __be16 tp_dst,
					    __be64 tun_id,
					    __be16 tun_flags,
					    const void *opts,
					    u8 opts_len)
{
	tun_info->tunnel.tun_id = tun_id;
	tun_info->tunnel.ipv4_src = saddr;
	tun_info->tunnel.ipv4_dst = daddr;
	tun_info->tunnel.ipv4_tos = tos;
	tun_info->tunnel.ipv4_ttl = ttl;
	tun_info->tunnel.tun_flags = tun_flags;

	/* For the tunnel types on the top of IPsec, the tp_src and tp_dst of
	 * the upper tunnel are used.
	 * E.g: GRE over IPSEC, the tp_src and tp_port are zero.
	 */
	tun_info->tunnel.tp_src = tp_src;
	tun_info->tunnel.tp_dst = tp_dst;

	/* Clear struct padding. */
	if (sizeof(tun_info->tunnel) != OVS_TUNNEL_KEY_SIZE)
		memset((unsigned char *)&tun_info->tunnel + OVS_TUNNEL_KEY_SIZE,
		       0, sizeof(tun_info->tunnel) - OVS_TUNNEL_KEY_SIZE);

	tun_info->options = opts;
	tun_info->options_len = opts_len;
}

static inline void ovs_flow_tun_info_init(struct ovs_tunnel_info *tun_info,
					  const struct iphdr *iph,
					  __be16 tp_src,
					  __be16 tp_dst,
					  __be64 tun_id,
					  __be16 tun_flags,
					  const void *opts,
					  u8 opts_len)
{
	__ovs_flow_tun_info_init(tun_info, iph->saddr, iph->daddr,
				 iph->tos, iph->ttl,
				 tp_src, tp_dst,
				 tun_id, tun_flags,
				 opts, opts_len);
}

#define OVS_SW_FLOW_KEY_METADATA_SIZE			\
	(offsetof(struct sw_flow_key, recirc_id) +	\
	FIELD_SIZEOF(struct sw_flow_key, recirc_id))

struct ovs_flow_mask {
	int ref_count;
	struct rcu_head rcu;
	struct list_head list;
	struct sw_flow_mask mask;
};

struct ovs_flow_match {
	struct sw_flow_key *key;
	struct sw_flow_key_range range;
	struct sw_flow_mask *mask;
};

#define MAX_UFID_LENGTH 16 /* 128 bits */

struct sw_flow_id {
	u32 ufid_len;
	union {
		u32 ufid[MAX_UFID_LENGTH / 4];
		struct sw_flow_key *unmasked_key;
	};
};

struct ovs_flow_actions {
	struct rcu_head rcu;
	u32 actions_len;
	struct nlattr actions[];
};

struct flow_stats {
	u64 packet_count;		/* Number of packets matched. */
	u64 byte_count;			/* Number of bytes matched. */
	unsigned long used;		/* Last used time (in jiffies). */
	spinlock_t lock;		/* Lock for atomic stats update. */
	__be16 tcp_flags;		/* Union of seen TCP flags. */
};

struct ovs_flow {
	struct rcu_head rcu;
	struct {
		struct hlist_node node[2];
		u32 hash;
	} flow_table, ufid_table;
	int stats_last_writer;		/* NUMA-node id of the last writer on
					 * 'stats[0]'.
					 */
	struct sw_flow flow;
	struct sw_flow_id id;
	struct ovs_flow_actions __rcu *sf_acts;
	struct flow_stats __rcu *stats[]; /* One for each NUMA node.  First one
					   * is allocated at flow creation time,
					   * the rest are allocated on demand
					   * while holding the 'stats[0].lock'.
					   */
};

struct arp_eth_header {
	__be16      ar_hrd;	/* format of hardware address   */
	__be16      ar_pro;	/* format of protocol address   */
	unsigned char   ar_hln;	/* length of hardware address   */
	unsigned char   ar_pln;	/* length of protocol address   */
	__be16      ar_op;	/* ARP opcode (command)     */

	/* Ethernet+IPv4 specific members. */
	unsigned char       ar_sha[ETH_ALEN];	/* sender hardware address  */
	unsigned char       ar_sip[4];		/* sender IP address        */
	unsigned char       ar_tha[ETH_ALEN];	/* target hardware address  */
	unsigned char       ar_tip[4];		/* target IP address        */
} __packed;

static inline bool ovs_identifier_is_ufid(const struct sw_flow_id *sfid)
{
	return sfid->ufid_len;
}

static inline bool ovs_identifier_is_key(const struct sw_flow_id *sfid)
{
	return !ovs_identifier_is_ufid(sfid);
}

void ovs_flow_stats_update(struct ovs_flow *, __be16 tcp_flags,
			   const struct sk_buff *);
void ovs_flow_stats_get(const struct ovs_flow *, struct ovs_flow_stats *,
			unsigned long *used, __be16 *tcp_flags);
void ovs_flow_stats_clear(struct ovs_flow *);
u64 ovs_flow_used_time(unsigned long flow_jiffies);

int ovs_flow_key_update(struct sk_buff *skb, struct sw_flow_key *key);
int ovs_flow_key_extract(const struct ovs_tunnel_info *tun_info,
			 struct sk_buff *skb,
			 struct sw_flow_key *key);
/* Extract key from packet coming from userspace. */
int ovs_flow_key_extract_userspace(const struct nlattr *attr,
				   struct sk_buff *skb,
				   struct sw_flow_key *key, bool log);

#endif /* flow.h */
