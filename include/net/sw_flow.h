/*
 * include/net/sw_flow.h - Generic switch flow structures
 * Copyright (c) 2007-2012 Nicira, Inc.
 * Copyright (c) 2014 Jiri Pirko <jiri@resnulli.us>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _NET_SW_FLOW_H_
#define _NET_SW_FLOW_H_

enum sw_flow_tunnel_type {
	SW_FLOW_TUNNEL_NONE,
	SW_FLOW_TUNNEL_VXLAN,
};

struct sw_flow_key_ipv4_tunnel {
	__be64 tun_id;
	__be32 ipv4_src;
	__be32 ipv4_dst;
	__be16 tun_flags;
	u8   ipv4_tos;
	u8   ipv4_ttl;
	__be16 tp_src;
	__be16 tp_dst;
} __packed __aligned(4); /* Minimize padding. */

struct sw_flow_key {
	u8 tun_opts[255];
	u8 tun_opts_len;
	struct sw_flow_key_ipv4_tunnel tun_key;  /* Encapsulating tunnel key. */
	struct {
		u32	priority;	/* Packet QoS priority. */
		u32	skb_mark;	/* SKB mark. */
		u16	in_port;	/* Input switch port (or DP_MAX_PORTS). */
	} __packed phy; /* Safe when right after 'tun_key'. */
	u32 ovs_flow_hash;		/* Datapath computed hash value.  */
	u32 recirc_id;			/* Recirculation ID.  */
	struct {
		u8     src[ETH_ALEN];	/* Ethernet source address. */
		u8     dst[ETH_ALEN];	/* Ethernet destination address. */
		__be16 tci;		/* 0 if no VLAN, VLAN_TAG_PRESENT set otherwise. */
		__be16 type;		/* Ethernet frame type. */
	} eth;
	union {
		struct {
			__be32 top_lse;	/* top label stack entry */
		} mpls;
		struct {
			u8     proto;	/* IP protocol or lower 8 bits of ARP opcode. */
			u8     tos;	    /* IP ToS. */
			u8     ttl;	    /* IP TTL/hop limit. */
			u8     frag;	/* One of OVS_FRAG_TYPE_*. */
		} ip;
	};
	struct {
		__be16 src;		/* TCP/UDP/SCTP source port. */
		__be16 dst;		/* TCP/UDP/SCTP destination port. */
		__be16 flags;		/* TCP flags. */
	} tp;
	union {
		struct {
			struct {
				__be32 src;	/* IP source address. */
				__be32 dst;	/* IP destination address. */
			} addr;
			struct {
				u8 sha[ETH_ALEN];	/* ARP source hardware address. */
				u8 tha[ETH_ALEN];	/* ARP target hardware address. */
			} arp;
		} ipv4;
		struct {
			struct {
				struct in6_addr src;	/* IPv6 source address. */
				struct in6_addr dst;	/* IPv6 destination address. */
			} addr;
			__be32 label;			/* IPv6 flow label. */
			struct {
				struct in6_addr target;	/* ND target address. */
				u8 sll[ETH_ALEN];	/* ND source link layer address. */
				u8 tll[ETH_ALEN];	/* ND target link layer address. */
			} nd;
		} ipv6;
	};
} __aligned(BITS_PER_LONG/8); /* Ensure that we can do comparisons as longs. */

struct sw_flow_key_range {
	unsigned short int start;
	unsigned short int end;
};

struct sw_flow_mask {
	struct sw_flow_key_range range;
	struct sw_flow_key key;
};

enum sw_flow_action_type {
	SW_FLOW_ACTION_TYPE_OUTPUT,
	SW_FLOW_ACTION_TYPE_VLAN_PUSH,
	SW_FLOW_ACTION_TYPE_VLAN_POP,
	SW_FLOW_ACTION_TYPE_DROP,
};

struct sw_flow_action {
	enum sw_flow_action_type type;
	union {
		u32 out_port_ifindex;
		struct {
			__be16 vlan_proto;
			u16 vlan_tci;
		} vlan;
	};
};

struct sw_flow_actions {
	unsigned count;
	struct sw_flow_action actions[0];
};

struct sw_flow {
	struct sw_flow_key key;
	struct sw_flow_key unmasked_key;
	struct sw_flow_mask *mask;
	struct sw_flow_actions *actions;
	enum sw_flow_tunnel_type tunnel_type;
	u16 tunnel_port;
};

#endif /* _NET_SW_FLOW_H_ */
