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

#include <net/switchdev.h>
#include <generated/utsrelease.h>
#include <linux/mlx5/flow_table.h>
#include <net/sw_flow.h>
#include <uapi/linux/openvswitch.h>
#include <net/ip_tunnels.h>
#include <net/vxlan.h>

#include "en.h"
#include "eswitch.h"
#include "en_rep.h"
#include "eswitch.h"

#define MATCH_PARAMS_SIZE MLX5_ST_SZ_DW(fte_match_param)

#define INVALID_FLOW_IX  (-1)

struct mlx5e_encap_info {
	enum sw_flow_tunnel_type tunnel_type;
	__be32 daddr;
/* TODO what if OVS want a different src addr ?*/
	__be32 tun_id;
	__be16 tp_dst;
};

struct mlx5e_encap_entry {
	struct hlist_node encap_hlist;
	struct list_head flows;
	u32 encap_id;
	struct neighbour *n;
	struct mlx5e_encap_info tun_info;

	bool valid_encap;
};

struct mlx5_flow_attr {
	struct sw_flow *sw_flow;
	struct mlx5e_priv *pf_dev;
	struct net *net;
	struct mlx5e_vf_rep *in_rep;
	struct mlx5e_vf_rep *out_rep;
	u32 match_c[MATCH_PARAMS_SIZE];
	u32 match_v[MATCH_PARAMS_SIZE];
	int mlx5_action;
	u16 mlx5_vlan;

	struct mlx5e_encap_entry *encap;
};

/* The default UDP port that ConnectX firmware uses for its VXLAN parser */
#define MLX5_DEFAULT_VXLAN_UDP_DPORT (4789)
static int check_vxlan_port(u16 port)
{
	/* TODO enable other UDP ports with the ADD_VXLAN_UDP_PORT
	 * firmware command
	 */
	if (port != MLX5_DEFAULT_VXLAN_UDP_DPORT)
		return -EOPNOTSUPP;

	return 0;
}

static int parse_vxlan_attr(struct mlx5_flow_attr *attr)
{
	struct sw_flow_key_ipv4_tunnel *key = &attr->sw_flow->key.tun_key;
	struct sw_flow_key_ipv4_tunnel *mask =
				&attr->sw_flow->mask->key.tun_key;
	void *headers_c = MLX5_ADDR_OF(fte_match_param, attr->match_c,
				       outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, attr->match_v,
				       outer_headers);
	void *misc_c = MLX5_ADDR_OF(fte_match_param, attr->match_c,
				    misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, attr->match_v,
				    misc_parameters);
	u16 dst_port = attr->sw_flow->tunnel_port;

	if (check_vxlan_port(dst_port))
		return -EOPNOTSUPP;

	if (mask->tun_flags & TUNNEL_KEY) {
		MLX5_SET(fte_match_set_misc, misc_c, vxlan_vni,
			 be64_to_cpu(mask->tun_id));
		MLX5_SET(fte_match_set_misc, misc_v, vxlan_vni,
			 be64_to_cpu(key->tun_id));
	}

	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_protocol);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol, IPPROTO_UDP);

	MLX5_SET(fte_match_set_lyr_2_4, headers_c, udp_sport,
		 ntohs(mask->tp_src));
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_sport,
		 ntohs(key->tp_src));

	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, udp_dport);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_dport, dst_port);

	return 0;
}

static int parse_tunnel_attr(struct mlx5_flow_attr *attr)
{
	void *headers_c = MLX5_ADDR_OF(fte_match_param, attr->match_c,
				       outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, attr->match_v,
				       outer_headers);

	struct sw_flow_key_ipv4_tunnel *key = &attr->sw_flow->key.tun_key;
	struct sw_flow_key_ipv4_tunnel *mask =
			&attr->sw_flow->mask->key.tun_key;

	switch (attr->sw_flow->tunnel_type) {
	case SW_FLOW_TUNNEL_VXLAN:
		if (parse_vxlan_attr(attr))
			return -EOPNOTSUPP;
		break;
	default:
		return -EOPNOTSUPP;
	}

	/* TODO: In a VXLAN netdev, the MAC address is filtered based
	 * on the source port netdev's address. Consider doing it for offloads.
	 */

	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ethertype);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype, ETH_P_IP);

	if (mask->ipv4_tos >> 2) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_dscp,
			 mask->ipv4_tos >> 2);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_dscp,
			 key->ipv4_tos  >> 2);
	}

	if (mask->ipv4_tos & 0x3) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_ecn,
			 mask->ipv4_tos & 0x3);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_ecn,
			 key->ipv4_tos & 0x3);
	}

	if (mask->ipv4_ttl) {
		pr_warn_once("%s: non zero mask %x (val %d) for IP TTL, unsupported by mlx5 hardware\n",
			     __func__, mask->ipv4_ttl, key->ipv4_ttl);
	}

	if (mask->tun_flags & TUNNEL_CSUM) {
		pr_warn_once("%s: mlx5 hardware cannot enforce %s checksum\n",
			     __func__, mask->tun_flags & TUNNEL_CSUM ?
			     "zero" : "non-zero");
	}

	if (mask->tun_flags & TUNNEL_DONT_FRAGMENT) {
		pr_warn_once("%s: mlx5 hardware cannot enforce don't fragment flag, request value is %d\n",
			     __func__, key->tun_flags & TUNNEL_DONT_FRAGMENT);
	}

	/* let software handle IP fragments */
	MLX5_SET(fte_match_set_lyr_2_4, headers_c, frag, 1);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, frag, 0);

	if (mask->ipv4_src) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, src_ip[3],
			 ntohl(mask->ipv4_src));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, src_ip[3],
			 ntohl(key->ipv4_src));
	}

	if (mask->ipv4_dst) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, dst_ip[3],
			 ntohl(mask->ipv4_dst));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, dst_ip[3],
			 ntohl(key->ipv4_dst));
	}

	return 0;
}

static int parse_flow_attr(struct mlx5_flow_attr *attr)
{
	struct sw_flow_key *key  = &attr->sw_flow->key;
	struct sw_flow_key *mask = &attr->sw_flow->mask->key;

	void *headers_c = MLX5_ADDR_OF(fte_match_param, attr->match_c,
				       outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, attr->match_v,
				       outer_headers);

	void *misc_c = MLX5_ADDR_OF(fte_match_param, attr->match_c,
				    misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, attr->match_v,
				    misc_parameters);

	u8 zero_mac[ETH_ALEN];

	eth_zero_addr(zero_mac);

	/* set source vport for the flow */
	MLX5_SET(fte_match_set_misc, misc_c, source_port, 0xffff);
	MLX5_SET(fte_match_set_misc, misc_v, source_port, attr->in_rep->vport);

	if (mask->tun_key.tun_flags &
	   ~(TUNNEL_KEY | TUNNEL_DONT_FRAGMENT | TUNNEL_CSUM)) {
		dev_warn_ratelimited(&attr->in_rep->dev->dev,
				     "got unknown tunnel flag in flow: 0x%x\n",
				     be16_to_cpu(mask->tun_key.tun_flags));
		return -EOPNOTSUPP;
	}

	if (attr->sw_flow->tunnel_type != SW_FLOW_TUNNEL_NONE) {
		if (parse_tunnel_attr(attr))
			return -EOPNOTSUPP;

		headers_c = MLX5_ADDR_OF(fte_match_param, attr->match_c,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, attr->match_v,
					 inner_headers);
	}

	if (memcmp(&mask->eth.src, zero_mac, ETH_ALEN)) {
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c, smac_47_16),
		       &mask->eth.src, ETH_ALEN);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, smac_47_16),
		       &key->eth.src, ETH_ALEN);
	}

	if (memcmp(&mask->eth.dst, zero_mac, ETH_ALEN)) {
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c, dmac_47_16),
		       &mask->eth.dst, ETH_ALEN);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, dmac_47_16),
		       &key->eth.dst, ETH_ALEN);
	}

	if ((ntohs(key->eth.tci) & VLAN_TAG_PRESENT) &&
	    (ntohs(mask->eth.tci) & VLAN_TAG_PRESENT)) {
		pr_debug("flow has VLAN tci mask %x key %x\n",
			 ntohs(mask->eth.tci), ntohs(key->eth.tci));
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, vlan_tag, 1);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, vlan_tag, 1);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, first_vid,
			 ntohs(mask->eth.tci) & VLAN_VID_MASK);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, first_vid,
			 ntohs(key->eth.tci) & VLAN_VID_MASK);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, first_prio,
			 ntohs(mask->eth.tci) >> VLAN_PRIO_SHIFT);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, first_prio,
			 ntohs(key->eth.tci) >> VLAN_PRIO_SHIFT);
	}

	/* on SX insertion is done after SX steering
	 * on RX stripping is done after RX steering
	 * src	      dst
	 * VM	 -->  VM	:: problematic in RX steering (VST)
	 * VM	 -->  UPLINK	:: no-vlan matching is unsupported by FW
	 * UPLINK --> VM	:: this one we can support
	 * as such we disallow matching on NO vlan for src being a VM
	 */
	if ((ntohs(mask->eth.tci) & VLAN_TAG_PRESENT) &&
	      !(ntohs(key->eth.tci) & VLAN_TAG_PRESENT)) {
		if (attr->in_rep->vport != FDB_UPLINK_VPORT) {
			pr_debug("NO vlan matches from non-uplink src disallowed with VST, ignoring\n");
		} else {
			MLX5_SET(fte_match_set_lyr_2_4, headers_c, vlan_tag, 1);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v, vlan_tag, 0);
		}
	}

	if (mask->eth.type) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ethertype, ntohs(mask->eth.type));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype, ntohs(key->eth.type));
	}

	if ((key->eth.type == ntohs(ETH_P_IPV6) && mask->eth.type) &&
	    memchr_inv(&mask->ipv6, 0, sizeof(mask->ipv6))) {
		pr_warn("flow matching on IPv6 header isn't supported yet\n");
		goto out_err;
	}

	if (mask->ip.proto) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_protocol, mask->ip.proto);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol, key->ip.proto);
	}

	if (mask->ip.tos >> 2) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_dscp, mask->ip.tos >> 2);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_dscp, key->ip.tos  >> 2);
	}

	if (mask->ip.tos & 0x3) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_ecn, mask->ip.tos & 0x3);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_ecn, key->ip.tos  & 0x3);
	}

	if (mask->ip.ttl) {
		printk(KERN_ERR "%s non zero mask %x (val %d) for IP TTL, unsupported by PRM\n",
		       __func__, mask->ip.ttl, key->ip.ttl);
		goto out_err;
	}

	if (mask->ip.frag && key->ip.frag == OVS_FRAG_TYPE_NONE) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, frag, 1);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, frag, 0);
	} else if (mask->ip.frag && key->ip.frag != OVS_FRAG_TYPE_NONE) {
		printk(KERN_ERR "%s non zero val for OVS_FRAG %d, supported by PRM?!\n",
			__func__, key->ip.frag);
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, frag, 1);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, frag, 1);
	}

	/* PRM mandates ip protocol full match to set rules on UDP/TCP ports using one rule */
	if (mask->tp.src && mask->ip.proto && key->ip.proto == IPPROTO_TCP) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, tcp_sport, ntohs(mask->tp.src));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_sport, ntohs(key->tp.src));
	}

	if (mask->tp.dst && mask->ip.proto && key->ip.proto == IPPROTO_TCP) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, tcp_dport, ntohs(mask->tp.dst));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_dport, ntohs(key->tp.dst));
	}

	if (mask->tp.flags) {
		pr_warn("flow matching on TCP flags need validating, falling back to slowpath\n");
		goto out_err;

		if (mask->tp.flags & htons(0xff00))
			goto out_err;

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, tcp_flags,
			 ntohs(mask->tp.flags));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_flags,
			 ntohs(key->tp.flags));
	}

	/* PRM mandates ip protocol full match to set rules on UDP/TCP ports using one rule */
	if (mask->tp.src && mask->ip.proto && key->ip.proto == IPPROTO_UDP) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, udp_sport, ntohs(mask->tp.src));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_sport, ntohs(key->tp.src));
	}

	if (mask->tp.dst && mask->ip.proto && key->ip.proto == IPPROTO_UDP) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, udp_dport, ntohs(mask->tp.dst));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_dport, ntohs(key->tp.dst));
	}

	if (mask->ipv4.addr.src && key->eth.type == ntohs(ETH_P_IP)) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, src_ip[3], ntohl(mask->ipv4.addr.src));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, src_ip[3], ntohl(key->ipv4.addr.src));
	}

	if (mask->ipv4.addr.dst && key->eth.type == ntohs(ETH_P_IP)) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, dst_ip[3], ntohl(mask->ipv4.addr.dst));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, dst_ip[3], ntohl(key->ipv4.addr.dst));
	}

	if ((key->eth.type == ntohs(ETH_P_ARP) || key->eth.type == ntohs(ETH_P_RARP)) &&
	    (memcmp(&mask->ipv4.arp.sha, zero_mac, ETH_ALEN) || mask->ipv4.addr.src ||
	    memcmp(&mask->ipv4.arp.tha, zero_mac, ETH_ALEN) || mask->ipv4.addr.dst)) {
		pr_warn("flow matching on ARP/RARP payload is unsupported\n");
		goto out_err;
	}

	/* FIXME: add IPv6 src/dst addressed */
	if (mask->ipv6.label) {
		/* TODO use the misc section and put the flow label there */
	}


	return 0;

out_err:

	return -EOPNOTSUPP;
}

static u8 generate_match_criteria_enable(u32 *match_c)
{
	u8 match_criteria_enable = 0;
	void *outer_headers_c = MLX5_ADDR_OF(fte_match_param, match_c,
					      outer_headers);
	void *inner_headers_c = MLX5_ADDR_OF(fte_match_param, match_c,
					      inner_headers);
	void *misc_c = MLX5_ADDR_OF(fte_match_param, match_c,
				     misc_parameters);
	size_t header_size = MLX5_ST_SZ_BYTES(fte_match_set_lyr_2_4);
	size_t misc_size = MLX5_ST_SZ_BYTES(fte_match_set_misc);

	if (memchr_inv(outer_headers_c, 0, header_size))
		match_criteria_enable |= MLX5_MATCH_OUTER_HEADERS;
	if (memchr_inv(misc_c, 0, misc_size))
		match_criteria_enable |= MLX5_MATCH_MISC_PARAMETERS;
	if (memchr_inv(inner_headers_c, 0, header_size))
		match_criteria_enable |= MLX5_MATCH_INNER_HEADERS;

	return match_criteria_enable;
}

enum mlx5_flow_action_type {
	MLX5_FLOW_ACTION_TYPE_OUTPUT    = 1 << SW_FLOW_ACTION_TYPE_OUTPUT,
	MLX5_FLOW_ACTION_TYPE_VLAN_PUSH = 1 << SW_FLOW_ACTION_TYPE_VLAN_PUSH,
	MLX5_FLOW_ACTION_TYPE_VLAN_POP  = 1 << SW_FLOW_ACTION_TYPE_VLAN_POP,
	MLX5_FLOW_ACTION_TYPE_DROP	= 1 << SW_FLOW_ACTION_TYPE_DROP,
	MLX5_FLOW_ACTION_TYPE_ENCAP     = 1 << SW_FLOW_ACTION_TYPE_ENCAP,
};

int mlx5_create_flow_group(void *ft, struct mlx5_flow_table_group *g,
			   u32 start_ix, u32 *id);

struct mlx5_flow_group {
	struct kref kref;
	u32 match_c[MATCH_PARAMS_SIZE];
	u32 group_ix;
	struct mlx5_flow_table_group g;

	struct list_head groups_list; /* list of groups */
	struct list_head flows_list;  /* flows for this group */
	struct mlx5_eswitch *eswitch;
};

struct mlx5_flow {
	u32 match_v[MATCH_PARAMS_SIZE];
	u32 flow_index;
	struct mlx5e_vf_rep *out_rep;
	int mlx5_action;

	struct mlx5_flow_group *group;
	struct list_head group_list; /* flows of the mother group */
	struct list_head encap; /* flows sharing the same encap */
};

enum {
	FLOW_ADD = 0x1,
	FLOW_DEL = 0x2
};

static int route_lookup(struct mlx5e_priv *pf_dev,
			struct flowi4 *fl4,
			struct neighbour **out_n,
			__be32 *saddr,
			int *out_ttl)
{
	struct rtable *rt;
	struct neighbour *n = NULL;
	int ttl;

	/* TODO: get the right name space */
	rt = ip_route_output_key(dev_net(pf_dev->netdev), fl4);
	if (IS_ERR(rt)) {
		/* TODO fl4.daddr is BE */
		pr_warn("%s: no route to %pI4\n",
			__func__, &fl4->daddr);
		return -EOPNOTSUPP;
	}
	if (rt->dst.dev != pf_dev->netdev) {
		pr_warn("%s: flow was routed to a different netdev\n",
			__func__);
		ip_rt_put(rt);
		return -EOPNOTSUPP;
	}

	ttl = ip4_dst_hoplimit(&rt->dst);
	n = dst_neigh_lookup(&rt->dst, &fl4->daddr);
	ip_rt_put(rt);
	if (!n)
		return -ENOMEM;

	*out_n = n;
	*saddr = fl4->saddr;
	*out_ttl = ttl;

	return 0;
}

static int gen_vxlan_header(struct mlx5e_priv *pf_dev,
			    char buf[],
			    struct neighbour *n,
			    int ttl,
			    __be32 saddr,
			    __be16 udp_dst_port,
			    __be32 vx_vni)
{
	int encap_size = VXLAN_HLEN + sizeof(struct iphdr) + ETH_HLEN;
	struct ethhdr *eth = (struct ethhdr *)buf;
	struct iphdr  *ip = (struct iphdr *)((char *)eth +
			sizeof(struct ethhdr));
	struct udphdr *udp = (struct udphdr *)((char *)ip +
			sizeof(struct iphdr));
	struct vxlanhdr *vxh = (struct vxlanhdr *)((char *)udp
			+ sizeof(struct udphdr));

	memset(buf, 0, encap_size);
	neigh_ha_snapshot(eth->h_dest, n, pf_dev->netdev);

	ether_addr_copy(eth->h_source, pf_dev->netdev->dev_addr);
	eth->h_proto = htons(ETH_P_IP);

	ip->daddr = *(u32 *)n->primary_key;
	ip->saddr = saddr;

	ip->ttl = ttl;
	ip->protocol = IPPROTO_UDP;
	ip->version = 0x4;
	ip->ihl = 0x5;

	udp->dest = udp_dst_port;
	vxh->vx_flags = htonl(VXLAN_HF_VNI);
	vxh->vx_vni = vx_vni;

	return encap_size;
}

#define MAX_ENCAP_SIZE (128)

static int create_encap_header(struct mlx5e_priv *pf_dev,
			       struct mlx5e_encap_entry *e)
{
	int err;
	char encap_header[MAX_ENCAP_SIZE];
	int encap_size;
	struct flowi4 fl4 = {};
	struct neighbour *n;
	__be32 saddr;
	int ttl;

	switch (e->tun_info.tunnel_type) {
	case SW_FLOW_TUNNEL_VXLAN:
		fl4.flowi4_proto = IPPROTO_UDP;
		fl4.fl4_dport = e->tun_info.tp_dst;
		break;
	default:
		return -EOPNOTSUPP;
	}

	fl4.daddr = e->tun_info.daddr;

	err = route_lookup(pf_dev, &fl4, &n, &saddr, &ttl);
	if (err)
		return err;

	e->n = n;

	if (!(n->nud_state & NUD_VALID)) {
		neigh_event_send(n, NULL);
		return -EAGAIN;
	}

	switch (e->tun_info.tunnel_type) {
	case SW_FLOW_TUNNEL_VXLAN:
		encap_size = gen_vxlan_header(pf_dev, encap_header,
					      n, ttl, saddr,
					      e->tun_info.tp_dst,
					      e->tun_info.tun_id);
		break;
	default:
		return -EOPNOTSUPP;
	}

	err = mlx5_alloc_encap_cmd(pf_dev->mdev, MLX5_HEADER_TYPE_VXLAN,
				   encap_size, encap_header, &e->encap_id);
	if (!err)
		e->valid_encap = true;

	return err;
}

static inline int cmp_encap_info(struct mlx5e_encap_info *a,
				 struct mlx5e_encap_info *b)
{
	return memcmp(a, b, sizeof(*a));
}

static inline int hash_encap_info(struct mlx5e_encap_info *info)
{
	return jhash(info, sizeof(*info), 0);
}

static int mlx5e_get_encap(struct mlx5_flow_attr *attr,
			   struct sw_flow_action *action) {
	struct mlx5e_encap_entry *e;
	struct mlx5e_encap_info info;
	uintptr_t key;
	bool found = false;

	info.tunnel_type = action->tunnel_type;
	switch (info.tunnel_type) {
	case SW_FLOW_TUNNEL_VXLAN:
		info.tp_dst = action->tun_key.tp_dst;
		if (check_vxlan_port(ntohs(info.tp_dst)))
			return -EOPNOTSUPP;

		info.tun_id = htonl(be64_to_cpu(action->tun_key.tun_id) << 8);
		break;
	default:
		return -EOPNOTSUPP;
	}

	info.daddr = action->tun_key.ipv4_dst;
	key = hash_encap_info(&info);

	hash_for_each_possible_rcu(attr->pf_dev->encap_tbl, e,
				   encap_hlist, key) {
		if (!cmp_encap_info(&e->tun_info, &info)) {
			found = true;
			break;
		}
	}

	if (found) {
		attr->encap = e;
		return 0;
	}

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	e->valid_encap = false;

	e->tun_info = info;
	attr->encap = e;

	hash_add_rcu(attr->pf_dev->encap_tbl,
		     &e->encap_hlist, key);

	return create_encap_header(attr->pf_dev, e);
}

static void mlx5e_detach_encap(struct mlx5e_priv *pf_dev,
			       struct mlx5_flow *flow) {
	struct list_head *next = flow->encap.next;

	list_del(&flow->encap);
	if (list_empty(next)) {
		struct mlx5e_encap_entry *e;

		e = list_entry(next, struct mlx5e_encap_entry, flows);
		if (e->n) {
			neigh_release(e->n);
			if (e->valid_encap) {
				mlx5_dealloc_encap_cmd(pf_dev->mdev,
						       e->encap_id);
				e->valid_encap = false;
			}
		}
		hlist_del_rcu(&e->encap_hlist);
		kfree(e);
	}
}

static void mlx5e_flow_group_release(struct kref *kref)
{
	struct mlx5_flow_group *group =
		container_of(kref, struct mlx5_flow_group, kref);

	mlx5_set_free_flow_group(group->eswitch->fdb_table.fdb,
				 group->group_ix);
	list_del(&group->groups_list);
	kfree(group);
}

static void mlx5e_flow_group_put(struct mlx5_flow_group *group)
{
	kref_put(&group->kref, mlx5e_flow_group_release);
}

int mlx5e_flow_set(struct mlx5_flow_attr *attr,
		   struct mlx5_flow_group *group)
{
	void *flow_context, *match_value, *dest;
	struct mlx5_flow *flow;
	int err = -ENOMEM;
	struct mlx5_eswitch *eswitch = attr->pf_dev->mdev->priv.eswitch;
	u16 flow_context_action;

	/* TODO: handle flows with fwding to > 1 output ports (multiple dests) */
	flow_context = mlx5_vzalloc(MLX5_ST_SZ_BYTES(flow_context) +
				    MLX5_ST_SZ_BYTES(dest_format_struct));
	if (!flow_context)
		return -ENOMEM;

	flow = kzalloc(sizeof(*flow), GFP_KERNEL);
	if (!flow)
		goto free_flow_context;

	memcpy(flow->match_v, attr->match_v, sizeof(flow->match_v));
	flow->out_rep	   = attr->out_rep;
	flow->mlx5_action  = attr->mlx5_action;
	flow->group = group;
	flow->flow_index = INVALID_FLOW_IX;

	match_value = MLX5_ADDR_OF(flow_context, flow_context, match_value);
	memcpy(match_value, attr->match_v, sizeof(flow->match_v));

	kref_get(&group->kref);
	list_add_tail(&flow->group_list, &group->flows_list);

	if (attr->mlx5_action & MLX5_FLOW_ACTION_TYPE_DROP) {
		MLX5_SET(flow_context, flow_context, action,
			 MLX5_FLOW_CONTEXT_ACTION_DROP);
		goto flow_set;
	}

	flow_context_action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	if (attr->mlx5_action & MLX5_FLOW_ACTION_TYPE_ENCAP) {
		err = mlx5e_get_encap(attr, attr->sw_flow->actions->actions);
		if (!attr->encap)
			goto encap_error;

		list_add(&flow->encap, &attr->encap->flows);
		if (!attr->encap->valid_encap) {
			err = 0;
			goto free_flow_context;
		}

		flow_context_action |= MLX5_FLOW_CONTEXT_ACTION_ENCAP;
		MLX5_SET(flow_context, flow_context, encap_id,
			 attr->encap->encap_id);
	}

	MLX5_SET(flow_context, flow_context, action, flow_context_action);

	MLX5_SET(flow_context, flow_context, destination_list_size, 1);

	dest = MLX5_ADDR_OF(flow_context, flow_context, destination);
	MLX5_SET(dest_format_struct, dest, destination_type,
		 MLX5_FLOW_CONTEXT_DEST_TYPE_VPORT);
	MLX5_SET(dest_format_struct, dest, destination_id,
		 attr->out_rep->vport);

flow_set:
	err = mlx5_set_flow_group_entry(eswitch->fdb_table.fdb, group->group_ix,
					&flow->flow_index, flow_context);
	if (err)
		goto flow_set_failed;

	pr_debug("%s added sw_flow %p flow index %x\n", __func__,
		 attr->sw_flow, flow->flow_index);
	kvfree(flow_context);
	return 0;

flow_set_failed:
	if (attr->mlx5_action & MLX5_FLOW_ACTION_TYPE_ENCAP)
		mlx5e_detach_encap(attr->pf_dev, flow);
encap_error:
	list_del(&flow->group_list);
	mlx5e_flow_group_put(group);
	kfree(flow);
free_flow_context:
	kvfree(flow_context);
	return err;
}

static struct mlx5e_vf_rep *mlx5e_uplink_rep(struct mlx5e_priv *pf_dev)
{
	return pf_dev->vf_reps[pf_dev->mdev->priv.sriov.num_vfs];
}

static inline bool is_tunnel_type_supported(struct mlx5_core_dev *dev,
					    enum sw_flow_tunnel_type type)
{
	switch (type) {
	case SW_FLOW_TUNNEL_VXLAN:
		return MLX5_CAP_ESW(dev, vxlan_encap_decap);
	default:
		return false;
	}
}

static inline bool is_encap_supported(struct mlx5_core_dev *dev,
				      enum sw_flow_tunnel_type type)
{
	if (!MLX5_CAP_ESW_FLOWTABLE_FDB(dev, encap))
		return false;

	return is_tunnel_type_supported(dev, type);
}

int mlx5e_flow_adjust(struct mlx5_flow_attr *attr)
{
	struct net_device *out_dev;
	struct switchdev_attr in_attr,out_attr;
	int out_ifindex = -1;
	struct sw_flow_action *action;
	int act, err1, err2, __mlx5_action;
	u16 vlan_proto;

	__mlx5_action = 0;
	for (act = 0; act < attr->sw_flow->actions->count; act++) {
		action = &attr->sw_flow->actions->actions[act];
		if (action->type == SW_FLOW_ACTION_TYPE_OUTPUT) {
			if (out_ifindex != -1) {
				pr_debug("%s not offloading floods\n",
					 __func__);
				goto out_err;
			}
			if (attr->sw_flow->tunnel_type !=
					SW_FLOW_TUNNEL_NONE) {
				pr_debug("%s not offloading decap\n",
					 __func__);
				goto out_err;
			}

			out_ifindex = action->out_port_ifindex;
			__mlx5_action |= MLX5_FLOW_ACTION_TYPE_OUTPUT;
		} else if (action->type == SW_FLOW_ACTION_TYPE_VLAN_PUSH) {
			__mlx5_action |= MLX5_FLOW_ACTION_TYPE_VLAN_PUSH;
			attr->mlx5_vlan = ntohs(action->vlan.vlan_tci);
			vlan_proto = ntohs(action->vlan.vlan_proto);
			if (vlan_proto != ETH_P_8021Q)
				goto out_err;
		} else if (action->type == SW_FLOW_ACTION_TYPE_VLAN_POP) {
			__mlx5_action |= MLX5_FLOW_ACTION_TYPE_VLAN_POP;
			attr->mlx5_vlan = ntohs(attr->sw_flow->key.eth.tci);
		} else if (action->type == SW_FLOW_ACTION_TYPE_DROP)
			__mlx5_action |= MLX5_FLOW_ACTION_TYPE_DROP;
		else if (action->type == SW_FLOW_ACTION_TYPE_ENCAP) {
			if (attr->sw_flow->actions->count != 1)
				goto out_err;
			if (!is_encap_supported(attr->pf_dev->mdev,
						action->tunnel_type))
				goto out_err;

			__mlx5_action |= MLX5_FLOW_ACTION_TYPE_ENCAP;
			attr->out_rep = mlx5e_uplink_rep(attr->pf_dev);
			goto skip_id_check;
		} else {
			printk(KERN_ERR "%s can't offload flow action %d\n", __func__, action->type);
			goto out_err;
		}
	}

	/* DROP action doesn't involve output port!! */
	if (__mlx5_action & MLX5_FLOW_ACTION_TYPE_DROP)
		goto skip_id_check;

	out_dev = dev_get_by_index_rcu(attr->net, out_ifindex);

	pr_debug("%s in/out dev %s/%s action %x\n", __func__,
		 attr->in_rep->dev->name, out_dev ? out_dev->name : "NULL",
		 __mlx5_action);

	if (!out_dev)
		return -EINVAL;

	/*
	 * Use switchdev ID attribute to make sure in_rep and out_rep
	 * belong to the same eSwitch and if not don't offload the flow
	 * FIXME: belongs to OVS
	 */
	in_attr.id = out_attr.id = SWITCHDEV_ATTR_PORT_PARENT_ID;
	in_attr.flags = out_attr.flags = SWITCHDEV_F_NO_RECURSE;

	err1 = switchdev_port_attr_get(attr->in_rep->dev, &in_attr);
	err2 = switchdev_port_attr_get(out_dev, &out_attr);

	if (err1 || err2)
		return -EOPNOTSUPP;

	if (!netdev_phys_item_ids_match(&in_attr.u.ppid, &out_attr.u.ppid)) {
		pr_err("devices in:%s out:%s not on same eSwitch, can't offload\n",
				attr->in_rep->dev->name, out_dev->name);
		goto out_err;
	}

	if (out_ifindex == attr->pf_dev->netdev->ifindex)
		attr->out_rep = mlx5e_uplink_rep(attr->pf_dev);
	else
		attr->out_rep = netdev_priv(out_dev);

skip_id_check:
	attr->mlx5_action = __mlx5_action;

	return 0;

out_err:
	return -EOPNOTSUPP;
}

static int mlx5e_handle_global_strip(struct mlx5e_priv *pf_dev, int flags)
{
	int vf, nvf, err = 0;
	u8 set_flags = 0;
	struct mlx5e_vf_rep *vport;
	struct mlx5_eswitch *eswitch = pf_dev->mdev->priv.eswitch;
	struct mlx5_core_sriov *sriov = &pf_dev->mdev->priv.sriov;

	nvf = sriov->num_vfs;

	if (flags == FLOW_DEL) {
		pf_dev->vlan_push_pop_refcount--;
		if (pf_dev->vlan_push_pop_refcount)
			return 0;
	}

	if (flags == FLOW_ADD) {
		if (!pf_dev->vlan_push_pop_refcount)
			set_flags = SET_VLAN_STRIP;

		pf_dev->vlan_push_pop_refcount++;

		if (!set_flags)
			return 0;
	}

	/* apply global vlan strip policy changes */
	pr_debug("%s applying global %s policy\n", __func__, set_flags ? "strip" : "no strip");
	for (vf = 0; vf < nvf; vf++) {
		vport = pf_dev->vf_reps[vf];
		err = __mlx5_eswitch_set_vport_vlan(eswitch, vport->vport,
						    0, 0, set_flags);
		if (err)
			goto out;
	}

out:
	return err;
}

static int mlx5e_handle_vlan_actions(struct mlx5_flow_attr *attr, int flags)
{
	int err = 0;
	u16 vlan_tag;
	u8 vlan_prio;
	struct mlx5e_vf_rep *vport = NULL;
	struct mlx5_core_dev *mdev = attr->in_rep->pf_dev->mdev;
	struct mlx5_eswitch *eswitch = mdev->priv.eswitch;

	if (attr->mlx5_action & MLX5_FLOW_ACTION_TYPE_VLAN_PUSH) {
		if (attr->in_rep->vport == FDB_UPLINK_VPORT) {
			mlx5_core_warn(mdev, "can't do vlan push on ingress\n");
			err = -ENOTSUPP;
			goto out;
		}
		vport = attr->in_rep;
	}

	if (attr->mlx5_action & MLX5_FLOW_ACTION_TYPE_VLAN_POP) {
		if (attr->out_rep->vport == FDB_UPLINK_VPORT) {
			mlx5_core_warn(mdev, "can't do vlan pop on egress\n");
			err = -ENOTSUPP;
			goto out;
		}
		vport = attr->out_rep;
	}

	if (flags == FLOW_DEL) {
		vport->vst_refcount--;
		if (!vport->vst_refcount) {
			vport->vst_vlan = 0;
			err = __mlx5_eswitch_set_vport_vlan(eswitch, vport->vport,
							    0, 0, SET_VLAN_STRIP);
		}
		mlx5e_handle_global_strip(vport->pf_dev, flags);
		goto out;
	}

	/* being here --> (flags == FLOW_ADD) holds */
	if (vport->vst_refcount && vport->vst_vlan != attr->mlx5_vlan) {
		mlx5_core_warn(mdev, "VST exists with vlan %x, can't do for vlan %x\n",
			       vport->vst_vlan, attr->mlx5_vlan);
		err = -ENOTSUPP;
		goto out;
	}

	mlx5e_handle_global_strip(vport->pf_dev, flags);

	vport->vst_refcount++;
	if (!vport->vst_vlan) {
		vlan_tag  = attr->mlx5_vlan & VLAN_VID_MASK;
		vlan_prio = attr->mlx5_vlan >> VLAN_PRIO_SHIFT;
		err = __mlx5_eswitch_set_vport_vlan(eswitch, vport->vport, vlan_tag, vlan_prio,
						    SET_VLAN_STRIP | SET_VLAN_INSERT);
		if (err) {
			mlx5_core_warn(mdev, "failed to set VST, vport %d vlan %d err %d\n",
				       vport->vport, attr->mlx5_vlan, err);
			vport->vst_refcount--;
			goto out;
		}
		vport->vst_vlan = attr->mlx5_vlan;
	}
out:
	return err;
}

static void mlx5e_destroy_flow(struct mlx5e_priv *pf_dev,
			       struct mlx5_flow *flow)
{
	if (flow->flow_index != INVALID_FLOW_IX)
		mlx5_del_flow_table_entry(
				pf_dev->mdev->priv.eswitch->fdb_table.fdb,
				flow->flow_index);
	list_del(&flow->group_list);

	if (flow->mlx5_action & MLX5_FLOW_ACTION_TYPE_ENCAP)
		mlx5e_detach_encap(pf_dev, flow);

	kfree(flow);
}

static int __mlx5e_flow_del(struct mlx5_flow_attr *attr,
			    struct mlx5_flow_group *group)
{
	struct mlx5_flow *flow = NULL;
	int err, flow_found = 0;

	/* find the flow based on the match values */
	list_for_each_entry(flow, &group->flows_list, group_list) {
		if (!memcmp(flow->match_v, attr->match_v, sizeof(flow->match_v))) {
			flow_found = 1;
			break;
		}
	}

	if (!flow_found) {
		pr_err("flow doesn't exist in group, can't remove it\n");
		return -EINVAL;
	}

	printk(KERN_ERR "%s deleting flow index %x \n", __func__, flow->flow_index);


	if (flow->mlx5_action & MLX5_FLOW_ACTION_TYPE_VLAN_PUSH ||
	    flow->mlx5_action & MLX5_FLOW_ACTION_TYPE_VLAN_POP) {
		attr->out_rep	   = flow->out_rep;
		attr->mlx5_action  = flow->mlx5_action;
		err = mlx5e_handle_vlan_actions(attr, FLOW_DEL);
		if (err)
			pr_err("handling vlan action failed, err %d\n", err);
	}

	mlx5e_destroy_flow(attr->pf_dev, flow);
	mlx5e_flow_group_put(group);
	return 0;
}

static struct mlx5_flow_group *mlx5e_get_flow_group(
		struct mlx5e_priv *pf_dev,
		u32 match_c[MATCH_PARAMS_SIZE])
{
	struct mlx5_flow_group *group;

	bool group_found = false;

	spin_lock(&pf_dev->flows_lock);
	/* find the group that this flow belongs to */
	list_for_each_entry(group, &pf_dev->mlx5_flow_groups, groups_list) {
		if (!memcmp(group->match_c, match_c, sizeof(group->match_c))) {
			kref_get(&group->kref);
			group_found = true;
			break;
		}
	}
	spin_unlock(&pf_dev->flows_lock);

	return group_found ? group : NULL;
}

static struct mlx5_flow_group *mlx5e_create_flow_group(
		struct mlx5e_priv *pf_dev,
		u32 match_c[MATCH_PARAMS_SIZE])
{
	struct mlx5_eswitch *eswitch = pf_dev->mdev->priv.eswitch;
	struct mlx5_flow_group *group = kzalloc(sizeof(*group), GFP_KERNEL);
	struct mlx5_flow_table_group *g;
	int g_index;
	int err;

	if (!group)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&group->flows_list);
	memcpy(group->match_c, match_c, sizeof(group->match_c));

	g = &group->g;
	g->log_sz = mlx5_flow_offload_group_size_log;
	g->match_criteria_enable = generate_match_criteria_enable(match_c);
	memcpy(g->match_criteria, match_c, sizeof(g->match_criteria));

	spin_lock(&pf_dev->flows_lock);
	g_index = mlx5_get_free_flow_group(eswitch->fdb_table.fdb, 2,
					   MLX5_OFFLOAD_GROUPS - 1);
	spin_unlock(&pf_dev->flows_lock);
	if (g_index == -1) {
		pr_err("can't find free flow group, can't add flow\n");
		kfree(group);
		return ERR_PTR(-ENOMEM);
	}
	err = mlx5_recreate_flow_group(eswitch->fdb_table.fdb, g_index, g);
	if (!err) {
		group->group_ix = g_index;
		spin_lock(&pf_dev->flows_lock);
		list_add_tail(&group->groups_list, &pf_dev->mlx5_flow_groups);
		spin_unlock(&pf_dev->flows_lock);
	} else {
		pr_err("can't allocate new flow group, can't add flow\n");
		kfree(group);
		return ERR_PTR(-ENOMEM);
	}

	group->eswitch = eswitch;
	kref_init(&group->kref);

	return group;
}

int mlx5e_flow_add(struct mlx5e_vf_rep *in_rep, struct sw_flow *sw_flow)
{
	struct mlx5_flow_group *group;
	int err;

	struct mlx5_flow_attr attr = {};

	attr.sw_flow = sw_flow;
	attr.in_rep = in_rep;
	attr.pf_dev = in_rep->pf_dev;

	attr.net = dev_net(attr.pf_dev->netdev);
	if (!attr.net) {
		pr_err("can't get net name space from dev %s\n",
		       attr.pf_dev->netdev->name);
		return -EOPNOTSUPP;
	}

	err = mlx5e_flow_adjust(&attr);
	if (err)
		return err;

	/* translate the flow from SW to PRM */
	err = parse_flow_attr(&attr);
	if (err)
		return err;

	if (attr.mlx5_action & MLX5_FLOW_ACTION_TYPE_VLAN_PUSH ||
	    attr.mlx5_action & MLX5_FLOW_ACTION_TYPE_VLAN_POP) {
		err = mlx5e_handle_vlan_actions(&attr, FLOW_ADD);
		if (err)
			return err;
	}

	group = mlx5e_get_flow_group(attr.pf_dev, attr.match_c);
	if (!group) {
		group = mlx5e_create_flow_group(attr.pf_dev, attr.match_c);
		if (IS_ERR(group))
			return PTR_ERR(group);
	}

	pr_debug("%s sw_flow %p group %p ref %d\n", __func__, sw_flow, group,
		 group ? atomic_read(&group->kref.refcount) : -100);

	err = mlx5e_flow_set(&attr, group);

	pr_debug("%s status %d group %p ref %d index %d\n", __func__, err,
		 group, atomic_read(&group->kref.refcount), group->group_ix);
	mlx5e_flow_group_put(group);

	return err;
}

int mlx5e_flow_del(struct mlx5e_vf_rep *in_rep, struct sw_flow *sw_flow)
{
	struct mlx5_flow_group *group;
	int err;

	struct mlx5_flow_attr attr = {};

	attr.sw_flow = sw_flow;
	attr.in_rep = in_rep;
	attr.pf_dev = in_rep->pf_dev;

	/* translate the flow from SW to PRM */
	err = parse_flow_attr(&attr);
	if (err)
		return err;

	group = mlx5e_get_flow_group(attr.pf_dev, attr.match_c);
	if (!group) {
		pr_err("%s sw_flow %p flow group doesn't exist, can't remove flow\n",
		       __func__, sw_flow);
		return -EINVAL;
	}

	pr_debug("%s sw_flow %p group %p ref %d\n", __func__, sw_flow, group,
		 group ? atomic_read(&group->kref.refcount) : -100);

	err = __mlx5e_flow_del(&attr, group);

	pr_debug("%s status %d group %p ref %d index %d\n", __func__, err,
		 group, atomic_read(&group->kref.refcount), group->group_ix);
	mlx5e_flow_group_put(group);


	return err;
}

void mlx5e_clear_flows(struct mlx5e_priv *pf_dev)
{
	struct mlx5_flow_group *group, *group_tmp;
	struct mlx5_flow *flow, *flow_tmp;

	/* find the group that this flow belongs to */
	list_for_each_entry_safe(group, group_tmp, &pf_dev->mlx5_flow_groups,
				 groups_list) {
		list_for_each_entry_safe(flow, flow_tmp, &group->flows_list,
					 group_list)
			mlx5e_destroy_flow(pf_dev, flow);
		list_del(&group->groups_list);
		kfree(group);
	}

}
