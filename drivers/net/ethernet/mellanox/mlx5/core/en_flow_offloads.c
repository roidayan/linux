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

#include "en.h"
#include "eswitch.h"
#include "en_rep.h"
#include "eswitch.h"

/* The default UDP port that ConnectX firmware uses for its VXLAN parser */
#define MLX5_DEFAULT_VXLAN_UDP_DPORT (4789)

static int parse_vxlan_attr(struct sw_flow_key_ipv4_tunnel *key,
			    struct sw_flow_key_ipv4_tunnel *mask,
			    u32 *match_c, u32 *match_v) {
	void *headers_c = MLX5_ADDR_OF(fte_match_param, match_c, outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, match_v, outer_headers);
	void *misc_c = MLX5_ADDR_OF(fte_match_param, match_c, misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, match_v, misc_parameters);

	if (key->tp_dst != htons(MLX5_DEFAULT_VXLAN_UDP_DPORT))
		/* TODO enable other UDP ports with the ADD_VXLAN_UDP_PORT
		 * firmware command
		 */
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

	MLX5_SET(fte_match_set_lyr_2_4, headers_c, udp_dport,
		 ntohs(mask->tp_dst));
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_dport,
		 ntohs(key->tp_dst));

	return 0;
}

static int parse_tunnel_attr(struct sw_flow_key_ipv4_tunnel *key,
			     struct sw_flow_key_ipv4_tunnel *mask,
			     u32 *match_c, u32 *match_v) {
	void *headers_c = MLX5_ADDR_OF(fte_match_param, match_c,
				       outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, match_v,
				       outer_headers);

	switch (key->tunnel_type) {
	case SW_FLOW_TUNNEL_VXLAN:
		if (parse_vxlan_attr(key, mask, match_c, match_v))
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

static int parse_flow_attr(struct sw_flow *flow, u32 *match_c, u32 *match_v,
			   struct mlx5e_vf_rep *in_rep)
{
	struct sw_flow_key *key  = &flow->key;
	struct sw_flow_key *mask = &flow->mask->key;

	void *headers_c = MLX5_ADDR_OF(fte_match_param, match_c, outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, match_v, outer_headers);

	void *misc_c = MLX5_ADDR_OF(fte_match_param, match_c, misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, match_v, misc_parameters);

	u8 zero_mac[ETH_ALEN];

	eth_zero_addr(zero_mac);

	/* set source vport for the flow */
	MLX5_SET(fte_match_set_misc, misc_c, source_port, 0xffff);
	MLX5_SET(fte_match_set_misc, misc_v, source_port, in_rep->vport);

	if (mask->tun_key.tun_flags &
	   ~(TUNNEL_KEY | TUNNEL_DONT_FRAGMENT | TUNNEL_CSUM)) {
		dev_warn_ratelimited(&in_rep->dev->dev, "got unknown tunnel flag in flow: 0x%x\n",
				     be16_to_cpu(mask->tun_key.tun_flags));
		return -EOPNOTSUPP;
	}

	if (key->tun_key.tunnel_type != SW_FLOW_TUNNEL_NONE) {
		if (parse_tunnel_attr(&flow->key.tun_key,
				      &flow->mask->key.tun_key,
				      match_c, match_v))
			return -EOPNOTSUPP;

		headers_c = MLX5_ADDR_OF(fte_match_param, match_c,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, match_v,
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
		printk(KERN_ERR "flow has VLAN tci mask %x key %x\n",
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

	if ((ntohs(mask->eth.tci) & VLAN_TAG_PRESENT) &&
	      !(ntohs(key->eth.tci) & VLAN_TAG_PRESENT)) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, vlan_tag, 1);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, vlan_tag, 0);
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
	MLX5_FLOW_ACTION_TYPE_DROP	= 1 << SW_FLOW_ACTION_TYPE_DROP
};

#define MATCH_PARAMS_SIZE MLX5_ST_SZ_DW(fte_match_param)

int mlx5_create_flow_group(void *ft, struct mlx5_flow_table_group *g,
			   u32 start_ix, u32 *id);

struct mlx5_flow_group {
	u32 match_c[MATCH_PARAMS_SIZE];
	u32 group_ix;
	struct mlx5_flow_table_group g;
	int refcount;

	struct list_head groups_list; /* list of groups */
	struct list_head flows_list;  /* flows for this group */
};

struct mlx5_flow {
	u32 match_v[MATCH_PARAMS_SIZE];
	u32 flow_index;

	struct list_head group_list; /* flows of the mother group */
};

int mlx5e_flow_set(struct mlx5e_priv *pf_dev, int mlx5_action,
		   struct mlx5e_vf_rep *out, struct sw_flow *sw_flow,
		   struct mlx5_flow_group *group, u32 *match_v)
{
	void *flow_context, *match_value, *dest;
	struct mlx5_flow *flow;
	int err = -ENOMEM;
	struct mlx5_eswitch *eswitch = pf_dev->mdev->priv.eswitch;

	flow = kzalloc(sizeof (*flow), GFP_KERNEL);
	if (!flow)
		goto flow_alloc_failed;
	memcpy(flow->match_v, match_v, sizeof(flow->match_v));

	/* TODO: handle flows with fwding to > 1 output ports (multiple dests) */
	flow_context = mlx5_vzalloc(MLX5_ST_SZ_BYTES(flow_context) +
				    MLX5_ST_SZ_BYTES(dest_format_struct));
	if (!flow_context)
		goto flow_context_alloc_failed;

	match_value = MLX5_ADDR_OF(flow_context, flow_context, match_value);
	memcpy(match_value, match_v, sizeof(flow->match_v));

	if (mlx5_action & MLX5_FLOW_ACTION_TYPE_DROP) {
		MLX5_SET(flow_context, flow_context, action,
			 MLX5_FLOW_CONTEXT_ACTION_DROP);
		goto flow_set;
	}

	MLX5_SET(flow_context, flow_context, action,
		 MLX5_FLOW_CONTEXT_ACTION_FWD_DEST);

	MLX5_SET(flow_context, flow_context, destination_list_size, 1);

	dest = MLX5_ADDR_OF(flow_context, flow_context, destination);
	MLX5_SET(dest_format_struct, dest, destination_type,
		 MLX5_FLOW_CONTEXT_DEST_TYPE_VPORT);
	MLX5_SET(dest_format_struct, dest, destination_id, out->vport);

flow_set:
	err = mlx5_set_flow_group_entry(eswitch->fdb_table.fdb, group->group_ix,
					&flow->flow_index, flow_context);
	if (err)
		goto flow_set_failed;

	group->refcount++;
	list_add_tail(&flow->group_list, &group->flows_list);

	printk(KERN_ERR "%s added sw_flow %p flow index %x \n", __func__, sw_flow, flow->flow_index);
	kfree(flow_context);
	return 0;

flow_set_failed:
	kfree(flow_context);

flow_context_alloc_failed:
	kfree(flow);

flow_alloc_failed:
	if (err == -ENOMEM)
		pr_warn("flow allocation failed\n");
	return err;
}

int mlx5e_flow_adjust(struct mlx5e_priv *pf_dev, struct sw_flow *sw_flow,
		      int *mlx5_action, u16 *mlx5_vlan,
		      struct mlx5e_vf_rep *in_rep,
		      struct mlx5e_vf_rep **out_rep)
{
	struct net *net;
	struct net_device *out_dev;
	struct switchdev_attr in_attr,out_attr;
	int out_ifindex = -1;
	struct sw_flow_action *action;
	int act, err1, err2, __mlx5_action;
	u16 vlan_proto;

	__mlx5_action = 0;
	for (act = 0; act < sw_flow->actions->count; act++) {
		action = &sw_flow->actions->actions[act];
		if (action->type == SW_FLOW_ACTION_TYPE_OUTPUT) {
			if (out_ifindex != -1) {
				pr_debug("%s not offloading floods\n",
					 __func__);
				goto out_err;
			}
			if (sw_flow->key.tun_key.tunnel_type !=
					SW_FLOW_TUNNEL_NONE) {
				pr_debug("%s not offloading decap\n",
					 __func__);
				goto out_err;
			}

			out_ifindex = action->out_port_ifindex;
			__mlx5_action |= MLX5_FLOW_ACTION_TYPE_OUTPUT;
		} else if (action->type == SW_FLOW_ACTION_TYPE_VLAN_PUSH) {
			__mlx5_action |= MLX5_FLOW_ACTION_TYPE_VLAN_PUSH;
			*mlx5_vlan = ntohs(action->vlan.vlan_tci) & ~VLAN_TAG_PRESENT;
			vlan_proto = ntohs(action->vlan.vlan_proto);
			printk(KERN_ERR "%s push vlan action tci %x proto %x TODO: set VST!!\n",
			       __func__, *mlx5_vlan, vlan_proto);
			if (vlan_proto != ETH_P_8021Q)
				goto out_err;
		} else if (action->type == SW_FLOW_ACTION_TYPE_VLAN_POP)
			__mlx5_action |= MLX5_FLOW_ACTION_TYPE_VLAN_POP;
		else if (action->type == SW_FLOW_ACTION_TYPE_DROP)
			__mlx5_action |= MLX5_FLOW_ACTION_TYPE_DROP;
		else {
			printk(KERN_ERR "%s can't offload flow action %d\n", __func__, action->type);
			goto out_err;
		}
	}

	if ((__mlx5_action & MLX5_FLOW_ACTION_TYPE_VLAN_PUSH) ||
	    (__mlx5_action & MLX5_FLOW_ACTION_TYPE_VLAN_POP)) {
		printk(KERN_WARNING "%s offloading push/pop vlan actions isn't supported yet\n", __func__);
		goto out_err;
	}

	net = dev_net(pf_dev->netdev);
	if (!net) {
		pr_err("can't get net name space from dev %s for ifindex conversion\n",
		       pf_dev->netdev->name);
		goto out_err;
	}

	/* DROP action doesn't involve output port!! */
	if (__mlx5_action & MLX5_FLOW_ACTION_TYPE_DROP)
		goto skip_id_check;

	out_dev = dev_get_by_index_rcu(net, out_ifindex);

	pr_debug("%s in/out dev %s/%s action %x\n", __func__,
		 in_rep->dev->name, out_dev ? out_dev->name : "NULL",
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

	err1 = switchdev_port_attr_get(in_rep->dev, &in_attr);
	err2 = switchdev_port_attr_get(out_dev, &out_attr);

	if (err1 || err2)
		return -EOPNOTSUPP;

	if (!netdev_phys_item_ids_match(&in_attr.u.ppid, &out_attr.u.ppid)) {
		pr_err("devices in:%s out:%s not on same eSwitch, can't offload\n",
				in_rep->dev->name, out_dev->name);
		goto out_err;
	}

	if (out_ifindex == pf_dev->netdev->ifindex)
		*out_rep = pf_dev->vf_reps[pf_dev->mdev->priv.sriov.num_vfs];
	else
		*out_rep = netdev_priv(out_dev);

skip_id_check:
	*mlx5_action = __mlx5_action;

	return 0;

out_err:
	return -EOPNOTSUPP;
}

static int __mlx5e_flow_del(struct mlx5e_priv *pf_dev,
			    struct mlx5_flow_group *group, u32 *match_v)
{
	struct mlx5_flow *flow = NULL;
	struct mlx5_eswitch *eswitch = pf_dev->mdev->priv.eswitch;
	int flow_found = 0;

	/* find the flow based on the match values */
	list_for_each_entry(flow, &group->flows_list, group_list) {
		if (!memcmp(flow->match_v, match_v, sizeof(flow->match_v))) {
			flow_found = 1;
			break;
		}
	}

	if (!flow_found) {
		pr_err("flow doesn't exist in group, can't remove it\n");
		return -EINVAL;
	}

	printk(KERN_ERR "%s deleting flow index %x \n", __func__, flow->flow_index);

	mlx5_del_flow_table_entry(eswitch->fdb_table.fdb, flow->flow_index);
	list_del(&flow->group_list);
	kfree(flow);

	group->refcount--;
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

	return group;
}

int mlx5e_flow_act(struct mlx5e_vf_rep *in_rep, struct sw_flow *sw_flow,
		   int flags)
{
	struct mlx5_flow_group *group;
	struct mlx5e_priv *pf_dev = in_rep->pf_dev;
	struct mlx5_eswitch *eswitch = pf_dev->mdev->priv.eswitch;
	int err, mlx5_action;

	u32 match_c[MATCH_PARAMS_SIZE];
	u32 match_v[MATCH_PARAMS_SIZE];

	struct mlx5e_vf_rep *out_rep;
	u16 mlx5_vlan = 0;

	err = mlx5e_flow_adjust(pf_dev, sw_flow, &mlx5_action, &mlx5_vlan,
				in_rep, &out_rep);
	if (err)
		return err;

	memset(match_c, 0, sizeof(match_c));
	memset(match_v, 0, sizeof(match_v));

	/* translate the flow from SW to PRM */
	err = parse_flow_attr(sw_flow, match_c, match_v, in_rep);
	if (err)
		return err;

	group = mlx5e_get_flow_group(pf_dev, match_c);

	if (!group && (flags & FLOW_DEL)) {
		// pr_err("%s sw_flow %p flow group doesn't exist, can't remove flow\n", __func__, sw_flow);
		printk(KERN_ERR "%s sw_flow %p flow group doesn't exist, can't remove flow\n", __func__, sw_flow);
		return -EINVAL;
	}

	if (group)
		pr_debug("%s flags %x sw_flow %p flow group %p\n", __func__, flags, sw_flow, group);

	if (!group) {
		group = mlx5e_create_flow_group(pf_dev, match_c);
		if (IS_ERR(group))
			return PTR_ERR(group);
	}

	err = -EINVAL;

	pr_debug("%s flags %x sw_flow %p group %p ref %d\n", __func__, flags, sw_flow, group, group? group->refcount: -100);

	if (flags & FLOW_ADD)
		err = mlx5e_flow_set(pf_dev, mlx5_action, out_rep,
				     sw_flow, group, match_v);
	else if (flags & FLOW_DEL)
		err = __mlx5e_flow_del(pf_dev, group, match_v);

	pr_debug("%s status %d flags %x group %p ref %d index %d\n",
		__func__, err, flags, group, group->refcount, group->group_ix);

	if ((!err || err == -EOPNOTSUPP) && !group->refcount) {
		/* if the group gets to be empty or add failed - mark it as free */
		pr_debug("%s status %d flags %x freeing flow group index %d\n",__func__, err, flags, group->group_ix);
		mlx5_set_free_flow_group(eswitch->fdb_table.fdb, group->group_ix);
		list_del(&group->groups_list);
		kfree(group);
	}

	return err;
}

void mlx5e_clear_flows(struct mlx5e_priv *pf_dev)
{
	struct mlx5_flow_group *group, *group_tmp;
	struct mlx5_flow *flow, *flow_tmp;
	struct mlx5_eswitch *eswitch = pf_dev->mdev->priv.eswitch;

	/* find the group that this flow belongs to */
	list_for_each_entry_safe(group, group_tmp, &pf_dev->mlx5_flow_groups,
				 groups_list) {
		list_for_each_entry_safe(flow, flow_tmp, &group->flows_list,
					 group_list) {
			mlx5_del_flow_table_entry(eswitch->fdb_table.fdb,
						  flow->flow_index);
			list_del(&flow->group_list);
			kfree(flow);
		}
		list_del(&group->groups_list);
		kfree(group);
	}
}
