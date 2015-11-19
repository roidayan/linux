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
#include "en.h"
#include "eswitch.h"

static int parse_flow_attr(struct sw_flow *flow, u32 *match_c, u32 *match_v)
{
	struct sw_flow_key *key  = &flow->key;
	struct sw_flow_key *mask = &flow->mask->key;

	void *outer_headers_c = MLX5_ADDR_OF(fte_match_param, match_c, outer_headers);
	void *outer_headers_v = MLX5_ADDR_OF(fte_match_param, match_v, outer_headers);

	void *misc_c = MLX5_ADDR_OF(fte_match_param, match_c, misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, match_c, misc_parameters);

	u8 zero_mac[ETH_ALEN];
	int vport = 0;

	eth_zero_addr(zero_mac);

	/* set source vport for the flow */
	misc_v = MLX5_ADDR_OF(fte_match_param, match_v, misc_parameters);
	MLX5_SET(fte_match_set_misc, misc_c, source_port, 0xffff);
	/* TODO: translate flow->key.misc.in_port_ifindex to FDB vport */
	MLX5_SET(fte_match_set_misc, misc_v, source_port, vport);

	if (memcmp(&mask->eth.src, zero_mac, ETH_ALEN)) {
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_c, smac_47_16),
		       &mask->eth.src, ETH_ALEN);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_v, smac_47_16),
		       &key->eth.src, ETH_ALEN);
	}

	if (memcmp(&mask->eth.dst, zero_mac, ETH_ALEN)) {
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_c, dmac_47_16),
		       &mask->eth.dst, ETH_ALEN);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_v, dmac_47_16),
		       &key->eth.dst, ETH_ALEN);
	}

	/* NOTE - vlan push/pop actions to be implemented by VST!! */
	if (mask->eth.tci) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, vlan_tag, 1);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, vlan_tag, 1);

		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, first_vid,
			 ntohs(mask->eth.tci) & ~VLAN_TAG_PRESENT);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, first_vid,
			 ntohs(mask->eth.tci) & ~VLAN_TAG_PRESENT);
	}

	if (mask->eth.type) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, ethertype, mask->eth.type);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, ethertype, key->eth.type);
	}

	if (mask->ip.proto) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, ip_protocol, mask->ip.proto);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, ip_protocol, key->ip.proto);
	}

	if (mask->ip.tos >> 2) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, ip_dscp, mask->ip.tos >> 2);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, ip_dscp, key->ip.tos  >> 2);
	}

	if (mask->ip.tos & 0x3) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, ip_ecn, mask->ip.tos & 0x3);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, ip_ecn, key->ip.tos  & 0x3);
	}

	if (mask->ip.ttl) {
		printk(KERN_ERR "%s non zero mask %x (val %d) for IP TTL, unsupported by PRM\n",
		       __func__, mask->ip.ttl, key->ip.ttl);
		goto out_err;
	}

	if (mask->ip.frag && key->ip.frag == OVS_FRAG_TYPE_NONE) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, frag, 1);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, frag, 0);
	} else if (mask->ip.frag && key->ip.frag != OVS_FRAG_TYPE_NONE) {
		printk(KERN_ERR "%s non zero val for OVS_FRAG %d, supported by PRM?!\n",
			__func__, key->ip.frag);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, frag, 1);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, frag, 1);
	}

	/* PRM mandates ip protocol full match to set rules on UDP/TCP ports using one rule */
	if (mask->tp.src && mask->ip.proto && key->ip.proto == IPPROTO_TCP) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, tcp_sport, ntohs(mask->tp.src));
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, tcp_sport, ntohs(key->tp.src));
	}

	if (mask->tp.dst && mask->ip.proto && key->ip.proto == IPPROTO_TCP) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, tcp_dport, ntohs(mask->tp.dst));
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, tcp_dport, ntohs(key->tp.dst));
	}

	if (mask->tp.flags) { /* FIXME: OVS flags are 16 bits, we need "only" 8 bits */
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, tcp_flags, mask->tp.flags);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, tcp_flags, key->tp.flags);
	}

	/* PRM mandates ip protocol full match to set rules on UDP/TCP ports using one rule */
	if (mask->tp.src && mask->ip.proto && key->ip.proto == IPPROTO_UDP) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, udp_sport, ntohs(mask->tp.src));
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, udp_sport, ntohs(key->tp.src));
	}

	if (mask->tp.dst && mask->ip.proto && key->ip.proto == IPPROTO_UDP) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, udp_dport, ntohs(mask->tp.dst));
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, udp_dport, ntohs(key->tp.dst));
	}

	/* FIXME: need to use meta data for realizing if this is IPv4/IPv6 */
	if (mask->ipv4.addr.src) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, src_ip[0], mask->ipv4.addr.src);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, src_ip[0], key->ipv4.addr.src);
	}

	if (mask->ipv4.addr.dst) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_c, dst_ip[0], mask->ipv4.addr.dst);
		MLX5_SET(fte_match_set_lyr_2_4, outer_headers_v, dst_ip[0], key->ipv4.addr.dst);
	}

	/* FIXME: add IPv6 src/dst addressed */
	if (mask->ipv6.label) {
		/* TODO use the misc section and put the flow label there */
	}


	return 0;

out_err:

	return -EINVAL;
}

//struct list_head mlx5_flow_groups;
static LIST_HEAD(mlx5_flow_groups);

#define MLX5_FLOW_OFFLOAD_GROUP_SIZE_LOG 10 /* 1K flows in group */
#define MATCH_PARAMS_SIZE MLX5_ST_SZ_DW(fte_match_param)

int mlx5_create_flow_group(void *ft, struct mlx5_flow_table_group *g,
			   u32 start_ix, u32 *id);

struct mlx5_flow_group {
	u32 match_c[MATCH_PARAMS_SIZE];
	u32 group_id;
	u32 start_ix;
	struct mlx5_flow_table_group g;

	struct list_head groups_list; /* list of groups */
	struct list_head flows_list;  /* flows for this group */
};

struct mlx5_flow {
	u32 match_v[MATCH_PARAMS_SIZE];
	u32 flow_index;

	struct list_head group_list; /* flows of the mother group */
};

int mlx5e_flow_add(struct mlx5e_priv *pf_dev,
		   struct sw_flow *sw_flow, struct mlx5_flow_group *group, u32 *match_v)
{
	void *flow_context, *match_value, *dest;
	struct mlx5_flow *flow;
	int err;
	struct mlx5_eswitch *eswitch = pf_dev->mdev->priv.eswitch;
	u16 out_vport = 0; /* TODO ..->actions[i].out_port_ifindex --> vport */

	flow = kzalloc(sizeof (*flow), GFP_KERNEL);
	if (!flow)
		goto flow_alloc_failed;
	memcpy(flow->match_v, match_v, MATCH_PARAMS_SIZE);

	/* TODO: handle flows with fwding to > 1 output ports (multiple dests) */
	flow_context = mlx5_vzalloc(MLX5_ST_SZ_BYTES(flow_context) +
				    MLX5_ST_SZ_BYTES(dest_format_struct));
	if (!flow_context)
		goto flow_context_alloc_failed;

	match_value = MLX5_ADDR_OF(flow_context, flow_context, match_value);
	memcpy(match_value, match_v, MATCH_PARAMS_SIZE);

	MLX5_SET(flow_context, flow_context, destination_list_size, 1);
	MLX5_SET(flow_context, flow_context, action,
		 MLX5_FLOW_CONTEXT_ACTION_FWD_DEST);

	dest = MLX5_ADDR_OF(flow_context, flow_context, destination);
	MLX5_SET(dest_format_struct, dest, destination_type,
		 MLX5_FLOW_CONTEXT_DEST_TYPE_VPORT);
	MLX5_SET(dest_format_struct, dest, destination_id, out_vport);

	err = mlx5_set_flow_group_entry(eswitch->fdb_table.fdb, group->group_id,
					&flow->flow_index, flow_context);

	list_add_tail(&flow->group_list, &group->flows_list);

	kfree(flow_context);
	return 0;

flow_context_alloc_failed:
	kfree(flow);

flow_alloc_failed:
	pr_warn("flow allocation failed\n");
	return -ENOMEM;
}

int mlx5e_flow_del(struct mlx5e_priv *pf_dev, struct mlx5_flow_group *group, u32 *match_v)
{
	struct mlx5_flow *flow = NULL;
	struct mlx5_eswitch *eswitch = pf_dev->mdev->priv.eswitch;

	/* find the group that this flow belongs to */
	list_for_each_entry(flow, &group->flows_list, group_list) {
		if (!memcmp(flow->match_v, match_v, MATCH_PARAMS_SIZE))
			break;
		flow = NULL;
	}

	if (!flow) {
		pr_err("flow doesn't exist in group, can't remove it\n");
		return -EINVAL;
	}

	mlx5_del_flow_table_entry(eswitch->fdb_table.fdb, flow->flow_index);
	list_del(&flow->group_list);
	kfree(flow);

	/* TODO: if the groups gets to be empty - remove it?! */
	return 0;
}

int mlx5e_flow_act(struct mlx5e_priv *pf_dev, struct sw_flow *sw_flow, int flags)
{
	struct mlx5_flow_group *group = NULL;
	struct mlx5_flow_table_group *g;
	struct mlx5_eswitch *eswitch = pf_dev->mdev->priv.eswitch;
	int err;

	u32 match_c[MATCH_PARAMS_SIZE];
	u32 match_v[MATCH_PARAMS_SIZE];

	memset(match_c, 0, sizeof(match_c));
	memset(match_v, 0, sizeof(match_v));

	/* translate the flow from SW to PRM */
	parse_flow_attr(sw_flow, match_c, match_v);

	/* find the group that this flow belongs to */
	list_for_each_entry(group, &mlx5_flow_groups, groups_list) {
		if (!memcmp(group->match_c, match_c, MATCH_PARAMS_SIZE))
			break;
		group = NULL;
	}

	if (!group && (flags & FLOW_DEL)) {
		pr_err("flow group doesn't exist, can't remove flow\n");
		return -EINVAL;
	}

	if (!group) {
		group = kzalloc(sizeof (*group), GFP_KERNEL);
		if (!group) {
			pr_err("can't allocate flow group\n");
			return -ENOMEM;
		}
		INIT_LIST_HEAD(&group->flows_list);
		memcpy(group->match_c, match_c, MATCH_PARAMS_SIZE);

		g = &group->g;
		g->log_sz = MLX5_FLOW_OFFLOAD_GROUP_SIZE_LOG;
		g->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS | MLX5_MATCH_MISC_PARAMETERS;
		memcpy(g->match_criteria, match_c, MATCH_PARAMS_SIZE);
		group->start_ix = 0; /* TODO: set the group start index */
		err = mlx5_create_flow_group(eswitch->fdb_table.fdb, g, group->start_ix, &group->group_id);
		if (!err)
			list_add_tail(&group->groups_list, &mlx5_flow_groups);

	}

	if (flags & FLOW_ADD)
		return mlx5e_flow_add(pf_dev, sw_flow, group, match_c);
	else if (flags & FLOW_DEL)
		return mlx5e_flow_del(pf_dev, group, match_c);
	else
		return -EINVAL;
}
