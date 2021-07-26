// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include <net/bareudp.h>
#include "tc_action.h"
#include "tc_priv.h"
#include "en_tc.h"

static int
tc_action_can_offload_mpls_push(struct mlx5e_tc_action_parse_state *parse_state,
				const struct flow_action_entry *act,
				int act_index)
{
	struct netlink_ext_ack *extack = parse_state->extack;
	struct mlx5e_priv *priv = parse_state->flow->priv;

	if (!mlx5e_is_eswitch_flow(parse_state->flow))
		return -EOPNOTSUPP;

	if (!MLX5_CAP_ESW_FLOWTABLE_FDB(priv->mdev, reformat_l2_to_l3_tunnel) ||
	    act->mpls_push.proto != htons(ETH_P_MPLS_UC)) {
		NL_SET_ERR_MSG_MOD(extack, "mpls push is supported only for mpls_uc protocol");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int
tc_action_parse_mpls_push(struct mlx5e_tc_action_parse_state *parse_state,
			  const struct flow_action_entry *act,
			  struct mlx5e_priv *priv,
			  struct mlx5_flow_attr *attr)
{
	parse_state->mpls_push = true;

	return 0;
}

static int
tc_action_can_offload_mpls_pop(struct mlx5e_tc_action_parse_state *parse_state,
			       const struct flow_action_entry *act,
			       int act_index)
{
	struct netlink_ext_ack *extack = parse_state->extack;
	struct mlx5e_tc_flow *flow = parse_state->flow;
	struct net_device *filter_dev;

	if (!mlx5e_is_eswitch_flow(parse_state->flow))
		return -EOPNOTSUPP;

	filter_dev = flow->attr->parse_attr->filter_dev;

	/* we only support mpls pop if it is the first action
	 * and the filter net device is bareudp. Subsequent
	 * actions can be pedit and the last can be mirred
	 * egress redirect.
	 */
	if (act_index) {
		NL_SET_ERR_MSG_MOD(extack, "mpls pop supported only as first action");
		return -EOPNOTSUPP;
	}

	if (!netif_is_bareudp(filter_dev)) {
		NL_SET_ERR_MSG_MOD(extack, "mpls pop supported only on bareudp devices");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int
tc_action_parse_mpls_pop(struct mlx5e_tc_action_parse_state *parse_state,
			 const struct flow_action_entry *act,
			 struct mlx5e_priv *priv,
			 struct mlx5_flow_attr *attr)
{
	attr->parse_attr->eth.h_proto = act->mpls_pop.proto;
	attr->action |= MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT;
	flow_flag_set(parse_state->flow, L3_TO_L2_DECAP);

	return 0;
}

struct mlx5e_tc_action mlx5e_tc_action_mpls_push = {
	.can_offload = tc_action_can_offload_mpls_push,
	.parse_action = tc_action_parse_mpls_push,
};

struct mlx5e_tc_action mlx5e_tc_action_mpls_pop = {
	.can_offload = tc_action_can_offload_mpls_pop,
	.parse_action = tc_action_parse_mpls_pop,
};
