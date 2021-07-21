// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include "tc_action.h"
#include "tc_priv.h"
#include "tc_ct.h"
#include "en_tc.h"

static int
tc_action_can_offload_ct(struct mlx5e_tc_action_parse_state *parse_state,
			 const struct flow_action_entry *act,
			 int act_index)
{
	struct netlink_ext_ack *extack = parse_state->extack;

	if (flow_flag_test(parse_state->flow, SAMPLE)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Sample action with connection tracking is not supported");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int
tc_action_parse_ct(struct mlx5e_tc_action_parse_state *parse_state,
		   const struct flow_action_entry *act,
		   struct mlx5e_priv *priv,
		   struct mlx5_flow_attr *attr)
{
	struct mlx5_esw_flow_attr *esw_attr = attr->esw_attr;
	int err;

	err = mlx5_tc_ct_parse_action(get_ct_priv(priv), attr, act, parse_state->extack);
	if (err)
		return err;

	flow_flag_set(parse_state->flow, CT);
	esw_attr->split_count = esw_attr->out_count;

	return 0;
}

struct mlx5e_tc_action mlx5e_tc_action_ct = {
	.can_offload = tc_action_can_offload_ct,
	.parse_action = tc_action_parse_ct,
};

