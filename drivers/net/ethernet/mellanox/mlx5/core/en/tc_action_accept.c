// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include "tc_action.h"
#include "en_tc.h"

static int
tc_action_can_offload_accept(struct mlx5e_tc_action_parse_state *parse_state,
			     const struct flow_action_entry *act,
			     int act_index)
{
	if (mlx5e_is_eswitch_flow(parse_state->flow))
		return -EOPNOTSUPP;

	return 0;
}

static int
tc_action_parse_accept(struct mlx5e_tc_action_parse_state *parse_state,
		       const struct flow_action_entry *act,
		       struct mlx5e_priv *priv,
		       struct mlx5_flow_attr *attr)
{
	attr->action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
			MLX5_FLOW_CONTEXT_ACTION_COUNT;

	return 0;
}

struct mlx5e_tc_action mlx5e_tc_action_accept = {
	.can_offload = tc_action_can_offload_accept,
	.parse_action = tc_action_parse_accept,
};
