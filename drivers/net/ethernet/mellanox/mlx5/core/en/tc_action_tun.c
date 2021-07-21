// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include "tc_action.h"
#include "tc_tun_encap.h"
#include "tc_priv.h"
#include "en_tc.h"

static int
tc_action_can_offload_tun_encap(struct mlx5e_tc_action_parse_state *parse_state,
				const struct flow_action_entry *act,
				int act_index)
{
	if (act->tunnel)
		return 0;

	return -EOPNOTSUPP;
}

static int
tc_action_parse_tun_encap(struct mlx5e_tc_action_parse_state *parse_state,
			  const struct flow_action_entry *act,
			  struct mlx5e_priv *priv,
			  struct mlx5_flow_attr *attr)
{
	parse_state->tun_info = act->tunnel;
	parse_state->encap = true;

	return 0;
}

static int
tc_action_can_offload_tun_decap(struct mlx5e_tc_action_parse_state *parse_state,
				const struct flow_action_entry *act,
				int act_index)
{
	return 0;
}

static int
tc_action_parse_tun_decap(struct mlx5e_tc_action_parse_state *parse_state,
			  const struct flow_action_entry *act,
			  struct mlx5e_priv *priv,
			  struct mlx5_flow_attr *attr)
{
	parse_state->decap = true;

	return 0;
}

struct mlx5e_tc_action mlx5e_tc_action_tun_encap = {
	.can_offload = tc_action_can_offload_tun_encap,
	.parse_action = tc_action_parse_tun_encap,
};

struct mlx5e_tc_action mlx5e_tc_action_tun_decap = {
	.can_offload = tc_action_can_offload_tun_decap,
	.parse_action = tc_action_parse_tun_decap,
};
