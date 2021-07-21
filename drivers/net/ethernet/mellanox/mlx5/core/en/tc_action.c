// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include "tc_action.h"
#include "tc_priv.h"
#include "en_tc.h"
#include "mlx5_core.h"

static struct mlx5e_tc_action *tc_actions[NUM_FLOW_ACTIONS];

void
mlx5e_tc_init_tc_actions(void)
{
	tc_actions[FLOW_ACTION_DROP] = &mlx5e_tc_action_drop;
	tc_actions[FLOW_ACTION_TRAP] = &mlx5e_tc_action_trap;
	tc_actions[FLOW_ACTION_GOTO] = &mlx5e_tc_action_goto;
}

struct mlx5e_tc_action *
mlx5e_tc_action_get(enum flow_action_id act_id)
{
	return tc_actions[act_id];
}

void
mlx5e_tc_action_init_parse_state(struct mlx5e_tc_action_parse_state *parse_state,
				 struct mlx5e_tc_flow *flow,
				 struct flow_action *flow_action,
				 struct netlink_ext_ack *extack)
{
	memset(parse_state, 0, sizeof(*parse_state));
	parse_state->flow = flow;
	parse_state->num_actions = flow_action->num_entries;
	parse_state->extack = extack;
}
