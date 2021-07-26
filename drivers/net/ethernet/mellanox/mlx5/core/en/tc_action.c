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
	tc_actions[FLOW_ACTION_REDIRECT] = &mlx5e_tc_action_mirred;
	tc_actions[FLOW_ACTION_MIRRED] = &mlx5e_tc_action_mirred;
	tc_actions[FLOW_ACTION_VLAN_PUSH] = &mlx5e_tc_action_vlan;
	tc_actions[FLOW_ACTION_VLAN_POP] = &mlx5e_tc_action_vlan;
	tc_actions[FLOW_ACTION_VLAN_MANGLE] = &mlx5e_tc_action_vlan_mangle;
	tc_actions[FLOW_ACTION_TUNNEL_ENCAP] = &mlx5e_tc_action_tun_encap;
	tc_actions[FLOW_ACTION_TUNNEL_DECAP] = &mlx5e_tc_action_tun_decap;
	tc_actions[FLOW_ACTION_CSUM] = &mlx5e_tc_action_csum;
	tc_actions[FLOW_ACTION_MPLS_PUSH] = &mlx5e_tc_action_mpls_push;
	tc_actions[FLOW_ACTION_MPLS_POP] = &mlx5e_tc_action_mpls_pop;
	tc_actions[FLOW_ACTION_CT] = &mlx5e_tc_action_ct;
	tc_actions[FLOW_ACTION_SAMPLE] = &mlx5e_tc_action_sample;
	tc_actions[FLOW_ACTION_MANGLE] = &mlx5e_tc_action_pedit;
	tc_actions[FLOW_ACTION_ADD] = &mlx5e_tc_action_pedit;
	tc_actions[FLOW_ACTION_ACCEPT] = &mlx5e_tc_action_accept;
	tc_actions[FLOW_ACTION_MARK] = &mlx5e_tc_action_mark;
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
