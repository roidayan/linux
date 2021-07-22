// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include <net/psample.h>
#include "tc_action.h"
#include "tc_priv.h"
#include "en_tc.h"

static int
tc_action_can_offload_sample(struct mlx5e_tc_action_parse_state *parse_state,
			     const struct flow_action_entry *act,
			     int act_index)
{
	struct netlink_ext_ack *extack = parse_state->extack;

	if (flow_flag_test(parse_state->flow, CT)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Sample action with connection tracking is not supported");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int
tc_action_parse_sample(struct mlx5e_tc_action_parse_state *parse_state,
		       const struct flow_action_entry *act,
		       struct mlx5e_priv *priv,
		       struct mlx5_flow_attr *attr)
{
	struct mlx5_sample_attr *sample = &parse_state->sample;

	sample->rate = act->sample.rate;
	sample->group_num = act->sample.psample_group->group_num;

	if (act->sample.truncate)
		sample->trunc_size = act->sample.trunc_size;

	flow_flag_set(parse_state->flow, SAMPLE);

	return 0;
}

struct mlx5e_tc_action mlx5e_tc_action_sample = {
	.can_offload = tc_action_can_offload_sample,
	.parse_action = tc_action_parse_sample,
};
