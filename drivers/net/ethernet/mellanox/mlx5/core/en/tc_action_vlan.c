// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include <linux/if_vlan.h>
#include "tc_action.h"
#include "tc_action_vlan.h"
#include "tc_priv.h"
#include "en_tc.h"

int
parse_tc_vlan_action(struct mlx5e_priv *priv,
		     const struct flow_action_entry *act,
		     struct mlx5_esw_flow_attr *attr,
		     u32 *action)
{
	u8 vlan_idx = attr->total_vlan;

	if (vlan_idx >= MLX5_FS_VLAN_DEPTH)
		return -EOPNOTSUPP;

	switch (act->id) {
	case FLOW_ACTION_VLAN_POP:
		if (vlan_idx) {
			if (!mlx5_eswitch_vlan_actions_supported(priv->mdev,
								 MLX5_FS_VLAN_DEPTH))
				return -EOPNOTSUPP;

			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_POP_2;
		} else {
			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_POP;
		}
		break;
	case FLOW_ACTION_VLAN_PUSH:
		attr->vlan_vid[vlan_idx] = act->vlan.vid;
		attr->vlan_prio[vlan_idx] = act->vlan.prio;
		attr->vlan_proto[vlan_idx] = act->vlan.proto;
		if (!attr->vlan_proto[vlan_idx])
			attr->vlan_proto[vlan_idx] = htons(ETH_P_8021Q);

		if (vlan_idx) {
			if (!mlx5_eswitch_vlan_actions_supported(priv->mdev,
								 MLX5_FS_VLAN_DEPTH))
				return -EOPNOTSUPP;

			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH_2;
		} else {
			if (!mlx5_eswitch_vlan_actions_supported(priv->mdev, 1) &&
			    (act->vlan.proto != htons(ETH_P_8021Q) ||
			     act->vlan.prio))
				return -EOPNOTSUPP;

			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH;
		}
		break;
	default:
		return -EINVAL;
	}

	attr->total_vlan = vlan_idx + 1;

	return 0;
}

int
mlx5e_tc_add_vlan_push_action(struct mlx5e_priv *priv,
			      struct mlx5_flow_attr *attr,
			      struct net_device **out_dev,
			      u32 *action)
{
	struct net_device *vlan_dev = *out_dev;
	struct flow_action_entry vlan_act = {
		.id = FLOW_ACTION_VLAN_PUSH,
		.vlan.vid = vlan_dev_vlan_id(vlan_dev),
		.vlan.proto = vlan_dev_vlan_proto(vlan_dev),
		.vlan.prio = 0,
	};
	int err;

	err = parse_tc_vlan_action(priv, &vlan_act, attr->esw_attr, action);
	if (err)
		return err;

	rcu_read_lock();
	*out_dev = dev_get_by_index_rcu(dev_net(vlan_dev), dev_get_iflink(vlan_dev));
	rcu_read_unlock();
	if (!*out_dev)
		return -ENODEV;

	if (is_vlan_dev(*out_dev))
		err = mlx5e_tc_add_vlan_push_action(priv, attr, out_dev, action);

	return err;
}

int
mlx5e_tc_add_vlan_pop_action(struct mlx5e_priv *priv,
			     struct mlx5_flow_attr *attr,
			     u32 *action)
{
	struct flow_action_entry vlan_act = {
		.id = FLOW_ACTION_VLAN_POP,
	};
	int nest_level, err = 0;

	nest_level = attr->parse_attr->filter_dev->lower_level -
						priv->netdev->lower_level;
	while (nest_level--) {
		err = parse_tc_vlan_action(priv, &vlan_act, attr->esw_attr, action);
		if (err)
			return err;
	}

	return err;
}

static int
tc_action_can_offload_vlan(struct mlx5e_tc_action_parse_state *parse_state,
			   const struct flow_action_entry *act,
			   int act_index)
{
	return 0;
}

static int
tc_action_parse_vlan(struct mlx5e_tc_action_parse_state *parse_state,
		     const struct flow_action_entry *act,
		     struct mlx5e_priv *priv,
		     struct mlx5_flow_attr *attr)
{
	struct mlx5_esw_flow_attr *esw_attr = attr->esw_attr;
	u32 action = attr->action;
	int err;

	if (act->id == FLOW_ACTION_VLAN_PUSH &&
	    (action & MLX5_FLOW_CONTEXT_ACTION_VLAN_POP)) {
		/* Replace vlan pop+push with vlan modify */
		return -EOPNOTSUPP;
	}

	err = parse_tc_vlan_action(priv, act, esw_attr, &action);

	if (err)
		return err;

	esw_attr->split_count = esw_attr->out_count;
	attr->action = action;

	return 0;
}

struct mlx5e_tc_action mlx5e_tc_action_vlan = {
	.can_offload = tc_action_can_offload_vlan,
	.parse_action = tc_action_parse_vlan,
};
