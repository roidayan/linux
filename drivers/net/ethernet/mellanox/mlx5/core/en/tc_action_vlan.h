/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_TC_ACTION_VLAN_H__
#define __MLX5_TC_ACTION_VLAN_H__

#include <net/flow_offload.h>
#include "en_tc.h"

int parse_tc_vlan_action(struct mlx5e_priv *priv,
			 const struct flow_action_entry *act,
			 struct mlx5_esw_flow_attr *attr,
			 u32 *action);

int
mlx5e_tc_add_vlan_push_action(struct mlx5e_priv *priv,
			      struct mlx5_flow_attr *attr,
			      struct net_device **out_dev,
			      u32 *action);

int
mlx5e_tc_add_vlan_pop_action(struct mlx5e_priv *priv,
			     struct mlx5_flow_attr *attr,
			     u32 *action);

#endif /* __MLX5_TC_ACTION_VLAN_H__ */
