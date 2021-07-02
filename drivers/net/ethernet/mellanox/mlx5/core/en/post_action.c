// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include "post_action.h"
#include "mlx5_core.h"

struct mlx5_post_action {
	enum mlx5_flow_namespace_type ns_type;
	struct mlx5_fs_chains *chains;
	struct mlx5_flow_table *ft;
};

struct mlx5_post_action *
mlx5_post_action_init(struct mlx5_fs_chains *chains, struct mlx5_core_dev *dev,
		      enum mlx5_flow_namespace_type ns_type)
{
	struct mlx5_post_action *post_action;
	int err;

	if (ns_type == MLX5_FLOW_NAMESPACE_FDB &&
	    !MLX5_CAP_ESW_FLOWTABLE_FDB(dev, ignore_flow_level)) {
		mlx5_core_warn(dev, "firmware level support is missing\n");
		err = -EOPNOTSUPP;
		goto err_check;
	} else if (!MLX5_CAP_FLOWTABLE_NIC_RX(dev, ignore_flow_level)) {
		mlx5_core_warn(dev, "firmware level support is missing\n");
		err = -EOPNOTSUPP;
		goto err_check;
	}

	post_action = kzalloc(sizeof(*post_action), GFP_KERNEL);
	if (!post_action) {
		err = -ENOMEM;
		goto err_check;
	}
	post_action->ft = mlx5_chains_create_global_table(chains);
	if (IS_ERR(post_action->ft)) {
		err = PTR_ERR(post_action->ft);
		mlx5_core_warn(dev, "failed to create post action table, err: %d\n", err);
		goto err_ft;
	}
	post_action->chains = chains;
	post_action->ns_type = ns_type;
	return post_action;

err_ft:
	kfree(post_action);
err_check:
	return ERR_PTR(err);
}

void
mlx5_post_action_destroy(struct mlx5_post_action *post_action)
{
	if (IS_ERR_OR_NULL(post_action))
		return;

	mlx5_chains_destroy_global_table(post_action->chains, post_action->ft);
	kfree(post_action);
}
