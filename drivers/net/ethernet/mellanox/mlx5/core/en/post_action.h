/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_POST_ACTION_H__
#define __MLX5_POST_ACTION_H__

#include "lib/fs_chains.h"

struct mlx5_post_action *
mlx5_post_action_init(struct mlx5_fs_chains *chains, struct mlx5_core_dev *dev,
		      enum mlx5_flow_namespace_type ns_type);

void
mlx5_post_action_destroy(struct mlx5_post_action *post_action);

#endif /* __MLX5_POST_ACTION_H__ */
