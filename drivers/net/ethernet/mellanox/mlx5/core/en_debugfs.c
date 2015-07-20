/*
 * Copyright (c) 2015, Mellanox Technologies inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/module.h>
#include <linux/debugfs.h>
#include "en.h"

void mlx5e_create_channel_debugfs(struct mlx5e_channel *c)
{
	struct net_device *netdev = c->netdev;
	char name[MLX5_MAX_NAME_LEN];
	int i;

	if (!c->priv->dfs_root)
		return;

	snprintf(name, MLX5_MAX_NAME_LEN, "channel-%d", c->ix);
	c->dfs_root = debugfs_create_dir(name, c->priv->dfs_root);
	if (!c->dfs_root) {
		netdev_err(netdev, "Failed to create channel debugfs for %s\n",
			   netdev->name);
		return;
	}

	for (i = 0; i < c->priv->params.num_tc; i++) {
		snprintf(name, MLX5_MAX_NAME_LEN, "sqn-%d", i);
		debugfs_create_u32(name, S_IRUSR, c->dfs_root, &c->sq[i].sqn);
		snprintf(name, MLX5_MAX_NAME_LEN, "sq-cqn-%d", i);
		debugfs_create_u32(name, S_IRUSR, c->dfs_root,
				   &c->sq[i].cq.mcq.cqn);
	}

	debugfs_create_u32("rqn", S_IRUSR, c->dfs_root, &c->rq.rqn);
	debugfs_create_u32("rq-cqn", S_IRUSR, c->dfs_root, &c->rq.cq.mcq.cqn);
}

void mlx5e_destroy_channel_debugfs(struct mlx5e_channel *c)
{
	debugfs_remove_recursive(c->dfs_root);
	c->dfs_root = NULL;
}

void mlx5e_create_debugfs(struct mlx5e_priv *priv)
{
	int i;
	char name[MLX5_MAX_NAME_LEN];

	priv->dfs_root = debugfs_create_dir(priv->netdev->name, NULL);
	if (!priv->dfs_root) {
		netdev_err(priv->netdev, "Failed to init debugfs files for %s\n",
			   priv->netdev->name);
		return;
	}

	debugfs_create_u32("uar", S_IRUSR, priv->dfs_root,
			   &priv->cq_uar.index);
	debugfs_create_u32("pdn", S_IRUSR, priv->dfs_root, &priv->pdn);
	debugfs_create_u32("mkey", S_IRUSR, priv->dfs_root,
			   &priv->mr.key);
	debugfs_create_u8("num_tc", S_IRUSR, priv->dfs_root,
			  &priv->params.num_tc);

	for (i = 0; i < priv->params.num_tc; i++) {
		snprintf(name, MLX5_MAX_NAME_LEN, "tisn-%d", i);
		debugfs_create_u32(name, S_IRUSR, priv->dfs_root,
				   &priv->tisn[i]);
	}

	for (i = 0; i < MLX5E_NUM_TT; i++) {
		snprintf(name, MLX5_MAX_NAME_LEN, "tirn-%d", i);
		debugfs_create_u32(name, S_IRUSR, priv->dfs_root,
				   &priv->tirn[i]);
	}
}

void mlx5e_destroy_debugfs(struct mlx5e_priv *priv)
{
	debugfs_remove_recursive(priv->dfs_root);
	priv->dfs_root = NULL;
}
