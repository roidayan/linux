/*
 * Copyright (c) 2016, Mellanox Technologies, Ltd.  All rights reserved.
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

#include <linux/mlx5/driver.h>
#include "mlx5_core.h"
#include "en.h"

#define MLX5E_MAX_REG_LEN             4096
#define MLX5E_MAX_CMD_OUT_LEN (MLX5E_MAX_REG_LEN - MLX5_ST_SZ_BYTES(mbox_in))

static void reg_out_alloc(struct mlx5e_reg *reg)
{
	if (reg->data_out) {
		memset(reg->data_out, 0, MLX5E_MAX_CMD_OUT_LEN);
		return;
	}

	reg->data_out = mlx5_vzalloc(MLX5E_MAX_CMD_OUT_LEN);
}

struct mlx5e_reg *mlx5e_regs_init(void)
{
	return kzalloc(sizeof(struct mlx5e_reg), GFP_KERNEL);
}

void mlx5e_regs_destroy(struct mlx5e_reg *reg)
{
	kvfree(reg->data_out);
	kfree(reg);
}

static bool opcode_valid(u16 opcode)
{
	switch (opcode) {
	case MLX5_CMD_OP_QUERY_HCA_CAP:
	case MLX5_CMD_OP_QUERY_DIAGNOSTIC_PARAMS:
	case MLX5_CMD_OP_SET_DIAGNOSTIC_PARAMS:
	case MLX5_CMD_OP_QUERY_DIAGNOSTICS_COUNTERS:
		return true;
	}

	return false;
}

int mlx5e_regs_set(struct net_device *dev, void *buff, int inlen)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_reg *reg = priv->reg;
	u16 opcode;

	if (!reg)
		return -ENOMEM;

	opcode = MLX5_GET(mbox_in, buff, opcode);
	if (!opcode_valid(opcode))
		return -EINVAL;

	reg_out_alloc(reg);
	if (!reg->data_out)
		return -ENOMEM;

	memcpy(reg->data_in, buff, sizeof(reg->data_in));

	return mlx5_cmd_exec(mdev, buff, inlen, reg->data_out,
			     MLX5E_MAX_CMD_OUT_LEN);
}

void mlx5e_regs_get(struct net_device *dev, void *buff)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_reg *reg = priv->reg;

	if (!reg)
		return;

	if (reg->data_out) {
		memcpy(buff, reg->data_in, sizeof(reg->data_in));
		memcpy(buff + sizeof(reg->data_in), reg->data_out,
		       MLX5E_MAX_CMD_OUT_LEN);
	}
}

int mlx5e_regs_get_len(void)
{
	return MLX5E_MAX_REG_LEN;
}
