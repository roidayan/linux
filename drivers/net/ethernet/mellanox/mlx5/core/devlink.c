/*
 * Copyright (c) 2018, Mellanox Technologies. All rights reserved.
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

#include <devlink.h>

enum {
	MLX5_DEVLINK_MPEGC_FIELD_SELECT_TX_OVERFLOW_DROP_EN = BIT(0),
	MLX5_DEVLINK_MPEGC_FIELD_SELECT_TX_OVERFLOW_SENSE = BIT(3),
	MLX5_DEVLINK_MPEGC_FIELD_SELECT_MARK_TX_ACTION_CQE = BIT(4),
	MLX5_DEVLINK_MPEGC_FIELD_SELECT_MARK_TX_ACTION_CNP = BIT(5),
};

enum {
	MLX5_DEVLINK_CONGESTION_ACTION_DISABLED,
	MLX5_DEVLIN_CONGESTION_ACTION_DROP,
	MLX5_DEVLINK_CONGESTION_ACTION_MARK,
	__MLX5_DEVLINK_CONGESTION_ACTION_MAX,
	MLX5_DEVLINK_CONGESTION_ACTION_MAX = __MLX5_DEVLINK_CONGESTION_ACTION_MAX - 1,
};

enum {
	MLX5_DEVLINK_CONGESTION_MODE_AGGRESSIVE,
	MLX5_DEVLINK_CONGESTION_MODE_DYNAMIC_ADJUSTMENT,
	__MLX5_DEVLINK_CONGESTION_MODE_MAX,
	MLX5_DEVLINK_CONGESTION_MODE_MAX = __MLX5_DEVLINK_CONGESTION_MODE_MAX - 1,
};

static int mlx5_devlink_set_mpegc(struct mlx5_core_dev *mdev, u32 *in, int size_in)
{
	u32 out[MLX5_ST_SZ_DW(mpegc_reg)] = {0};

	if (!MLX5_CAP_MCAM_REG(mdev, mpegc))
		return -EOPNOTSUPP;

	return mlx5_core_access_reg(mdev, in, size_in, out,
				    sizeof(out), MLX5_REG_MPEGC, 0, 1);
}

static int mlx5_devlink_set_tx_lossy_overflow(struct mlx5_core_dev *mdev, u8 tx_lossy_overflow)
{
	u32 in[MLX5_ST_SZ_DW(mpegc_reg)] = {0};
	u8 field_select = 0;

	if (tx_lossy_overflow == MLX5_DEVLINK_CONGESTION_ACTION_MARK) {
		if (MLX5_CAP_MCAM_FEATURE(mdev, mark_tx_action_cqe))
			field_select |=
				MLX5_DEVLINK_MPEGC_FIELD_SELECT_MARK_TX_ACTION_CQE;

		if (MLX5_CAP_MCAM_FEATURE(mdev, mark_tx_action_cnp))
			field_select |=
				MLX5_DEVLINK_MPEGC_FIELD_SELECT_MARK_TX_ACTION_CNP;

		if (!field_select)
			return -EOPNOTSUPP;
	}

	MLX5_SET(mpegc_reg, in, field_select,
		 field_select |
		 MLX5_DEVLINK_MPEGC_FIELD_SELECT_TX_OVERFLOW_DROP_EN);
	MLX5_SET(mpegc_reg, in, tx_lossy_overflow_oper, tx_lossy_overflow);
	MLX5_SET(mpegc_reg, in, mark_cqe, 0x1);
	MLX5_SET(mpegc_reg, in, mark_cnp, 0x1);

	return mlx5_devlink_set_mpegc(mdev, in, sizeof(in));
}

static int mlx5_devlink_set_tx_overflow_sense(struct mlx5_core_dev *mdev,
					      u8 tx_overflow_sense)
{
	u32 in[MLX5_ST_SZ_DW(mpegc_reg)] = {0};

	if (!MLX5_CAP_MCAM_FEATURE(mdev, dynamic_tx_overflow))
		return -EOPNOTSUPP;

	MLX5_SET(mpegc_reg, in, field_select,
		 MLX5_DEVLINK_MPEGC_FIELD_SELECT_TX_OVERFLOW_SENSE);
	MLX5_SET(mpegc_reg, in, tx_overflow_sense, tx_overflow_sense);

	return mlx5_devlink_set_mpegc(mdev, in, sizeof(in));
}

static int mlx5_devlink_query_mpegc(struct mlx5_core_dev *mdev, u32 *out,
				    int size_out)
{
	u32 in[MLX5_ST_SZ_DW(mpegc_reg)] = {0};

	if (!MLX5_CAP_MCAM_REG(mdev, mpegc))
		return -EOPNOTSUPP;

	return mlx5_core_access_reg(mdev, in, sizeof(in), out,
				    size_out, MLX5_REG_MPEGC, 0, 0);
}

static int mlx5_devlink_query_tx_lossy_overflow(struct mlx5_core_dev *mdev,
						u8 *tx_lossy_overflow)
{
	u32 out[MLX5_ST_SZ_DW(mpegc_reg)] = {0};
	int err;

	err = mlx5_devlink_query_mpegc(mdev, out, sizeof(out));
	if (err)
		return err;

	*tx_lossy_overflow = MLX5_GET(mpegc_reg, out, tx_lossy_overflow_oper);

	return 0;
}

static int mlx5_devlink_query_tx_overflow_sense(struct mlx5_core_dev *mdev,
						u8 *tx_overflow_sense)
{
	u32 out[MLX5_ST_SZ_DW(mpegc_reg)] = {0};
	int err;

	if (!MLX5_CAP_MCAM_FEATURE(mdev, dynamic_tx_overflow))
		return -EOPNOTSUPP;

	err = mlx5_devlink_query_mpegc(mdev, out, sizeof(out));
	if (err)
		return err;

	*tx_overflow_sense = MLX5_GET(mpegc_reg, out, tx_overflow_sense);

	return 0;
}

static int mlx5_devlink_set_congestion_action(struct devlink *devlink, u32 id,
					      struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	u8 max = MLX5_DEVLINK_CONGESTION_ACTION_MAX;
	u8 sense;
	int err;

	if (!MLX5_CAP_MCAM_FEATURE(dev, mark_tx_action_cqe) &&
	    !MLX5_CAP_MCAM_FEATURE(dev, mark_tx_action_cnp))
		max = MLX5_DEVLINK_CONGESTION_ACTION_MARK - 1;

	if (ctx->val.vu8 > max)
		return -ERANGE;

	err = mlx5_devlink_query_tx_overflow_sense(dev, &sense);
	if (err)
		return err;

	if (ctx->val.vu8 == MLX5_DEVLINK_CONGESTION_ACTION_DISABLED &&
	    sense != MLX5_DEVLINK_CONGESTION_MODE_AGGRESSIVE)
		return -EINVAL;

	return mlx5_devlink_set_tx_lossy_overflow(dev, ctx->val.vu8);
}

static int mlx5_devlink_get_congestion_action(struct devlink *devlink, u32 id,
					      struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	return mlx5_devlink_query_tx_lossy_overflow(dev, &ctx->val.vu8);
}

static int mlx5_devlink_set_congestion_mode(struct devlink *devlink, u32 id,
					    struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);
	u8 tx_lossy_overflow;
	int err;

	if (ctx->val.vu8 > MLX5_DEVLINK_CONGESTION_MODE_MAX)
		return -ERANGE;

	err = mlx5_devlink_query_tx_lossy_overflow(dev, &tx_lossy_overflow);
	if (err)
		return err;

	if (ctx->val.vu8 != MLX5_DEVLINK_CONGESTION_MODE_AGGRESSIVE &&
	    tx_lossy_overflow == MLX5_DEVLINK_CONGESTION_ACTION_DISABLED)
		return -EINVAL;

	return mlx5_devlink_set_tx_overflow_sense(dev, ctx->val.vu8);
}

static int mlx5_devlink_get_congestion_mode(struct devlink *devlink, u32 id,
					    struct devlink_param_gset_ctx *ctx)
{
	struct mlx5_core_dev *dev = devlink_priv(devlink);

	return mlx5_devlink_query_tx_overflow_sense(dev, &ctx->val.vu8);
}

enum mlx5_devlink_param_id {
	MLX5_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	MLX5_DEVLINK_PARAM_ID_CONGESTION_ACTION,
	MLX5_DEVLINK_PARAM_ID_CONGESTION_MODE,
};

static const struct devlink_param mlx5_devlink_params[] = {
	DEVLINK_PARAM_DRIVER(MLX5_DEVLINK_PARAM_ID_CONGESTION_ACTION,
			     "congestion_action",
			     DEVLINK_PARAM_TYPE_U8,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     mlx5_devlink_get_congestion_action,
			     mlx5_devlink_set_congestion_action, NULL),
	DEVLINK_PARAM_DRIVER(MLX5_DEVLINK_PARAM_ID_CONGESTION_MODE,
			     "congestion_mode",
			     DEVLINK_PARAM_TYPE_U8,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     mlx5_devlink_get_congestion_mode,
			     mlx5_devlink_set_congestion_mode, NULL),
};

int mlx5_devlink_register(struct devlink *devlink, struct device *dev)
{
	int err;

	err = devlink_register(devlink, dev);
	if (err)
		return err;

	err = devlink_params_register(devlink, mlx5_devlink_params,
				      ARRAY_SIZE(mlx5_devlink_params));
	if (err) {
		dev_err(dev, "devlink_params_register failed, err = %d\n", err);
		goto unregister;
	}

	return 0;

unregister:
	devlink_unregister(devlink);
	return err;
}

void mlx5_devlink_unregister(struct devlink *devlink)
{
	devlink_params_unregister(devlink, mlx5_devlink_params,
				  ARRAY_SIZE(mlx5_devlink_params));
	devlink_unregister(devlink);
}
