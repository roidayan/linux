/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
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
#include <linux/device.h>
#include <linux/netdevice.h>
#include "en.h"

#define MLX5E_MAX_PRIORITY 8

static int mlx5e_dcbnl_ieee_getets(struct net_device *netdev,
				   struct ieee_ets *ets)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	int err;

	ets->ets_cap = mlx5_max_tc(mdev) + 1;

	err = mlx5_query_port_prio_tc(mdev, ets->prio_tc);
	if (err)
		return err;

	err = mlx5_query_port_tc_bw_alloc(mdev, ets->tc_tx_bw);
	if (err)
		return err;

	return 0;
}

enum {
	MLX5E_VENDOR_GROUP_NUM	= 0,
	MLX5E_ETS_GROUP_NUM	= 7,
};

static void mlx5e_build_tc_group(struct ieee_ets *ets, u8 *tc_group, int max_tc,
				 int *vendor_group_num_tcs)
{
	int strict_group = 0;
	int i;

	(*vendor_group_num_tcs) = 0;

	for (i = max_tc; i >= 0; i--) {
		switch (ets->tc_tsa[i]) {
		case IEEE_8021QAZ_TSA_VENDOR:
			(*vendor_group_num_tcs)++;
			tc_group[i] = MLX5E_VENDOR_GROUP_NUM;
			break;
		case IEEE_8021QAZ_TSA_STRICT:
			if (strict_group == MLX5E_VENDOR_GROUP_NUM)
				(*vendor_group_num_tcs)++;
			tc_group[i] = strict_group++;
			break;
		case IEEE_8021QAZ_TSA_ETS:
			tc_group[i] = MLX5E_ETS_GROUP_NUM;
			break;
		}
	}
}

static void mlx5e_build_tc_tx_bw(struct ieee_ets *ets, u8 *tc_tx_bw,
				 u8 *tc_group, int max_tc,
				 int vendor_group_num_tcs)
{
	int i;

	for (i = 0; i <= max_tc; i++) {
		switch (ets->tc_tsa[i]) {
		case IEEE_8021QAZ_TSA_VENDOR:
			tc_tx_bw[i] = 100 / vendor_group_num_tcs;
			break;
		case IEEE_8021QAZ_TSA_STRICT:
			tc_tx_bw[i] = 100;
			if (tc_group[i] == MLX5E_VENDOR_GROUP_NUM)
				tc_tx_bw[i] /= vendor_group_num_tcs;
			break;
		case IEEE_8021QAZ_TSA_ETS:
			tc_tx_bw[i] = ets->tc_tx_bw[i] ?: 1;
			break;
		}
	}
}

static int mlx5e_dcbnl_ieee_setets(struct net_device *netdev,
				   struct ieee_ets *ets)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u8 tc_tx_bw[IEEE_8021QAZ_MAX_TCS];
	u8 tc_group[IEEE_8021QAZ_MAX_TCS];
	int vendor_group_num_tcs;
	int max_tc = mlx5_max_tc(mdev);
	int err;

	mlx5e_build_tc_group(ets, tc_group, max_tc, &vendor_group_num_tcs);
	mlx5e_build_tc_tx_bw(ets, tc_tx_bw, tc_group, max_tc,
			     vendor_group_num_tcs);

	err = mlx5_set_port_prio_tc(mdev, ets->prio_tc);
	if (err)
		return err;

	err = mlx5_set_port_tc_group(mdev, tc_group);
	if (err)
		return err;

	return mlx5_set_port_tc_bw_alloc(mdev, tc_tx_bw);
}

static int mlx5e_dcbnl_ieee_getpfc(struct net_device *dev,
				   struct ieee_pfc *pfc)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;

	pfc->pfc_cap = mlx5_max_tc(mdev) + 1;

	return mlx5_query_port_pfc(mdev, &pfc->pfc_en, NULL);
}

static int mlx5e_dcbnl_ieee_setpfc(struct net_device *dev,
				   struct ieee_pfc *pfc)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	enum mlx5_port_status ps;
	u8 curr_pfc_en;
	int ret;

	mlx5_query_port_pfc(mdev, &curr_pfc_en, NULL);

	if (pfc->pfc_en == curr_pfc_en)
		return 0;

	mlx5_query_port_admin_status(mdev, &ps);
	if (ps == MLX5_PORT_UP)
		mlx5_set_port_admin_status(mdev, MLX5_PORT_DOWN);

	ret = mlx5_set_port_pfc(mdev, pfc->pfc_en, pfc->pfc_en);

	if (ps == MLX5_PORT_UP)
		mlx5_set_port_admin_status(mdev, MLX5_PORT_UP);

	return ret;
}

static u8 mlx5e_dcbnl_getdcbx(struct net_device *dev)
{
	return DCB_CAP_DCBX_HOST | DCB_CAP_DCBX_VER_IEEE;
}

static u8 mlx5e_dcbnl_setdcbx(struct net_device *dev, u8 mode)
{
	if ((mode & DCB_CAP_DCBX_LLD_MANAGED) ||
	    (mode & DCB_CAP_DCBX_VER_CEE) ||
	    !(mode & DCB_CAP_DCBX_VER_IEEE) ||
	    !(mode & DCB_CAP_DCBX_HOST))
		return 1;

	return 0;
}

int mlx5e_dcbnl_ieee_getmaxrate(struct net_device *netdev,
				struct ieee_maxrate *maxrate)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u8 max_bw_value[IEEE_8021QAZ_MAX_TCS];
	u8 max_bw_unit[IEEE_8021QAZ_MAX_TCS];
	int err;
	int i;

	err = mlx5_query_port_ets_rate_limit(mdev, max_bw_value, max_bw_unit);
	if (err)
		return err;

	memset(maxrate->tc_maxrate, 0, sizeof(maxrate->tc_maxrate));

	for (i = 0; i <= mlx5_max_tc(mdev); i++) {
		switch (max_bw_unit[i]) {
		case MLX5_100_MBPS_UNIT:
			maxrate->tc_maxrate[i] = max_bw_value[i] * 100000;
			break;
		case MLX5_GBPS_UNIT:
			maxrate->tc_maxrate[i] = max_bw_value[i] * 1000000;
			break;
		default:
			BUG_ON(true);
			break;
		}
	}

	return 0;
}

int mlx5e_dcbnl_ieee_setmaxrate(struct net_device *netdev,
				struct ieee_maxrate *maxrate)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u8 max_bw_value[IEEE_8021QAZ_MAX_TCS];
	u8 max_bw_unit[IEEE_8021QAZ_MAX_TCS];
	int i;

	for (i = 0; i <= mlx5_max_tc(mdev); i++) {
		__u64 upper_limit_mbps = roundup(255 * 100000, 1000000);

		if (maxrate->tc_maxrate[i] < upper_limit_mbps) {
			max_bw_value[i] = round_down(maxrate->tc_maxrate[i] / 100000, 1);
			if (maxrate->tc_maxrate[i] && max_bw_value[i] == 0)
				max_bw_value[i] = 1;
			max_bw_value[i] = max_bw_value[i] > 255 ?
				255 : max_bw_value[i];
			max_bw_unit[i]  = MLX5_100_MBPS_UNIT;
		} else {
			max_bw_value[i] = round_down(maxrate->tc_maxrate[i] / 1000000, 1);
			max_bw_value[i] = max_bw_value[i] > 255 ?
				255 : max_bw_value[i];
			max_bw_unit[i]  = MLX5_GBPS_UNIT;
		}
	}

	return mlx5_modify_port_ets_rate_limit(mdev, max_bw_value, max_bw_unit);
}

const struct dcbnl_rtnl_ops mlx5e_dcbnl_ops = {
	.ieee_getets	= mlx5e_dcbnl_ieee_getets,
	.ieee_setets	= mlx5e_dcbnl_ieee_setets,
	.ieee_getmaxrate = mlx5e_dcbnl_ieee_getmaxrate,
	.ieee_setmaxrate = mlx5e_dcbnl_ieee_setmaxrate,
	.ieee_getpfc	= mlx5e_dcbnl_ieee_getpfc,
	.ieee_setpfc	= mlx5e_dcbnl_ieee_setpfc,
	.getdcbx	= mlx5e_dcbnl_getdcbx,
	.setdcbx	= mlx5e_dcbnl_setdcbx,
};
