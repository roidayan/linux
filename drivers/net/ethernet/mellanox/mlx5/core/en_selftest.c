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

#include "en.h"

enum {
	MLX5E_ST_LINK_STATE,
	MLX5E_ST_LINK_SPEED,
	MLX5E_ST_HEALTH_INFO,

	MLX5E_OFFLINE_TESTS, /* offline tests */
	MLX5E_ST_INTERRUPT = MLX5E_OFFLINE_TESTS,

	MLX5E_ST_NUM,
};

const char mlx5e_self_tests[][ETH_GSTRING_LEN] = {
	"Link Test",
	"Speed Test",
	"Health Test",
	"Interrupt Test",
};

int mlx5e_self_test_num(struct mlx5e_priv *priv)
{
	return ARRAY_SIZE(mlx5e_self_tests);
}

static int mlx5e_test_health_info(struct mlx5e_priv *priv)
{
	struct mlx5_core_health *health = &priv->mdev->priv.health;

	return health->sick ? 1 : 0;
}

static int mlx5e_test_link_state(struct mlx5e_priv *priv)
{
	u8 port_state;

	if (!netif_carrier_ok(priv->netdev))
		return 1;

	port_state = mlx5_query_vport_state(priv->mdev, MLX5_QUERY_VPORT_STATE_IN_OP_MOD_VNIC_VPORT, 0);
	return port_state == VPORT_STATE_UP ? 0 : 1;
}

static int mlx5e_test_link_speed(struct mlx5e_priv *priv)
{
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	u32 eth_proto_oper;
	int i;

	if (!netif_carrier_ok(priv->netdev))
		return 1;

	if (mlx5_query_port_ptys(priv->mdev, out, sizeof(out), MLX5_PTYS_EN, 1))
		return 1;

	eth_proto_oper = MLX5_GET(ptys_reg, out, eth_proto_oper);
	for (i = 0; i < MLX5E_LINK_MODES_NUMBER; i++) {
		if (eth_proto_oper & MLX5E_PROT_MASK(i))
			return 0;
	}
	return 1;
}

#define MLX5E_NOP_PACKET_TIMEOUT 100
static int mlx5e_test_interrupt(struct mlx5e_priv *priv)
{
	int num_channels = priv->params.num_channels;
	u64 nops_arr[MLX5E_MAX_NUM_CHANNELS];
	struct mlx5e_sq *sq;
	int err = 0;
	int i;

	for (i = 0; i < num_channels; i++) {
		sq = &priv->channel[i]->sq[0];
		nops_arr[i] = sq->stats.nop;
		mlx5e_send_nop(sq, true);
	}

	msleep(MLX5E_NOP_PACKET_TIMEOUT);
	for (i = 0; i < num_channels; i++) {
		sq = &priv->channel[i]->sq[0];

		if (sq->stats.nop == (nops_arr[i] + 1))
			continue;

		err += 1;
		netdev_err(priv->netdev,
			   "Interrupt Test for channel %d failed (%llu != %llu)\n",
			   i, sq->stats.nop, nops_arr[i] + 1);
	}
	return err;
}

int (*mlx5e_st_func[MLX5E_ST_NUM])(struct mlx5e_priv *) = {
	mlx5e_test_link_state,
	mlx5e_test_link_speed,
	mlx5e_test_health_info,

	/* Offline tests */
	mlx5e_test_interrupt
};

#define MLX5E_WAIT_TX_QUEUE_EMPTY 200
void mlx5e_self_test(struct net_device *ndev, struct ethtool_test *etest,
		     u64 *buf)
{
	struct mlx5e_priv *priv = netdev_priv(ndev);
	bool carrier_ok = false;
	int i;

	memset(buf, 0, sizeof(u64) * MLX5E_ST_NUM);

	mutex_lock(&priv->state_lock);
	netdev_info(ndev, "Self test start..\n");

	for (i = 0; i < MLX5E_OFFLINE_TESTS; i++) {
		netdev_info(ndev, "\t[%d] %s start..\n",
			    i, mlx5e_self_tests[i]);
		buf[i] = mlx5e_st_func[i](priv);
		netdev_info(ndev, "\t[%d] %s end: result(%lld)\n",
			    i, mlx5e_self_tests[i], buf[i]);
	}

	if (!(etest->flags & ETH_TEST_FL_OFFLINE))
		goto unlock;

	for (i = MLX5E_OFFLINE_TESTS; i < MLX5E_ST_NUM; i++)
		buf[i] = 1;

	if (!test_bit(MLX5E_STATE_OPENED, &priv->state))
		goto unlock;

	/* Save current state */
	carrier_ok = netif_carrier_ok(ndev);
	/* Disable interface */
	netif_carrier_off(ndev);
	/* Wait until all the TX queues get empty.
	 * There should not be any additional incoming traffic
	 * since we turned the carrier off
	 */
	msleep(MLX5E_WAIT_TX_QUEUE_EMPTY);

	for (i = MLX5E_OFFLINE_TESTS; i < MLX5E_ST_NUM; i++) {
		netdev_info(ndev, "\t[%d] %s start..\n",
			    i, mlx5e_self_tests[i]);
		buf[i] = mlx5e_st_func[i](priv);
		netdev_info(ndev, "\t[%d] %s end: result(%lld)\n",
			    i, mlx5e_self_tests[i], buf[i]);
	}

	/* Restore state */
	if (carrier_ok)
		netif_carrier_on(ndev);

unlock:
	mutex_unlock(&priv->state_lock);

	for (i = 0; i < MLX5E_ST_NUM; i++) {
		if (buf[i]) {
			etest->flags |= ETH_TEST_FL_FAILED;
			break;
		}
	}
	netdev_info(ndev, "Self test out: status flags(0x%x)\n",
		    etest->flags);
}
