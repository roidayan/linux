/*
 * Copyright (c) 2017 Mellanox Technologies. All rights reserved.
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
 *
 */

#include <linux/ethtool.h>
#include <net/sock.h>

#include "en.h"
#include "ipsec_sadb.h"
#include "fpga/sdk.h"
#include "en_ipsec/ipsec.h"

static const char * const mlx5e_ipsec_stats_desc[MLX5E_IPSEC_STATS_COUNT] = {
	"ipsec_dec_in_packets",
	"ipsec_dec_out_packets",
	"ipsec_dec_bypass_packets",
	"ipsec_enc_in_packets",
	"ipsec_enc_out_packets",
	"ipsec_enc_bypass_packets",
	"ipsec_dec_drop_packets",
	"ipsec_dec_auth_fail_packets",
	"ipsec_enc_drop_packets",
	"ipsec_add_sa_success",
	"ipsec_add_sa_fail",
	"ipsec_del_sa_success",
	"ipsec_del_sa_fail",
	"ipsec_cmd_drop",
};

static int mlx5e_ipsec_counters_count(struct mlx5e_ipsec_dev *dev)
{
	return min_t(u32, mlx5_core_ipsec_counters_count(dev->en_priv->mdev),
		     MLX5E_IPSEC_STATS_COUNT);
}

int mlx5e_ipsec_get_count(struct mlx5e_priv *priv)
{
	if (!priv->ipsec)
		return 0;

	return mlx5e_ipsec_counters_count(priv->ipsec);
}

int mlx5e_ipsec_get_strings(struct mlx5e_priv *priv, uint8_t *data)
{
	unsigned int i;
	u32 count;

	if (!priv->ipsec)
		return 0;

	count = mlx5e_ipsec_counters_count(priv->ipsec);
	for (i = 0; i < count; i++)
		strcpy(data + (i * ETH_GSTRING_LEN), mlx5e_ipsec_stats_desc[i]);

	return count;
}

void mlx5e_ipsec_update_stats(struct mlx5e_priv *priv)
{
	int ret;

	ret = mlx5_core_ipsec_counters_read(priv->mdev, priv->ipsec->stats);
	if (ret)
		memset(&priv->ipsec->stats, 0, sizeof(priv->ipsec->stats));
}

int mlx5e_ipsec_get_stats(struct mlx5e_priv *priv, u64 *data)
{
	u32 count;

	if (!priv->ipsec)
		return 0;

	count = mlx5e_ipsec_counters_count(priv->ipsec);
	memcpy(data, &priv->ipsec->stats, sizeof(u64) * count);
	return count;
}
