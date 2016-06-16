/*
 * Copyright (c) 2016, Mellanox Technologies. All rights reserved.
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

#define MLX5_DRV_VER_SZ 64
#define MLX5_DEV_NAME_SZ 64

#define DIAG_BLK_SZ(data_size) (sizeof(struct mlx5_diag_blk) + data_size)
#define DIAG_GET_NEXT_BLK(dump_hdr) \
	((struct mlx5_diag_blk *)(dump_hdr->dump + dump_hdr->total_length))

static int mlx5e_diag_fill_device_name(struct mlx5e_priv *priv, void *buff)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	size_t pci_name_sz = strlen(pci_name(mdev->pdev));

	memset(buff, 0, MLX5_DEV_NAME_SZ);
	strncpy(buff, pci_name(mdev->pdev), MLX5_DEV_NAME_SZ);
	if (pci_name_sz >= MLX5_DEV_NAME_SZ - 2)
		goto out;

	/* there is at least 2 bytes left */
	buff += pci_name_sz;
	strncpy(buff, ":", 1);
	buff += 1;

	strncpy(buff, priv->netdev->name, MLX5_DEV_NAME_SZ - pci_name_sz - 1);
out:
	return MLX5_DEV_NAME_SZ;
}

static int mlx5e_diag_fill_driver_version(void *buff)
{
	memset(buff, 0, MLX5_DRV_VER_SZ);
	strlcpy(buff, DRIVER_VERSION " (" DRIVER_RELDATE ")", MLX5_DRV_VER_SZ);
	return MLX5_DRV_VER_SZ;
}

int mlx5e_set_dump(struct net_device *netdev, struct ethtool_dump *dump)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	priv->dump.flag = dump->flag;
	return 0;
}

int mlx5e_get_dump_flag(struct net_device *netdev, struct ethtool_dump *dump)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	__u32 extra_len = 0;

	dump->version = MLX5_DIAG_DUMP_VERSION;
	dump->flag = priv->dump.flag;

	if (dump->flag & MLX5_DIAG_FLAG_MST) {
		u32 mst_size = mlx5_mst_capture(priv->mdev);

		if (mst_size <= 0) {
			dump->flag &= ~MLX5_DIAG_FLAG_MST;
			netdev_warn(priv->netdev,
				    "Failed to get mst dump, err (%d)\n",
				    mst_size);
			mst_size = 0;
		}
		priv->dump.mst_size = mst_size;
		extra_len += mst_size ? DIAG_BLK_SZ(mst_size) : 0;
	}

	dump->len = sizeof(struct mlx5_diag_dump) +
		    DIAG_BLK_SZ(MLX5_DRV_VER_SZ)  +
		    DIAG_BLK_SZ(MLX5_DEV_NAME_SZ) +
		    extra_len;
	return 0;
}

int mlx5e_get_dump_data(struct net_device *netdev, struct ethtool_dump *dump,
			void *buffer)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_diag_dump *dump_hdr = buffer;
	struct mlx5_diag_blk *dump_blk;

	dump_hdr->version = MLX5_DIAG_DUMP_VERSION;
	dump_hdr->flag = 0;
	dump_hdr->num_blocks = 0;
	dump_hdr->total_length = 0;

	/* Dump driver version */
	dump_blk = DIAG_GET_NEXT_BLK(dump_hdr);
	dump_blk->type = MLX5_DIAG_DRV_VERSION;
	dump_blk->length = mlx5e_diag_fill_driver_version(&dump_blk->data);
	dump_hdr->total_length += DIAG_BLK_SZ(dump_blk->length);
	dump_hdr->num_blocks++;

	/* Dump device name */
	dump_blk = DIAG_GET_NEXT_BLK(dump_hdr);
	dump_blk->type = MLX5_DIAG_DEVICE_NAME;
	dump_blk->length = mlx5e_diag_fill_device_name(priv, &dump_blk->data);
	dump_hdr->total_length += DIAG_BLK_SZ(dump_blk->length);
	dump_hdr->num_blocks++;

	if (priv->dump.flag & MLX5_DIAG_FLAG_MST) {
		/* Dump mst buffer */
		dump_blk = DIAG_GET_NEXT_BLK(dump_hdr);
		dump_blk->type = MLX5_DIAG_MST;
		dump_blk->length = mlx5_mst_dump(priv->mdev, &dump_blk->data,
						 priv->dump.mst_size);
		dump_hdr->total_length += DIAG_BLK_SZ(dump_blk->length);
		dump_hdr->num_blocks++;
		dump_hdr->flag |= MLX5_DIAG_FLAG_MST;
	}

	return 0;
}
