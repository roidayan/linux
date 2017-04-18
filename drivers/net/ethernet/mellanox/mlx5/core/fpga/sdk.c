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

#include <linux/mlx5/device.h>

#include "fpga/core.h"
#include "fpga/conn.h"
#include "fpga/sdk.h"

struct mlx5_fpga_conn *
mlx5_fpga_sbu_conn_create(struct mlx5_fpga_device *fdev,
			  struct mlx5_fpga_conn_attr *attr)
{
	return mlx5_fpga_conn_create(fdev, attr, MLX5_FPGA_QPC_QP_TYPE_SANDBOX_QP);
}
EXPORT_SYMBOL(mlx5_fpga_sbu_conn_create);

void mlx5_fpga_sbu_conn_destroy(struct mlx5_fpga_conn *conn)
{
	mlx5_fpga_conn_destroy(conn);
}
EXPORT_SYMBOL(mlx5_fpga_sbu_conn_destroy);

int mlx5_fpga_sbu_conn_sendmsg(struct mlx5_fpga_conn *conn,
			       struct mlx5_fpga_dma_buf *buf)
{
	return mlx5_fpga_conn_send(conn, buf);
}
EXPORT_SYMBOL(mlx5_fpga_sbu_conn_sendmsg);
