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

#include <linux/mlx5/mlx5_ifc.h>
#include <linux/mlx5/device.h>
#include <linux/module.h>
#include <linux/mlx5/device.h>

#include "fs_core.h"
#include "mlx5_core.h"

int mlx5_cmd_fs_create_ft(struct mlx5_core_dev *dev,
			  enum fs_ft_type type, unsigned int level,
			  unsigned int log_size, unsigned int *table_id)
{
	u32 in[MLX5_ST_SZ_DW(create_flow_table_in)];
	u32 out[MLX5_ST_SZ_DW(create_flow_table_out)];
	int err;

	if (!dev)
		return -EINVAL;
	memset(in, 0, sizeof(in));

	MLX5_SET(create_flow_table_in, in, opcode,
		 MLX5_CMD_OP_CREATE_FLOW_TABLE);

	MLX5_SET(create_flow_table_in, in, table_type, type);
	MLX5_SET(create_flow_table_in, in, level, level);
	MLX5_SET(create_flow_table_in, in, log_size, log_size);

	memset(out, 0, sizeof(out));
	err = mlx5_cmd_exec_check_status(dev, in, sizeof(in), out,
					 sizeof(out));
	if (err)
		return err;

	*table_id = MLX5_GET(create_flow_table_out, out, table_id);

	return 0;
}

int mlx5_cmd_fs_destroy_ft(struct mlx5_core_dev *dev,
			   enum fs_ft_type type, unsigned int table_id)
{
	u32 in[MLX5_ST_SZ_DW(destroy_flow_table_in)];
	u32 out[MLX5_ST_SZ_DW(destroy_flow_table_out)];

	if (!dev)
		return -EINVAL;
	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));

	MLX5_SET(destroy_flow_table_in, in, opcode,
		 MLX5_CMD_OP_DESTROY_FLOW_TABLE);
	MLX5_SET(destroy_flow_table_in, in, table_type, type);
	MLX5_SET(destroy_flow_table_in, in, table_id, table_id);

	return mlx5_cmd_exec_check_status(dev, in, sizeof(in), out,
					  sizeof(out));
}

int mlx5_cmd_fs_create_fg(struct mlx5_core_dev *dev,
			  u32 *in,
			  enum fs_ft_type type, unsigned int table_id,
			  unsigned int *group_id)
{
	u32 out[MLX5_ST_SZ_DW(create_flow_group_out)];
	int err;
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	if (!dev)
		return -EINVAL;
	memset(out, 0, sizeof(out));

	MLX5_SET(create_flow_group_in, in, opcode,
		 MLX5_CMD_OP_CREATE_FLOW_GROUP);
	MLX5_SET(create_flow_group_in, in, table_type, type);
	MLX5_SET(create_flow_group_in, in, table_id, table_id);

	err = mlx5_cmd_exec_check_status(dev, in,
					 inlen, out,
					 sizeof(out));
	if (!err)
		*group_id = MLX5_GET(create_flow_group_out, out,
				     group_id);

	return err;
}

int mlx5_cmd_fs_destroy_fg(struct mlx5_core_dev *dev,
			   enum fs_ft_type type, unsigned int table_id,
			   unsigned int group_id)
{
	u32 in[MLX5_ST_SZ_DW(destroy_flow_group_in)];
	u32 out[MLX5_ST_SZ_DW(destroy_flow_group_out)];

	if (!dev)
		return -EINVAL;
	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));

	MLX5_SET(destroy_flow_group_in, in, opcode,
		 MLX5_CMD_OP_DESTROY_FLOW_GROUP);
	MLX5_SET(destroy_flow_group_in, in, table_type, type);
	MLX5_SET(destroy_flow_group_in, in, table_id,   table_id);
	MLX5_SET(destroy_flow_group_in, in, group_id, group_id);

	return mlx5_cmd_exec_check_status(dev, in, sizeof(in), out,
					  sizeof(out));
}

int mlx5_cmd_fs_set_fte(struct mlx5_core_dev *dev,
			u32 *match_val,
			enum fs_ft_type type, unsigned int table_id,
			unsigned int index, unsigned int group_id,
			unsigned int flow_tag,
			unsigned short action, int dest_size,
			struct list_head *dests)  /* mlx5_flow_desination */
{
	u32 out[MLX5_ST_SZ_DW(set_fte_out)];
	u32 *in;
	unsigned int inlen = MLX5_ST_SZ_BYTES(set_fte_in) +
		dest_size * MLX5_ST_SZ_BYTES(dest_format_struct);
	struct mlx5_flow_rule *dst;
	void *in_flow_context;
	void *in_match_value;
	void *in_dests;
	int err;

	if (!dev)
		return -EINVAL;

	in = mlx5_vzalloc(inlen);
	if (!in) {
		mlx5_core_warn(dev, "failed to allocate inbox\n");
		return -ENOMEM;
	}

	MLX5_SET(set_fte_in, in, opcode, MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY);
	MLX5_SET(set_fte_in, in, table_type, type);
	MLX5_SET(set_fte_in, in, table_id,   table_id);
	MLX5_SET(set_fte_in, in, flow_index, index);

	in_flow_context = MLX5_ADDR_OF(set_fte_in, in, flow_context);
	MLX5_SET(flow_context, in_flow_context, group_id, group_id);
	MLX5_SET(flow_context, in_flow_context, flow_tag, flow_tag);
	MLX5_SET(flow_context, in_flow_context, action, action);
	MLX5_SET(flow_context, in_flow_context, destination_list_size,
		 dest_size);
	in_match_value = MLX5_ADDR_OF(flow_context, in_flow_context,
				      match_value);
	memcpy(in_match_value, match_val, MLX5_ST_SZ_BYTES(fte_match_param));

	in_dests = MLX5_ADDR_OF(flow_context, in_flow_context, destination);
	list_for_each_entry(dst, dests, base.list) {
		unsigned int id;

		MLX5_SET(dest_format_struct, in_dests, destination_type,
			 dst->dest_attr.type);
		if (dst->dest_attr.type ==
		    MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE)
			id = dst->dest_attr.ft->id;
		else
			id = dst->dest_attr.tir_num;
		MLX5_SET(dest_format_struct, in_dests, destination_id, id);
		in_dests += MLX5_ST_SZ_BYTES(dest_format_struct);
	}
	memset(out, 0, sizeof(out));
	err = mlx5_cmd_exec_check_status(dev, in, inlen, out,
					 sizeof(out));
	kvfree(in);

	return err;
}

int mlx5_cmd_fs_delete_fte(struct mlx5_core_dev *dev,
			   enum fs_ft_type type, unsigned int table_id,
			   unsigned int index)
{
	u32 in[MLX5_ST_SZ_DW(delete_fte_in)];
	u32 out[MLX5_ST_SZ_DW(delete_fte_out)];

	if (!dev)
		return -EINVAL;
	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));

	MLX5_SET(delete_fte_in, in, opcode, MLX5_CMD_OP_DELETE_FLOW_TABLE_ENTRY);
	MLX5_SET(delete_fte_in, in, table_type, type);
	MLX5_SET(delete_fte_in, in, table_id, table_id);
	MLX5_SET(delete_fte_in, in, flow_index, index);

	return mlx5_cmd_exec_check_status(dev, in, sizeof(in), out,
					  sizeof(out));
}

