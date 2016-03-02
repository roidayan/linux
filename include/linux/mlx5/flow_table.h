/*
 * Copyright (c) 2013-2015, Mellanox Technologies, Ltd.  All rights reserved.
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

#ifndef MLX5_FLOW_TABLE_H
#define MLX5_FLOW_TABLE_H

#include <linux/mlx5/driver.h>

enum {
	mlx5_flow_table_decap_en = BIT(0),
	mlx5_flow_table_encap_en = BIT(1)
};

struct mlx5_flow_table_group {
	u8	log_sz;
	u8	match_criteria_enable;
	u32	match_criteria[MLX5_ST_SZ_DW(fte_match_param)];
};

struct mlx5_flow_destination {
	enum mlx5_flow_destination_type	type;
	union {
		u32			tir_num;
		void			*ft;
		u32			vport_num;
	};
};

void *mlx5_create_flow_table(struct mlx5_core_dev *dev, u8 level, u8 table_type,
			     u32 flags, u16 num_groups,
			     struct mlx5_flow_table_group *group);
void mlx5_destroy_flow_table(void *flow_table);
int mlx5_add_flow_table_entry(void *flow_table, u8 match_criteria_enable,
			      void *match_criteria, void *flow_context,
			      u32 *flow_index);
int mlx5_set_flow_group_entry(void *ft, u32 group_ix,
			      u32 *flow_index,
			      void *flow_context);
void mlx5_del_flow_table_entry(void *flow_table, u32 flow_index);
u32 mlx5_get_flow_table_id(void *flow_table);

int mlx5_alloc_encap_cmd(struct mlx5_core_dev *dev,
			 int header_type,
			 size_t size,
			 void *encap_header,
			 u32 *encap_id);
void mlx5_dealloc_encap_cmd(struct mlx5_core_dev *dev, u32 encap_id);

void mlx5_set_free_flow_group(void *flow_table, int g_index);
int  mlx5_get_free_flow_group(void *flow_table, int start, int end);
int  mlx5_recreate_flow_group(void *flow_table, int g_index, struct mlx5_flow_table_group *g);

#endif /* MLX5_FLOW_TABLE_H */
