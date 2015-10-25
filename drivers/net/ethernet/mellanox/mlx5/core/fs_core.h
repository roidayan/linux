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

#ifndef _MLX5_FS_CORE_
#define _MLX5_FS_CORE_

#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/mlx5/fs.h>

enum fs_type {
	FS_TYPE_NAMESPACE,
	FS_TYPE_PRIO,
	FS_TYPE_FLOW_TABLE,
	FS_TYPE_FLOW_GROUP,
	FS_TYPE_FLOW_ENTRY,
	FS_TYPE_FLOW_DEST
};

enum fs_ft_type {
	FS_FT_NIC_RX	 = 0x0,
};

/* Should always be the first variable in the struct */
struct fs_base {
	struct list_head		list;
	struct fs_base			*parent;
	enum fs_type			type;
	struct kref			refcount;
	/* lock the node for writing and traversing */
	struct mutex			lock;
	struct completion		complete;
	atomic_t			users_refcount;
	const char			*name;
};

struct mlx5_flow_rule {
	struct fs_base				base;
	struct mlx5_flow_destination		dest_attr;
};

struct mlx5_flow_table {
	struct fs_base			base;
	uint32_t			id;
	/* sorted list by start_index */
	struct list_head		fgs;
	unsigned int			level;
};

struct fs_prio {
	struct fs_base			base;
	struct list_head		objs; /* each object is a namespace or ft */
	unsigned int			max_ft;
	unsigned int			prio;
};

struct mlx5_flow_namespace {
	/* parent == NULL => root ns */
	struct	fs_base			base;
	/* sorted by priority number */
	struct	list_head		prios; /* list of fs_prios */
};

struct mlx5_core_fs_mask {
	u8	match_criteria_enable;
	u32	match_criteria[MLX5_ST_SZ_DW(fte_match_param)];
};

#define fs_list_for_each_entry(pos, cond, root)		\
	list_for_each_entry(pos, root, base.list)	\
		if (!(cond)) {} else

#define fs_list_for_each_entry_continue(pos, cond, root)	\
	list_for_each_entry_continue(pos, root, base.list)	\
		if (!(cond)) {} else

#define fs_list_for_each_entry_reverse(pos, cond, root)		\
	list_for_each_entry_reverse(pos, root, base.list)	\
		if (!(cond)) {} else

#define fs_list_for_each_entry_continue_reverse(pos, cond, root)	\
	list_for_each_entry_continue_reverse(pos, root, base.list)	\
		if (!(cond)) {} else

#define fs_for_each_ft(pos, prio)			\
	fs_list_for_each_entry(pos, (pos)->base.type == FS_TYPE_FLOW_TABLE, \
			       &(prio)->objs)

#define fs_for_each_ft_reverse(pos, prio)			\
	fs_list_for_each_entry_reverse(pos,			\
				       (pos)->base.type == FS_TYPE_FLOW_TABLE, \
				       &(prio)->objs)

#define fs_for_each_ns(pos, prio)			\
	fs_list_for_each_entry(pos,			\
			       (pos)->base.type == FS_TYPE_NAMESPACE, \
			       &(prio)->objs)

#define fs_for_each_ns_or_ft_reverse(pos, prio)			\
	list_for_each_entry_reverse(pos, &(prio)->objs, list)		\
		if (!((pos)->type == FS_TYPE_NAMESPACE ||		\
		      (pos)->type == FS_TYPE_FLOW_TABLE)) {} else

#define fs_for_each_ns_or_ft(pos, prio)			\
	list_for_each_entry(pos, &(prio)->objs, list)		\
		if (!((pos)->type == FS_TYPE_NAMESPACE ||	\
		      (pos)->type == FS_TYPE_FLOW_TABLE)) {} else

#define fs_for_each_ns_or_ft_continue_reverse(pos, prio)		\
	list_for_each_entry_continue_reverse(pos, &(prio)->objs, list)	\
		if (!((pos)->type == FS_TYPE_NAMESPACE ||		\
		      (pos)->type == FS_TYPE_FLOW_TABLE)) {} else

#define fs_for_each_ns_or_ft_continue(pos, prio)			\
	list_for_each_entry_continue(pos, &(prio)->objs, list)		\
		if (!((pos)->type == FS_TYPE_NAMESPACE ||		\
		      (pos)->type == FS_TYPE_FLOW_TABLE)) {} else

#define fs_for_each_prio(pos, ns)			\
	fs_list_for_each_entry(pos, (pos)->base.type == FS_TYPE_PRIO, \
			       &(ns)->prios)

#define fs_for_each_prio_reverse(pos, ns)			\
	fs_list_for_each_entry_reverse(pos, (pos)->base.type == FS_TYPE_PRIO, \
				       &(ns)->prios)

#define fs_for_each_prio_continue(pos, ns)			\
	fs_list_for_each_entry_continue(pos, (pos)->base.type == FS_TYPE_PRIO, \
				       &(ns)->prios)

#define fs_for_each_prio_continue_reverse(pos, ns)			\
	fs_list_for_each_entry_continue_reverse(pos,			\
						(pos)->base.type == FS_TYPE_PRIO, \
						&(ns)->prios)

#define fs_for_each_fg(pos, ft)			\
	fs_list_for_each_entry(pos, (pos)->base.type == FS_TYPE_FLOW_GROUP, \
			       &(ft)->fgs)

#define fs_for_each_fte(pos, fg)			\
	fs_list_for_each_entry(pos, (pos)->base.type == FS_TYPE_FLOW_ENTRY, \
			       &(fg)->ftes)
#define fs_for_each_dst(pos, fte)			\
	fs_list_for_each_entry(pos, (pos)->base.type == FS_TYPE_FLOW_DEST, \
			       &(fte)->dests)

int mlx5_cmd_fs_create_ft(struct mlx5_core_dev *dev,
			  enum fs_ft_type type, unsigned int level,
			  unsigned int log_size, unsigned int *table_id);

int mlx5_cmd_fs_destroy_ft(struct mlx5_core_dev *dev,
			   enum fs_ft_type type, unsigned int table_id);

int mlx5_cmd_fs_create_fg(struct mlx5_core_dev *dev,
			  u32 *in,
			  enum fs_ft_type type, unsigned int table_id,
			  unsigned int *group_id);

int mlx5_cmd_fs_destroy_fg(struct mlx5_core_dev *dev,
			   enum fs_ft_type type, unsigned int table_id,
			   unsigned int group_id);


int mlx5_cmd_fs_set_fte(struct mlx5_core_dev *dev,
			u32 *match_val,
			enum fs_ft_type type, unsigned int table_id,
			unsigned int index, unsigned int group_id,
			unsigned int flow_tag,
			unsigned short action, int dest_size,
			struct list_head *dests);  /* mlx5_flow_desination */

int mlx5_cmd_fs_delete_fte(struct mlx5_core_dev *dev,
			   enum fs_ft_type type, unsigned int table_id,
			   unsigned int index);
#endif

