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

#include <linux/module.h>
#include "fs_core.h"
#include <linux/string.h>
#include <linux/compiler.h>
#include "mlx5_core.h"

static void _fs_put(struct fs_base *node, void (*kref_cb)(struct kref *kref),
		    bool parent_locked)
{
	struct fs_base *parent_node = node->parent;

	if (parent_node && !parent_locked)
		mutex_lock(&parent_node->lock);
	if (atomic_dec_and_test(&node->users_refcount)) {
		if (parent_node) {
			/*remove from parent's list*/
			list_del_init(&node->list);
			mutex_unlock(&parent_node->lock);
		}
		kref_put(&node->refcount, kref_cb);
		if (parent_node && parent_locked)
			mutex_lock(&parent_node->lock);
	} else if (parent_node && !parent_locked) {
		mutex_unlock(&parent_node->lock);
	}
}

static void fs_init_node(struct fs_base *node,
			 unsigned int refcount)
{
	kref_init(&node->refcount);
	atomic_set(&node->users_refcount, refcount);
	init_completion(&node->complete);
	INIT_LIST_HEAD(&node->list);
	mutex_init(&node->lock);
}

static void _fs_add_node(struct fs_base *node,
			 const char *name,
			 struct fs_base *parent)
{
	if (parent)
		atomic_inc(&parent->users_refcount);
	node->name = kstrdup_const(name, GFP_KERNEL);
	node->parent = parent;
}

static void fs_add_node(struct fs_base *node,
			struct fs_base *parent, const char *name,
			unsigned int refcount)
{
	fs_init_node(node, refcount);
	_fs_add_node(node, name, parent);
}

void _fs_remove_node(struct kref *kref);
static void fs_del_dst(struct mlx5_flow_rule *dst);
static void _fs_del_ft(struct mlx5_flow_table *ft);
static void fs_del_fg(struct mlx5_flow_group *fg);
static void fs_del_fte(struct fs_fte *fte);

static void cmd_remove_node(struct fs_base *base)
{
	switch (base->type) {
	case FS_TYPE_FLOW_DEST:
		fs_del_dst(container_of(base, struct mlx5_flow_rule, base));
		break;
	case FS_TYPE_FLOW_TABLE:
		_fs_del_ft(container_of(base, struct mlx5_flow_table, base));
		break;
	case FS_TYPE_FLOW_GROUP:
		fs_del_fg(container_of(base, struct mlx5_flow_group, base));
		break;
	case FS_TYPE_FLOW_ENTRY:
		fs_del_fte(container_of(base, struct fs_fte, base));
		break;
	default:
		break;
	}
}

static void __fs_remove_node(struct kref *kref)
{
	struct fs_base *node = container_of(kref, struct fs_base, refcount);

	if (node->parent)
		mutex_lock(&node->parent->lock);
	mutex_lock(&node->lock);
	cmd_remove_node(node);
	mutex_unlock(&node->lock);
	complete(&node->complete);
	if (node->parent) {
		mutex_unlock(&node->parent->lock);
		_fs_put(node->parent, _fs_remove_node, false);
	}
}

void _fs_remove_node(struct kref *kref)
{
	struct fs_base *node = container_of(kref, struct fs_base, refcount);

	__fs_remove_node(kref);
	kfree_const(node->name);
	kfree(node);
}

static void fs_get(struct fs_base *node)
{
	atomic_inc(&node->users_refcount);
}

static void fs_put(struct fs_base *node)
{
	_fs_put(node, __fs_remove_node, false);
}

static void fs_put_parent_locked(struct fs_base *node)
{
	_fs_put(node, __fs_remove_node, true);
}

static void fs_remove_node(struct fs_base *node)
{
	fs_put(node);
	wait_for_completion(&node->complete);
	kfree_const(node->name);
	kfree(node);
}

static void fs_remove_node_parent_locked(struct fs_base *node)
{
	fs_put_parent_locked(node);
	wait_for_completion(&node->complete);
	kfree(node);
}

static struct fs_prio *find_prio(struct mlx5_flow_namespace *ns,
				 unsigned int prio)
{
	struct fs_prio *iter_prio;

	fs_for_each_prio(iter_prio, ns) {
		if (iter_prio->prio == prio)
			return iter_prio;
	}

	return NULL;
}

static unsigned int _alloc_new_level(struct fs_prio *prio,
				     struct mlx5_flow_namespace *match);

static unsigned int __alloc_new_level(struct mlx5_flow_namespace *ns,
				      struct fs_prio *prio)
{
	unsigned int level = 0;
	struct fs_prio *p;

	if (!ns)
		return 0;

	mutex_lock(&ns->base.lock);
	fs_for_each_prio(p, ns) {
		if (p != prio)
			level += p->max_ft;
		else
			break;
	}
	mutex_unlock(&ns->base.lock);

	fs_get_parent(prio, ns);
	if (prio)
		WARN_ON(prio->base.type != FS_TYPE_PRIO);

	return level + _alloc_new_level(prio, ns);
}

/* Called under lock of priority, hence locking all upper objects */
static unsigned int _alloc_new_level(struct fs_prio *prio,
				     struct mlx5_flow_namespace *match)
{
	struct mlx5_flow_namespace *ns;
	struct fs_base *it;
	unsigned int level = 0;

	if (!prio)
		return 0;

	mutex_lock(&prio->base.lock);
	fs_for_each_ns_or_ft_reverse(it, prio) {
		if (it->type == FS_TYPE_NAMESPACE) {
			struct fs_prio *p;

			fs_get_obj(ns, it);

			if (match != ns) {
				mutex_lock(&ns->base.lock);
				fs_for_each_prio(p, ns)
					level += p->max_ft;
				mutex_unlock(&ns->base.lock);
			} else {
				break;
			}
		} else {
			struct mlx5_flow_table *ft;

			fs_get_obj(ft, it);
			mutex_unlock(&prio->base.lock);
			return level + ft->level + 1;
		}
	}

	fs_get_parent(ns, prio);
	mutex_unlock(&prio->base.lock);
	return __alloc_new_level(ns, prio) + level;
}

static unsigned int alloc_new_level(struct fs_prio *prio)
{
	return _alloc_new_level(prio, NULL);
}

static bool fs_match_exact_mask(u8 match_criteria_enable1,
				u8 match_criteria_enable2,
				void *mask1, void *mask2)
{
	return match_criteria_enable1 == match_criteria_enable2 &&
		!memcmp(mask1, mask2, MLX5_ST_SZ_BYTES(fte_match_param));
}

static struct mlx5_flow_table *find_first_ft_in_ns_reverse(struct mlx5_flow_namespace *ns,
							   struct list_head *start);

static struct mlx5_flow_table *_find_first_ft_in_prio_reverse(struct fs_prio *prio,
							      struct list_head *start)
{
	struct fs_base *it = container_of(start, struct fs_base, list);

	if (!prio)
		return NULL;

	fs_for_each_ns_or_ft_continue_reverse(it, prio) {
		struct mlx5_flow_namespace	*ns;
		struct mlx5_flow_table		*ft;

		if (it->type == FS_TYPE_FLOW_TABLE) {
			fs_get_obj(ft, it);
			fs_get(&ft->base);
			return ft;
		}

		fs_get_obj(ns, it);
		WARN_ON(ns->base.type != FS_TYPE_NAMESPACE);

		ft = find_first_ft_in_ns_reverse(ns, &ns->prios);
		if (ft)
			return ft;
	}

	return NULL;
}

static struct mlx5_flow_table *find_first_ft_in_prio_reverse(struct fs_prio *prio,
							     struct list_head *start)
{
	struct mlx5_flow_table *ft;

	if (!prio)
		return NULL;

	mutex_lock(&prio->base.lock);
	ft = _find_first_ft_in_prio_reverse(prio, start);
	mutex_unlock(&prio->base.lock);

	return ft;
}

static struct mlx5_flow_table *find_first_ft_in_ns_reverse(struct mlx5_flow_namespace *ns,
							   struct list_head *start)
{
	struct fs_prio *prio;

	if (!ns)
		return NULL;

	fs_get_obj(prio, container_of(start, struct fs_base, list));
	mutex_lock(&ns->base.lock);
	fs_for_each_prio_continue_reverse(prio, ns) {
		struct mlx5_flow_table *ft;

		ft = find_first_ft_in_prio_reverse(prio, &prio->objs);
		if (ft) {
			mutex_unlock(&ns->base.lock);
			return ft;
		}
	}
	mutex_unlock(&ns->base.lock);

	return NULL;
}

/* Returned a held ft, assumed curr is protected, assumed curr's parent is
 * locked
 */
static struct mlx5_flow_table *find_prev_ft(struct mlx5_flow_table *curr,
					    struct fs_prio *prio)
{
	struct mlx5_flow_table *ft = NULL;
	struct fs_base *curr_base;

	if (!curr)
		return NULL;

	/* prio has either namespace or flow-tables, but not both */
	if (!list_empty(&prio->objs) &&
	    list_first_entry(&prio->objs, struct mlx5_flow_table, base.list) !=
	    curr)
		return NULL;

	while (!ft && prio) {
		struct mlx5_flow_namespace *ns;

		fs_get_parent(ns, prio);
		ft = find_first_ft_in_ns_reverse(ns, &prio->base.list);
		curr_base = &ns->base;
		fs_get_parent(prio, ns);

		if (prio && !ft)
			ft = find_first_ft_in_prio_reverse(prio,
							   &curr_base->list);
	}
	return ft;
}

static struct mlx5_flow_table *find_first_ft_in_ns(struct mlx5_flow_namespace *ns,
						   struct list_head *start);

static struct mlx5_flow_table *_find_first_ft_in_prio(struct fs_prio *prio,
						      struct list_head *start)
{
	struct fs_base	*it = container_of(start, struct fs_base, list);

	if (!prio)
		return NULL;

	fs_for_each_ns_or_ft_continue(it, prio) {
		struct mlx5_flow_namespace	*ns;
		struct mlx5_flow_table		*ft;

		if (it->type == FS_TYPE_FLOW_TABLE) {
			fs_get_obj(ft, it);
			fs_get(&ft->base);
			return ft;
		}

		fs_get_obj(ns, it);
		WARN_ON(ns->base.type != FS_TYPE_NAMESPACE);

		ft = find_first_ft_in_ns(ns, &ns->prios);
		if (ft)
			return ft;
	}

	return NULL;
}

static struct mlx5_flow_table *find_first_ft_in_prio(struct fs_prio *prio,
						     struct list_head *start)
{
	struct mlx5_flow_table *ft;

	if (!prio)
		return NULL;

	mutex_lock(&prio->base.lock);
	ft = _find_first_ft_in_prio(prio, start);
	mutex_unlock(&prio->base.lock);

	return ft;
}

static struct mlx5_flow_table *find_first_ft_in_ns(struct mlx5_flow_namespace *ns,
						   struct list_head *start)
{
	struct fs_prio *prio;

	if (!ns)
		return NULL;

	fs_get_obj(prio, container_of(start, struct fs_base, list));
	mutex_lock(&ns->base.lock);
	fs_for_each_prio_continue(prio, ns) {
		struct mlx5_flow_table *ft;

		ft = find_first_ft_in_prio(prio, &prio->objs);
		if (ft) {
			mutex_unlock(&ns->base.lock);
			return ft;
		}
	}
	mutex_unlock(&ns->base.lock);

	return NULL;
}

/* returned a held ft, assumed curr is protected, assumed curr's parent is
 * locked
 */
static struct mlx5_flow_table *find_next_ft(struct fs_prio *prio)
{
	struct mlx5_flow_table *ft = NULL;
	struct fs_base *curr_base;

	while (!ft && prio) {
		struct mlx5_flow_namespace *ns;

		fs_get_parent(ns, prio);
		ft = find_first_ft_in_ns(ns, &prio->base.list);
		curr_base = &ns->base;
		fs_get_parent(prio, ns);

		if (!ft && prio)
			ft = _find_first_ft_in_prio(prio, &curr_base->list);
	}
	return ft;
}

static struct fs_fte *fs_alloc_fte(u8 action,
				   u32 flow_tag,
				   u32 *match_value,
				   unsigned int index)
{
	struct fs_fte *fte;


	fte = kzalloc(sizeof(*fte), GFP_KERNEL);
	if (!fte)
		return ERR_PTR(-ENOMEM);

	memcpy(fte->val, match_value, sizeof(fte->val));
	fte->base.type =  FS_TYPE_FLOW_ENTRY;
	fte->dests_size = 0;
	fte->flow_tag = flow_tag;
	fte->index = index;
	INIT_LIST_HEAD(&fte->dests);
	fte->action = action;

	return fte;
}

static struct fs_fte *alloc_star_ft_entry(struct mlx5_flow_table *ft,
					  struct mlx5_flow_group *fg,
					  u32 *match_value,
					  unsigned int index)
{
	int err;
	struct fs_fte *fte;
	struct mlx5_flow_rule *dst;

	if (fg->num_ftes == fg->max_ftes)
		return ERR_PTR(-ENOSPC);

	fte = fs_alloc_fte(MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
			   MLX5_FS_DEFAULT_FLOW_TAG, match_value, index);
	if (IS_ERR(fte))
		return fte;

	/*create dst*/
	dst = kzalloc(sizeof(*dst), GFP_KERNEL);
	if (!dst) {
		err = -ENOMEM;
		goto free_fte;
	}

	fte->base.parent = &fg->base;
	fte->dests_size = 1;
	dst->dest_attr.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dst->base.parent = &fte->base;
	list_add(&dst->base.list, &fte->dests);
	/* assumed that the callee creates the star rules sorted by index */
	list_add_tail(&fte->base.list, &fg->ftes);
	fg->num_ftes++;

	return fte;

free_fte:
	kfree(fte);
	return ERR_PTR(err);
}

/* assume that fte can't be changed */
static void free_star_fte_entry(struct fs_fte *fte)
{
	struct mlx5_flow_group	*fg;
	struct mlx5_flow_rule	*dst, *temp;

	fs_get_parent(fg, fte);

	list_for_each_entry_safe(dst, temp, &fte->dests, base.list) {
		fte->dests_size--;
		list_del(&dst->base.list);
		kfree(dst);
	}

	list_del(&fte->base.list);
	fg->num_ftes--;
	kfree(fte);
}

static struct mlx5_flow_group *fs_alloc_fg(u32 *create_fg_in)
{
	struct mlx5_flow_group *fg;
	void *match_criteria = MLX5_ADDR_OF(create_flow_group_in,
					    create_fg_in, match_criteria);
	u8 match_criteria_enable = MLX5_GET(create_flow_group_in,
					    create_fg_in,
					    match_criteria_enable);
	fg = kzalloc(sizeof(*fg), GFP_KERNEL);
	if (!fg)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&fg->ftes);
	fg->mask.match_criteria_enable = match_criteria_enable;
	memcpy(&fg->mask.match_criteria, match_criteria,
	       sizeof(fg->mask.match_criteria));
	fg->base.type =  FS_TYPE_FLOW_GROUP;
	fg->start_index = MLX5_GET(create_flow_group_in, create_fg_in,
				   start_flow_index);
	fg->max_ftes = MLX5_GET(create_flow_group_in, create_fg_in,
				end_flow_index) - fg->start_index + 1;
	return fg;
}

static struct mlx5_flow_rule *get_unused_star_dest(struct mlx5_flow_table *ft)
{
	struct fs_fte *fte = ft->star_rules.fte_star[(ft->star_rules.used_index + 1) % 2];

	return list_first_entry(&fte->dests, struct mlx5_flow_rule, base.list);
}

static struct mlx5_flow_rule *get_used_star_dest(struct mlx5_flow_table *ft)
{
	struct fs_fte *fte = ft->star_rules.fte_star[ft->star_rules.used_index];

	return list_first_entry(&fte->dests, struct mlx5_flow_rule, base.list);
}

static struct mlx5_flow_root_namespace *find_root(struct fs_base *node)
{
	struct fs_base *parent;

	/* Make sure we only read it once while we go up the tree */
	while ((parent = node->parent))
		node = parent;

	if (WARN_ON(node->type != FS_TYPE_NAMESPACE)) {
		pr_warn("mlx5: flow steering node %s is not in tree or garbaged\n",
			node->name);
		return NULL;
	}

	return container_of(container_of(node,
					 struct mlx5_flow_namespace,
					 base),
			    struct mlx5_flow_root_namespace,
			    ns);
}

static inline struct mlx5_core_dev *fs_get_dev(struct fs_base *node)
{
	struct mlx5_flow_root_namespace *root = find_root(node);

	if (root)
		return root->dev;
	return NULL;
}

/* assumed src_ft and dst_ft can't be freed */
static int fs_set_star_rules(struct mlx5_core_dev *dev,
			     struct mlx5_flow_table *src_ft,
			     struct mlx5_flow_table *dst_ft)
{
	struct mlx5_flow_rule *old_src_dst = get_used_star_dest(src_ft);
	struct mlx5_flow_rule *new_src_dst = get_unused_star_dest(src_ft);
	struct fs_fte *new_src_fte, *old_src_fte;
	int err = 0;
	u32 *match_value;
	int match_len = MLX5_ST_SZ_BYTES(fte_match_param);

	match_value = mlx5_vzalloc(match_len);
	if (!match_value) {
		pr_warn("failed to allocate inbox\n");
		return -ENOMEM;
	}
	/*Create match context*/

	fs_get_parent(new_src_fte, new_src_dst);
	fs_get_parent(old_src_fte, old_src_dst);

	new_src_dst->dest_attr.ft = dst_ft;
	if (dst_ft) {
		err = mlx5_cmd_fs_set_fte(dev,
					  match_value, src_ft->type,
					  src_ft->id, new_src_fte->index,
					  src_ft->star_rules.fg->id,
					  new_src_fte->flow_tag,
					  new_src_fte->action,
					  new_src_fte->dests_size,
					  &new_src_fte->dests);
		if (err)
			goto destroy_ctx;

		fs_get(&dst_ft->base);
	}

	if (old_src_dst->dest_attr.ft) {
		/*Remove old fte from prev*/
		err = mlx5_cmd_fs_delete_fte(dev,
					     src_ft->type, src_ft->id,
					     old_src_fte->index);
	}

	src_ft->star_rules.used_index = (src_ft->star_rules.used_index + 1) % 2;
	old_src_dst->dest_attr.ft = NULL;

destroy_ctx:
	kvfree(match_value);
	return err;
}

static int connect_prev_fts(struct fs_prio *locked_prio,
			    struct fs_prio *prev_prio,
			    struct mlx5_flow_table *next_ft)
{
	struct mlx5_flow_table *iter;
	int err = 0;
	struct mlx5_core_dev *dev = fs_get_dev(&prev_prio->base);

	if (!dev)
		return -ENODEV;

	mutex_lock(&prev_prio->base.lock);
	fs_for_each_ft(iter, prev_prio) {
		struct mlx5_flow_table *prev_ft =
			get_used_star_dest(iter)->dest_attr.ft;

		if (prev_ft == next_ft)
			continue;

		err = fs_set_star_rules(dev, iter, next_ft);
		if (err) {
			pr_warn("mlx5: flow steering can't connect prev and next\n");
			goto unlock;
		} else {
			/* Assume ft's prio is locked */
			if (prev_ft) {
				struct fs_prio *prio;

				fs_get_parent(prio, prev_ft);
				if (prio == locked_prio)
					fs_put_parent_locked(&prev_ft->base);
				else
					fs_put(&prev_ft->base);
			}
		}
	}

unlock:
	mutex_unlock(&prev_prio->base.lock);
	return 0;
}

static int create_star_rules(struct mlx5_flow_table *ft, struct fs_prio *prio)
{
	/*When new flow table is created, we need to allocate two
	 * flow entries for star rules(rules that points to the next FT),
	 * the needed of two star rules is for ensure atomic insertion of
	 * new flow table.
	 * steps:
	 * 1. Allocate two star rules
	 * 2. make star rules#1 point on the next ft
	 * 3. make star rule of the previous table on the new ft
	 * 4. remove the old pointer from the prev table by removing flow entry.
	 */
	int i;
	struct mlx5_flow_group *fg;
	int err;
	u32 *fg_in;
	u32 *match_value;
	struct mlx5_flow_table *next_ft;
	struct mlx5_flow_table *prev_ft;
	struct mlx5_flow_root_namespace *root = find_root(&prio->base);
	int fg_inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	int match_len = MLX5_ST_SZ_BYTES(fte_match_param);

	fg_in = mlx5_vzalloc(fg_inlen);
	if (!fg_in) {
		pr_warn("failed to allocate inbox\n");
		return -ENOMEM;
	}

	match_value = mlx5_vzalloc(match_len);
	if (!match_value) {
		pr_warn("failed to allocate inbox\n");
		kvfree(fg_in);
		return -ENOMEM;
	}

	MLX5_SET(create_flow_group_in, fg_in, start_flow_index, ft->max_fte);
	MLX5_SET(create_flow_group_in, fg_in, end_flow_index, ft->max_fte + 1);
	fg = fs_alloc_fg(fg_in);
	if (IS_ERR(fg)) {
		err = PTR_ERR(fg);
		goto out;
	}
	ft->star_rules.fg = fg;
	err =  mlx5_cmd_fs_create_fg(fs_get_dev(&prio->base), fg_in, ft->type,
				     ft->id,
				     &fg->id);
	if (err)
		goto free_fg;

	ft->star_rules.used_index = 0;
	/* Create star rules */
	for (i = 0; i < ARRAY_SIZE(ft->star_rules.fte_star); i++) {
		ft->star_rules.fte_star[i] = alloc_star_ft_entry(ft, fg,
								 match_value,
								 ft->max_fte + i);
		if (IS_ERR(ft->star_rules.fte_star[i]))
			goto free_star_rules;
	}

	mutex_lock(&root->fs_chain_lock);
	next_ft = find_next_ft(prio);
	err = fs_set_star_rules(root->dev, ft, next_ft);
	if (err) {
		mutex_unlock(&root->fs_chain_lock);
		goto free_star_rules;
	}
	if (next_ft) {
		struct fs_prio *parent;

		fs_get_parent(parent, next_ft);
		fs_put(&next_ft->base);
	}
	prev_ft = find_prev_ft(ft, prio);
	if (prev_ft) {
		struct fs_prio *prev_parent;

		fs_get_parent(prev_parent, prev_ft);

		err = connect_prev_fts(NULL, prev_parent, ft);
		if (err) {
			mutex_unlock(&root->fs_chain_lock);
			goto destroy_chained_start_rule;
		}
		fs_put(&prev_ft->base);
	}
	mutex_unlock(&root->fs_chain_lock);
	kvfree(fg_in);
	kvfree(match_value);

	return 0;

destroy_chained_start_rule:
	fs_set_star_rules(fs_get_dev(&prio->base), ft, NULL);
	if (next_ft)
		fs_put(&next_ft->base);
free_star_rules:
	while (--i >= 0) {
		free_star_fte_entry(ft->star_rules.fte_star[i]);
		ft->star_rules.fte_star[i] = NULL;
	}
	mlx5_cmd_fs_destroy_fg(fs_get_dev(&ft->base), ft->type, ft->id,
			       fg->id);
free_fg:
	kfree(fg);
out:
	kvfree(fg_in);
	kvfree(match_value);
	return err;
}

static void destroy_star_rules(struct mlx5_flow_table *ft, struct fs_prio *prio)
{
	unsigned int i;
	int err;
	struct mlx5_flow_root_namespace *root;
	struct mlx5_core_dev *dev = fs_get_dev(&prio->base);
	struct mlx5_flow_table *prev_ft, *next_ft;
	struct fs_prio *prev_prio;

	WARN_ON(!dev);

	root = find_root(&prio->base);
	if (!root)
		pr_err("mlx5: flow steering failed to find root of priority %s",
		       prio->base.name);

	/* In order to ensure atomic deletion, first update
	 * prev ft to point on the next ft.
	 */
	mutex_lock(&root->fs_chain_lock);
	prev_ft = find_prev_ft(ft, prio);
	next_ft = find_next_ft(prio);
	if (prev_ft) {
		fs_get_parent(prev_prio, prev_ft);
		/*Prev is connected to ft, only if ft is the first(last) in the prio*/
		err = connect_prev_fts(prio, prev_prio, next_ft);
		if (err)
			pr_warn("flow steering can't connect prev and next of flow table\n");
		fs_put(&prev_ft->base);
	}

	err = fs_set_star_rules(root->dev, ft, NULL);
	/*One put is for fs_get in find next ft*/
	if (next_ft) {
		fs_put(&next_ft->base);
		if (!err)
			fs_put(&next_ft->base);
	}

	mutex_unlock(&root->fs_chain_lock);

	err = mlx5_cmd_fs_destroy_fg(dev, ft->type, ft->id,
				     ft->star_rules.fg->id);
	if (err)
		pr_warn("flow steering can't destroy star entry group\n");

	for (i = 0; i < ARRAY_SIZE(ft->star_rules.fte_star); i++) {
		free_star_fte_entry(ft->star_rules.fte_star[i]);
		ft->star_rules.fte_star[i] = NULL;
	}

	kfree(ft->star_rules.fg);
	ft->star_rules.fg = NULL;
}

static struct mlx5_flow_table *mlx5_create_flow_table(struct mlx5_flow_namespace *ns,
						      int prio,
						      const char *name,
						      int max_fte)
{
	struct mlx5_flow_table *ft;
	int err;
	int log_table_sz;
	int ft_size;
	char gen_name[20];
	struct mlx5_flow_root_namespace *root =
		find_root(&ns->base);
	struct fs_prio *fs_prio = NULL;

	if (!root) {
		pr_err("mlx5: flow steering failed to find root of namespace %s",
		       ns->base.name);
		return ERR_PTR(-ENODEV);
	}

	fs_prio = find_prio(ns, prio);
	if (!fs_prio)
		return ERR_PTR(-EINVAL);

	ft  = kzalloc(sizeof(*ft), GFP_KERNEL);
	if (!ft)
		return ERR_PTR(-ENOMEM);

	fs_init_node(&ft->base, 1);
	INIT_LIST_HEAD(&ft->fgs);
	ft->level = alloc_new_level(fs_prio);
	ft->base.type = FS_TYPE_FLOW_TABLE;
	ft->type = root->table_type;
	/*Two entries are reserved for star rules*/
	ft_size = roundup_pow_of_two(max_fte + 2);
	/*User isn't aware to those rules*/
	ft->max_fte = ft_size - 2;
	log_table_sz = ilog2(ft_size);
	err = mlx5_cmd_fs_create_ft(root->dev, ft->type, ft->level, log_table_sz,
				    &ft->id);
	if (err)
		goto free_ft;

	err = create_star_rules(ft, fs_prio);
	if (err)
		goto del_ft;

	if (!name || !strlen(name)) {
		snprintf(gen_name, 20, "flow_table_%u", ft->id);
		_fs_add_node(&ft->base, gen_name, &fs_prio->base);
	} else {
		_fs_add_node(&ft->base, name, &fs_prio->base);
	}
	list_add_tail(&ft->base.list, &fs_prio->objs);

	return ft;

del_ft:
	mlx5_cmd_fs_destroy_ft(root->dev, ft->type, ft->id);
free_ft:
	kfree(ft);
	return ERR_PTR(err);
}

static struct mlx5_flow_group *mlx5_create_flow_group(struct mlx5_flow_table *ft,
						      u32 *fg_in)
{
	struct mlx5_flow_group *fg;
	struct mlx5_core_dev *dev = fs_get_dev(&ft->base);
	int err;
	unsigned int end_index;
	char name[20];

	if (!dev)
		return ERR_PTR(-ENODEV);

	fg = fs_alloc_fg(fg_in);
	if (IS_ERR(fg))
		return fg;

	end_index = fg->start_index + fg->max_ftes - 1;
	err =  mlx5_cmd_fs_create_fg(dev, fg_in, ft->type, ft->id,
				     &fg->id);
	if (err)
		goto free_fg;

	mutex_lock(&ft->base.lock);
	snprintf(name, sizeof(name), "group_%u", fg->id);
	/*Add node to tree*/
	fs_add_node(&fg->base, &ft->base, name, 1);
	/*Add node to group list*/
	list_add(&fg->base.list, ft->fgs.prev);
	mutex_unlock(&ft->base.lock);

	return fg;

free_fg:
	kfree(fg);
	return ERR_PTR(err);
}

/* fte should not be deleted while calling this function */
static struct mlx5_flow_rule *fs_add_dst_fte(struct fs_fte *fte,
						struct mlx5_flow_group *fg,
						struct mlx5_flow_destination *dest)
{
	struct mlx5_flow_table *ft;
	struct mlx5_flow_rule *dst;
	int err;

	dst = kzalloc(sizeof(*dst), GFP_KERNEL);
	if (!dst)
		return ERR_PTR(-ENOMEM);

	memcpy(&dst->dest_attr, dest, sizeof(*dest));
	dst->base.type = FS_TYPE_FLOW_DEST;
	fs_get_parent(ft, fg);
	/*Add dest to dests list- added as first element after the head*/
	list_add_tail(&dst->base.list, &fte->dests);
	fte->dests_size++;
	err = mlx5_cmd_fs_set_fte(fs_get_dev(&ft->base), fte->val, ft->type,
				  ft->id, fte->index, fg->id, fte->flow_tag,
				  fte->action, fte->dests_size, &fte->dests);
	if (err)
		goto free_dst;

	list_del(&dst->base.list);

	return dst;

free_dst:
	list_del(&dst->base.list);
	kfree(dst);
	fte->dests_size--;
	return ERR_PTR(err);
}

static void _fs_del_ft(struct mlx5_flow_table *ft)
{
	int err;
	struct mlx5_core_dev *dev = fs_get_dev(&ft->base);

	err = mlx5_cmd_fs_destroy_ft(dev, ft->type, ft->id);
	if (err)
		pr_warn("flow steering can't destroy ft\n");
}

static void fs_del_dst(struct mlx5_flow_rule *dst)
{
	struct mlx5_flow_table *ft;
	struct mlx5_flow_group *fg;
	struct fs_fte *fte;
	u32	*match_value;
	struct mlx5_core_dev *dev = fs_get_dev(&dst->base);
	int match_len = MLX5_ST_SZ_BYTES(fte_match_param);
	int err;

	WARN_ON(!dev);

	match_value = mlx5_vzalloc(match_len);
	if (!match_value) {
		pr_warn("failed to allocate inbox\n");
		return;
	}

	fs_get_parent(fte, dst);
	fs_get_parent(fg, fte);
	mutex_lock(&fg->base.lock);
	memcpy(match_value, fte->val, sizeof(fte->val));
	/* ft can't be changed as fg is locked */
	fs_get_parent(ft, fg);
	list_del(&dst->base.list);
	fte->dests_size--;
	if (fte->dests_size) {
		err = mlx5_cmd_fs_set_fte(dev, match_value, ft->type,
					  ft->id, fte->index, fg->id,
					  fte->flow_tag, fte->action,
					  fte->dests_size, &fte->dests);
		if (err) {
			pr_warn("%s can't delete dst %s\n",
				       __func__, dst->base.name);
			goto err;
		}
	}
err:
	mutex_unlock(&fg->base.lock);
	kvfree(match_value);
}

static void fs_del_fte(struct fs_fte *fte)
{
	struct mlx5_flow_table *ft;
	struct mlx5_flow_group *fg;
	int err;
	struct mlx5_core_dev *dev;

	fs_get_parent(fg, fte);
	fs_get_parent(ft, fg);

	dev = fs_get_dev(&ft->base);
	WARN_ON(!dev);

	err = mlx5_cmd_fs_delete_fte(dev, ft->type, ft->id, fte->index);
	if (err)
		pr_warn("flow steering can't delete fte %s\n",
			       fte->base.name);

	fg->num_ftes--;
}

/* assumed fg is locked */
static unsigned int fs_get_free_fg_index(struct mlx5_flow_group *fg,
					 struct list_head **prev)
{
	struct fs_fte *fte;
	unsigned int start = fg->start_index;

	if (prev)
		*prev = &fg->ftes;

	/* assumed list is sorted by index */
	fs_for_each_fte(fte, fg) {
		if (fte->index != start)
			return start;
		start++;
		if (prev)
			*prev = &fte->base.list;
	}

	return start;
}

struct fs_fte *fs_create_fte(struct mlx5_flow_group *fg,
			     u32 *match_value,
			     u8 action,
			     u32 flow_tag,
			     struct list_head **prev)
{
	struct fs_fte *fte;
	int index = 0;

	index = fs_get_free_fg_index(fg, prev);
	fte = fs_alloc_fte(action, flow_tag, match_value, index);
	if (IS_ERR(fte))
		return fte;

	return fte;
}

static char *get_dest_name(struct mlx5_flow_destination *dest)
{
	char *name = kzalloc(sizeof(char) * 20, GFP_KERNEL);

	switch (dest->type) {
	case MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE:
		snprintf(name, 20, "dest_%s_%u", "flow_table",
			 dest->ft->id);
		return name;
	case MLX5_FLOW_DESTINATION_TYPE_TIR:
		snprintf(name, 20, "dest_%s_%u", "tir", dest->tir_num);
		return name;
	}

	return NULL;
}

/* assuming parent fg is locked */
static struct mlx5_flow_rule *fs_add_dst_fg(struct mlx5_flow_group *fg,
						   u32 *match_value,
						   u8 action,
						   u32 flow_tag,
						   struct mlx5_flow_destination *dest)
{
	struct fs_fte *fte;
	struct mlx5_flow_rule *dst;
	struct mlx5_flow_table *ft;
	struct list_head *prev;
	char fte_name[20];
	char *dest_name;

	mutex_lock(&fg->base.lock);
	fs_get_parent(ft,fg);
	if (fg->num_ftes >= fg->max_ftes) {
		dst = ERR_PTR(-ENOSPC);
		goto unlock_fg;
	}

	fte = fs_create_fte(fg, match_value, action, flow_tag, &prev);
	if (IS_ERR(fte)) {
		dst = (void *)fte;
		goto unlock_fg;
	}
	dst = fs_add_dst_fte(fte, fg, dest);
	if (IS_ERR(dst)) {
		kfree(fte);
		goto unlock_fg;
	}

	fg->num_ftes++;

	snprintf(fte_name, sizeof(fte_name), "fte%u", fte->index);
	/* Add node to tree */
	fs_add_node(&fte->base, &fg->base, fte_name, 0);
	list_add(&fte->base.list, prev);

	/* Add node to tree */
	dest_name = get_dest_name(dest);
	fs_add_node(&dst->base, &fte->base, dest_name, 1);
	kfree(dest_name);
	/* re-add to list, since fs_add_node reset our list */
	list_add_tail(&dst->base.list, &fte->dests);
unlock_fg:
	mutex_unlock(&fg->base.lock);
	return dst;
}

static struct mlx5_flow_rule *
mlx5_add_flow_rule(struct mlx5_flow_table *ft,
		   u8 match_criteria_enable,
		   u32 *match_criteria,
		   u32 *match_value,
		   u32 action,
		   u32 flow_tag,
		   struct mlx5_flow_destination *dest)
{
	struct mlx5_flow_group *g;
	struct mlx5_flow_rule *dst = ERR_PTR(-EINVAL);

	fs_get(&ft->base);
	mutex_lock(&ft->base.lock);
	fs_for_each_fg(g, ft)
		if (fs_match_exact_mask(g->mask.match_criteria_enable,
					match_criteria_enable,
					g->mask.match_criteria,
					match_criteria)) {
			mutex_unlock(&ft->base.lock);

			dst = fs_add_dst_fg(g, match_value,
					    action, flow_tag, dest);
			mutex_unlock(&ft->base.lock);
			goto unlock;
		}
	mutex_unlock(&ft->base.lock);
unlock:
	fs_put(&ft->base);
	return dst;

}

static void mlx5_del_flow_rule(struct mlx5_flow_rule *dst)
{
	fs_remove_node(&dst->base);
}

/*Objects in the same prio are destroyed in the reverse order they were createrd*/
static int mlx5_destroy_flow_table(struct mlx5_flow_table *ft)
{
	int err = 0;
	struct fs_prio *prio;
	struct mlx5_flow_root_namespace *root;

	fs_get_parent(prio, ft);
	root = find_root(&prio->base);

	if (!root) {
		pr_err("mlx5: flow steering failed to find root of priority %s",
		       prio->base.name);
		return -ENODEV;
	}

	mutex_lock(&prio->base.lock);
	mutex_lock(&ft->base.lock);
	if (!list_is_last(&ft->base.list, &prio->objs)) {
		pr_warn("flow steering tried to delete flow table %s which isn't last in prio\n",
				ft->base.name);
		err =  -EPERM;
		goto unlock_ft;
	}

	/* delete two last entries */
	destroy_star_rules(ft, prio);

	mutex_unlock(&ft->base.lock);
	fs_remove_node_parent_locked(&ft->base);
	mutex_unlock(&prio->base.lock);
	return err;

unlock_ft:
	mutex_unlock(&ft->base.lock);
	mutex_unlock(&prio->base.lock);

	return err;
}

/*Group is destoyed when all the rules in the group were removed*/
static void fs_del_fg(struct mlx5_flow_group *fg)
{
	struct mlx5_flow_table *parent_ft;
	struct mlx5_core_dev *dev;

	fs_get_parent(parent_ft, fg);
	dev = fs_get_dev(&parent_ft->base);
	WARN_ON(!dev);

	if (mlx5_cmd_fs_destroy_fg(dev, parent_ft->type,
				   parent_ft->id, fg->id))
		pr_warn("flow steering can't destroy fg\n");
}

static void mlx5_destroy_flow_group(struct mlx5_flow_group *fg)
{
	fs_remove_node(&fg->base);
}

