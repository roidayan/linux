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

static void __fs_remove_node(struct kref *kref)
{
	struct fs_base *node = container_of(kref, struct fs_base, refcount);

	if (node->parent)
		mutex_lock(&node->parent->lock);
	mutex_lock(&node->lock);
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
