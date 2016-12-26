/*
 * Copyright (c) 2016, Mellanox Technologies inc.  All rights reserved.
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

#ifndef _UVERBS_IOCTL_
#define _UVERBS_IOCTL_

#include <rdma/uverbs_types.h>

/*
 * =======================================
 *	Verbs action specifications
 * =======================================
 */

#define UVERBS_ID_GROUP_MASK 0xF000
#define UVERBS_ID_GROUP_SHIFT 12

enum uverbs_attr_type {
	UVERBS_ATTR_TYPE_NA,
	UVERBS_ATTR_TYPE_PTR_IN,
	UVERBS_ATTR_TYPE_PTR_OUT,
	UVERBS_ATTR_TYPE_IDR,
	UVERBS_ATTR_TYPE_FD,
};

enum uverbs_obj_access {
	UVERBS_ACCESS_READ,
	UVERBS_ACCESS_WRITE,
	UVERBS_ACCESS_NEW,
	UVERBS_ACCESS_DESTROY
};

enum uverbs_attr_spec_flags {
	UVERBS_ATTR_SPEC_F_MANDATORY	= 1U << 0,
	/* Support extending attributes by length */
	UVERBS_ATTR_SPEC_F_MIN_SZ	= 1U << 1,
};

struct uverbs_attr_spec {
	enum uverbs_attr_type		type;
	/* a combination of enum uverbs_attr_spec_flags */
	u8				flags;
	union {
		u16				len;
		struct {
			/*
			 * higher bits mean the group and lower bits mean
			 * the type id within the group.
			 */
			u16			obj_type;
			u8			access;
		} obj;
	};
};

struct uverbs_attr_spec_group {
	struct uverbs_attr_spec		*attrs;
	size_t				num_attrs;
	/* populate at runtime */
	unsigned long			*mandatory_attrs_bitmask;
};

struct uverbs_attr_array;
struct ib_uverbs_file;

enum uverbs_action_flags {
	/*
	 * Action marked with this flag creates a context (or root for all
	 * objects).
	 */
	UVERBS_ACTION_FLAG_CREATE_ROOT = 1U << 0,
};

struct uverbs_action {
	struct uverbs_attr_spec_group			**attr_groups;
	size_t						num_groups;
	size_t						num_child_attrs;
	/* Combination of bits from enum uverbs_action_flags */
	u32 flags;
	int (*handler)(struct ib_device *ib_dev, struct ib_uverbs_file *ufile,
		       struct uverbs_attr_array *ctx, size_t num);
};

struct uverbs_action_group {
	size_t					num_actions;
	struct uverbs_action			**actions;
};

struct uverbs_type {
	size_t					num_groups;
	const struct uverbs_action_group	**action_groups;
	const struct uverbs_obj_type		*type_attrs;
};

struct uverbs_type_group {
	size_t					num_types;
	const struct uverbs_type		**types;
};

struct uverbs_spec_root {
	const struct uverbs_type_group		**type_groups;
	size_t					num_groups;
};

#define DECLARE_UVERBS_TYPE(name, _type_attrs)			\
	const struct uverbs_type name = {				\
		.type_attrs = _type_attrs,				\
	}
#define _UVERBS_TYPE_SZ(...)						\
	(sizeof((const struct uverbs_type *[]){__VA_ARGS__}) /	\
	 sizeof(const struct uverbs_type *))
#define ADD_UVERBS_TYPE(type_idx, type_ptr)				\
	[type_idx] = ((const struct uverbs_type * const)&(type_ptr))
#define UVERBS_TYPES(...)  ((const struct uverbs_type_group)		\
	{.num_types = _UVERBS_TYPE_SZ(__VA_ARGS__),			\
	 .types = (const struct uverbs_type *[]){__VA_ARGS__} })
#define DECLARE_UVERBS_TYPES(name, ...)				\
	const struct uverbs_type_group name = UVERBS_TYPES(__VA_ARGS__)

/* =================================================
 *              Parsing infrastructure
 * =================================================
 */

struct uverbs_ptr_attr {
	void	__user *ptr;
	u16		len;
};

struct uverbs_obj_attr {
	/*
	 * pointer to the user-space given attribute, in order to write the
	 * new uobject's id.
	 */
	struct ib_uverbs_attr __user	*uattr;
	/* pointer to the kernel descriptor -> type, access, etc */
	const struct uverbs_obj_type	*type;
	struct ib_uobject		*uobject;
	/* fd or id in idr of this object */
	int				id;
};

struct uverbs_attr {
	union {
		struct uverbs_ptr_attr	ptr_attr;
		struct uverbs_obj_attr	obj_attr;
	};
};

struct uverbs_attr_array {
	/* if bit i is set, it means attrs[i] contains valid information */
	unsigned long *valid_bitmap;
	size_t num_attrs;
	/*
	 * arrays of attributes, each element corresponds to the specification
	 * of the attribute in the same index.
	 */
	struct uverbs_attr *attrs;
};

static inline bool uverbs_is_valid(const struct uverbs_attr_array *attr_array,
				   unsigned int idx)
{
	return test_bit(idx, attr_array->valid_bitmap);
}

#endif

