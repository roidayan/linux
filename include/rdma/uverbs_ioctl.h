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
#include <linux/uaccess.h>
#include <rdma/rdma_user_ioctl.h>

struct uverbs_object_type;
struct uverbs_uobject_type;

/*
 * =======================================
 *	Verbs action specifications
 * =======================================
 */

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

#define UA_FLAGS(_flags)  .flags = _flags
#define __UVERBS_ATTR0(_id, _len, _type, ...)				\
	[_id] = {.type = _type, .flags = 0, {.len = _len} }
#define __UVERBS_ATTR1(_id, _len, _type, _flags)			\
	[_id] = {.type = _type, _flags, {.len = _len} }
#define __UVERBS_ATTR(_id, _len, _type, _flags, _n, ...)		\
	__UVERBS_ATTR##_n(_id, _len, _type, _flags)
/*
 * In new compiler, UVERBS_ATTR could be simplified by declaring it as
 * [_id] = {.type = _type, .len = _len, ##__VA_ARGS__}
 * But since we support older compilers too, we need the more complex code.
 */
#define UVERBS_ATTR(_id, _len, _type, ...)				\
	__UVERBS_ATTR(_id, _len, _type, ##__VA_ARGS__, 1, 0)
#define UVERBS_ATTR_PTR_IN_SZ(_id, _len, ...)				\
	UVERBS_ATTR(_id, _len, UVERBS_ATTR_TYPE_PTR_IN, ##__VA_ARGS__)
/* If sizeof(_type) <= sizeof(u64), this will be inlined rather than a pointer */
#define UVERBS_ATTR_PTR_IN(_id, _type, ...)				\
	UVERBS_ATTR_PTR_IN_SZ(_id, sizeof(_type), ##__VA_ARGS__)
#define UVERBS_ATTR_PTR_OUT_SZ(_id, _len, ...)				\
	UVERBS_ATTR(_id, _len, UVERBS_ATTR_TYPE_PTR_OUT, ##__VA_ARGS__)
#define UVERBS_ATTR_PTR_OUT(_id, _type, ...)				\
	UVERBS_ATTR_PTR_OUT_SZ(_id, sizeof(_type), ##__VA_ARGS__)

/*
 * In new compiler, UVERBS_ATTR_IDR (and FD) could be simplified by declaring
 * it as
 * [_id] = {.type = __obj_class,					\
 *         .obj = {.obj_type = _idr_type,				\
 *                       .access = _access                              \
 *                }, ##__VA_ARGS__ }
 * But since we support older compilers too, we need the more complex code.
 */
#define ___UVERBS_ATTR_OBJ0(_id, _obj_class, _obj_type, _access, ...)	\
	[_id] = {.type = _obj_class, .flags = 0,			\
		 {.obj = {.obj_type = _obj_type, .access = _access,} } }
#define ___UVERBS_ATTR_OBJ1(_id, _obj_class, _obj_type, _access, _flags)\
	[_id] = {.type = _obj_class, _flags,				\
		 {.obj = {.obj_type = _obj_type, .access = _access,} } }
#define ___UVERBS_ATTR_OBJ(_id, _obj_class, _obj_type, _access, _flags, \
			   _n, ...)					\
	___UVERBS_ATTR_OBJ##_n(_id, _obj_class, _obj_type, _access, _flags)
#define __UVERBS_ATTR_OBJ(_id, _obj_class, _obj_type, _access, ...)	\
	___UVERBS_ATTR_OBJ(_id, _obj_class, _obj_type, _access,		\
			   ##__VA_ARGS__, 1, 0)
#define UVERBS_ATTR_IDR(_id, _idr_type, _access, ...)			 \
	__UVERBS_ATTR_OBJ(_id, UVERBS_ATTR_TYPE_IDR, _idr_type, _access,\
			  ##__VA_ARGS__)
#define UVERBS_ATTR_FD(_id, _fd_type, _access, ...)			\
	__UVERBS_ATTR_OBJ(_id, UVERBS_ATTR_TYPE_FD, _fd_type,		\
			  (_access) + BUILD_BUG_ON_ZERO(		\
				(_access) != UVERBS_ACCESS_NEW &&	\
				(_access) != UVERBS_ACCESS_READ),	\
			  ##__VA_ARGS__)
#define _UVERBS_ATTR_SPEC_SZ(...)					\
	(sizeof((struct uverbs_attr_spec[]){__VA_ARGS__}) /	\
	 sizeof(struct uverbs_attr_spec))
#define UVERBS_ATTR_SPEC(...)					\
	((struct uverbs_attr_spec_group)				\
	 {.attrs = (struct uverbs_attr_spec[]){__VA_ARGS__},		\
	  .num_attrs = _UVERBS_ATTR_SPEC_SZ(__VA_ARGS__),		\
	 .mandatory_attrs_bitmask =					\
		((unsigned long[BITS_TO_LONGS(_UVERBS_ATTR_SPEC_SZ(__VA_ARGS__))]) {})})
#define DECLARE_UVERBS_ATTR_SPEC(name, ...)			\
	struct uverbs_attr_spec_group name =			\
		UVERBS_ATTR_SPEC(__VA_ARGS__)
#define _UVERBS_ATTR_ACTION_SPEC_SZ(...)				  \
	(sizeof((struct uverbs_attr_spec_group *[]){__VA_ARGS__}) /	  \
	 sizeof(struct uverbs_attr_spec_group *))
#define _UVERBS_ACTION(_handler, _flags, ...)				       \
	((struct uverbs_action) {					       \
		.flags = _flags,					       \
		.handler = _handler,					       \
		.num_groups =	_UVERBS_ATTR_ACTION_SPEC_SZ(__VA_ARGS__),      \
		.attr_groups = (struct uverbs_attr_spec_group *[]){__VA_ARGS__} })
#define UVERBS_ACTION(_handler, ...)			\
	_UVERBS_ACTION(_handler, 0, __VA_ARGS__)
#define UVERBS_CTX_ACTION(_handler, ...)			\
	_UVERBS_ACTION(_handler, UVERBS_ACTION_FLAG_CREATE_ROOT, __VA_ARGS__)
#define _UVERBS_ACTIONS_SZ(...)					\
	(sizeof((struct uverbs_action *[]){__VA_ARGS__}) /	\
	 sizeof(struct uverbs_action *))
#define ADD_UVERBS_ACTION(action_idx, _handler,  ...)		\
	[action_idx] = &UVERBS_ACTION(_handler, __VA_ARGS__)
#define ADD_UVERBS_CTX_ACTION(action_idx, _handler,  ...)	\
	[action_idx] = &UVERBS_CTX_ACTION(_handler, __VA_ARGS__)
#define UVERBS_ACTIONS(...)						\
	((const struct uverbs_action_group)			\
	  {.num_actions = _UVERBS_ACTIONS_SZ(__VA_ARGS__),		\
	   .actions = (struct uverbs_action *[]){__VA_ARGS__} })
#define _UVERBS_ACTIONS_GROUP_SZ(...)					\
	(sizeof((const struct uverbs_action_group*[]){__VA_ARGS__}) / \
	 sizeof(const struct uverbs_action_group *))

#define DECLARE_UVERBS_TYPE(name, _type_attrs, ...)			\
	const struct uverbs_type name = {				\
		.type_attrs = _type_attrs,				\
		.num_groups = _UVERBS_ACTIONS_GROUP_SZ(__VA_ARGS__),	\
		.action_groups = (const struct uverbs_action_group *[]){__VA_ARGS__} \
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

#define _UVERBS_TYPES_SZ(...)						\
	(sizeof((const struct uverbs_type_group *[]){__VA_ARGS__}) /	\
	 sizeof(const struct uverbs_type_group *))

#define UVERBS_TYPES_GROUP(...)						\
	((const struct uverbs_spec_root){				\
		.type_groups = (const struct uverbs_type_group *[]){__VA_ARGS__},\
		.num_groups = _UVERBS_TYPES_SZ(__VA_ARGS__)})
#define DECLARE_UVERBS_TYPES_GROUP(name, ...)		\
	const struct uverbs_spec_root name = UVERBS_TYPES_GROUP(__VA_ARGS__)

/* =================================================
 *              Parsing infrastructure
 * =================================================
 */

struct uverbs_ptr_attr {
	union {
		u64		data;
		void	__user *ptr;
	};
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

static inline int uverbs_copy_to(struct uverbs_attr_array *attr_array,
				 size_t idx, const void *from)
{
	if (!uverbs_is_valid(attr_array, idx))
		return -ENOENT;

	return copy_to_user(attr_array->attrs[idx].ptr_attr.ptr, from,
			    attr_array->attrs[idx].ptr_attr.len) ? -EFAULT : 0;
}

#define uverbs_copy_from(to, attr_array, idx)				\
	(uverbs_is_valid((attr_array), idx) ?				\
	 (sizeof(*(to)) <= sizeof(((struct ib_uverbs_attr *)0)->data) ? \
	  (memcpy((to), &(attr_array)->attrs[idx].ptr_attr.data,	\
		 (attr_array)->attrs[idx].ptr_attr.len), 0) :		\
	  (copy_from_user((to), (attr_array)->attrs[idx].ptr_attr.ptr,	\
			 (attr_array)->attrs[idx].ptr_attr.len) ?	\
	   -EFAULT : 0)) : -ENOENT)
#define uverbs_get_attr(to, attr_array, idx)				\
	(uverbs_is_valid((attr_array), idx) ?				\
	 (sizeof(to) <= sizeof(((struct ib_uverbs_attr *)0)->data) ? \
	  (sizeof(to) == sizeof((&(to))[0]) ?				\
	   ((to) = *(typeof(to) *)&(attr_array)->attrs[idx].ptr_attr.data, 0) :\
	   (memcpy(&(to), &(attr_array)->attrs[idx].ptr_attr.data,	\
		 (attr_array)->attrs[idx].ptr_attr.len), 0)) :		\
	  (copy_from_user(&(to), (attr_array)->attrs[idx].ptr_attr.ptr,	\
			 (attr_array)->attrs[idx].ptr_attr.len) ?	\
	   -EFAULT : 0)) : -ENOENT)

#endif

