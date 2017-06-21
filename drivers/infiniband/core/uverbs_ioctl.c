/*
 * Copyright (c) 2017, Mellanox Technologies inc.  All rights reserved.
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

#include <rdma/rdma_user_ioctl.h>
#include <rdma/uverbs_ioctl.h>
#include "rdma_core.h"
#include "uverbs.h"

static int uverbs_process_attr(struct ib_device *ibdev,
			       struct ib_ucontext *ucontext,
			       const struct ib_uverbs_attr *uattr,
			       u16 attr_id,
			       const struct uverbs_attr_spec_group *attr_spec_group,
			       struct uverbs_attr_array *attr_array,
			       struct ib_uverbs_attr __user *uattr_ptr)
{
	const struct uverbs_attr_spec *spec;
	struct uverbs_attr *e;
	const struct uverbs_type *type;
	struct uverbs_obj_attr *o_attr;
	struct uverbs_attr *elements = attr_array->attrs;

	if (uattr->reserved)
		return -EINVAL;

	if (attr_id >= attr_spec_group->num_attrs) {
		if (uattr->flags & UVERBS_ATTR_F_MANDATORY)
			return -EINVAL;
		else
			return 0;
	}

	spec = &attr_spec_group->attrs[attr_id];
	e = &elements[attr_id];

	switch (spec->type) {
	case UVERBS_ATTR_TYPE_PTR_IN:
	case UVERBS_ATTR_TYPE_PTR_OUT:
		if (uattr->len < spec->len ||
		    (!(spec->flags & UVERBS_ATTR_SPEC_F_MIN_SZ) &&
		     uattr->len > spec->len))
			return -EINVAL;

		e->ptr_attr.data = uattr->data;
		e->ptr_attr.len = uattr->len;
		break;

	case UVERBS_ATTR_TYPE_IDR:
		if (uattr->data >> 32)
			return -EINVAL;
	/* fall through */
	case UVERBS_ATTR_TYPE_FD:
		if (uattr->len != 0 || !ucontext || uattr->data > INT_MAX)
			return -EINVAL;

		o_attr = &e->obj_attr;
		type = uverbs_get_type(ibdev, spec->obj.obj_type);
		if (!type)
			return -EINVAL;
		o_attr->type = type->type_attrs;
		o_attr->uattr = uattr_ptr;

		o_attr->id = (int)uattr->data;
		o_attr->uobject = uverbs_get_uobject_from_context(
					o_attr->type,
					ucontext,
					spec->obj.access,
					o_attr->id);

		if (IS_ERR(o_attr->uobject))
			return PTR_ERR(o_attr->uobject);

		if (spec->obj.access == UVERBS_ACCESS_NEW) {
			u64 id = o_attr->uobject->id;

			/* Copy the allocated id to the user-space */
			if (put_user(id, &o_attr->uattr->data)) {
				uverbs_finalize_object(o_attr->uobject,
						       UVERBS_ACCESS_NEW,
						       false);
				return -EFAULT;
			}
		}

		break;
	default:
		return -EOPNOTSUPP;
	}

	set_bit(attr_id, attr_array->valid_bitmap);
	return 0;
}

static int uverbs_uattrs_process(struct ib_device *ibdev,
				 struct ib_ucontext *ucontext,
				 const struct ib_uverbs_attr *uattrs,
				 size_t num_uattrs,
				 const struct uverbs_action *action,
				 struct uverbs_attr_array *attr_array,
				 struct ib_uverbs_attr __user *uattr_ptr)
{
	size_t i;
	int ret = 0;
	int num_given_groups = 0;

	for (i = 0; i < num_uattrs; i++) {
		const struct ib_uverbs_attr *uattr = &uattrs[i];
		u16 attr_id = uattr->attr_id;
		const struct uverbs_attr_spec_group *attr_spec_group;

		ret = uverbs_group_idx(&attr_id, action->num_groups);
		if (ret < 0) {
			if (uattr->flags & UVERBS_ATTR_F_MANDATORY) {
				uverbs_finalize_objects(attr_array,
							action->attr_groups,
							num_given_groups,
							false);
				return ret;
			}
			continue;
		}

		/*
		 * ret is the found group, so increase num_give_groups if
		 * necessary.
		 */
		if (ret >= num_given_groups)
			num_given_groups = ret + 1;

		attr_spec_group = action->attr_groups[ret];
		ret = uverbs_process_attr(ibdev, ucontext, uattr, attr_id,
					  attr_spec_group, &attr_array[ret],
					  uattr_ptr++);
		if (ret) {
			uverbs_finalize_objects(attr_array,
						action->attr_groups,
						num_given_groups,
						false);
			return ret;
		}
	}

	return num_given_groups;
}

static int uverbs_validate_kernel_mandatory(const struct uverbs_action *action,
					    struct uverbs_attr_array *attr_array,
					    unsigned int num_given_groups)
{
	unsigned int i;

	for (i = 0; i < num_given_groups; i++) {
		const struct uverbs_attr_spec_group *attr_spec_group =
			action->attr_groups[i];

		if (!bitmap_subset(attr_spec_group->mandatory_attrs_bitmask,
				   attr_array[i].valid_bitmap,
				   attr_spec_group->num_attrs))
			return -EINVAL;
	}

	return 0;
}

static int uverbs_handle_action(struct ib_uverbs_attr __user *uattr_ptr,
				const struct ib_uverbs_attr *uattrs,
				size_t num_uattrs,
				struct ib_device *ibdev,
				struct ib_uverbs_file *ufile,
				const struct uverbs_action *action,
				struct uverbs_attr_array *attr_array)
{
	int ret;
	int finalize_ret;
	int num_given_groups;

	num_given_groups = uverbs_uattrs_process(ibdev, ufile->ucontext, uattrs,
						 num_uattrs, action, attr_array,
						 uattr_ptr);
	if (num_given_groups <= 0)
		return -EINVAL;

	ret = uverbs_validate_kernel_mandatory(action, attr_array,
					       num_given_groups);
	if (ret)
		goto cleanup;

	ret = action->handler(ibdev, ufile, attr_array, num_given_groups);
cleanup:
	finalize_ret = uverbs_finalize_objects(attr_array, action->attr_groups,
					       num_given_groups, !ret);

	return ret ? ret : finalize_ret;
}

#define UVERBS_OPTIMIZE_USING_STACK_SZ  256
static long ib_uverbs_cmd_verbs(struct ib_device *ib_dev,
				struct ib_uverbs_file *file,
				struct ib_uverbs_ioctl_hdr *hdr,
				void __user *buf)
{
	const struct uverbs_type *type;
	const struct uverbs_action *action;
	long err = 0;
	unsigned int i;
	struct {
		struct ib_uverbs_attr		*uattrs;
		struct uverbs_attr_array	*uverbs_attr_array;
	} *ctx = NULL;
	struct uverbs_attr *curr_attr;
	unsigned long *curr_bitmap;
	size_t ctx_size;
#ifdef UVERBS_OPTIMIZE_USING_STACK_SZ
	uintptr_t data[UVERBS_OPTIMIZE_USING_STACK_SZ / sizeof(uintptr_t)];
#endif

	if (hdr->reserved)
		return -EINVAL;

	type = uverbs_get_type(ib_dev, hdr->object_type);
	if (!type)
		return -EOPNOTSUPP;

	action = uverbs_get_action(type, hdr->action);
	if (!action)
		return -EOPNOTSUPP;

	if ((action->flags & UVERBS_ACTION_FLAG_CREATE_ROOT) ^ !file->ucontext)
		return -EINVAL;

	ctx_size = sizeof(*ctx) +
		   sizeof(struct uverbs_attr_array) * action->num_groups +
		   sizeof(*ctx->uattrs) * hdr->num_attrs +
		   sizeof(*ctx->uverbs_attr_array->attrs) *
		   action->num_child_attrs +
		   sizeof(*ctx->uverbs_attr_array->valid_bitmap) *
			(action->num_child_attrs / BITS_PER_LONG +
			 action->num_groups);

#ifdef UVERBS_OPTIMIZE_USING_STACK_SZ
	if (ctx_size <= UVERBS_OPTIMIZE_USING_STACK_SZ)
		ctx = (void *)data;

	if (!ctx)
#endif
	ctx = kmalloc(ctx_size, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->uverbs_attr_array = (void *)ctx + sizeof(*ctx);
	ctx->uattrs = (void *)(ctx->uverbs_attr_array +
			       action->num_groups);
	curr_attr = (void *)(ctx->uattrs + hdr->num_attrs);
	curr_bitmap = (void *)(curr_attr + action->num_child_attrs);

	/*
	 * We just fill the pointers and num_attrs here. The data itself will be
	 * filled at a later stage (uverbs_process_attr)
	 */
	for (i = 0; i < action->num_groups; i++) {
		unsigned int curr_num_attrs = action->attr_groups[i]->num_attrs;

		ctx->uverbs_attr_array[i].attrs = curr_attr;
		curr_attr += curr_num_attrs;
		ctx->uverbs_attr_array[i].num_attrs = curr_num_attrs;
		ctx->uverbs_attr_array[i].valid_bitmap = curr_bitmap;
		bitmap_zero(curr_bitmap, curr_num_attrs);
		curr_bitmap += BITS_TO_LONGS(curr_num_attrs);
	}

	err = copy_from_user(ctx->uattrs, buf,
			     sizeof(*ctx->uattrs) * hdr->num_attrs);
	if (err) {
		err = -EFAULT;
		goto out;
	}

	err = uverbs_handle_action(buf, ctx->uattrs, hdr->num_attrs, ib_dev,
				   file, action, ctx->uverbs_attr_array);
out:
#ifdef UVERBS_OPTIMIZE_USING_STACK_SZ
	if (ctx_size > UVERBS_OPTIMIZE_USING_STACK_SZ)
#endif
	kfree(ctx);
	return err;
}

#define IB_UVERBS_MAX_CMD_SZ 4096

long ib_uverbs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct ib_uverbs_file *file = filp->private_data;
	struct ib_uverbs_ioctl_hdr __user *user_hdr =
		(struct ib_uverbs_ioctl_hdr __user *)arg;
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_device *ib_dev;
	int srcu_key;
	long err;

	srcu_key = srcu_read_lock(&file->device->disassociate_srcu);
	ib_dev = srcu_dereference(file->device->ib_dev,
				  &file->device->disassociate_srcu);
	if (!ib_dev) {
		err = -EIO;
		goto out;
	}

	if (cmd == RDMA_VERBS_IOCTL) {
		err = copy_from_user(&hdr, user_hdr, sizeof(hdr));

		if (err || hdr.length > IB_UVERBS_MAX_CMD_SZ ||
		    hdr.length != sizeof(hdr) + hdr.num_attrs * sizeof(struct ib_uverbs_attr)) {
			err = -EINVAL;
			goto out;
		}

		if (hdr.reserved) {
			err = -EOPNOTSUPP;
			goto out;
		}

		err = ib_uverbs_cmd_verbs(ib_dev, file, &hdr,
					  (__user void *)arg + sizeof(hdr));
	} else {
		err = -ENOIOCTLCMD;
	}
out:
	srcu_read_unlock(&file->device->disassociate_srcu, srcu_key);

	return err;
}

static void uverbs_initialize_action(struct uverbs_action *action)
{
	size_t attr_group_idx;

	for (attr_group_idx = 0; attr_group_idx < action->num_groups;
	     attr_group_idx++) {
		struct uverbs_attr_spec_group *attr_group =
			action->attr_groups[attr_group_idx];
		size_t attr_idx;

		if (!attr_group)
			continue;
		action->num_child_attrs += attr_group->num_attrs;
		for (attr_idx = 0; attr_idx < attr_group->num_attrs;
		     attr_idx++) {
			struct uverbs_attr_spec *attr =
				&attr_group->attrs[attr_idx];

			if (attr->flags & UVERBS_ATTR_SPEC_F_MANDATORY)
				set_bit(attr_idx,
					attr_group->mandatory_attrs_bitmask);
		}
	}
}

void uverbs_initialize_type_group(const struct uverbs_type_group *type_group)
{
	size_t type_idx;

	for (type_idx = 0; type_idx < type_group->num_types; type_idx++) {
		const struct uverbs_type *type = type_group->types[type_idx];
		size_t action_group_idx;

		if (!type)
			continue;
		for (action_group_idx = 0;
		     action_group_idx < type->num_groups;
		     action_group_idx++) {
			const struct uverbs_action_group *action_group =
				type->action_groups[action_group_idx];
			size_t action_idx;

			if (!action_group)
				continue;
			for (action_idx = 0;
			     action_idx < action_group->num_actions;
			     action_idx++) {
				struct uverbs_action *action =
					action_group->actions[action_idx];

				if (!action)
					continue;
				uverbs_initialize_action(action);
			}
		}
	}
}
