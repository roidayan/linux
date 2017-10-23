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

#include <rdma/uverbs_std_types.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>
#include <linux/bug.h>
#include <linux/file.h>
#include <rdma/restrack.h>
#include "rdma_core.h"
#include "uverbs.h"

static int uverbs_free_ah(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	return rdma_destroy_ah((struct ib_ah *)uobject->object);
}

static int uverbs_free_flow(struct ib_uobject *uobject,
			    enum rdma_remove_reason why)
{
	return ib_destroy_flow((struct ib_flow *)uobject->object);
}

static int uverbs_free_flow_action(struct ib_uobject *uobject,
				   enum rdma_remove_reason why)
{
	struct ib_flow_action *action = uobject->object;

	if (why == RDMA_REMOVE_DESTROY &&
	    atomic_read(&action->usecnt))
		return -EBUSY;

	return action->device->destroy_flow_action(action);
}

static int uverbs_free_mw(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	return uverbs_dealloc_mw((struct ib_mw *)uobject->object);
}

static int uverbs_free_qp(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_qp *qp = uobject->object;
	struct ib_uqp_object *uqp =
		container_of(uobject, struct ib_uqp_object, uevent.uobject);
	int ret;

	if (why == RDMA_REMOVE_DESTROY) {
		if (!list_empty(&uqp->mcast_list))
			return -EBUSY;
	} else if (qp == qp->real_qp) {
		ib_uverbs_detach_umcast(qp, uqp);
	}

	ret = ib_destroy_qp(qp);
	if (ret && why == RDMA_REMOVE_DESTROY)
		return ret;

	if (uqp->uxrcd)
		atomic_dec(&uqp->uxrcd->refcnt);

	ib_uverbs_release_uevent(uobject->context->ufile, &uqp->uevent);
	return ret;
}

static int uverbs_free_rwq_ind_tbl(struct ib_uobject *uobject,
				   enum rdma_remove_reason why)
{
	struct ib_rwq_ind_table *rwq_ind_tbl = uobject->object;
	struct ib_wq **ind_tbl = rwq_ind_tbl->ind_tbl;
	int ret;

	ret = ib_destroy_rwq_ind_table(rwq_ind_tbl);
	if (!ret || why != RDMA_REMOVE_DESTROY)
		kfree(ind_tbl);
	return ret;
}

static int uverbs_free_wq(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_wq *wq = uobject->object;
	struct ib_uwq_object *uwq =
		container_of(uobject, struct ib_uwq_object, uevent.uobject);
	int ret;

	ret = ib_destroy_wq(wq);
	if (!ret || why != RDMA_REMOVE_DESTROY)
		ib_uverbs_release_uevent(uobject->context->ufile, &uwq->uevent);
	return ret;
}

static int uverbs_free_srq(struct ib_uobject *uobject,
			   enum rdma_remove_reason why)
{
	struct ib_srq *srq = uobject->object;
	struct ib_uevent_object *uevent =
		container_of(uobject, struct ib_uevent_object, uobject);
	enum ib_srq_type  srq_type = srq->srq_type;
	int ret;

	ret = ib_destroy_srq(srq);

	if (ret && why == RDMA_REMOVE_DESTROY)
		return ret;

	if (srq_type == IB_SRQT_XRC) {
		struct ib_usrq_object *us =
			container_of(uevent, struct ib_usrq_object, uevent);

		atomic_dec(&us->uxrcd->refcnt);
	}

	ib_uverbs_release_uevent(uobject->context->ufile, uevent);
	return ret;
}

static int uverbs_free_cq(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_cq *cq = uobject->object;
	struct ib_uverbs_event_queue *ev_queue = cq->cq_context;
	struct ib_ucq_object *ucq =
		container_of(uobject, struct ib_ucq_object, uobject);
	int ret;

	ret = ib_destroy_cq(cq);
	if (!ret || why != RDMA_REMOVE_DESTROY)
		ib_uverbs_release_ucq(uobject->context->ufile, ev_queue ?
				      container_of(ev_queue,
						   struct ib_uverbs_completion_event_file,
						   ev_queue) : NULL,
				      ucq);
	return ret;
}

static int uverbs_free_mr(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	return ib_dereg_mr((struct ib_mr *)uobject->object);
}

static int uverbs_free_xrcd(struct ib_uobject *uobject,
			    enum rdma_remove_reason why)
{
	struct ib_xrcd *xrcd = uobject->object;
	struct ib_uxrcd_object *uxrcd =
		container_of(uobject, struct ib_uxrcd_object, uobject);
	int ret;

	mutex_lock(&uobject->context->ufile->device->xrcd_tree_mutex);
	if (why == RDMA_REMOVE_DESTROY && atomic_read(&uxrcd->refcnt))
		ret = -EBUSY;
	else
		ret = ib_uverbs_dealloc_xrcd(uobject->context->ufile->device,
					     xrcd, why);
	mutex_unlock(&uobject->context->ufile->device->xrcd_tree_mutex);

	return ret;
}

static int uverbs_free_pd(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_pd *pd = uobject->object;

	if (why == RDMA_REMOVE_DESTROY && atomic_read(&pd->usecnt))
		return -EBUSY;

	ib_dealloc_pd((struct ib_pd *)uobject->object);
	return 0;
}

static int uverbs_hot_unplug_completion_event_file(struct ib_uobject_file *uobj_file,
						   enum rdma_remove_reason why)
{
	struct ib_uverbs_completion_event_file *comp_event_file =
		container_of(uobj_file, struct ib_uverbs_completion_event_file,
			     uobj_file);
	struct ib_uverbs_event_queue *event_queue = &comp_event_file->ev_queue;

	spin_lock_irq(&event_queue->lock);
	event_queue->is_closed = 1;
	spin_unlock_irq(&event_queue->lock);

	if (why == RDMA_REMOVE_DRIVER_REMOVE) {
		wake_up_interruptible(&event_queue->poll_wait);
		kill_fasync(&event_queue->async_queue, SIGIO, POLL_IN);
	}
	return 0;
};

#define UVERBS_METHOD(id)	uverbs_method_##id
#define UVERBS_HANDLER(id)	uverbs_handler_##id

#define DECLARE_COMMON_METHOD(id, ...)	\
	DECLARE_UVERBS_METHOD(UVERBS_METHOD(id), id, UVERBS_HANDLER(id), ##__VA_ARGS__)

#define DECLARE_COMMON_OBJECT(id, ...)	\
	DECLARE_UVERBS_OBJECT(UVERBS_OBJECT(id), id, ##__VA_ARGS__)

static int uverbs_destroy_def_handler(struct ib_device *ib_dev,
				      struct ib_uverbs_file *file,
				      struct uverbs_attr_bundle *attrs)
{
	return 0;
}

/*
 * This spec is used in order to pass information to the hardware driver in a
 * legacy way. Every verb that could get driver specific data should get this
 * spec.
 */
static const struct uverbs_attr_def uverbs_uhw_compat_in =
	UVERBS_ATTR_PTR_IN_SZ(UVERBS_ATTR_UHW_IN, UVERBS_ATTR_SIZE(0, USHRT_MAX),
			      UA_FLAGS(UVERBS_ATTR_SPEC_F_MIN_SZ_OR_ZERO));
static const struct uverbs_attr_def uverbs_uhw_compat_out =
	UVERBS_ATTR_PTR_OUT_SZ(UVERBS_ATTR_UHW_OUT, UVERBS_ATTR_SIZE(0, USHRT_MAX),
			       UA_FLAGS(UVERBS_ATTR_SPEC_F_MIN_SZ_OR_ZERO));

static void create_udata(struct uverbs_attr_bundle *ctx,
			 struct ib_udata *udata)
{
	/*
	 * This is for ease of conversion. The purpose is to convert all drivers
	 * to use uverbs_attr_bundle instead of ib_udata.
	 * Assume attr == 0 is input and attr == 1 is output.
	 */
	const struct uverbs_attr *uhw_in =
		uverbs_attr_get(ctx, UVERBS_ATTR_UHW_IN);
	const struct uverbs_attr *uhw_out =
		uverbs_attr_get(ctx, UVERBS_ATTR_UHW_OUT);

	if (!IS_ERR(uhw_in)) {
		udata->inlen = uhw_in->ptr_attr.len;
		if (uverbs_attr_ptr_is_inline(uhw_in))
			udata->inbuf = &uhw_in->uattr->data;
		else
			udata->inbuf = u64_to_user_ptr(uhw_in->ptr_attr.data);
	} else {
		udata->inbuf = NULL;
		udata->inlen = 0;
	}

	if (!IS_ERR(uhw_out)) {
		udata->outbuf = u64_to_user_ptr(uhw_out->ptr_attr.data);
		udata->outlen = uhw_out->ptr_attr.len;
	} else {
		udata->outbuf = NULL;
		udata->outlen = 0;
	}
}

static int UVERBS_HANDLER(UVERBS_METHOD_CQ_CREATE)(struct ib_device *ib_dev,
						   struct ib_uverbs_file *file,
						   struct uverbs_attr_bundle *attrs)
{
	struct ib_ucontext *ucontext = file->ucontext;
	struct ib_ucq_object           *obj;
	struct ib_udata uhw;
	int ret;
	u64 user_handle;
	struct ib_cq_init_attr attr = {};
	struct ib_cq                   *cq;
	struct ib_uverbs_completion_event_file    *ev_file = NULL;
	const struct uverbs_attr *ev_file_attr;
	struct ib_uobject *ev_file_uobj;

	if (!(ib_dev->uverbs_cmd_mask & 1ULL << IB_USER_VERBS_CMD_CREATE_CQ))
		return -EOPNOTSUPP;

	ret = uverbs_copy_from(&attr.comp_vector, attrs,
			       UVERBS_ATTR_CREATE_CQ_COMP_VECTOR);
	if (!ret)
		ret = uverbs_copy_from(&attr.cqe, attrs,
				       UVERBS_ATTR_CREATE_CQ_CQE);
	if (!ret)
		ret = uverbs_copy_from(&user_handle, attrs,
				       UVERBS_ATTR_CREATE_CQ_USER_HANDLE);
	if (ret)
		return ret;

	/* Optional param, if it doesn't exist, we get -ENOENT and skip it */
	if (IS_UVERBS_COPY_ERR(uverbs_copy_from(&attr.flags, attrs,
						UVERBS_ATTR_CREATE_CQ_FLAGS)))
		return -EFAULT;

	ev_file_attr = uverbs_attr_get(attrs, UVERBS_ATTR_CREATE_CQ_COMP_CHANNEL);
	if (!IS_ERR(ev_file_attr)) {
		ev_file_uobj = ev_file_attr->obj_attr.uobject;

		ev_file = container_of(ev_file_uobj,
				       struct ib_uverbs_completion_event_file,
				       uobj_file.uobj);
		uverbs_uobject_get(ev_file_uobj);
	}

	if (attr.comp_vector >= ucontext->ufile->device->num_comp_vectors) {
		ret = -EINVAL;
		goto err_event_file;
	}

	obj = container_of(uverbs_attr_get(attrs,
					   UVERBS_ATTR_CREATE_CQ_HANDLE)->obj_attr.uobject,
			   typeof(*obj), uobject);
	obj->uverbs_file	   = ucontext->ufile;
	obj->comp_events_reported  = 0;
	obj->async_events_reported = 0;
	INIT_LIST_HEAD(&obj->comp_list);
	INIT_LIST_HEAD(&obj->async_list);

	/* Temporary, only until drivers get the new uverbs_attr_bundle */
	create_udata(attrs, &uhw);

	cq = ib_dev->create_cq(ib_dev, &attr, ucontext, &uhw);
	if (IS_ERR(cq)) {
		ret = PTR_ERR(cq);
		goto err_event_file;
	}

	cq->device        = ib_dev;
	cq->uobject       = &obj->uobject;
	cq->comp_handler  = ib_uverbs_comp_handler;
	cq->event_handler = ib_uverbs_cq_event_handler;
	cq->cq_context    = ev_file ? &ev_file->ev_queue : NULL;
	obj->uobject.object = cq;
	obj->uobject.user_handle = user_handle;
	atomic_set(&cq->usecnt, 0);
	cq->res.type = RDMA_RESTRACK_CQ;
	rdma_restrack_add(&cq->res);

	ret = uverbs_copy_to(attrs, UVERBS_ATTR_CREATE_CQ_RESP_CQE, &cq->cqe,
			     sizeof(cq->cqe));
	if (ret)
		goto err_cq;

	return 0;
err_cq:
	ib_destroy_cq(cq);

err_event_file:
	if (ev_file)
		uverbs_uobject_put(ev_file_uobj);
	return ret;
};

static DECLARE_COMMON_METHOD(UVERBS_METHOD_CQ_CREATE,
	&UVERBS_ATTR_IDR(UVERBS_ATTR_CREATE_CQ_HANDLE, UVERBS_OBJECT_CQ,
			 UVERBS_ACCESS_NEW,
			 UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	&UVERBS_ATTR_PTR_IN(UVERBS_ATTR_CREATE_CQ_CQE,
			    UVERBS_ATTR_TYPE(u32),
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	&UVERBS_ATTR_PTR_IN(UVERBS_ATTR_CREATE_CQ_USER_HANDLE,
			    UVERBS_ATTR_TYPE(u64),
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	&UVERBS_ATTR_FD(UVERBS_ATTR_CREATE_CQ_COMP_CHANNEL,
			UVERBS_OBJECT_COMP_CHANNEL,
			UVERBS_ACCESS_READ),
	&UVERBS_ATTR_PTR_IN(UVERBS_ATTR_CREATE_CQ_COMP_VECTOR, UVERBS_ATTR_TYPE(u32),
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	&UVERBS_ATTR_PTR_IN(UVERBS_ATTR_CREATE_CQ_FLAGS, UVERBS_ATTR_TYPE(u32)),
	&UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_CREATE_CQ_RESP_CQE, UVERBS_ATTR_TYPE(u32),
			     UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	&uverbs_uhw_compat_in, &uverbs_uhw_compat_out);

static int UVERBS_HANDLER(UVERBS_METHOD_CQ_DESTROY)(struct ib_device *ib_dev,
						    struct ib_uverbs_file *file,
						    struct uverbs_attr_bundle *attrs)
{
	struct ib_uverbs_destroy_cq_resp resp;
	struct ib_uobject *uobj =
		uverbs_attr_get(attrs, UVERBS_ATTR_DESTROY_CQ_HANDLE)->obj_attr.uobject;
	struct ib_ucq_object *obj = container_of(uobj, struct ib_ucq_object,
						 uobject);
	int ret;

	if (!(ib_dev->uverbs_cmd_mask & 1ULL << IB_USER_VERBS_CMD_DESTROY_CQ))
		return -EOPNOTSUPP;

	ret = rdma_explicit_destroy(uobj);
	if (ret)
		return ret;

	resp.comp_events_reported  = obj->comp_events_reported;
	resp.async_events_reported = obj->async_events_reported;

	return uverbs_copy_to(attrs, UVERBS_ATTR_DESTROY_CQ_RESP, &resp,
			      sizeof(resp));
}

static DECLARE_COMMON_METHOD(UVERBS_METHOD_CQ_DESTROY,
	&UVERBS_ATTR_IDR(UVERBS_ATTR_DESTROY_CQ_HANDLE, UVERBS_OBJECT_CQ,
			 UVERBS_ACCESS_DESTROY,
			 UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	&UVERBS_ATTR_PTR_OUT(UVERBS_ATTR_DESTROY_CQ_RESP,
			     UVERBS_ATTR_TYPE(struct ib_uverbs_destroy_cq_resp),
			     UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

static u64 esp_flags_uverbs_to_verbs(struct uverbs_attr_bundle *attrs,
				     u32 flags)
{
	u64 verbs_flags = flags;

	if (uverbs_attr_is_valid(attrs, UVERBS_ATTR_FLOW_ACTION_ESP_ESN))
		verbs_flags |= IB_FLOW_ACTION_ESP_FLAGS_ESN_TRIGGERED;

	return verbs_flags;
};

static int validate_flow_action_esp_keymat_aes_gcm(union ib_flow_action_attrs_esp_keymats *keymat)
{
	struct ib_flow_action_attrs_esp_keymat_aes_gcm *aes_gcm =
		&keymat->aes_gcm;

	if (aes_gcm->attrs.iv_algo > IB_UVERBS_FLOW_ACTION_IV_ALGO_SEQ)
		return -EOPNOTSUPP;

	if (aes_gcm->attrs.key_len != 32 &&
	    aes_gcm->attrs.key_len != 24 &&
	    aes_gcm->attrs.key_len != 16)
		return -EINVAL;

	if (aes_gcm->attrs.icv_len != 16 &&
	    aes_gcm->attrs.icv_len != 8 &&
	    aes_gcm->attrs.icv_len != 12)
		return -EINVAL;

	return 0;
}

static int (*flow_action_esp_keymat_validate[])(union ib_flow_action_attrs_esp_keymats *keymat) = {
	[IB_UVERBS_FLOW_ACTION_ESP_KEYMAT_AES_GCM] = validate_flow_action_esp_keymat_aes_gcm,
};

static int parse_esp_ip(enum ib_flow_spec_type proto,
			const void __user *val_ptr,
			size_t len, union ib_flow_spec *out)
{
	int ret;
	const struct ib_uverbs_flow_ipv4_filter ipv4 = {
		.src_ip = cpu_to_be32(0xffffffffUL),
		.dst_ip = cpu_to_be32(0xffffffffUL),
		.proto = 0xff,
		.tos = 0xff,
		.ttl = 0xff,
		.flags = 0xff,
	};
	const struct ib_uverbs_flow_ipv6_filter ipv6 = {
		.src_ip = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		.dst_ip = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		.flow_label = cpu_to_be32(0xffffffffUL),
		.next_hdr = 0xff,
		.traffic_class = 0xff,
		.hop_limit = 0xff,
	};
	union {
		struct ib_uverbs_flow_ipv4_filter ipv4;
		struct ib_uverbs_flow_ipv6_filter ipv6;
	} user_val = {};
	const void *user_pmask;
	size_t val_len;

	/* If the flow IPv4/IPv6 flow specifications are extended, the mask
	 * should be changed as well.
	 */
	BUILD_BUG_ON(offsetof(struct ib_uverbs_flow_ipv4_filter, flags) +
		     sizeof(ipv4.flags) != sizeof(ipv4));
	BUILD_BUG_ON(offsetof(struct ib_uverbs_flow_ipv6_filter, reserved) +
		     sizeof(ipv6.reserved) != sizeof(ipv6));

	switch (proto) {
	case IB_FLOW_SPEC_IPV4:
		if (len > sizeof(user_val.ipv4) &&
		    !ib_is_buffer_cleared(val_ptr + sizeof(user_val.ipv4),
					  len - sizeof(user_val.ipv4)))
			return -EOPNOTSUPP;

		val_len = min_t(size_t, len, sizeof(user_val.ipv4));
		ret = copy_from_user(&user_val.ipv4, val_ptr,
				     val_len);
		if (ret)
			return -EFAULT;

		user_pmask = &ipv4;
		break;
	case IB_FLOW_SPEC_IPV6:
		if (len > sizeof(user_val.ipv6) &&
		    !ib_is_buffer_cleared(val_ptr + sizeof(user_val.ipv6),
					  len - sizeof(user_val.ipv6)))
			return -EOPNOTSUPP;

		val_len = min_t(size_t, len, sizeof(user_val.ipv6));
		ret = copy_from_user(&user_val.ipv6, val_ptr,
				     val_len);
		if (ret)
			return -EFAULT;

		user_pmask = &ipv6;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return ib_uverbs_kern_spec_to_ib_spec_filter(proto, user_pmask,
						     &user_val,
						     val_len, out);
}

static int flow_action_esp_get_encap(struct ib_flow_spec_list *out,
				     struct uverbs_attr_bundle *attrs)
{
	struct ib_uverbs_flow_action_esp_encap uverbs_encap;
	int ret;

	ret = uverbs_copy_from(&uverbs_encap, attrs,
			       UVERBS_ATTR_FLOW_ACTION_ESP_ENCAP);
	if (ret)
		return ret;

	/* We currently support only one encap */
	if (uverbs_encap.next_ptr)
		return -EOPNOTSUPP;

	if (uverbs_encap.type != IB_FLOW_SPEC_IPV4 &&
	    uverbs_encap.type != IB_FLOW_SPEC_IPV6)
		return -EOPNOTSUPP;

	return parse_esp_ip(uverbs_encap.type,
			    (__force const void __user *)uverbs_encap.val_ptr,
			    uverbs_encap.len,
			    &out->spec);
}

struct ib_flow_action_esp_attr {
	struct	ib_flow_action_attrs_esp		hdr;
	union	ib_flow_action_attrs_esp_keymats	keymat;
	union	ib_flow_action_attrs_esp_replays	replay;
	/* We currently support only one spec */
	struct	ib_flow_spec_list			encap;
};

#define ESP_LAST_SUPPORTED_FLAG		IB_UVERBS_FLOW_ACTION_ESP_FLAGS_ESN_NEW_WINDOW
static int parse_flow_action_esp(struct ib_device *ib_dev,
				 struct ib_uverbs_file *file,
				 struct uverbs_attr_bundle *attrs,
				 struct ib_flow_action_esp_attr *esp_attr)
{
	struct ib_uverbs_flow_action_esp uverbs_esp = {};
	int ret;

	/* Optional param, if it doesn't exist, we get -ENOENT and skip it */
	ret = uverbs_copy_from(&esp_attr->hdr.esn, attrs,
			       UVERBS_ATTR_FLOW_ACTION_ESP_ESN);
	if (IS_UVERBS_COPY_ERR(ret))
		return ret;

	/* This can be called from FLOW_ACTION_ESP_MODIFY where
	 * UVERBS_ATTR_FLOW_ACTION_ESP_ATTRS is optional
	 */
	if (uverbs_attr_is_valid(attrs, UVERBS_ATTR_FLOW_ACTION_ESP_ATTRS)) {
		ret = uverbs_copy_from_or_zero(&uverbs_esp, attrs,
					       UVERBS_ATTR_FLOW_ACTION_ESP_ATTRS);
		if (ret)
			return ret;

		if (uverbs_esp.flags & ~((ESP_LAST_SUPPORTED_FLAG << 1) - 1))
			return -EOPNOTSUPP;

		esp_attr->hdr.spi = uverbs_esp.spi;
		esp_attr->hdr.seq = uverbs_esp.seq;
		esp_attr->hdr.tfc_pad = uverbs_esp.tfc_pad;
		esp_attr->hdr.hard_limit_pkts = uverbs_esp.hard_limit_pkts;
	}
	esp_attr->hdr.flags = esp_flags_uverbs_to_verbs(attrs, uverbs_esp.flags);

	if (uverbs_attr_is_valid(attrs, UVERBS_ATTR_FLOW_ACTION_ESP_KEYMAT)) {
		esp_attr->keymat.keymat.protocol =
			uverbs_attr_get_enum_id(attrs,
						UVERBS_ATTR_FLOW_ACTION_ESP_KEYMAT);
		ret = _uverbs_copy_from_or_zero(&esp_attr->keymat.keymat + 1,
						attrs,
						UVERBS_ATTR_FLOW_ACTION_ESP_KEYMAT,
						sizeof(esp_attr->keymat));
		if (ret)
			return ret;

		ret = flow_action_esp_keymat_validate[esp_attr->keymat.keymat.protocol](&esp_attr->keymat);
		if (ret)
			return ret;

		esp_attr->hdr.keymat = &esp_attr->keymat.keymat;
	}

	if (uverbs_attr_is_valid(attrs, UVERBS_ATTR_FLOW_ACTION_ESP_REPLAY)) {
		esp_attr->replay.replay.protocol =
			uverbs_attr_get_enum_id(attrs,
						UVERBS_ATTR_FLOW_ACTION_ESP_REPLAY);

		ret = _uverbs_copy_from_or_zero(&esp_attr->replay.replay + 1,
						attrs,
						UVERBS_ATTR_FLOW_ACTION_ESP_REPLAY,
						sizeof(esp_attr->replay));
		if (ret)
			return ret;

		esp_attr->hdr.replay = &esp_attr->replay.replay;
	}

	if (uverbs_attr_is_valid(attrs, UVERBS_ATTR_FLOW_ACTION_ESP_ENCAP)) {
		ret = flow_action_esp_get_encap(&esp_attr->encap, attrs);
		if (ret)
			return ret;

		esp_attr->hdr.encap = &esp_attr->encap;
	}

	return 0;
}

static int UVERBS_HANDLER(UVERBS_METHOD_FLOW_ACTION_ESP_CREATE)(struct ib_device *ib_dev,
								struct ib_uverbs_file *file,
								struct uverbs_attr_bundle *attrs)
{
	int				  ret;
	struct ib_uobject		  *uobj;
	struct ib_flow_action		  *action;
	struct ib_flow_action_esp_attr	  esp_attr = {};

	if (!ib_dev->create_flow_action_esp)
		return -EOPNOTSUPP;

	ret = parse_flow_action_esp(ib_dev, file, attrs, &esp_attr);
	if (ret)
		return ret;

	/* No need to check as this attribute is marked as MANDATORY */
	uobj = uverbs_attr_get(attrs, UVERBS_ATTR_FLOW_ACTION_ESP_HANDLE)->obj_attr.uobject;
	action = ib_dev->create_flow_action_esp(ib_dev, &esp_attr.hdr, attrs);
	if (IS_ERR(action))
		return PTR_ERR(action);

	atomic_set(&action->usecnt, 0);
	action->device = ib_dev;
	action->type = IB_FLOW_ACTION_ESP;
	action->uobject = uobj;
	uobj->object = action;

	return 0;
}

static struct uverbs_attr_spec uverbs_flow_action_esp_keymat[] = {
	[IB_UVERBS_FLOW_ACTION_ESP_KEYMAT_AES_GCM] = {
		.ptr = {
			.type = UVERBS_ATTR_TYPE_PTR_IN,
			UVERBS_ATTR_TYPE(struct ib_uverbs_flow_action_esp_keymat_aes_gcm),
			.flags = UVERBS_ATTR_SPEC_F_MIN_SZ_OR_ZERO,
		},
	},
};

static struct uverbs_attr_spec uverbs_flow_action_esp_replay[] = {
	[IB_UVERBS_FLOW_ACTION_ESP_REPLAY_BMP] = {
		.ptr = {
			.type = UVERBS_ATTR_TYPE_PTR_IN,
			UVERBS_ATTR_STRUCT(struct ib_uverbs_flow_action_esp_replay_bmp, size),
			.flags = UVERBS_ATTR_SPEC_F_MIN_SZ_OR_ZERO,
		}
	},
};

static DECLARE_COMMON_METHOD(UVERBS_METHOD_FLOW_ACTION_ESP_CREATE,
	&UVERBS_ATTR_IDR(UVERBS_ATTR_FLOW_ACTION_ESP_HANDLE, UVERBS_OBJECT_FLOW_ACTION,
			 UVERBS_ACCESS_NEW,
			 UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	&UVERBS_ATTR_PTR_IN(UVERBS_ATTR_FLOW_ACTION_ESP_ATTRS,
			    UVERBS_ATTR_STRUCT(struct ib_uverbs_flow_action_esp, hard_limit_pkts),
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY |
				     UVERBS_ATTR_SPEC_F_MIN_SZ_OR_ZERO)),
	&UVERBS_ATTR_PTR_IN(UVERBS_ATTR_FLOW_ACTION_ESP_ESN, UVERBS_ATTR_TYPE(__u32)),
	&UVERBS_ATTR_ENUM_IN(UVERBS_ATTR_FLOW_ACTION_ESP_KEYMAT,
			     uverbs_flow_action_esp_keymat,
			     UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	&UVERBS_ATTR_ENUM_IN(UVERBS_ATTR_FLOW_ACTION_ESP_REPLAY,
			     uverbs_flow_action_esp_replay),
	&UVERBS_ATTR_PTR_IN(UVERBS_ATTR_FLOW_ACTION_ESP_ENCAP,
			    UVERBS_ATTR_STRUCT(struct ib_uverbs_flow_action_esp_encap, type)));

static DECLARE_UVERBS_METHOD(UVERBS_METHOD(UVERBS_METHOD_FLOW_ACTION_DESTROY),
	UVERBS_METHOD_FLOW_ACTION_DESTROY, uverbs_destroy_def_handler,
	&UVERBS_ATTR_IDR(UVERBS_ATTR_DESTROY_FLOW_ACTION_HANDLE,
			 UVERBS_OBJECT_FLOW_ACTION,
			 UVERBS_ACCESS_DESTROY,
			 UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

DECLARE_COMMON_OBJECT(UVERBS_OBJECT_COMP_CHANNEL,
		      &UVERBS_TYPE_ALLOC_FD(0,
					      sizeof(struct ib_uverbs_completion_event_file),
					      uverbs_hot_unplug_completion_event_file,
					      &uverbs_event_fops,
					      "[infinibandevent]", O_RDONLY));

DECLARE_COMMON_OBJECT(UVERBS_OBJECT_CQ,
		      &UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_ucq_object), 0,
						  uverbs_free_cq),
		      &UVERBS_METHOD(UVERBS_METHOD_CQ_CREATE),
		      &UVERBS_METHOD(UVERBS_METHOD_CQ_DESTROY)
		      );

DECLARE_COMMON_OBJECT(UVERBS_OBJECT_QP,
		      &UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_uqp_object), 0,
						  uverbs_free_qp));

DECLARE_COMMON_OBJECT(UVERBS_OBJECT_MW,
		      &UVERBS_TYPE_ALLOC_IDR(0, uverbs_free_mw));

DECLARE_COMMON_OBJECT(UVERBS_OBJECT_MR,
		      /* 1 is used in order to free the MR after all the MWs */
		      &UVERBS_TYPE_ALLOC_IDR(1, uverbs_free_mr));

DECLARE_COMMON_OBJECT(UVERBS_OBJECT_SRQ,
		      &UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_usrq_object), 0,
						  uverbs_free_srq));

DECLARE_COMMON_OBJECT(UVERBS_OBJECT_AH,
		      &UVERBS_TYPE_ALLOC_IDR(0, uverbs_free_ah));

DECLARE_COMMON_OBJECT(UVERBS_OBJECT_FLOW,
		      &UVERBS_TYPE_ALLOC_IDR(0, uverbs_free_flow));

DECLARE_COMMON_OBJECT(UVERBS_OBJECT_FLOW_ACTION,
		      &UVERBS_TYPE_ALLOC_IDR(0, uverbs_free_flow_action),
		      &UVERBS_METHOD(UVERBS_METHOD_FLOW_ACTION_ESP_CREATE),
		      &UVERBS_METHOD(UVERBS_METHOD_FLOW_ACTION_DESTROY));

DECLARE_COMMON_OBJECT(UVERBS_OBJECT_WQ,
		      &UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_uwq_object), 0,
						  uverbs_free_wq));

DECLARE_COMMON_OBJECT(UVERBS_OBJECT_RWQ_IND_TBL,
		      &UVERBS_TYPE_ALLOC_IDR(0, uverbs_free_rwq_ind_tbl));

DECLARE_COMMON_OBJECT(UVERBS_OBJECT_XRCD,
		      &UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_uxrcd_object), 0,
						  uverbs_free_xrcd));

DECLARE_COMMON_OBJECT(UVERBS_OBJECT_PD,
		      /* 2 is used in order to free the PD after MRs */
		      &UVERBS_TYPE_ALLOC_IDR(2, uverbs_free_pd));

DECLARE_COMMON_OBJECT(UVERBS_OBJECT_DEVICE, NULL);

DECLARE_UVERBS_OBJECT_TREE(uverbs_default_objects,
			   &UVERBS_OBJECT(UVERBS_OBJECT_DEVICE),
			   &UVERBS_OBJECT(UVERBS_OBJECT_PD),
			   &UVERBS_OBJECT(UVERBS_OBJECT_MR),
			   &UVERBS_OBJECT(UVERBS_OBJECT_COMP_CHANNEL),
			   &UVERBS_OBJECT(UVERBS_OBJECT_CQ),
			   &UVERBS_OBJECT(UVERBS_OBJECT_QP),
			   &UVERBS_OBJECT(UVERBS_OBJECT_AH),
			   &UVERBS_OBJECT(UVERBS_OBJECT_MW),
			   &UVERBS_OBJECT(UVERBS_OBJECT_SRQ),
			   &UVERBS_OBJECT(UVERBS_OBJECT_FLOW),
			   &UVERBS_OBJECT(UVERBS_OBJECT_WQ),
			   &UVERBS_OBJECT(UVERBS_OBJECT_RWQ_IND_TBL),
			   &UVERBS_OBJECT(UVERBS_OBJECT_XRCD),
			   &UVERBS_OBJECT(UVERBS_OBJECT_FLOW_ACTION));
