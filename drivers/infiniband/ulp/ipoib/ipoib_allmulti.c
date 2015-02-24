/*
 * Copyright (c) 2014 Mellanox, LTD. All rights reserved.
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

#include <linux/moduleparam.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include "ipoib.h"

#ifdef CONFIG_INFINIBAND_IPOIB_DEBUG
int allmulti_debug_level;

module_param(allmulti_debug_level, int, 0644);
MODULE_PARM_DESC(allmulti_debug_level,
		 "Enable multicast promisc debug tracing if > 0");
#endif

#define MCP_REG_MAX_DELAY (IPOIB_MAX_BACKOFF_SECONDS*1000) /* in msecs */
#define INFORM_CRE_DONE(mcp_flags) test_bit(MC_CREATE_REG, mcp_flags)
#define INFORM_DEL_DONE(mcp_flags) test_bit(MC_DELETE_REG, mcp_flags)
#define MCVALIDATE_DONE(mcp_flags) test_bit(MC_VALIDATE, mcp_flags)

#define REGISTRATION_DONE(mcp_flags)          \
		(INFORM_CRE_DONE(mcp_flags) && \
		 INFORM_DEL_DONE(mcp_flags) && \
		 MCVALIDATE_DONE(mcp_flags))

union mcp_action_data {
	u8 gid[16];
	struct ipoib_mc_rule rule;
};

struct promisc_mc_work {
	struct delayed_work work;
	struct ipoib_dev_priv *priv;
	enum mc_action action;
	union mcp_action_data data;
};

/* This struct is used for rules validation, so that during callback execution
 * the queue will not handle any other requests that might involve rules.
 * The usual get_table operation is not executed this way because it has no
 * effect on the rules or on MCG creation/deletion processing.
 */
struct promisc_mc_query_context {
	struct ipoib_dev_priv *priv;
	struct ib_sa_query *query;
	int query_id;
	int status;
	struct completion done;
};

/*
 * Returns the pkey part of the given MGID.
 */
static u16 mgid_get_pkey(u8 mgid[16])
{
	u16 ret;
	ret = (mgid[4] << 8) + mgid[5];
	return ret;
}

/*
* Checks whether or not the provided mgid is an IPoIB mgid.
* Returns 1 if it's either IPoIB ipv4 mgid or IPoIB ipv6 mgid, else 0.
*/
static int is_ipoib_mgid(u8 *mgid, u8 *broadcast)
{
	u8 *bcast_gid =  broadcast + 4;
	u8 ipoib_ipv4_prefix[4] = {bcast_gid[0], bcast_gid[1], 0x40, 0x1b};
	u8 ipoib_ipv6_prefix[4] = {bcast_gid[0], bcast_gid[1], 0x60, 0x1b};

	if (!memcmp(mgid, ipoib_ipv4_prefix, 4))
		return 1;

	if (!memcmp(mgid, ipoib_ipv6_prefix, 4))
		return 1;

	return 0;
}

/*
 * Compares two masked u8 arrays.
 * Returns an integer less than, equals to or greater than 0 if the first masked
 * array is less than, equals or is greater than the second.
 */
static int guid_mask_cmp(u8 first[16], u8 second[16], u8 mask[16])
{
	int i;

	for (i = 0; i < 16; i++) {
		if ((first[i] & mask[i]) != (second[i] & mask[i]))
			return (first[i] & mask[i]) - (second[i] & mask[i]);
	}
	return 0;
}

static int ipoib_mc_add_rule(struct rb_root *root,
			     struct ipoib_mc_rule *rule)
{
	struct rb_node **n , *pn = NULL;
	n = &root->rb_node;

	while (*n) {
		struct ipoib_mc_rule *trule;
		int ret;

		pn = *n;
		trule = rb_entry(pn, struct ipoib_mc_rule, rb_node);

		ret = guid_mask_cmp(rule->mgid, trule->mgid, trule->mask);
		if (ret < 0)
			n = &pn->rb_left;
		else if (ret > 0)
			n = &pn->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&rule->rb_node, pn, n);
	rb_insert_color(&rule->rb_node, root);
	return 0;
}

static struct ipoib_mc_rule *ipoib_rule_find(u8 gid[16],
					     struct rb_root *root)
{
	struct rb_node *n;

	n = root->rb_node;

	while (n) {
		struct ipoib_mc_rule *rule;
		int ret;

		rule = rb_entry(n, struct ipoib_mc_rule, rb_node);

		ret = guid_mask_cmp(gid, rule->mgid, rule->mask);
		if (ret < 0)
			n = n->rb_left;
		else if (ret > 0)
			n = n->rb_right;
		else
			return rule;
	}

	return NULL;
}

static void update_rules_tree(struct promisc_mc *promisc)
{
	struct rb_node **n, *m;
	struct ipoib_mc_rule *rule;

	/* Cleanup previous rules */
	m = rb_first(&promisc->rules_tree);
	while (m) {
		rule = rb_entry(m, struct ipoib_mc_rule, rb_node);
		m = rb_next(m);
		rb_erase(&rule->rb_node, &promisc->rules_tree);
		kfree(rule);
	}

	/* Move rules from new_rules_tree to rules_tree */
	n = &promisc->new_rules_tree.rb_node;

	while (*n) {
		rule = rb_entry(*n, struct ipoib_mc_rule, rb_node);
		*n = rb_next(*n);
		rb_erase(&rule->rb_node, &promisc->new_rules_tree);
		ipoib_mc_add_rule(&promisc->rules_tree, rule);
	}

	return;
}

/*
 * Returns 1 if the provided gid is a part of IPoIB's multicast tree.
 * This will help to avoid a double attach, since a double detach is not
 * possible and causes lockup.
 */
static int is_mcast_in_multicast_tree(struct ipoib_dev_priv *priv, u8 gid[16])
{
	struct ipoib_mcast *mcast;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	mcast = __ipoib_mcast_find(priv->dev, gid, &priv->multicast_tree);
	if (mcast) {
		ipoib_dbg_mcp(priv,
			      "%s %pI6 MCG already joined by ipoib multicast\n",
			      __func__, gid);
		spin_unlock_irqrestore(&priv->lock, flags);
		return 1;
	}
	spin_unlock_irqrestore(&priv->lock, flags);
	return 0;
}

struct mcp_mcast {
	struct list_head list;
	struct ib_sa_mcmember_rec rec;
};

static void ipoib_static_mcasts2list(struct ipoib_dev_priv *priv,
				     struct list_head *list)
{
	struct rb_node *n;
	unsigned long flags;
	struct ipoib_mcast *mcast;

	spin_lock_irqsave(&priv->lock, flags);
	n = rb_first(&priv->multicast_tree);
	while (n) {
		mcast = rb_entry(n, struct ipoib_mcast, rb_node);
		n = rb_next(n);

		if (mcast->flags && IPOIB_MCAST_FLAG_ATTACHED) {
			struct mcp_mcast *mcp_mcast;

			mcp_mcast = kzalloc(sizeof(*mcp_mcast), GFP_ATOMIC);
			if (!mcp_mcast)
				goto out;

			mcp_mcast->rec = mcast->mcmember;
			list_add_tail(&mcp_mcast->list, list);
		}
	}
out:
	spin_unlock_irqrestore(&priv->lock, flags);
}

static void ipoib_allmulti_mcasts2list(struct ipoib_dev_priv *priv,
				       struct list_head *list)
{
	struct rb_node *n;
	struct ipoib_mcast *mcast;

	mutex_lock(&priv->promisc.tree_lock);
	n = rb_first(&priv->promisc.multicast_tree);
	while (n) {
		mcast = rb_entry(n, struct ipoib_mcast, rb_node);
		n = rb_next(n);

		if (mcast->flags && IPOIB_MCAST_FLAG_JOINED) {
			struct mcp_mcast *mcp_mcast;

			mcp_mcast = kzalloc(sizeof(*mcp_mcast), GFP_KERNEL);
			if (!mcp_mcast)
				goto out;

			mcp_mcast->rec = mcast->mcmember;
			list_add_tail(&mcp_mcast->list, list);
		}
	}
out:
	mutex_unlock(&priv->promisc.tree_lock);
}

static void ipoib_notify_mcasts(struct ipoib_dev_priv *priv,
				enum notification_type notift)
{
	struct mcp_mcast *mcast, *tmcast;
	u8 join_state = NON_MEMBER;
	struct ipoib_mc_rule *rule;
	LIST_HEAD(mcast_list);

	if (notift != NOTIFY_DETAILS && notift != NOTIFY_JOIN) {
		ipoib_warn(priv, "%s Wrong notifcation type(%d), aborting ..",
			   __func__, notift);
		return;
	}

	ipoib_static_mcasts2list(priv, &mcast_list);
	/* When asking for details, add the dynamic multicasts also */
	if (notift == NOTIFY_DETAILS)
		ipoib_allmulti_mcasts2list(priv, &mcast_list);

	list_for_each_entry_safe(mcast, tmcast, &mcast_list, list) {
		mutex_lock(&priv->promisc.tree_lock);
		rule = ipoib_rule_find(mcast->rec.mgid.raw,
				       &priv->promisc.rules_tree);
		join_state = rule ? rule->join_state : NON_MEMBER;
		mutex_unlock(&priv->promisc.tree_lock);

		ipoib_dbg_mcp(priv,
			      "%s: %s an applicable rule: %pI6 Rule join state:%s, mcast join State: %s\n",
			      __func__, rule ? "found" : "didn't find",
			      mcast->rec.mgid.raw, status_to_str(join_state),
			      status_to_str(mcast->rec.join_state));

		if (join_state != DONT_JOIN)
			ipoib_mc_raise_notification(priv, &mcast->rec,
						    notift);

		/* Don't notify leaves when asking for DETAILS */
		if (join_state == DONT_JOIN && notift != NOTIFY_DETAILS)
			ipoib_mc_raise_notification(priv, &mcast->rec,
						    NOTIFY_LEAVE);

		list_del(&mcast->list);
		kfree(mcast);
	}
}

/*
 * This function receives join and leave notifications from ipoib_multicast.
 * If there's a DONT_JOIN rule regarding this MGid, the notification will NOT
 * be sent to the user.
 */
void ipoib_mc_raise_notification(struct ipoib_dev_priv *priv,
				 struct ib_sa_mcmember_rec *rec,
				 enum notification_type type)
{
	struct ipoib_mc_rule *rule;
	struct ipoib_mcast *mcast;
	u8 join_state;
	bool mcast_found = true;

	if ((type == NOTIFY_JOIN || type == NOTIFY_DETAILS) && !rec->mlid) {
		ipoib_dbg_mcp(priv,
			      "%s %s notification %pI6 mlid=0 Dropping ...\n",
			      __func__,
			      type == NOTIFY_JOIN ? "Join" : "Details",
			      rec->mgid.raw);
		return;
	}

	mutex_lock(&priv->promisc.tree_lock);
	rule = ipoib_rule_find(rec->mgid.raw, &priv->promisc.rules_tree);
	join_state = rule ? rule->join_state : NON_MEMBER;
	mutex_unlock(&priv->promisc.tree_lock);

	/* Don't notify join/details in case of don't Join Rule */
	if ((type == NOTIFY_JOIN || type == NOTIFY_DETAILS) &&
	    join_state == DONT_JOIN)
		return;

	switch (type) {
	case NOTIFY_JOIN:
		ipoib_mc_join_notify(priv, rec);
		return;
	case NOTIFY_LEAVE:
		mutex_lock(&priv->promisc.tree_lock);
		mcast = __ipoib_mcast_find(priv->dev, rec->mgid.raw,
					   &priv->promisc.multicast_tree);
		mcast_found = (mcast != NULL) ||
			is_mcast_in_multicast_tree(priv, rec->mgid.raw);
		mutex_unlock(&priv->promisc.tree_lock);

		/* notify only in case of mcast was truly left (!found)
		 * Or there is a Don't Join Rule
		 */
		if (!mcast_found || join_state == DONT_JOIN)
			ipoib_mc_leave_notify(priv, rec);
		return;
	case NOTIFY_DETAILS:
		ipoib_mcg_details_notify(priv, rec);
		return;
	default:
		ipoib_warn(priv, "Illegal notification type (%d)\n",
			   type);
	}
}

static int ipoib_queue_mcp_work(struct promisc_mc *promisc_mc,
				union mcp_action_data *data,
				enum mc_action action, int delay)
{
	struct promisc_mc_work *work;
	struct ipoib_dev_priv *priv =
		container_of(promisc_mc, struct ipoib_dev_priv, promisc);

	if (!priv->promisc.workqueue)
		return -ENOMEM;

	work = kzalloc(sizeof(*work), GFP_KERNEL);
	if (!work) {
		ipoib_err(priv, "%s: couldn't allocate work struct\n",
			  __func__);
		return -ENOMEM;
	}
	work->priv = priv;
	work->action = action;
	if (data)
		work->data = *data;

	INIT_DELAYED_WORK(&work->work, ipoib_mcp_work_handler);
	queue_delayed_work(priv->promisc.workqueue, &work->work,
			   msecs_to_jiffies(delay));
	return 0;
}

int ipoib_queue_mcg_create_work(struct promisc_mc *promisc, u8 gid[16],
				int delay)
{
	return ipoib_queue_mcp_work(promisc, (union mcp_action_data *)gid,
				    MC_CREATE_ACTION, delay);
}

int ipoib_queue_mcg_delete_work(struct promisc_mc *promisc, u8 gid[16],
				int delay)
{
	return ipoib_queue_mcp_work(promisc, (union mcp_action_data *)gid,
				    MC_DELETE_ACTION, delay);
}

int ipoib_queue_add_rule(struct promisc_mc *promisc, struct ipoib_mc_rule rule)
{
	return ipoib_queue_mcp_work(promisc, (union mcp_action_data *)&rule,
				    MC_ADD_RULE_ACTION, 0);
}

static void mcp_mcast_free(struct ipoib_mcast *mcast)
{
	struct ipoib_dev_priv *priv = netdev_priv(mcast->dev);

	ipoib_dbg_mcp(priv, "deleting multicast group %pI6\n",
		      mcast->mcmember.mgid.raw);
	kfree(mcast);
}

struct ipoib_mcast *mcp_mcast_alloc(struct net_device *dev,
					     int can_sleep)
{
	struct ipoib_mcast *mcast;

	mcast = kzalloc(sizeof *mcast, can_sleep ? GFP_KERNEL : GFP_ATOMIC);
	if (!mcast)
		return NULL;

	mcast->dev = dev;
	mcast->created = jiffies;
	mcast->backoff = 100;

	INIT_LIST_HEAD(&mcast->list);
	INIT_LIST_HEAD(&mcast->neigh_list);
	skb_queue_head_init(&mcast->pkt_queue);

	return mcast;
}

static int mcp_mcast_join_complete(int status,
				   struct ib_sa_multicast *multicast)
{
	struct ipoib_mcast *mcast = multicast->context;
	struct net_device *dev = mcast->dev;
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	ipoib_dbg_mcp(priv, "join completion for %pI6 (status %d)\n",
			mcast->mcmember.mgid.raw, status);

	/* We trap for port events ourselves. */
	if (status == -ENETRESET){
		status = 0;
		goto out;
	}

	if (!status) {
		int ret;

		mcast->mcmember = multicast->rec;
		set_bit(IPOIB_MCAST_FLAG_JOINED, &mcast->flags);
		ipoib_mc_raise_notification(priv, &mcast->mcmember,
					    NOTIFY_JOIN);
		if (test_and_set_bit(IPOIB_MCAST_FLAG_ATTACHED, &mcast->flags)) {
			ipoib_warn(priv, "multicast group %pI6 already attached\n",
				   mcast->mcmember.mgid.raw);
			goto out;
		}
		/* attach QP to multicast group */
		ret = ib_attach_mcast(priv->qp, &mcast->mcmember.mgid,
				      be16_to_cpu(mcast->mcmember.mlid));
		if (ret < 0) {
			ipoib_warn(priv, "couldn't attach QP to multicast group %pI6\n",
				   mcast->mcmember.mgid.raw);
			clear_bit(IPOIB_MCAST_FLAG_ATTACHED, &mcast->flags);
		}
		goto out;
	}

	if (mcast->logcount++ < 20) {
		if (status == -ETIMEDOUT || status == -EAGAIN) {
			ipoib_dbg_mcp(priv, "multicast join failed for %pI6, status %d\n",
				      mcast->mcmember.mgid.raw, status);
		} else {
			ipoib_warn(priv, "multicast join failed for %pI6, status %d\n",
				   mcast->mcmember.mgid.raw, status);
		}
	}

	mcast->backoff *= 2;
	if (mcast->backoff > MCP_REG_MAX_DELAY)
		mcast->backoff = MCP_REG_MAX_DELAY;
out:
	/* Clear the busy flag so we try again */
	clear_bit(IPOIB_MCAST_FLAG_BUSY, &mcast->flags);
	if (status) {
		if (status == -ETIMEDOUT || status == -EAGAIN) { /* Retry */
			ipoib_warn(priv,
				   "multicast join failed for %pI6, status %d, retry in %ld msecs\n",
				   mcast->mcmember.mgid.raw, status,
				   mcast->backoff);
			ipoib_queue_mcg_create_work(&priv->promisc,
						    mcast->mcmember.mgid.raw,
						    mcast->backoff);
		} else {
			ipoib_warn(priv,
				   "multicast join failed for %pI6, status %d, deleting..\n",
				   mcast->mcmember.mgid.raw, status);
			ipoib_queue_mcg_delete_work(&priv->promisc,
						    mcast->mcmember.mgid.raw,
						    0);
		}
	}

	complete(&mcast->done);
	return 0; /* We handle free our selves */
}

static void mcp_mcast_join(struct ipoib_dev_priv *priv,
			   struct ipoib_mcast *mcast,
			   int create, int join_state)
{
	struct ib_sa_mcmember_rec rec = {
		.join_state = join_state
	};
	ib_sa_comp_mask comp_mask;
	int ret = 0;
	ipoib_dbg_mcp(priv, "joining MGID %pI6\n", mcast->mcmember.mgid.raw);

	rec.mgid     = mcast->mcmember.mgid;
	rec.port_gid = priv->local_gid;
	rec.pkey     = cpu_to_be16(priv->pkey);

	comp_mask =
		IB_SA_MCMEMBER_REC_MGID		|
		IB_SA_MCMEMBER_REC_PORT_GID	|
		IB_SA_MCMEMBER_REC_PKEY		|
		IB_SA_MCMEMBER_REC_JOIN_STATE;

	if (create) {
		comp_mask |=
			IB_SA_MCMEMBER_REC_QKEY			|
			IB_SA_MCMEMBER_REC_MTU_SELECTOR		|
			IB_SA_MCMEMBER_REC_MTU			|
			IB_SA_MCMEMBER_REC_TRAFFIC_CLASS	|
			IB_SA_MCMEMBER_REC_RATE_SELECTOR	|
			IB_SA_MCMEMBER_REC_RATE			|
			IB_SA_MCMEMBER_REC_SL			|
			IB_SA_MCMEMBER_REC_FLOW_LABEL		|
			IB_SA_MCMEMBER_REC_HOP_LIMIT;

		rec.qkey	  = priv->broadcast->mcmember.qkey;
		rec.mtu_selector  = IB_SA_EQ;
		rec.mtu		  = priv->broadcast->mcmember.mtu;
		rec.traffic_class = priv->broadcast->mcmember.traffic_class;
		rec.rate_selector = IB_SA_EQ;
		rec.rate	  = priv->broadcast->mcmember.rate;
		rec.sl		  = priv->broadcast->mcmember.sl;
		rec.flow_label	  = priv->broadcast->mcmember.flow_label;
		rec.hop_limit	  = priv->broadcast->mcmember.hop_limit;
	}

	if (!IS_ERR(mcast->mc) &&
	    test_bit(IPOIB_MCAST_JOIN_STARTED, &mcast->flags)) {
		ib_sa_free_multicast(mcast->mc);
		clear_bit(IPOIB_MCAST_JOIN_STARTED, &mcast->flags);
	}

	set_bit(IPOIB_MCAST_FLAG_BUSY, &mcast->flags);
	init_completion(&mcast->done);
	set_bit(IPOIB_MCAST_JOIN_STARTED, &mcast->flags);

	mcast->mc = ib_sa_join_multicast(&ipoib_sa_client, priv->ca, priv->port,
					 &rec, comp_mask, GFP_KERNEL,
					 mcp_mcast_join_complete, mcast);
	if (IS_ERR(mcast->mc)) {
		clear_bit(IPOIB_MCAST_FLAG_BUSY, &mcast->flags);
		complete(&mcast->done);
		ret = PTR_ERR(mcast->mc);
		ipoib_warn(priv, "ib_sa_join_multicast failed, status %d\n", ret);

		mcast->backoff *= 2;
		if (mcast->backoff > MCP_REG_MAX_DELAY)
			mcast->backoff = MCP_REG_MAX_DELAY;
		ipoib_queue_mcg_create_work(&priv->promisc,
					    mcast->mcmember.mgid.raw,
					    mcast->backoff);
	}
}

static int mcp_mcast_leave(struct ipoib_dev_priv *priv,
			   struct ipoib_mcast *mcast)
{

	int ret = 0;

	if (test_and_clear_bit(IPOIB_MCAST_JOIN_STARTED, &mcast->flags))
		ib_sa_free_multicast(mcast->mc);

	if (test_and_clear_bit(IPOIB_MCAST_FLAG_JOINED, &mcast->flags))
		ipoib_mc_raise_notification(priv, &mcast->mcmember,
					    NOTIFY_LEAVE);

	if (test_and_clear_bit(IPOIB_MCAST_FLAG_ATTACHED, &mcast->flags)) {
		ipoib_dbg_mcp(priv, "leaving MGID %pI6\n",
				mcast->mcmember.mgid.raw);

		/* Remove ourselves from the multicast group */
		ret = ib_detach_mcast(priv->qp, &mcast->mcmember.mgid,
				      be16_to_cpu(mcast->mcmember.mlid));
		if (ret)
			pr_warn("ib_detach_mcast failed (result = %d)\
				\n", ret);
	}
	return 0;
}

struct ipoib_mcast *mcp_add_mgid(struct ipoib_dev_priv *priv, u8 gid[16])
{
	struct ipoib_mcast *mcast;
	int ret;

	/* alloc new mcast and join it as non member */
	mcast = mcp_mcast_alloc(priv->dev, 1);
	if (!mcast) {
		ipoib_err(priv, "%s: couldn't allocate mcast group\n",
		  __func__);
		return NULL;
	}
	memcpy(mcast->mcmember.mgid.raw, gid, sizeof(union ib_gid));

	mutex_lock(&priv->promisc.tree_lock);
	ret = __ipoib_mcast_add(priv->dev, mcast,
				&priv->promisc.multicast_tree);
	if (ret) {
		ipoib_warn(priv, "%s %pI6 MCG Failed to add (%d), Already exists\n",
			   __func__, mcast->mcmember.mgid.raw, ret);
		mutex_unlock(&priv->promisc.tree_lock);
		mcp_mcast_free(mcast);
		return NULL;
	}
	mutex_unlock(&priv->promisc.tree_lock);
	return mcast;
}

static int mcp_remove_mgid(struct ipoib_dev_priv *priv, u8 gid[16])
{
	struct ipoib_mcast *mcast;

	mutex_lock(&priv->promisc.tree_lock);
	mcast = __ipoib_mcast_find(priv->dev, gid,
				   &priv->promisc.multicast_tree);
	if (!mcast) {
		mutex_unlock(&priv->promisc.tree_lock);
		ipoib_dbg_mcp(priv,
			      "%s: mcast %pI6 was either not joined by ipoib mc promisc or already removed\n",
			      __func__, gid);
		return -ENOENT;
	}
	rb_erase(&mcast->rb_node,
		 &priv->promisc.multicast_tree);
	mutex_unlock(&priv->promisc.tree_lock);

	if (test_bit(IPOIB_MCAST_JOIN_STARTED, &mcast->flags))
		wait_for_completion(&mcast->done);
	mcp_mcast_leave(priv, mcast);
	mcp_mcast_free(mcast);
	ipoib_dbg_mcp(priv, "%s %pI6 MCG Removed\n", __func__, gid);
	return 0;
}

/*
 * mc promisc handlers should only run form priv->promisc.work_queue context:
 * void ipoib_mcp_work_handler(struct work_struct *work)
 */
static void ipoib_handle_mcg_create(struct ipoib_dev_priv *priv,
				    u8 gid[16])
{
	struct ipoib_mcast *mcast;
	u8 join_state = NON_MEMBER;
	struct ipoib_mc_rule *rule;

	mutex_lock(&priv->promisc.state_lock);
	if (test_bit(MCP_STOPPED, &priv->promisc.flags)) {
		ipoib_dbg_mcp(priv,
			      "%s: allmulti is being stopped, aborting ..\n",
			      __func__);
		mutex_unlock(&priv->promisc.state_lock);
		return;
	}
	mutex_unlock(&priv->promisc.state_lock);

	if (is_mcast_in_multicast_tree(priv, gid))
		return;

	mutex_lock(&priv->promisc.tree_lock);

	/* Find a rule/mcast that matches this gid */
	rule = ipoib_rule_find(gid, &priv->promisc.rules_tree);
	join_state = rule ? rule->join_state : NON_MEMBER;
	mcast = __ipoib_mcast_find(priv->dev, gid,
				   &priv->promisc.multicast_tree);

	mutex_unlock(&priv->promisc.tree_lock);

	if (!mcast && join_state == DONT_JOIN) {
		ipoib_dbg_mcp(priv,
			      "%s %pI6 GID with Don't Join Rule, Skipping ..\n",
			      __func__, gid);
		return;
	}

	if (mcast && join_state == DONT_JOIN) {
		ipoib_warn(priv, "%s %pI6 MCG Was Found with Don't Join Rule, deleting..\n",
			   __func__, mcast->mcmember.mgid.raw);
		mcp_remove_mgid(priv, gid);
		return;
	}

	if (!mcast) {
		mcast = mcp_add_mgid(priv, gid);
		if (!mcast)
			return;
	}

	if (test_bit(IPOIB_MCAST_FLAG_JOINED, &mcast->flags) ||
	    test_bit(IPOIB_MCAST_FLAG_BUSY, &mcast->flags)) {
		ipoib_warn(priv,
			   "%s %pI6 MCG is Already Joined/Joining ! Skipping\n",
			   __func__, mcast->mcmember.mgid.raw);
		return;
	}

	/* Store the join state initialy in mcast->mcmember.join_state */
	mcast->mcmember.join_state = join_state;
	mcp_mcast_join(priv, mcast, 0, join_state);
	ipoib_dbg_mcp(priv, "%s %pI6 MCG was added, sent join as %s\n",
		      __func__, gid, status_to_str(join_state));
}

static void ipoib_handle_mcg_delete(struct ipoib_dev_priv *priv,
				    u8 gid[16])
{
	mutex_lock(&priv->promisc.state_lock);
	if (test_bit(MCP_STOPPED, &priv->promisc.flags)) {
		ipoib_dbg_mcp(priv,
			      "%s: allmulti is being stopped, aborting ..\n",
			      __func__);
		mutex_unlock(&priv->promisc.state_lock);
		return;
	}
	mutex_unlock(&priv->promisc.state_lock);

	mcp_remove_mgid(priv, gid);
}

static void ipoib_handle_add_rule(struct ipoib_dev_priv *priv,
				  struct ipoib_mc_rule rule)
{
	struct ipoib_mc_rule *new_rule;
	int ret;
	new_rule = kzalloc(sizeof(*new_rule), GFP_KERNEL);

	if (!new_rule) {
		ipoib_err(priv, "%s: couldn't allocate rule struct\n",
			  __func__);
		return;
	}
	*new_rule = rule;
	ipoib_dbg_mcp(priv,
		      "%s: Adding new rule MGID: %pI6 MASK: %pI6 prio:%d join_state:%d\n",
		      __func__, rule.mgid, rule.mask,
		      rule.priority, rule.join_state);
	mutex_lock(&priv->promisc.tree_lock);
	ret = ipoib_mc_add_rule(&priv->promisc.new_rules_tree, new_rule);
	mutex_unlock(&priv->promisc.tree_lock);
	if (ret) {
		pr_err("%s: couldn't add rule (%d)\n", __func__, ret);
		kfree(new_rule);
	}
}

static void ipoib_mgid_update(struct ipoib_dev_priv *priv, u8 mgid[16])
{
	struct ipoib_mcast *mcast = NULL;
	bool add = false, del = false;
	struct ipoib_mc_rule *rule;
	u8 join_state;

	/* If the group is joined by IPoIB, return */
	if (is_mcast_in_multicast_tree(priv, mgid))
		return;

	mutex_lock(&priv->promisc.tree_lock);
	/* find rule and group if exist */
	rule = ipoib_rule_find(mgid, &priv->promisc.rules_tree);
	join_state = rule ? rule->join_state : NON_MEMBER;
	mcast = __ipoib_mcast_find(priv->dev, mgid,
				   &priv->promisc.multicast_tree);
	ipoib_dbg_mcp(priv,
		      "%s: %s an applicable rule: %pI6 join state:%s Rule join State: %s\n",
		      __func__, rule ? "found" : "didn't find",
		      mgid, status_to_str(join_state),
		      status_to_str(mcast ? mcast->mcmember.join_state : -1));

	if (!mcast) { /* Mcast was not found handle as a new MCG ! */
		ipoib_dbg_mcp(priv,
			      "%s: MCG was not found %pI6 handling as a new one\n",
			      __func__, mgid);
		if (join_state != DONT_JOIN)
			add = true;
		goto unlock;
	}

	/* mcast found */
	if (join_state == DONT_JOIN) {
		/* New Rule: Don't Join => remove leave destroy */
		del = true;
		goto unlock;
	}

	if (mcast->mcmember.join_state != join_state) {
		/* (Prev Join State != current Join state) => leave/join */
		del = true;
		add = true;
	}
unlock:
	mutex_unlock(&priv->promisc.tree_lock);
	if (del)
		ipoib_queue_mcg_delete_work(&priv->promisc, mgid, 0);
	if (add)
		ipoib_queue_mcg_create_work(&priv->promisc, mgid, 0);
}

void ipoib_validate_gettable_cb(int status, struct ib_sa_mcmember_rec *resp,
				void *context)
{
	struct promisc_mc_query_context *query_context = context;
	struct ipoib_dev_priv *priv = query_context->priv;

	/* error code from core layer, should be followed by NULL resp. */
	query_context->status = status;
	if (status < 0) {
		ipoib_printk(KERN_ERR, priv, "%s: received error status %d\n",
			     __func__, status);
		if (resp)
			ipoib_warn(priv, "%s: resp should be NULL when receiving error status\n",
				   __func__);
		goto out;
	}

	/* This shouldn't be possible with status >= 0 */
	if (!resp) {
		ipoib_warn(priv, "%s: status is %d but resp is NULL\n",
			   __func__, status);
		goto out;
	}

	/* If this is not an IPoIB MCG, return */
	if (!is_ipoib_mgid(resp->mgid.raw, priv->dev->broadcast)) {
		ipoib_dbg_mcp_lvl(2, priv,
				  "%s: %pI6 is not an IPoIB mgid, skipping\n",
				  __func__, resp->mgid.raw);
		goto out;
	}

	ipoib_mgid_update(priv, resp->mgid.raw);
out:
	/* eventually we will get status != 0 */
	if (status != 0)
		complete(&query_context->done);
	return;
}

/*
 * This function uses an internal query, so that the workqueue is blocked until
 * rules validation is complete. This way new rules received during validation
 * will not be dropped, and MCG create/delete notifications received will be
 * processed according to the new rules.
 */
static int ipoib_handle_validate_rules(struct ipoib_dev_priv *priv,
				       int update_rules)
{
	struct ib_sa_mcmember_rec rec = {};
	struct promisc_mc_query_context context;

	if (update_rules) {
		/* change trees */
		ipoib_dbg_mcp(priv,
			      "%s: Replacing Old rules with new ones\n",
			      __func__);
		mutex_lock(&priv->promisc.tree_lock);
		update_rules_tree(&priv->promisc);
		mutex_unlock(&priv->promisc.tree_lock);
	}

	if (!test_bit(IPOIB_ALL_MULTI, &priv->flags))
		return 0; /* All multi is OFF, No need to query table */

	init_completion(&context.done);
	/* query SM and handle the results with the new tree */
	rec.pkey = cpu_to_be16(priv->pkey);
	context.status = -EINVAL;
	context.priv = priv;
	context.query_id =
		ib_sa_mcmember_gettable(&ipoib_sa_client, priv->ca, priv->port,
					&rec, GFP_KERNEL,
					ipoib_validate_gettable_cb, &context,
					&context.query);

	if (context.query_id < 0) {
		ipoib_warn(priv, "%s: ib_sa_mcmember_gettable returned %d\n",
			   __func__, context.query_id);
		context.status = context.query_id;
	} else {
		/* in case of success ipoib_validate_gettable_cb
		 * will handle the rest
		 */
		ipoib_dbg_mcp(priv,
			      "%s: Applying new rules to known MC groups\n",
			      __func__);
		wait_for_completion(&context.done);
		/* Notify user of static mcast entries when rules changed */
		ipoib_notify_mcasts(priv, NOTIFY_JOIN);
		ipoib_dbg_mcp(priv,
			      "%s: Rules validation is done status (%d)\n",
			      __func__, context.status);
	}
	return context.status;
}

static const char *regflag2str(unsigned long reg_flag)
{
	switch (reg_flag) {
	case MC_CREATE_REG:
		return "MCG Create";
	case MC_DELETE_REG:
		return "MCG Delete";
	}
	return "Unknown";
}

static void mcp_registeration_complete(int status,
				       struct ib_inform_info *info,
				       int reg_flag) {
	struct ipoib_dev_priv *priv = info->context;

	/*
	 * This is not manadatory (best effort :))
	 * NOTE: DO NOT take &promisc->state_lock in here !
	 */
	if (test_bit(MCP_STOPPED, &priv->promisc.flags)) {
		ipoib_dbg_mcp(priv,
			      "%s: %s allmulti is being stopped, aborting registration..\n",
			      __func__, regflag2str(reg_flag));
		return;
	}

	ipoib_dbg_mcp(priv, "%s: %s Handling registration..\n",
		      __func__, regflag2str(reg_flag));
	/*
	 * in case if MCP_STOPPED and we passed the above check
	 * it is OK, since we are scheduling a work that will quit.
	 */
	if (status >= 0) { /* ALL GOOD :-) */
		ipoib_dbg_mcp(priv, "%s: %s Registration success (%d)..\n",
			      __func__, regflag2str(reg_flag), status);
		set_bit(reg_flag, &priv->promisc.flags);
		priv->promisc.reg_delay = 100;
		if (ipoib_queue_mcp_work(&priv->promisc, NULL,
					 MC_REGISTER, 0)) {
			ipoib_err(priv, "%s: %s Registration falied to queue\n",
				  regflag2str(reg_flag), __func__);
		}
		return;
	}

	/* Something is wrong print status and handle */
	switch (status) {
	case -ENETRESET:
		ipoib_err(priv, "%s: Registration failed -ENETRESET. Aborting..\n",
			  __func__);
		return;
	case -ETIMEDOUT: /* Fall through */
	case -EAGAIN: /* Fall through */
	default: /* Retry .. */
		ipoib_err(priv, "%s: Registration failed (%d) retry in %ld msecs\n",
			  __func__, status,
			  priv->promisc.reg_delay);
		if (priv->promisc.reg_delay >= MCP_REG_MAX_DELAY) {
			ipoib_err(priv, "%s: Registration timeout exceeded, giving up\n",
				  __func__);
			return;
		}
		if (ipoib_queue_mcp_work(&priv->promisc, NULL, MC_REGISTER,
					 priv->promisc.reg_delay)) {
			ipoib_err(priv,
				  "%s: Retry Registration falied to queue\n",
				  __func__);
		}
		priv->promisc.reg_delay *= 2;
	}
}

/* Do not take promisc->state_lock in here !*/
static int ipoib_inform_info_cb(int status, struct ib_inform_info *info,
				struct ib_sa_notice *notice)
{
	struct ipoib_dev_priv *priv = info->context;
	struct ib_sa_notice_data_gid *gid_data;
	int reg_flag;
	u16 pkey;

	ipoib_dbg_mcp_lvl(2, priv, "%s: Handling Inform Info Trap: (%d)\n",
			  __func__, info->trap_number);

	/*
	 * This is not manadatory (best effort :))
	 * NOTE: DO NOT take &promisc->state_lock in here !
	 */
	if (test_bit(MCP_STOPPED, &priv->promisc.flags)) {
		ipoib_dbg_mcp(priv,
			      "%s: allmulti is being stopped, aborting..\n",
			      __func__);
		return 0;
	}

	if (info->trap_number != IB_SA_SM_TRAP_CREATE_MC_GROUP &&
	    info->trap_number != IB_SA_SM_TRAP_DELETE_MC_GROUP) {
		ipoib_warn(priv, "%s: Got unexpected trap number (%d)!\n",
			   __func__, info->trap_number);
		return 0;
	}
	reg_flag = info->trap_number == IB_SA_SM_TRAP_CREATE_MC_GROUP ?
		MC_CREATE_REG : MC_DELETE_REG;

	if (!test_bit(reg_flag, &priv->promisc.flags)) {
		if (notice)
			ipoib_warn(priv,
				   "%s: %s Got Registration completion with status (%d) but notice is not NULL!",
				   __func__, regflag2str(reg_flag), status);
		mcp_registeration_complete(status, info, reg_flag);
		if (!notice || status)
			return 0;
		/* continue handling in case notice/status
		 * have a valid data to process
		 */
	}

	if (status) {
		ipoib_warn(priv, "%s: %s Got status(%d) aborting..\n",
			   __func__, regflag2str(reg_flag), status);
		return 0;
	}

	if (!notice) {
		ipoib_warn(priv,
			   "%s: %s notification Got notice(null) while already registered\n",
			   __func__, regflag2str(reg_flag));
		return 0;
	}

	/* process notice data */
	gid_data = (struct ib_sa_notice_data_gid *)&notice->data_details;
	if (!gid_data) {
		ipoib_warn(priv,
			   "%s: %s notification Got GID(null), aborting..\n",
			   __func__, regflag2str(reg_flag));
		return 0;
	}

	/* If this is not an IPoIB MCG, return */
	if (!is_ipoib_mgid(gid_data->gid, priv->dev->broadcast)) {
		ipoib_dbg_mcp_lvl(2, priv,
				  "%s: %s %pI6 is not an IPoIB mgid, skipping\n",
				  __func__, regflag2str(reg_flag),
				  gid_data->gid);
		return 0;
	}

	/* If the MGid doesn't match the priv's PKey, return */
	pkey = mgid_get_pkey(gid_data->gid);
	if (priv->pkey != pkey) {
		ipoib_dbg_mcp_lvl(2, priv,
				  "%s: %s %pI6 doesn't match the interface's PKey (%x), skipping\n",
				  __func__, regflag2str(reg_flag),
				  gid_data->gid, priv->pkey);
		return 0;
	}

	ipoib_dbg_mcp(priv, "%s: %s MGID = %pI6\n",
		      __func__, regflag2str(reg_flag), gid_data->gid);

	/* Sanity checks passed ..*/
	if (reg_flag == MC_CREATE_REG)
		ipoib_queue_mcg_create_work(&priv->promisc, gid_data->gid, 0);
	else
		ipoib_queue_mcg_delete_work(&priv->promisc, gid_data->gid, 0);

	return 0;
}

/*
 * Registartion State Machine !
 * ipoib_inform_info_cb will re-schedule this work for continue handling.
 * Registers to MCG creation / deletion notofications from the SM
 * Scheduling for this work is done only via start or inform CB
 */
static void ipoib_handle_registration(struct ipoib_dev_priv *priv)
{
	int ret;

	/*
	 * state lock to make sure not send more registration requests
	 * while all multi is being stopped
	 */
	mutex_lock(&priv->promisc.state_lock);
	if (test_bit(MCP_STOPPED, &priv->promisc.flags)) {
		ipoib_dbg_mcp(priv,
			      "%s: %s allmulti is being stopped, aborting registration..\n",
			      __func__, regflag2str(MC_CREATE_REG));
		mutex_unlock(&priv->promisc.state_lock);
		return;
	}

	if (!INFORM_CRE_DONE(&priv->promisc.flags)) {
		u16 cre_trap_num = IB_SA_SM_TRAP_CREATE_MC_GROUP;

		if (priv->promisc.create_mcg)
			ib_sa_unregister_inform_info(priv->promisc.create_mcg);

		ipoib_dbg_mcp(priv,
			      "%s: %s Sending Register Inform info to SA\n",
			      __func__, regflag2str(MC_CREATE_REG));

		priv->promisc.create_mcg =
			ib_sa_register_inform_info(&ipoib_sa_client, priv->ca,
						   priv->port,
						   cre_trap_num,
						   GFP_KERNEL,
						   ipoib_inform_info_cb,
						   priv);

		if (IS_ERR_OR_NULL(priv->promisc.create_mcg)) {
			ipoib_err(priv,
				  "%s: ib_sa_register_inform_info returned %ld\n",
			       __func__, PTR_ERR(priv->promisc.create_mcg));
			priv->promisc.create_mcg = NULL;
		}
		mutex_unlock(&priv->promisc.state_lock);
		return;
	}

	if (!INFORM_DEL_DONE(&priv->promisc.flags)) {
		u16 del_trap_num = IB_SA_SM_TRAP_DELETE_MC_GROUP;

		if (priv->promisc.delete_mcg)
			ib_sa_unregister_inform_info(priv->promisc.delete_mcg);
		ipoib_dbg_mcp(priv,
			      "%s: %s Sending Register Inform info to SA\n",
			      __func__, regflag2str(MC_DELETE_REG));
		priv->promisc.delete_mcg =
			ib_sa_register_inform_info(&ipoib_sa_client, priv->ca,
						   priv->port,
						   del_trap_num,
						   GFP_KERNEL,
						   ipoib_inform_info_cb,
						   priv);

		if (IS_ERR_OR_NULL(priv->promisc.delete_mcg)) {
			ipoib_err(priv, "%s: ib_sa_register_inform_info returned %ld\n",
				  __func__, PTR_ERR(priv->promisc.delete_mcg));
			/* FATAL error complete registration */
			priv->promisc.delete_mcg = NULL;
		}
		mutex_unlock(&priv->promisc.state_lock);
		return;
	}
	mutex_unlock(&priv->promisc.state_lock);

	ipoib_dbg_mcp(priv,
		      "%s: Create/Delete inform Info registration Complete..\n",
		      __func__);
	/*
	 * Looks like MCG Create/Delete notifications are already registered
	 * send Validate Rules request to update MCGs
	 * No need to queue a new MCP work
	 * (we already running in MCP WQ context)
	 */
	ret = ipoib_handle_validate_rules(priv, 0 /* Don't update rules*/);
	if (ret < 0) {
		ipoib_err(priv, "%s: Failed to Get MCG table status(%d) retry in %ld msecs\n",
			  __func__, ret, priv->promisc.reg_delay);

		if (priv->promisc.reg_delay >= MCP_REG_MAX_DELAY) {
			ipoib_err(priv, "%s: Registration timeout exceeded, giving up\n",
				  __func__);
			return;
		}

		if (ipoib_queue_mcp_work(&priv->promisc, NULL, MC_REGISTER,
					 priv->promisc.reg_delay)) {
			ipoib_err(priv,
				  "%s: Retry Registration falied to queue\n",
				  __func__);
		}

		priv->promisc.reg_delay *= 2;
		return;
	}
	set_bit(MC_VALIDATE, &priv->promisc.flags);

	ipoib_warn(priv, "Promiscuous multicast is running\n");
}

static int ipoib_handle_get_mcg_table(struct ipoib_dev_priv *priv)
{
	ipoib_dbg_mcp(priv, "%s: Notifying ALL Joined MCGs ..\n",
		      __func__);
	ipoib_notify_mcasts(priv, NOTIFY_DETAILS);
	return 0;
}

/*
 * This function is the core engine of mc promic (ipoib allmulti),
 * it should run ONLY from priv->promisc.workqueue context!
 */
void ipoib_mcp_work_handler(struct work_struct *work)
{
	struct promisc_mc_work *mc_work = container_of(work,
						       struct promisc_mc_work,
						       work.work);
	struct ipoib_dev_priv *priv = mc_work->priv;

	switch (mc_work->action) {
	case MC_REGISTER:
		ipoib_handle_registration(priv);
		break;
	case MC_CREATE_ACTION:
		ipoib_handle_mcg_create(priv, mc_work->data.gid);
		break;
	case MC_DELETE_ACTION:
		ipoib_handle_mcg_delete(priv, mc_work->data.gid);
		break;
	case MC_ADD_RULE_ACTION:
		ipoib_handle_add_rule(priv, mc_work->data.rule);
		break;
	case MC_VALIDATE_RULES_ACTION:
		ipoib_handle_validate_rules(priv, 1/* update rules */);
		break;
	case MC_GET_MCG_TABLE:
		ipoib_handle_get_mcg_table(priv);
		break;
	default:
		ipoib_warn(priv, "%s Unsupported action type (%d)\n",
			   __func__, mc_work->action);
	}
	kfree(mc_work);
}

/*
 * Queues a rules validation work into the work queue. This work must be
 * synchronized with notice handling and rules addition.
 */
int ipoib_queue_validate_rules(struct promisc_mc *promisc)
{
	return ipoib_queue_mcp_work(promisc, NULL, MC_VALIDATE_RULES_ACTION, 0);
}

int ipoib_queue_get_mcg_table(struct promisc_mc *promisc)
{
	return ipoib_queue_mcp_work(promisc, NULL, MC_GET_MCG_TABLE, 0);
}

/*
 * Initializes resources used by ipoib promiscuous multicast.
 */
int ipoib_promisc_mc_init(struct promisc_mc *promisc)
{
	struct ipoib_dev_priv *priv =
		container_of(promisc, struct ipoib_dev_priv, promisc);

	mutex_init(&promisc->tree_lock);
	mutex_init(&promisc->state_lock);

	/* create the MC workqueue */
	promisc->workqueue = create_singlethread_workqueue("notice");
	if (!promisc->workqueue) {
		ipoib_printk(KERN_CRIT, priv, "%s: couldn't allocate notice workqueue\n",
			     __func__);
		return -ENOMEM;
	}

	ipoib_dbg_mcp(priv, "Notice workqueue is ready\n");
	return 0;
}

/*
 * Starts ipoib_promiscuous:
 *	Registers to II notifications.
 *	Calls get table and applies rules to the groups.
 */
int ipoib_promisc_mc_start(struct promisc_mc *promisc)
{
	int ret = 0;
	struct ib_port_attr attr;
	struct ipoib_dev_priv *priv =
		container_of(promisc, struct ipoib_dev_priv, promisc);

	if (ib_query_port(priv->ca, priv->port, &attr) ||
	    attr.state != IB_PORT_ACTIVE) {
		ipoib_dbg_mcp(priv, "%s: port state is not ACTIVE (state = %d)\n",
			      __func__, attr.state);
		return -EPERM;
	}

	/* lock to make sure no registration/stop is in progress */
	mutex_lock(&promisc->state_lock);
	set_bit(IPOIB_ALL_MULTI, &priv->flags);
	clear_bit(MCP_STOPPED, &promisc->flags);
	clear_bit(MC_CREATE_REG, &promisc->flags);
	clear_bit(MC_DELETE_REG, &promisc->flags);
	clear_bit(MC_VALIDATE, &priv->promisc.flags);
	/* start the registration Flow */
	promisc->reg_delay = 100; /* initial msecs */
	ret = ipoib_queue_mcp_work(promisc, NULL, MC_REGISTER, 0);
	if (ret)
		clear_bit(IPOIB_ALL_MULTI, &priv->flags);
	else
		ipoib_warn(priv, "Promiscuous multicast is now started\n");
	mutex_unlock(&promisc->state_lock);
	return ret;
}

/*
 * Flushes promiscuous_mc MCG list during dev flush.
 * No need to flush ... just remove at stop.
 *
 */
static void ipoib_promisc_mc_flush(struct promisc_mc *promisc)
{
	struct ipoib_dev_priv *priv =
		container_of(promisc, struct ipoib_dev_priv, promisc);
	struct rb_node *n;
	struct ipoib_mcast *mcast, *tmcast;
	LIST_HEAD(remove_list);

	/* Clean MC tree */
	if (&priv->promisc.multicast_tree == NULL)
		return;

	mutex_lock(&priv->promisc.tree_lock);
	n = rb_first(&priv->promisc.multicast_tree);
	while (n) {
		mcast = rb_entry(n, struct ipoib_mcast, rb_node);
		n = rb_next(n);
		rb_erase(&mcast->rb_node,
			 &priv->promisc.multicast_tree);
		list_add_tail(&mcast->list, &remove_list);
	}
	mutex_unlock(&priv->promisc.tree_lock);

	/*seperate between the wait to the leave.*/
	list_for_each_entry_safe(mcast, tmcast, &remove_list, list)
		if (test_bit(IPOIB_MCAST_JOIN_STARTED, &mcast->flags))
			wait_for_completion(&mcast->done);

	list_for_each_entry_safe(mcast, tmcast, &remove_list, list) {
		mcp_mcast_leave(priv, mcast);
		mcp_mcast_free(mcast);
	}
}

/*
 * Stops ipoib_promisc during interface down:
 *	Unregisters from II notifications.
 *	Flushes rules.
 *	Disables ALLMULTI.
 */
int ipoib_promisc_mc_stop(struct promisc_mc *promisc)
{
	struct ipoib_dev_priv *priv =
		container_of(promisc, struct ipoib_dev_priv, promisc);

	mutex_lock(&promisc->state_lock);
	set_bit(MCP_STOPPED, &promisc->flags);
	if (!test_bit(IPOIB_ALL_MULTI, &priv->flags)) {
		ipoib_dbg_mcp(priv, "MC Promisc is already stopped\n");
		mutex_unlock(&promisc->state_lock);
		return 0;
	}
	clear_bit(MC_VALIDATE, &priv->promisc.flags);

	/* Unregister II notifications */
	if (promisc->create_mcg) {
		ib_sa_unregister_inform_info(promisc->create_mcg);
		promisc->create_mcg = NULL;
	}
	clear_bit(MC_CREATE_REG, &promisc->flags);
	ipoib_dbg_mcp(priv, "%s: unregistered IB_SA_SM_TRAP_CREATE_MC_GROUP\n",
		      __func__);

	if (promisc->delete_mcg) {
		ib_sa_unregister_inform_info(promisc->delete_mcg);
		promisc->delete_mcg = NULL;
	}

	clear_bit(MC_DELETE_REG, &promisc->flags);
	mutex_unlock(&promisc->state_lock);

	ipoib_dbg_mcp(priv, "%s: unregistered IB_SA_SM_TRAP_DELETE_MC_GROUP\n",
		      __func__);

	flush_workqueue(promisc->workqueue);
	ipoib_promisc_mc_flush(promisc);
	clear_bit(IPOIB_ALL_MULTI, &priv->flags);
	ipoib_warn(priv, "Promiscuous multicast is now stopped\n");
	return 0;
}

int ipoib_promisc_mc_destroy(struct promisc_mc *promisc)
{
	struct ipoib_dev_priv *priv =
		container_of(promisc, struct ipoib_dev_priv, promisc);
	struct rb_node *n;
	struct ipoib_mc_rule *rule;

	if (promisc->workqueue) {
		flush_workqueue(promisc->workqueue);
		destroy_workqueue(promisc->workqueue);
		promisc->workqueue = NULL;
		ipoib_dbg_mcp(priv, "Notice workqueue was destroyed\n");
	}

	ipoib_promisc_mc_flush(promisc);

	/* Clear rules */
	mutex_lock(&priv->promisc.tree_lock);
	n = rb_first(&priv->promisc.rules_tree);
	while (n) {
		rule = rb_entry(n, struct ipoib_mc_rule, rb_node);
		n = rb_next(n);
		rb_erase(&rule->rb_node, &priv->promisc.rules_tree);
		kfree(rule);
	}

	n = rb_first(&priv->promisc.new_rules_tree);
	while (n) {
		rule = rb_entry(n, struct ipoib_mc_rule, rb_node);
		n = rb_next(n);
		rb_erase(&rule->rb_node, &priv->promisc.new_rules_tree);
		kfree(rule);
	}
	mutex_unlock(&priv->promisc.tree_lock);

	return 0;
}
