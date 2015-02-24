/*
 * Copyright (c) 2012 Mellanox Technologies, Inc. -  All rights reserved.
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

#include "ipoib.h"
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/if.h>

/* netlink flags bits */
#define GENL_PATH_NOTIFICATIONS_ACTIVE 2
#define GENL_MC_NOTIFICATIONS_ACTIVE 4

/* attributes types
 * 0 causes issues with Netlink */
enum {
	ATTRIBUTE_UNSPECIFIED,
	PATH_ADD,
	PATH_DEL,
	MC_JOIN,
	MC_LEAVE,
	MCG_DETAILS,
	__IPOIB_NETLINK_ATT_MAX
};

#define	IPOIB_NETLINK_ATT_MAX (__IPOIB_NETLINK_ATT_MAX - 1)

/* command types
 * 0 causes issues with Netlink */
enum {
	COMMAND_UNSPECIFIED,
	ENABLE_PATH,
	REPORT_PATH,
	ENABLE_MC,
	GET_MCG,
	REPORT_MCG,
	ADD_RULE,
	VALIDATE_RULES
};

struct ipoib_family_header {
	char	name[IFNAMSIZ];
};

struct ipoib_path_notice {
	u8	gid[16];
	__be16	lid;
	u8	sl;
	u8	reserved;
};

struct ipoib_path_del_notice {
	u8	gid[16];
};

struct ipoib_mc_join_notice {
	u8	mgid[16];
	__be16	mlid;
	u8	sl;
	u8	join_status;
};

struct ipoib_mc_leave_notice {
	u8	mgid[16];
};

struct ipoib_ge_netlink_notify {
	union {
		struct ipoib_path_notice	path_rec;
		struct ipoib_path_del_notice	path_del;
		struct ipoib_mc_join_notice	mc_join;
		struct ipoib_mc_leave_notice	mc_leave;
	};
};

struct ipoib_genl_work {
	struct work_struct work;
	struct ipoib_dev_priv *priv;
	struct ipoib_ge_netlink_notify record;
	int type;
};

static LIST_HEAD(genl_if_list);
static DEFINE_MUTEX(genl_if_mutex);
/* genl_registered's value is changed only on module load/unload */
static int genl_registered;

/*
 * Handler module, contains the logic to process notifications and user
 * requests but not the sending-via-GENL logic.
 */

void generate_reply(struct work_struct *work);

void ipoib_path_add_notify(struct ipoib_dev_priv *priv,
			    struct ib_sa_path_rec *pathrec)
{
	struct ipoib_genl_work *genl_work;

	/* make sure notifications were enabled */
	if (!test_bit(GENL_PATH_NOTIFICATIONS_ACTIVE, &priv->netlink.flags))
		return;

	genl_work = kzalloc(sizeof(struct ipoib_genl_work),
		       GFP_KERNEL);
	if (!genl_work) {
		ipoib_err(priv, "%s: allocation of ipoib_genl_work failed\n",
			  __func__);
		return;
	}

	memcpy(genl_work->record.path_rec.gid, pathrec->dgid.raw,
	       sizeof(union ib_gid));
	genl_work->record.path_rec.lid = pathrec->dlid;
	genl_work->record.path_rec.sl = pathrec->sl;

	INIT_WORK(&genl_work->work, generate_reply);
	genl_work->priv = priv;
	genl_work->type = PATH_ADD;
	queue_work(ipoib_workqueue, &genl_work->work);
}

void ipoib_path_del_notify(struct ipoib_dev_priv *priv,
			   struct ib_sa_path_rec *pathrec)
{
	struct ipoib_genl_work *genl_work;

	/* make sure notifications were enabled */
	if (!test_bit(GENL_PATH_NOTIFICATIONS_ACTIVE, &priv->netlink.flags))
		return;

	genl_work = kzalloc(sizeof(struct ipoib_genl_work),
		       GFP_ATOMIC);
	if (!genl_work) {
		ipoib_err(priv, "%s: allocation of ipoib_genl_work failed\n",
			  __func__);
		return;
	}

	memcpy(genl_work->record.path_del.gid, pathrec->dgid.raw,
	       sizeof(union ib_gid));
	INIT_WORK(&genl_work->work, generate_reply);
	genl_work->priv = priv;
	genl_work->type = PATH_DEL;
	queue_work(ipoib_workqueue, &genl_work->work);
}

void __send_mcg_notification(struct ipoib_dev_priv *priv,
			      struct ib_sa_mcmember_rec *rec, int work_type)
{
	struct ipoib_genl_work *genl_work;
	/* make sure notifications were enabled for JOIN only */
	if (work_type != MCG_DETAILS &&
	    !test_bit(GENL_MC_NOTIFICATIONS_ACTIVE, &priv->netlink.flags))
		return;
	if (work_type != MC_JOIN && work_type != MCG_DETAILS) {
		ipoib_warn(priv, "%s: got bad work_type %d, should get %d or %d\n",
			   __func__, work_type, MC_JOIN, MCG_DETAILS);
		return;
	}

	genl_work = kzalloc(sizeof(struct ipoib_genl_work),
		       GFP_KERNEL);
	if (!genl_work) {
		ipoib_err(priv, "%s: allocation of ipoib_genl_work failed\n",
			  __func__);
		return;
	}

	memcpy(genl_work->record.mc_join.mgid, rec->mgid.raw,
	       sizeof(union ib_gid));
	genl_work->record.mc_join.mlid = rec->mlid;
	genl_work->record.mc_join.sl = rec->sl;
	genl_work->record.mc_join.join_status = rec->join_state;

	INIT_WORK(&genl_work->work, generate_reply);
	genl_work->priv = priv;
	genl_work->type = work_type;
	queue_work(ipoib_workqueue, &genl_work->work);
}

void ipoib_mcg_details_notify(struct ipoib_dev_priv *priv,
			      struct ib_sa_mcmember_rec *rec)
{
	__send_mcg_notification(priv, rec, MCG_DETAILS);
}

void ipoib_mc_join_notify(struct ipoib_dev_priv *priv,
			  struct ib_sa_mcmember_rec *rec)
{
	__send_mcg_notification(priv, rec, MC_JOIN);
}

void ipoib_mc_leave_notify(struct ipoib_dev_priv *priv,
			   struct ib_sa_mcmember_rec *rec)
{
	struct ipoib_genl_work *genl_work;

	/* make sure notifications were enabled */
	if (!test_bit(GENL_MC_NOTIFICATIONS_ACTIVE, &priv->netlink.flags))
		return;

	genl_work = kzalloc(sizeof(struct ipoib_genl_work),
		       GFP_KERNEL);
	if (!genl_work) {
		ipoib_err(priv, "%s: allocation of ipoib_genl_work failed\n",
			  __func__);
		return;
	}

	memcpy(genl_work->record.mc_leave.mgid, rec->mgid.raw,
	       sizeof(union ib_gid));
	INIT_WORK(&genl_work->work, generate_reply);
	genl_work->priv = priv;
	genl_work->type = MC_LEAVE;
	queue_work(ipoib_workqueue, &genl_work->work);
}

/* Must be called under genl_if_mutex*/
static struct ipoib_dev_priv *genl_if_name_priv(char *name)
{
	struct genl_mdata *netlink;
	struct ipoib_dev_priv *priv = NULL;

	list_for_each_entry(netlink, &genl_if_list, ipoib_genl_if) {
		priv = container_of(netlink,
				    struct ipoib_dev_priv, netlink);
		if (!strcmp(name, priv->dev->name))
			return priv;
	}
	return ERR_PTR(-EINVAL);
}

static int verify_allmulti_conditions(struct ipoib_dev_priv *priv, int command)
{
	if (!priv) {
		ipoib_err(priv, "%pS: priv is NULL\n",
			  __builtin_return_address(0));
		return -EINVAL;
	}
	if (!test_bit(IPOIB_ALL_MULTI, &priv->flags)) {
		ipoib_warn(priv, "%pS: activate allmulti before %s command\n",
			   __builtin_return_address(0),
			   command_to_str(command));
		return -EINVAL;
	}
	return 0;
}

static int ipoib_gnl_cb_selector(struct ipoib_dev_priv *priv,
					struct sk_buff *skb,
					struct genl_info *info)
{
	int rc = 0;
	struct ipoib_mc_rule rule;

	switch (info->genlhdr->cmd) {
	case ENABLE_PATH:
		if (test_and_set_bit(GENL_PATH_NOTIFICATIONS_ACTIVE,
				     &priv->netlink.flags))
			ipoib_dbg(priv, "%s: Multiple ENABLE_PATH packets\n",
				  __func__);
		break;
	case ENABLE_MC:
		if (test_and_set_bit(GENL_MC_NOTIFICATIONS_ACTIVE,
				     &priv->netlink.flags))
			ipoib_dbg(priv, "%s: Multiple ENABLE_MC packets\n",
				  __func__);
		break;
	case GET_MCG:
		if (verify_allmulti_conditions(priv, GET_MCG)) {
			rc = -EINVAL;
			break;
		}
		rc = ipoib_queue_get_mcg_table(&priv->promisc);
		break;
	case ADD_RULE:
		if (!skb) {
			ipoib_err(priv, "%s: skb is NULL for ADD_RULE command\n",
				  __func__);
			rc = -EINVAL;
			break;
		}
		memcpy(&rule, skb->data + GENL_SKB_DATA_OFFSET,
		       IPOIB_RULE_DATA_SIZE);
		rc = ipoib_queue_add_rule(&priv->promisc, rule);
		break;
	case VALIDATE_RULES:
		rc = ipoib_queue_validate_rules(&priv->promisc);
		break;
	default:
		ipoib_warn(priv, "%s: got an unexpected command (%d)\n",
			   __func__, info->genlhdr->cmd);
		rc = -ENOTSUPP;
	}
	return rc;
}

int ipoib_gnl_cb(struct sk_buff *skb, struct genl_info *info)
{
	struct ipoib_family_header *hdr = info->userhdr;
	struct genl_mdata *netlink;
	struct ipoib_dev_priv *priv = NULL;
	int rc = 0;

	/* First, check to see if interfaces list is empty. It may happen since
	 * GENL is registered before IPoIB client.
	 * Further processing is done under mutex to avoid unregistration
	 * during operation. */

	mutex_lock(&genl_if_mutex);
	if (list_empty(&genl_if_list)) {
		mutex_unlock(&genl_if_mutex);
		return -ENODEV;
	}
	mutex_unlock(&genl_if_mutex);

	if (!hdr->name[0]) {
		pr_debug("%s: no family name specified, applying for all interfaces\n",
			 __func__);
		mutex_lock(&genl_if_mutex);
		list_for_each_entry(netlink, &genl_if_list, ipoib_genl_if) {
			priv = container_of(netlink,
					struct ipoib_dev_priv, netlink);
			rc += ipoib_gnl_cb_selector(priv, skb, info);
		}
		mutex_unlock(&genl_if_mutex);
	} else {
		pr_debug("family name specified is %s\n", hdr->name);
		mutex_lock(&genl_if_mutex);
		priv = genl_if_name_priv(hdr->name);
		if (!IS_ERR(priv)) {
			rc = ipoib_gnl_cb_selector(priv, skb, info);
		} else {
			pr_err("%s: couldn't get priv for %s, err = %ld\n",
			       __func__, hdr->name, PTR_ERR(priv));
			rc = PTR_ERR(priv);
		}
		mutex_unlock(&genl_if_mutex);
	}
	return rc;
}

/* Adds netlink's ipoib interface to the genl_if_list and sets netlink's flags
*  to 1. */
inline void ipoib_genl_intf_add(struct genl_mdata *netlink)
{
	pr_debug("%s: Adding Dev\n", __func__);
	if (!genl_registered)
		return;
	mutex_lock(&genl_if_mutex);
	list_add_tail(&netlink->ipoib_genl_if, &genl_if_list);
	mutex_unlock(&genl_if_mutex);
}

inline void ipoib_genl_intf_del(struct genl_mdata *netlink)
{
	pr_debug("%s: Removing Dev\n", __func__);
	if (!genl_registered)
		return;
	mutex_lock(&genl_if_mutex);
	list_del_init(&netlink->ipoib_genl_if);
	mutex_unlock(&genl_if_mutex);
}

/*
 * Notifier module. Contains the needed functions to send messages to
 * userspace using GENL.
 */

static DEFINE_MUTEX(genl_flags_mutex);

static struct genl_family ipoib_genl_family = {
	.id		= GENL_ID_GENERATE,
	.hdrsize	= sizeof(struct ipoib_family_header),
	.name		= "GENETLINK_IPOIB",
	.version	= 1,
	.maxattr	= IPOIB_NETLINK_ATT_MAX,
};

/* attribute policy */
static struct nla_policy ipoib_genl_policy[__IPOIB_NETLINK_ATT_MAX] = {
	[PATH_ADD]	= { .type = NLA_BINARY },
	[PATH_DEL]	= { .type = NLA_BINARY },
	[MC_JOIN]	= { .type = NLA_BINARY },
	[MC_LEAVE]	= { .type = NLA_BINARY },
};

/* ipoib mcast group for path rec */
struct genl_multicast_group ipoib_path_notify_grp = {
	.name = "PATH_NOTIFY",
};

/* ipoib mcast group for IB MC changes */
struct genl_multicast_group ipoib_mc_notify_grp = {
	.name = "MC_NOTIFY",
};

/* operation definition */
static struct genl_ops ipoib_genl_path_ops[] = {
	{
	.cmd		= ENABLE_PATH,
	.flags		= GENL_ADMIN_PERM,
	.policy		= ipoib_genl_policy,
	.doit		= ipoib_gnl_cb,
	.dumpit		= NULL,
	}
};

static struct genl_ops ipoib_genl_mc_ops[] = {
	{
	.cmd		= ENABLE_MC,
	.flags		= GENL_ADMIN_PERM,
	.policy		= ipoib_genl_policy,
	.doit		= ipoib_gnl_cb,
	.dumpit		= NULL,
	}
};

static struct genl_ops ipoib_genl_mcg_get_ops[] = {
	{
	.cmd		= GET_MCG,
	.flags		= GENL_ADMIN_PERM,
	.policy		= ipoib_genl_policy,
	.doit		= ipoib_gnl_cb,
	.dumpit		= NULL,
	}
};

static struct genl_ops ipoib_genl_add_rule_ops[] = {
	{
	.cmd		= ADD_RULE,
	.flags		= GENL_ADMIN_PERM,
	.policy		= ipoib_genl_policy,
	.doit		= ipoib_gnl_cb,
	.dumpit		= NULL,
	}
};

static struct genl_ops ipoib_genl_validate_rules_ops[] = {
	{
	.cmd		= VALIDATE_RULES,
	.flags		= GENL_ADMIN_PERM,
	.policy		= ipoib_genl_policy,
	.doit		= ipoib_gnl_cb,
	.dumpit		= NULL,
	}
};

static inline char *get_command(int command)
{
	switch(command) {
		case PATH_ADD:
			return "PATH_ADD";
		case PATH_DEL:
			return "PATH_DEL";
		case MC_JOIN:
			return "MC_JOIN";
		case MC_LEAVE:
			return "MC_LEAVE";
		default:
			return "";
	}
}

void generate_reply(struct work_struct *work)
{
	struct ipoib_genl_work *genl_work = container_of(work,
						   struct ipoib_genl_work,
						   work);
	struct ipoib_dev_priv *priv;
	struct sk_buff *skb;
	void *msg_head;
	struct nlattr *nla;
	unsigned int seq = 0;
	int i = 0;
	int type = genl_work->type;
	struct ipoib_ge_netlink_notify *record = &genl_work->record;

	priv = genl_work->priv;
	if (!priv) {
		pr_crit("%s: priv is NULL\n", __func__);
		return;
	}

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL) {
		ipoib_printk(KERN_CRIT, priv, "%s: skb allocation failed\n",
			     __func__);
		goto out;
	}

	msg_head = genlmsg_put(skb, 0, seq++, &ipoib_genl_family, 0,
			       REPORT_PATH);
	/* Warning:
	 *  genlmsg_put can return NULL in case there is not enough room
	 *  in the skb for the family and netlink headers. As long as
	 *  allock succeeded and is NLMSG_GOODSIZE the command can't
	 *  fail.
	 */

	memcpy(msg_head, priv->dev->name, IFNAMSIZ);
	nla = __nla_reserve(skb, type, 0);

	nla->nla_type = type;
	switch(type) {
	case PATH_ADD:
	{
		struct ipoib_path_notice *p;
		nla->nla_len += sizeof(struct ipoib_path_notice);
		p = (struct ipoib_path_notice *)skb_put(skb,
		     sizeof(struct ipoib_path_notice));
		memcpy(p, &record->path_rec,
		       sizeof(struct ipoib_path_notice));
		genlmsg_end(skb, msg_head);
		i = genlmsg_multicast(skb, 0, ipoib_path_notify_grp.id,
				      GFP_KERNEL);
		break;
	}
	case PATH_DEL:
	{
		struct ipoib_path_del_notice *p;
		nla->nla_len += sizeof(struct ipoib_path_del_notice);
		p = (struct ipoib_path_del_notice *)skb_put(skb,
		     sizeof(struct ipoib_path_del_notice));
		memcpy(p, &record->path_del,
		       sizeof(struct ipoib_path_del_notice));
		genlmsg_end(skb, msg_head);
		i = genlmsg_multicast(skb, 0, ipoib_path_notify_grp.id,
				      GFP_KERNEL);
		break;
	}
	case MCG_DETAILS:
	case MC_JOIN:
	{
		struct ipoib_mc_join_notice *m;
		nla->nla_len += sizeof(struct ipoib_mc_join_notice);
		m = (struct ipoib_mc_join_notice *)skb_put(skb,
		     sizeof(struct ipoib_mc_join_notice));
		memcpy(m, &record->mc_join,
		       sizeof(struct ipoib_mc_join_notice));
		genlmsg_end(skb, msg_head);
		i = genlmsg_multicast(skb, 0, ipoib_mc_notify_grp.id,
				      GFP_KERNEL);
		break;
	}
	case MC_LEAVE:
	{
		struct ipoib_mc_leave_notice *m;
		nla->nla_len += sizeof(struct ipoib_mc_leave_notice);
		m = (struct ipoib_mc_leave_notice *)skb_put(skb,
		     sizeof(struct ipoib_mc_leave_notice));
		memcpy(m, &record->mc_leave,
		       sizeof(struct ipoib_mc_leave_notice));
		genlmsg_end(skb, msg_head);
		i = genlmsg_multicast(skb, 0, ipoib_mc_notify_grp.id,
				      GFP_KERNEL);
		break;
	}
	}
	if (i && i != -ESRCH) {
		pr_err("%s: sending GENL %s message returned %d\n", __func__,
		       get_command(type), i);
	}
out:
	kfree(genl_work);
	return;
}

/*
 * Initiates the genl_mdata struct and adds it to the ipoib msg recieve
 * multiplexer (This ipoib interface can now recieve notifications from user
 * space)
 */
inline void ipoib_genl_intf_init(struct genl_mdata *netlink)
{
	INIT_LIST_HEAD(&netlink->ipoib_genl_if);
	netlink->flags = 0;
}

/* If needed, deletes the netlink interfaces from the ipoib_genl_if list
 * and resets the flags. */
void ipoib_unregister_genl(void)
{
	if (!genl_registered)
		return;
	if (!list_empty(&genl_if_list))
		pr_warn("%s: interfaces list is not empty\n", __func__);
	genl_registered = 0;
	genl_unregister_family(&ipoib_genl_family);
}

int ipoib_register_genl(void)
{
	int rc;
	rc = genl_register_family(&ipoib_genl_family);
	if (rc != 0)
		goto out;
	genl_registered = 1;
	rc = genl_register_ops(&ipoib_genl_family, ipoib_genl_path_ops);
	if (rc != 0)
		goto unregister;
	rc = genl_register_ops(&ipoib_genl_family, ipoib_genl_mc_ops);
	if (rc != 0)
		goto unregister;
	rc = genl_register_ops(&ipoib_genl_family, ipoib_genl_mcg_get_ops);
	if (rc != 0)
		goto unregister;
	rc = genl_register_ops(&ipoib_genl_family, ipoib_genl_add_rule_ops);
	if (rc != 0)
		goto unregister;
	rc = genl_register_ops(&ipoib_genl_family,
			       ipoib_genl_validate_rules_ops);
	if (rc != 0)
		goto unregister;
	rc = genl_register_mc_group(&ipoib_genl_family, &ipoib_path_notify_grp);
	if (rc < 0)
		goto unregister;
	rc = genl_register_mc_group(&ipoib_genl_family, &ipoib_mc_notify_grp);
	if (rc < 0)
		goto unregister;
	return 0;
unregister:
/*	unregistering the family will cause:
 *	all assigned operations to be unregistered automatically.
 *	all assigned multicast groups to be unregistered automatically. */
	ipoib_unregister_genl();
out:
	return rc;
}
