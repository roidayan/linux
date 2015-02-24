/*
 * Copyright (c) 2007 Mellanox Technologies. All rights reserved.
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

#include <linux/kernel.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>

#include "ipoib.h"

enum ipoib_auto_moder_operation {
	NONE,
	MOVING_TO_ON,
	MOVING_TO_OFF
};

static int ipoib_ethtool_dev_init(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	int result = -ENOMEM;

	ipoib_dbg(priv, "ethtool: initializing interface %s\n", dev->name);

	result = ipoib_dev_init(priv->dev, priv->ca, priv->port);
	if (result < 0) {
		netdev_warn(dev, "%s: failed to initialize port %d (ret = %d)\n",
			    dev->name, priv->port, result);
		return -ENOMEM;
	}

	return 0;
}

static int ipoib_set_ring_param(struct net_device *dev,
				struct ethtool_ringparam *ringparam)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	unsigned int new_recvq_size, new_sendq_size;
	unsigned long priv_current_flags;
	unsigned int dev_current_flags;
	bool init = false;

	if (ringparam->rx_pending <= IPOIB_MAX_QUEUE_SIZE &&
	    ringparam->rx_pending >= IPOIB_MIN_QUEUE_SIZE) {
		new_recvq_size = roundup_pow_of_two(ringparam->rx_pending);
		if (ringparam->rx_pending != new_recvq_size)
			pr_warn("%s: %s: rx_pending should be power of two. rx_pending is %d\n",
				dev->name, __func__, new_recvq_size);
	} else {
		pr_err(KERN_ERR "rx_pending (%d) is out of bounds [%d-%d]\n",
		       ringparam->rx_pending,
		       IPOIB_MIN_QUEUE_SIZE, IPOIB_MAX_QUEUE_SIZE);
		return -EINVAL;
	}

	if (ringparam->tx_pending <= IPOIB_MAX_QUEUE_SIZE &&
	    ringparam->tx_pending >= IPOIB_MIN_QUEUE_SIZE) {
		new_sendq_size = roundup_pow_of_two(ringparam->tx_pending);
		if (ringparam->tx_pending != new_sendq_size)
			pr_warn("%s: %s: tx_pending should be power of two. tx_pending is %d\n",
				dev->name, __func__, new_sendq_size);
	} else {
		pr_err(KERN_ERR "tx_pending (%d) is out of bounds [%d-%d]\n",
		       ringparam->tx_pending,
		       IPOIB_MIN_QUEUE_SIZE, IPOIB_MAX_QUEUE_SIZE);
		return -EINVAL;
	}

	if ((new_recvq_size != priv->recvq_size) ||
	    (new_sendq_size != priv->sendq_size)) {
		priv_current_flags = priv->flags;
		dev_current_flags = dev->flags;

		dev_change_flags(dev, dev->flags & ~IFF_UP);
		ipoib_dev_uninit(dev);

		do {
			priv->recvq_size = new_recvq_size;
			priv->sendq_size = new_sendq_size;
			if (ipoib_ethtool_dev_init(dev)) {
				new_recvq_size >>= 1;
				new_sendq_size >>= 1;
				/* keep the values always legal */
				new_recvq_size = max_t(unsigned int, new_recvq_size, IPOIB_MIN_QUEUE_SIZE);
				new_sendq_size = max_t(unsigned int, new_sendq_size, IPOIB_MIN_QUEUE_SIZE);
			} else {
				init = true;
			}
		} while (!init &&
			 !(new_recvq_size == IPOIB_MIN_QUEUE_SIZE &&
			   new_sendq_size == IPOIB_MIN_QUEUE_SIZE));

		if (!init) {
			pr_err(KERN_ERR "%s: Failed to init interface %s, removing it\n",
			       __func__, dev->name);
			return -ENOMEM;
		}

		if (dev_current_flags & IFF_UP)
			dev_change_flags(dev, dev_current_flags);
	}

	return 0;
}

static void ipoib_get_ring_param(struct net_device *dev,
				 struct ethtool_ringparam *ringparam)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	ringparam->rx_max_pending = IPOIB_MAX_QUEUE_SIZE;
	ringparam->tx_max_pending = IPOIB_MAX_QUEUE_SIZE;
	ringparam->rx_mini_max_pending = 0;
	ringparam->rx_jumbo_max_pending = 0;
	ringparam->rx_pending = priv->recvq_size;
	ringparam->tx_pending = priv->sendq_size;
	ringparam->rx_mini_pending = 0;
	ringparam->rx_jumbo_pending = 0;
}

static void ipoib_get_drvinfo(struct net_device *netdev,
			      struct ethtool_drvinfo *drvinfo)
{
	struct ipoib_dev_priv *priv = netdev_priv(netdev);
	struct ib_device_attr *attr;

	attr = kmalloc(sizeof(*attr), GFP_KERNEL);
	if (attr && !ib_query_device(priv->ca, attr))
		snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version),
			 "%d.%d.%d", (int)(attr->fw_ver >> 32),
			 (int)(attr->fw_ver >> 16) & 0xffff,
			 (int)attr->fw_ver & 0xffff);
	kfree(attr);

	strlcpy(drvinfo->bus_info, dev_name(priv->ca->dma_device),
		sizeof(drvinfo->bus_info));

	strlcpy(drvinfo->version, ipoib_driver_version,
		sizeof(drvinfo->version));

	strlcpy(drvinfo->driver, "ib_ipoib", sizeof(drvinfo->driver));
}

static int ipoib_get_coalesce(struct net_device *dev,
			      struct ethtool_coalesce *coal)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	coal->rx_coalesce_usecs = priv->ethtool.rx_coalesce_usecs;
	coal->rx_max_coalesced_frames = priv->ethtool.rx_max_coalesced_frames;
	coal->pkt_rate_low = priv->ethtool.pkt_rate_low;
	coal->rx_coalesce_usecs_low = priv->ethtool.rx_coalesce_usecs_low;
	coal->rx_coalesce_usecs_high = priv->ethtool.rx_coalesce_usecs_high;
	coal->pkt_rate_high = priv->ethtool.pkt_rate_high;
	coal->rate_sample_interval = priv->ethtool.rate_sample_interval;
	coal->use_adaptive_rx_coalesce = priv->ethtool.use_adaptive_rx_coalesce;

	return 0;
}

static int ipoib_set_coalesce(struct net_device *dev,
			      struct ethtool_coalesce *coal)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	int ret, i;
	enum ipoib_auto_moder_operation moder_operation = NONE;

	/*
	 * These values are saved in the private data and returned
	 * when ipoib_get_coalesce() is called
	 */
	if (coal->rx_coalesce_usecs       > 0xffff ||
	    coal->rx_max_coalesced_frames > 0xffff)
		return -EINVAL;

	priv->ethtool.rx_max_coalesced_frames =
	(coal->rx_max_coalesced_frames ==
		IPOIB_AUTO_CONF) ?
		IPOIB_RX_COAL_TARGET :
		coal->rx_max_coalesced_frames;

	priv->ethtool.rx_coalesce_usecs = (coal->rx_coalesce_usecs ==
	       IPOIB_AUTO_CONF) ?
	       IPOIB_RX_COAL_TIME :
	       coal->rx_coalesce_usecs;

	for (i = 0; i < priv->num_rx_queues; i++) {
		struct ib_cq_attr  attr;

		memset(&attr, 0, sizeof(attr));
		attr.moderation.cq_count = coal->rx_max_coalesced_frames;
		attr.moderation.cq_period = coal->rx_coalesce_usecs;
		ret = ib_modify_cq(priv->recv_ring[i].recv_cq,
					&attr,
					IB_CQ_MODERATION);
		if (ret && ret != -ENOSYS) {
			ipoib_warn(priv, "failed modifying CQ (%d)\n", ret);
			return ret;
		}
	}
	priv->ethtool.pkt_rate_low = coal->pkt_rate_low;
	priv->ethtool.rx_coalesce_usecs_low = coal->rx_coalesce_usecs_low;
	priv->ethtool.rx_coalesce_usecs_high = coal->rx_coalesce_usecs_high;
	priv->ethtool.pkt_rate_high = coal->pkt_rate_high;
	priv->ethtool.rate_sample_interval = coal->rate_sample_interval;
	priv->ethtool.pkt_rate_low_per_ring = priv->ethtool.pkt_rate_low;
	priv->ethtool.pkt_rate_high_per_ring = priv->ethtool.pkt_rate_high;

	if (priv->ethtool.use_adaptive_rx_coalesce &&
		!coal->use_adaptive_rx_coalesce) {
		/* switch from adaptive-mode to non-adaptive mode:
		cancell the adaptive moderation task. */
		clear_bit(IPOIB_FLAG_AUTO_MODER, &priv->flags);
		cancel_delayed_work(&priv->adaptive_moder_task);
		moder_operation = MOVING_TO_OFF;
	} else if ((!priv->ethtool.use_adaptive_rx_coalesce &&
		coal->use_adaptive_rx_coalesce)) {
		/* switch from non-adaptive-mode to adaptive mode,
		starts it now */
		set_bit(IPOIB_FLAG_AUTO_MODER, &priv->flags);
		moder_operation = MOVING_TO_ON;
		priv->ethtool.use_adaptive_rx_coalesce = 1;
		queue_delayed_work(ipoib_auto_moder_workqueue,
			&priv->adaptive_moder_task, 0);
	}

	if (MOVING_TO_OFF == moder_operation)
		flush_workqueue(ipoib_auto_moder_workqueue);
	else if (MOVING_TO_ON == moder_operation) {
		struct ib_cq_attr  attr;

		memset(&attr, 0, sizeof(attr));
		attr.moderation.cq_count = priv->ethtool.rx_max_coalesced_frames;
		attr.moderation.cq_period = priv->ethtool.rx_coalesce_usecs;
		/* move to initial values */
		for (i = 0; i < priv->num_rx_queues; i++) {
			ret = ib_modify_cq(priv->recv_ring[i].recv_cq,
						&attr,
						IB_CQ_MODERATION);

			if (ret && ret != -ENOSYS) {
				ipoib_warn(priv, "failed modifying CQ (%d)"
				"(when moving to auto-moderation)\n",
				ret);
				return ret;
			}
		}
	}

	priv->ethtool.use_adaptive_rx_coalesce =
		coal->use_adaptive_rx_coalesce;


	return 0;
}

static void ipoib_get_strings(struct net_device *dev, u32 stringset, u8 *data)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	int i, index = 0;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < priv->num_rx_queues; i++) {
			sprintf(data + (index++) * ETH_GSTRING_LEN,
				"rx%d_packets", i);
			sprintf(data + (index++) * ETH_GSTRING_LEN,
				"rx%d_bytes", i);
			sprintf(data + (index++) * ETH_GSTRING_LEN,
				"rx%d_errors", i);
			sprintf(data + (index++) * ETH_GSTRING_LEN,
				"rx%d_dropped", i);
		}
		for (i = 0; i < priv->num_tx_queues; i++) {
			sprintf(data + (index++) * ETH_GSTRING_LEN,
				"tx%d_packets", i);
			sprintf(data + (index++) * ETH_GSTRING_LEN,
				"tx%d_bytes", i);
			sprintf(data + (index++) * ETH_GSTRING_LEN,
				"tx%d_errors", i);
			sprintf(data + (index++) * ETH_GSTRING_LEN,
				"tx%d_dropped", i);
		}
		break;
	}
}

static int ipoib_get_sset_count(struct net_device *dev, int sset)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	switch (sset) {
	case ETH_SS_STATS:
		return (priv->num_rx_queues + priv->num_tx_queues) * 4;
	default:
		return -EOPNOTSUPP;
	}
}

static int ipoib_get_settings(struct net_device *dev, struct ethtool_cmd *ecmd)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ib_port_attr attr;
	char *speed = "";
	int rate;/* in deci-Gb/sec */
	int ret;

	ret = ib_query_port(priv->ca, priv->port, &attr);
	if (ret)
		return ret;

	/* SUPPORTED_1000baseT_Half isn't supported */
	ecmd->supported = 0;
	ecmd->supported = SUPPORTED_1000baseT_Full
			|SUPPORTED_10000baseT_Full
			|SUPPORTED_1000baseKX_Full
			|SUPPORTED_10000baseKX4_Full
			|SUPPORTED_10000baseKR_Full
			|SUPPORTED_10000baseR_FEC
			|SUPPORTED_40000baseKR4_Full
			|SUPPORTED_40000baseCR4_Full
			|SUPPORTED_40000baseSR4_Full
			|SUPPORTED_40000baseLR4_Full;

	ecmd->advertising = ADVERTISED_1000baseT_Full
			|ADVERTISED_10000baseT_Full
			|ADVERTISED_1000baseKX_Full
			|ADVERTISED_10000baseKX4_Full
			|ADVERTISED_10000baseKR_Full
			|ADVERTISED_10000baseR_FEC
			|ADVERTISED_40000baseKR4_Full
			|ADVERTISED_40000baseCR4_Full
			|ADVERTISED_40000baseSR4_Full
			|ADVERTISED_40000baseLR4_Full;


	ecmd->duplex = DUPLEX_FULL;
	ecmd->autoneg = AUTONEG_ENABLE;
	ecmd->phy_address = 1;
	ecmd->port = PORT_OTHER;/* till define IB port type */

	ib_active_speed_enum_to_rate(attr.active_speed,
				     &rate,
				     &speed);

	rate *= ib_width_enum_to_int(attr.active_width);
	if (rate < 0)
		rate = -1;

	ethtool_cmd_speed_set(ecmd, rate * 100/*in Mb/sec*/);

	return 0;
}

static void ipoib_get_ethtool_stats(struct net_device *dev,
				struct ethtool_stats *stats, uint64_t *data)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_recv_ring *recv_ring;
	struct ipoib_send_ring *send_ring;
	int index = 0;
	int i;

	/* Get per QP stats */
	recv_ring = priv->recv_ring;
	for (i = 0; i < priv->num_rx_queues; i++) {
		struct ipoib_rx_ring_stats *rx_stats = &recv_ring->stats;
		data[index++] = rx_stats->rx_packets;
		data[index++] = rx_stats->rx_bytes;
		data[index++] = rx_stats->rx_errors;
		data[index++] = rx_stats->rx_dropped;
		recv_ring++;
	}
	send_ring = priv->send_ring;
	for (i = 0; i < priv->num_tx_queues; i++) {
		struct ipoib_tx_ring_stats *tx_stats = &send_ring->stats;
		data[index++] = tx_stats->tx_packets;
		data[index++] = tx_stats->tx_bytes;
		data[index++] = tx_stats->tx_errors;
		data[index++] = tx_stats->tx_dropped;
		send_ring++;
	}
}

static void ipoib_get_channels(struct net_device *dev,
			struct ethtool_channels *channel)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	channel->max_rx = priv->max_rx_queues;
	channel->max_tx = priv->max_tx_queues;
	channel->max_other = 0;
	channel->max_combined = priv->max_rx_queues +
				priv->max_tx_queues;
	channel->rx_count = priv->num_rx_queues;
	channel->tx_count = priv->num_tx_queues;
	channel->other_count = 0;
	channel->combined_count = priv->num_rx_queues +
				priv->num_tx_queues;
}

static int ipoib_set_channels(struct net_device *dev,
			struct ethtool_channels *channel)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	if (channel->other_count)
		return -EINVAL;

	if (channel->combined_count !=
		priv->num_rx_queues + priv->num_tx_queues)
		return -EINVAL;

	if (channel->rx_count == 0 ||
		channel->rx_count > priv->max_rx_queues)
		return -EINVAL;

	if (!is_power_of_2(channel->rx_count))
		return -EINVAL;

	if (channel->tx_count  == 0 ||
		channel->tx_count > priv->max_tx_queues)
		return -EINVAL;

	/* Nothing to do ? */
	if (channel->rx_count == priv->num_rx_queues &&
		channel->tx_count == priv->num_tx_queues)
		return 0;

	/* 1 is always O.K. */
	if (channel->tx_count > 1) {
		if (priv->hca_caps & IB_DEVICE_UD_TSS) {
			/* with HW TSS tx_count is 2^N */
			if (!is_power_of_2(channel->tx_count))
				return -EINVAL;
		} else {
			/*
			* with SW TSS tx_count = 1 + 2 ^ N,
			* 2 is not allowed, make no sense.
			* if want to disable TSS use 1.
			*/
			if (!is_power_of_2(channel->tx_count - 1) ||
			    channel->tx_count == 2)
				return -EINVAL;
		}
	}

	return ipoib_reinit(dev, channel->rx_count, channel->tx_count);
}

static const struct ethtool_ops ipoib_ethtool_ops = {
	.get_drvinfo		= ipoib_get_drvinfo,
	.set_ringparam		= ipoib_set_ring_param,
	.get_ringparam		= ipoib_get_ring_param,
	.get_coalesce		= ipoib_get_coalesce,
	.set_coalesce		= ipoib_set_coalesce,
	.get_settings		= ipoib_get_settings,
	.get_link		= ethtool_op_get_link,
	.get_strings		= ipoib_get_strings,
	.get_sset_count		= ipoib_get_sset_count,
	.get_ethtool_stats	= ipoib_get_ethtool_stats,
	.get_channels		= ipoib_get_channels,
	.set_channels		= ipoib_set_channels,
};

void ipoib_set_ethtool_ops(struct net_device *dev)
{
	SET_ETHTOOL_OPS(dev, &ipoib_ethtool_ops);
}
