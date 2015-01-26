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
 *
 */


#include <linux/if_vlan.h>

#include <linux/mlx4/device.h>
#include <linux/mlx4/cmd.h>

#include "en_port.h"
#include "mlx4_en.h"


int mlx4_SET_VLAN_FLTR(struct mlx4_dev *dev, struct mlx4_en_priv *priv)
{
	struct mlx4_cmd_mailbox *mailbox;
	struct mlx4_set_vlan_fltr_mbox *filter;
	int i;
	int j;
	int index = 0;
	u32 entry;
	int err = 0;

	mailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	filter = mailbox->buf;
	for (i = VLAN_FLTR_SIZE - 1; i >= 0; i--) {
		entry = 0;
		for (j = 0; j < 32; j++)
			if (test_bit(index++, priv->active_vlans))
				entry |= 1 << j;
		filter->entry[i] = cpu_to_be32(entry);
	}
	err = mlx4_cmd(dev, mailbox->dma, priv->port, 0, MLX4_CMD_SET_VLAN_FLTR,
		       MLX4_CMD_TIME_CLASS_B, MLX4_CMD_WRAPPED);
	mlx4_free_cmd_mailbox(dev, mailbox);
	return err;
}

int mlx4_en_QUERY_PORT(struct mlx4_en_dev *mdev, u8 port)
{
	struct mlx4_en_query_port_context *qport_context;
	struct mlx4_en_priv *priv = netdev_priv(mdev->pndev[port]);
	struct mlx4_en_port_state *state = &priv->port_state;
	struct mlx4_cmd_mailbox *mailbox;
	int err;

	mailbox = mlx4_alloc_cmd_mailbox(mdev->dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);
	err = mlx4_cmd_box(mdev->dev, 0, mailbox->dma, port, 0,
			   MLX4_CMD_QUERY_PORT, MLX4_CMD_TIME_CLASS_B,
			   MLX4_CMD_WRAPPED);
	if (err)
		goto out;
	qport_context = mailbox->buf;

	/* This command is always accessed from Ethtool context
	 * already synchronized, no need in locking */
	state->link_state = !!(qport_context->link_up & MLX4_EN_LINK_UP_MASK);
	switch (qport_context->link_speed & MLX4_EN_SPEED_MASK) {
	case MLX4_EN_100M_SPEED:
		state->link_speed = SPEED_100;
		break;
	case MLX4_EN_1G_SPEED:
		state->link_speed = SPEED_1000;
		break;
	case MLX4_EN_10G_SPEED_XAUI:
	case MLX4_EN_10G_SPEED_XFI:
		state->link_speed = SPEED_10000;
		break;
	case MLX4_EN_20G_SPEED:
		state->link_speed = SPEED_20000;
		break;
	case MLX4_EN_40G_SPEED:
		state->link_speed = SPEED_40000;
		break;
	case MLX4_EN_56G_SPEED:
		state->link_speed = SPEED_56000;
		break;
	default:
		state->link_speed = -1;
		break;
	}

	state->transceiver = qport_context->transceiver;

	state->flags = 0; /* Reset and recalculate the port flags */
	state->flags |= (qport_context->link_up & MLX4_EN_ANC_MASK) ?
		MLX4_EN_PORT_ANC : 0;
	state->flags |= (qport_context->autoneg & MLX4_EN_AUTONEG_MASK) ?
		MLX4_EN_PORT_ANE : 0;

out:
	mlx4_free_cmd_mailbox(mdev->dev, mailbox);
	return err;
}

/* Each counter set is located in struct mlx4_en_stat_out_mbox
 * with a const offset between its prio components.
 * This function runs over a counter set and sum all of it's prio components.
 */
static unsigned long en_stats_adder(__be64 *start, __be64 *next, int num)
{
	__be64 *curr = start;
	unsigned long ret = 0;
	int i;
	int offset = next - start;

	for (i = 0; i <= num; i++) {
		ret += be64_to_cpu(*curr);
		curr += offset;
	}

	return ret;
}

int mlx4_en_DUMP_ETH_STATS(struct mlx4_en_dev *mdev, u8 port, u8 reset)
{
	struct mlx4_en_stat_out_mbox *mlx4_en_stats;
	struct mlx4_en_stat_out_flow_control_mbox *flowstats;
	struct mlx4_en_priv *priv = netdev_priv(mdev->pndev[port]);
	struct mlx4_cmd_mailbox *mailbox = NULL;
	u64 in_mod = reset << 8 | port;
	int err;
	int i;

	mailbox = mlx4_alloc_cmd_mailbox(mdev->dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);
	err = mlx4_cmd_box(mdev->dev, 0, mailbox->dma, in_mod, 0,
			   MLX4_CMD_DUMP_ETH_STATS, MLX4_CMD_TIME_CLASS_B,
			   MLX4_CMD_WRAPPED);
	if (err)
		goto out;

	mlx4_en_stats = mailbox->buf;

	spin_lock_bh(&priv->stats_lock);

	priv->port_stats.rx_chksum_good = 0;
	priv->port_stats.rx_chksum_none = 0;
	priv->port_stats.rx_chksum_complete = 0;
	for (i = 0; i < priv->rx_ring_num; i++) {
		priv->port_stats.rx_chksum_good += priv->rx_ring[i]->csum_ok;
		priv->port_stats.rx_chksum_none += priv->rx_ring[i]->csum_none;
		priv->port_stats.rx_chksum_complete += priv->rx_ring[i]->csum_complete;
	}
	priv->port_stats.tx_chksum_offload = 0;
	priv->port_stats.tx_queue_stopped = 0;
	priv->port_stats.tx_wake_queue = 0;
	priv->port_stats.tx_tso_packets = 0;
	priv->port_stats.xmit_more = 0;

	for (i = 0; i < priv->tx_ring_num; i++) {
		priv->port_stats.tx_chksum_offload += priv->tx_ring[i]->tx_csum;
		priv->port_stats.tx_queue_stopped +=
				priv->tx_ring[i]->queue_stopped;
		priv->port_stats.tx_wake_queue	+= priv->tx_ring[i]->wake_queue;
		priv->port_stats.tx_tso_packets	+=
				priv->tx_ring[i]->tso_packets;
		priv->port_stats.xmit_more	+= priv->tx_ring[i]->xmit_more;
	}
	/* RX Statistics */
	priv->pkstats.rx_packets =
		en_stats_adder(&mlx4_en_stats->RTOT_prio_0,
			       &mlx4_en_stats->RTOT_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.rx_bytes =
		en_stats_adder(&mlx4_en_stats->ROCT_prio_0,
			       &mlx4_en_stats->ROCT_prio_1,
			       NUM_PRIORITIES);

	priv->pkstats.rx_multicast_packets =
		en_stats_adder(&mlx4_en_stats->MCAST_prio_0,
			       &mlx4_en_stats->MCAST_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.rx_broadcast_packets =
		en_stats_adder(&mlx4_en_stats->RBCAST_prio_0,
			       &mlx4_en_stats->RBCAST_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.rx_errors = be64_to_cpu(mlx4_en_stats->PCS) +
		be32_to_cpu(mlx4_en_stats->RJBBR) +
		be32_to_cpu(mlx4_en_stats->RCRC) +
		be32_to_cpu(mlx4_en_stats->RRUNT) +
		be64_to_cpu(mlx4_en_stats->RInRangeLengthErr) +
		be64_to_cpu(mlx4_en_stats->ROutRangeLengthErr) +
		be32_to_cpu(mlx4_en_stats->RSHORT) +
		en_stats_adder(&mlx4_en_stats->RGIANT_prio_0,
			       &mlx4_en_stats->RGIANT_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.rx_dropped = be32_to_cpu(mlx4_en_stats->RdropOvflw);
	priv->pkstats.rx_length_errors =
		be32_to_cpu(mlx4_en_stats->RdropLength);
	priv->pkstats.rx_over_errors = be32_to_cpu(mlx4_en_stats->RdropOvflw);
	priv->pkstats.rx_crc_errors = be32_to_cpu(mlx4_en_stats->RCRC);
	priv->pkstats.rx_jabbers = be32_to_cpu(mlx4_en_stats->RJBBR);
	priv->pkstats.rx_in_range_length_error =
		be64_to_cpu(mlx4_en_stats->RInRangeLengthErr);
	priv->pkstats.rx_out_range_length_error =
		be64_to_cpu(mlx4_en_stats->ROutRangeLengthErr);
	priv->pkstats.rx_lt_64_bytes_packets =
		en_stats_adder(&mlx4_en_stats->R64_prio_0,
			       &mlx4_en_stats->R64_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.rx_127_bytes_packets =
		en_stats_adder(&mlx4_en_stats->R127_prio_0,
			       &mlx4_en_stats->R127_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.rx_255_bytes_packets =
		en_stats_adder(&mlx4_en_stats->R255_prio_0,
			       &mlx4_en_stats->R255_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.rx_511_bytes_packets =
		en_stats_adder(&mlx4_en_stats->R511_prio_0,
			       &mlx4_en_stats->R511_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.rx_1023_bytes_packets =
		en_stats_adder(&mlx4_en_stats->R1023_prio_0,
			       &mlx4_en_stats->R1023_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.rx_1518_bytes_packets =
		en_stats_adder(&mlx4_en_stats->R1518_prio_0,
			       &mlx4_en_stats->R1518_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.rx_1522_bytes_packets =
		en_stats_adder(&mlx4_en_stats->R1522_prio_0,
			       &mlx4_en_stats->R1522_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.rx_1548_bytes_packets =
		en_stats_adder(&mlx4_en_stats->R1548_prio_0,
			       &mlx4_en_stats->R1548_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.rx_gt_1548_bytes_packets =
		en_stats_adder(&mlx4_en_stats->R2MTU_prio_0,
			       &mlx4_en_stats->R2MTU_prio_1,
			       NUM_PRIORITIES);

	/* Tx Stats */
	priv->pkstats.tx_packets =
		en_stats_adder(&mlx4_en_stats->TTOT_prio_0,
			       &mlx4_en_stats->TTOT_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.tx_bytes =
		en_stats_adder(&mlx4_en_stats->TOCT_prio_0,
			       &mlx4_en_stats->TOCT_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.tx_multicast_packets =
		en_stats_adder(&mlx4_en_stats->TMCAST_prio_0,
			       &mlx4_en_stats->TMCAST_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.tx_broadcast_packets =
		en_stats_adder(&mlx4_en_stats->TBCAST_prio_0,
			       &mlx4_en_stats->TBCAST_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.tx_errors =
		en_stats_adder(&mlx4_en_stats->TGIANT_prio_0,
			       &mlx4_en_stats->TGIANT_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.tx_dropped = be32_to_cpu(mlx4_en_stats->TDROP) -
		priv->pkstats.tx_errors;
	priv->pkstats.tx_lt_64_bytes_packets =
		en_stats_adder(&mlx4_en_stats->T64_prio_0,
			       &mlx4_en_stats->T64_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.tx_127_bytes_packets =
		en_stats_adder(&mlx4_en_stats->T127_prio_0,
			       &mlx4_en_stats->T127_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.tx_255_bytes_packets =
		en_stats_adder(&mlx4_en_stats->T255_prio_0,
			       &mlx4_en_stats->T255_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.tx_511_bytes_packets =
		en_stats_adder(&mlx4_en_stats->T511_prio_0,
			       &mlx4_en_stats->T511_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.tx_1023_bytes_packets =
		en_stats_adder(&mlx4_en_stats->T1023_prio_0,
			       &mlx4_en_stats->T1023_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.tx_1518_bytes_packets =
		en_stats_adder(&mlx4_en_stats->T1518_prio_0,
			       &mlx4_en_stats->T1518_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.tx_1522_bytes_packets =
		en_stats_adder(&mlx4_en_stats->T1522_prio_0,
			       &mlx4_en_stats->T1522_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.tx_1548_bytes_packets =
		en_stats_adder(&mlx4_en_stats->T1548_prio_0,
			       &mlx4_en_stats->T1548_prio_1,
			       NUM_PRIORITIES);
	priv->pkstats.tx_gt_1548_bytes_packets =
		en_stats_adder(&mlx4_en_stats->T2MTU_prio_0,
			       &mlx4_en_stats->T2MTU_prio_1,
			       NUM_PRIORITIES);

	priv->pkstats.rx_prio[0][0] = be64_to_cpu(mlx4_en_stats->RTOT_prio_0);
	priv->pkstats.rx_prio[0][1] = be64_to_cpu(mlx4_en_stats->ROCT_prio_0);
	priv->pkstats.rx_prio[1][0] = be64_to_cpu(mlx4_en_stats->RTOT_prio_1);
	priv->pkstats.rx_prio[1][1] = be64_to_cpu(mlx4_en_stats->ROCT_prio_1);
	priv->pkstats.rx_prio[2][0] = be64_to_cpu(mlx4_en_stats->RTOT_prio_2);
	priv->pkstats.rx_prio[2][1] = be64_to_cpu(mlx4_en_stats->ROCT_prio_2);
	priv->pkstats.rx_prio[3][0] = be64_to_cpu(mlx4_en_stats->RTOT_prio_3);
	priv->pkstats.rx_prio[3][1] = be64_to_cpu(mlx4_en_stats->ROCT_prio_3);
	priv->pkstats.rx_prio[4][0] = be64_to_cpu(mlx4_en_stats->RTOT_prio_4);
	priv->pkstats.rx_prio[4][1] = be64_to_cpu(mlx4_en_stats->ROCT_prio_4);
	priv->pkstats.rx_prio[5][0] = be64_to_cpu(mlx4_en_stats->RTOT_prio_5);
	priv->pkstats.rx_prio[5][1] = be64_to_cpu(mlx4_en_stats->ROCT_prio_5);
	priv->pkstats.rx_prio[6][0] = be64_to_cpu(mlx4_en_stats->RTOT_prio_6);
	priv->pkstats.rx_prio[6][1] = be64_to_cpu(mlx4_en_stats->ROCT_prio_6);
	priv->pkstats.rx_prio[7][0] = be64_to_cpu(mlx4_en_stats->RTOT_prio_7);
	priv->pkstats.rx_prio[7][1] = be64_to_cpu(mlx4_en_stats->ROCT_prio_7);
	priv->pkstats.rx_prio[8][0] = be64_to_cpu(mlx4_en_stats->RTOT_novlan);
	priv->pkstats.rx_prio[8][1] = be64_to_cpu(mlx4_en_stats->ROCT_novlan);
	priv->pkstats.tx_prio[0][0] = be64_to_cpu(mlx4_en_stats->TTOT_prio_0);
	priv->pkstats.tx_prio[0][1] = be64_to_cpu(mlx4_en_stats->TOCT_prio_0);
	priv->pkstats.tx_prio[1][0] = be64_to_cpu(mlx4_en_stats->TTOT_prio_1);
	priv->pkstats.tx_prio[1][1] = be64_to_cpu(mlx4_en_stats->TOCT_prio_1);
	priv->pkstats.tx_prio[2][0] = be64_to_cpu(mlx4_en_stats->TTOT_prio_2);
	priv->pkstats.tx_prio[2][1] = be64_to_cpu(mlx4_en_stats->TOCT_prio_2);
	priv->pkstats.tx_prio[3][0] = be64_to_cpu(mlx4_en_stats->TTOT_prio_3);
	priv->pkstats.tx_prio[3][1] = be64_to_cpu(mlx4_en_stats->TOCT_prio_3);
	priv->pkstats.tx_prio[4][0] = be64_to_cpu(mlx4_en_stats->TTOT_prio_4);
	priv->pkstats.tx_prio[4][1] = be64_to_cpu(mlx4_en_stats->TOCT_prio_4);
	priv->pkstats.tx_prio[5][0] = be64_to_cpu(mlx4_en_stats->TTOT_prio_5);
	priv->pkstats.tx_prio[5][1] = be64_to_cpu(mlx4_en_stats->TOCT_prio_5);
	priv->pkstats.tx_prio[6][0] = be64_to_cpu(mlx4_en_stats->TTOT_prio_6);
	priv->pkstats.tx_prio[6][1] = be64_to_cpu(mlx4_en_stats->TOCT_prio_6);
	priv->pkstats.tx_prio[7][0] = be64_to_cpu(mlx4_en_stats->TTOT_prio_7);
	priv->pkstats.tx_prio[7][1] = be64_to_cpu(mlx4_en_stats->TOCT_prio_7);
	priv->pkstats.tx_prio[8][0] = be64_to_cpu(mlx4_en_stats->TTOT_novlan);
	priv->pkstats.tx_prio[8][1] = be64_to_cpu(mlx4_en_stats->TOCT_novlan);

	spin_unlock_bh(&priv->stats_lock);

	/* 0xffs indicates invalid value */
	memset(mailbox->buf, 0xff, sizeof(*flowstats) * MLX4_NUM_PRIORITIES);

	if (mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_FLOWSTATS_EN) {
		memset(mailbox->buf, 0,
		       sizeof(*flowstats) * MLX4_NUM_PRIORITIES);
		err = mlx4_cmd_box(mdev->dev, 0, mailbox->dma,
				   in_mod | MLX4_DUMP_ETH_STATS_FLOW_CONTROL,
				   0, MLX4_CMD_DUMP_ETH_STATS,
				   MLX4_CMD_TIME_CLASS_B, MLX4_CMD_WRAPPED);
		if (err)
			goto out;
	}

	flowstats = mailbox->buf;

	spin_lock_bh(&priv->stats_lock);

	for (i = 0; i < MLX4_NUM_PRIORITIES; i++)	{
		priv->flowstats[i].rx_pause =
			be64_to_cpu(flowstats[i].rx_pause);
		priv->flowstats[i].rx_pause_duration =
			be64_to_cpu(flowstats[i].rx_pause_duration);
		priv->flowstats[i].rx_pause_transition =
			be64_to_cpu(flowstats[i].rx_pause_transition);
		priv->flowstats[i].tx_pause =
			be64_to_cpu(flowstats[i].tx_pause);
		priv->flowstats[i].tx_pause_duration =
			be64_to_cpu(flowstats[i].tx_pause_duration);
		priv->flowstats[i].tx_pause_transition =
			be64_to_cpu(flowstats[i].tx_pause_transition);
	}

	if (!mlx4_is_mfunc(mdev->dev)) {
		/* netdevice stats format */
		priv->stats.rx_packets = priv->pkstats.rx_packets;
		priv->stats.tx_packets = priv->pkstats.tx_packets;
		priv->stats.rx_bytes = priv->pkstats.rx_bytes;
		priv->stats.tx_bytes = priv->pkstats.tx_bytes;
		priv->stats.rx_errors = priv->pkstats.rx_errors;
		priv->stats.rx_dropped = priv->pkstats.rx_dropped;
		priv->stats.tx_dropped = priv->pkstats.tx_dropped;
		priv->stats.multicast = priv->pkstats.rx_multicast_packets;
		priv->stats.rx_length_errors = priv->pkstats.rx_length_errors;
		priv->stats.rx_over_errors = priv->pkstats.rx_over_errors;
		priv->stats.rx_crc_errors = priv->pkstats.rx_crc_errors;
	}

	spin_unlock_bh(&priv->stats_lock);

out:
	mlx4_free_cmd_mailbox(mdev->dev, mailbox);
	return err;
}

