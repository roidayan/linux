/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
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

#include <linux/clocksource.h>
#include "en.h"

enum {
	MLX5E_PTP_SHIFT	= 23
};

void mlx5e_fill_hwstamp(struct mlx5e_tstamp *tstamp,
			struct skb_shared_hwtstamps *hwts,
			u64 timestamp)
{
	unsigned long flags;
	u64 nsec;

	memset(hwts, 0, sizeof(struct skb_shared_hwtstamps));
	if (!tstamp->ptp)
		return;

	read_lock_irqsave(&tstamp->lock, flags);
	nsec = timecounter_cyc2time(&tstamp->clock, timestamp);
	read_unlock_irqrestore(&tstamp->lock, flags);

	hwts->hwtstamp = ns_to_ktime(nsec);
}

static int mlx5e_ptp_settime(struct ptp_clock_info *ptp,
			     const struct timespec64 *ts)
{
	struct mlx5e_tstamp *tstamp = container_of(ptp, struct mlx5e_tstamp,
						   ptp_info);
	u64 ns = timespec64_to_ns(ts);
	unsigned long flags;

	write_lock_irqsave(&tstamp->lock, flags);
	timecounter_init(&tstamp->clock, &tstamp->cycles, ns);
	write_unlock_irqrestore(&tstamp->lock, flags);

	return 0;
}

static int mlx5e_ptp_gettime(struct ptp_clock_info *ptp,
			     struct timespec64 *ts)
{
	struct mlx5e_tstamp *tstamp = container_of(ptp, struct mlx5e_tstamp,
						   ptp_info);
	u64 ns;
	unsigned long flags;

	write_lock_irqsave(&tstamp->lock, flags);
	ns = timecounter_read(&tstamp->clock);
	write_unlock_irqrestore(&tstamp->lock, flags);

	*ts = ns_to_timespec64(ns);

	return 0;
}

static int mlx5e_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct mlx5e_tstamp *tstamp = container_of(ptp, struct mlx5e_tstamp,
						   ptp_info);
	unsigned long flags;

	write_lock_irqsave(&tstamp->lock, flags);
	timecounter_adjtime(&tstamp->clock, delta);
	write_unlock_irqrestore(&tstamp->lock, flags);

	return 0;
}

static int mlx5e_ptp_adjfreq(struct ptp_clock_info *ptp, s32 delta)
{
	u64 adj;
	u32 diff;
	int neg_adj = 0;
	unsigned long flags;
	struct mlx5e_tstamp *tstamp = container_of(ptp, struct mlx5e_tstamp,
						  ptp_info);

	if (delta < 0) {
		neg_adj = 1;
		delta = -delta;
	}

	adj = tstamp->nominal_c_mult;
	adj *= delta;
	diff = div_u64(adj, 1000000000ULL);

	write_lock_irqsave(&tstamp->lock, flags);
	timecounter_read(&tstamp->clock);
	tstamp->cycles.mult = neg_adj ? tstamp->nominal_c_mult - diff :
					tstamp->nominal_c_mult + diff;
	write_unlock_irqrestore(&tstamp->lock, flags);

	return 0;
}

static const struct ptp_clock_info mlx5e_ptp_clock_info = {
	.owner		= THIS_MODULE,
	.max_adj	= 100000000,
	.n_alarm	= 0,
	.n_ext_ts	= 0,
	.n_per_out	= 0,
	.n_pins		= 0,
	.pps		= 0,
	.adjfreq	= mlx5e_ptp_adjfreq,
	.adjtime	= mlx5e_ptp_adjtime,
	.gettime64	= mlx5e_ptp_gettime,
	.settime64	= mlx5e_ptp_settime,
	.enable		= NULL,
};

static cycle_t mlx5e_read_clock(const struct cyclecounter *cc)
{
	struct mlx5e_tstamp *tstamp = container_of(cc, struct mlx5e_tstamp,
						   cycles);
	struct mlx5e_priv *priv = container_of(tstamp, struct mlx5e_priv,
					       tstamp);
	struct mlx5_core_dev *dev = priv->mdev;

	return mlx5_core_read_clock(dev) & cc->mask;
}

void mlx5e_ptp_overflow_check(struct mlx5e_priv *priv)
{
	bool timeout = time_is_before_jiffies(priv->tstamp.last_overflow_check +
					      priv->tstamp.overflow_period);
	unsigned long flags;

	if (timeout) {
		write_lock_irqsave(&priv->tstamp.lock, flags);
		timecounter_read(&priv->tstamp.clock);
		write_unlock_irqrestore(&priv->tstamp.lock, flags);
		priv->tstamp.last_overflow_check = jiffies;
	}
}

static void mlx5e_ptp_init_config(struct mlx5e_tstamp *tstamp)
{
	tstamp->hwtstamp_config.flags = 0;
	tstamp->hwtstamp_config.tx_type = HWTSTAMP_TX_OFF;
	tstamp->hwtstamp_config.rx_filter = HWTSTAMP_FILTER_NONE;
}

void mlx5e_ptp_init(struct mlx5e_priv *priv)
{
	struct net_device *netdev = priv->netdev;
	struct mlx5e_tstamp *tstamp = &priv->tstamp;
	unsigned long flags;
	u64 ns, zero = 0;

	rwlock_init(&tstamp->lock);
	mlx5e_ptp_init_config(tstamp);
	memset(&tstamp->cycles, 0, sizeof(tstamp->cycles));
	if (!MLX5_CAP_GEN(priv->mdev, device_frequency_khz)) {
		netdev_dbg(netdev, "%s: invalid device_frequency_khz. ptp_clock_register failed\n",
			   __func__);
		return;
	}
	tstamp->cycles.read = mlx5e_read_clock;
	tstamp->cycles.shift = MLX5E_PTP_SHIFT;
	tstamp->cycles.mult =
		clocksource_khz2mult(MLX5_CAP_GEN(priv->mdev,
						  device_frequency_khz),
				     tstamp->cycles.shift);
	tstamp->nominal_c_mult = tstamp->cycles.mult;
	tstamp->cycles.mask = CLOCKSOURCE_MASK(41);

	write_lock_irqsave(&tstamp->lock, flags);
	timecounter_init(&tstamp->clock, &tstamp->cycles,
			 ktime_to_ns(ktime_get_real()));
	write_unlock_irqrestore(&tstamp->lock, flags);

	/* Calculate period in seconds to call the overflow watchdog - to make
	 * sure counter is checked at least once every wrap around.
	 */
	ns = cyclecounter_cyc2ns(&tstamp->cycles, tstamp->cycles.mask, zero,
				 &zero);
	do_div(ns, NSEC_PER_SEC / 2 / HZ);
	tstamp->overflow_period = ns;

	/* Configure the PHC */
	tstamp->ptp_info = mlx5e_ptp_clock_info;
	snprintf(tstamp->ptp_info.name, 16, "mlx5 ptp");

	tstamp->ptp = ptp_clock_register(&tstamp->ptp_info,
					 &priv->mdev->pdev->dev);
	if (IS_ERR(tstamp->ptp)) {
		tstamp->ptp = NULL;
		netdev_err(netdev, "%s: ptp_clock_register failed\n",
			   __func__);
	}
}

void mlx5e_ptp_cleanup(struct mlx5e_priv *priv)
{
	if (priv->tstamp.ptp) {
		ptp_clock_unregister(priv->tstamp.ptp);
		priv->tstamp.ptp = NULL;
	}
}
