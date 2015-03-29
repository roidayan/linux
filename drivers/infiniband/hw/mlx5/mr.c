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


#include <linux/kref.h>
#include <linux/random.h>
#include <linux/debugfs.h>
#include <linux/export.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/sysfs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_umem_odp.h>
#include <rdma/ib_verbs.h>
#include "mlx5_ib.h"

enum {
	MAX_PENDING_REG_MR = 8,
};

#define MLX5_UMR_ALIGN 2048
#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
static __be64 mlx5_ib_update_mtt_emergency_buffer[
		MLX5_UMR_MTT_MIN_CHUNK_SIZE/sizeof(__be64)]
	__aligned(MLX5_UMR_ALIGN);
static DEFINE_MUTEX(mlx5_ib_update_mtt_emergency_buffer_mutex);
#endif

static int mlx5_mr_sysfs_init(struct mlx5_ib_dev *dev);
static void mlx5_mr_sysfs_cleanup(struct mlx5_ib_dev *dev);

static int destroy_mkey(struct mlx5_ib_dev *dev, struct mlx5_ib_mr *mr)
{
	int err = mlx5_core_destroy_mkey(dev->mdev, &mr->mmr);

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	/* Wait until all page fault handlers using the mr complete. */
	synchronize_srcu(&dev->mr_srcu);
#endif

	return err;
}

static int order2idx(struct mlx5_ib_dev *dev, int order)
{
	struct mlx5_mr_cache *cache = &dev->cache;

	if (order < cache->ent[0].order)
		return 0;
	else
		return order - cache->ent[0].order;
}

static void reg_mr_callback(int status, void *context)
{
	struct mlx5_ib_mr *mr = context;
	struct mlx5_ib_dev *dev = mr->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	int c = order2idx(dev, mr->order);
	struct mlx5_cache_ent *ent = &cache->ent[c];
	u8 key;
	unsigned long flags;
	struct mlx5_mr_table *table = &dev->mdev->priv.mr_table;
	int err;

	spin_lock_irqsave(&ent->lock, flags);
	ent->pending--;
	spin_unlock_irqrestore(&ent->lock, flags);
	if (status) {
		mlx5_ib_warn(dev, "async reg mr failed. status %d\n", status);
		kfree(mr);
		dev->fill_delay = 1;
		mod_timer(&dev->delay_timer, jiffies + HZ);
		return;
	}

	if (mr->out.hdr.status) {
		mlx5_ib_warn(dev, "failed - status %d, syndorme 0x%x\n",
			     mr->out.hdr.status,
			     be32_to_cpu(mr->out.hdr.syndrome));
		kfree(mr);
		dev->fill_delay = 1;
		mod_timer(&dev->delay_timer, jiffies + HZ);
		return;
	}

	spin_lock_irqsave(&dev->mdev->priv.mkey_lock, flags);
	key = dev->mdev->priv.mkey_key++;
	spin_unlock_irqrestore(&dev->mdev->priv.mkey_lock, flags);
	mr->mmr.key = mlx5_idx_to_mkey(be32_to_cpu(mr->out.mkey) & 0xffffff) | key;

	cache->last_add = jiffies;

	spin_lock_irqsave(&ent->lock, flags);
	list_add_tail(&mr->list, &ent->head);
	ent->cur++;
	ent->size++;
	spin_unlock_irqrestore(&ent->lock, flags);

	write_lock_irqsave(&table->lock, flags);
	err = radix_tree_insert(&table->tree, mlx5_base_mkey(mr->mmr.key),
				&mr->mmr);
	if (err)
		pr_err("Error inserting to mr tree. 0x%x\n", -err);
	write_unlock_irqrestore(&table->lock, flags);
}

static int add_keys(struct mlx5_ib_dev *dev, int c, int num)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[c];
	struct mlx5_create_mkey_mbox_in *in;
	struct mlx5_ib_mr *mr;
	int npages = 1 << ent->order;
	int err = 0;
	int i;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	for (i = 0; i < num; i++) {
		if (ent->pending >= MAX_PENDING_REG_MR) {
			err = -EAGAIN;
			break;
		}

		mr = kzalloc(sizeof(*mr), GFP_KERNEL);
		if (!mr) {
			err = -ENOMEM;
			break;
		}
		mr->order = ent->order;
		mr->umred = 1;
		mr->dev = dev;
		in->seg.status = MLX5_MKEY_STATUS_FREE;
		in->seg.xlt_oct_size = cpu_to_be32((npages + 1) / 2);
		in->seg.qpn_mkey7_0 = cpu_to_be32(0xffffff << 8);
		in->seg.flags = MLX5_ACCESS_MODE_MTT | MLX5_PERM_UMR_EN;
		in->seg.log2_page_size = 12;

		spin_lock_irq(&ent->lock);
		ent->pending++;
		spin_unlock_irq(&ent->lock);
		err = mlx5_core_create_mkey(dev->mdev, &mr->mmr, in,
					    sizeof(*in), reg_mr_callback,
					    mr, &mr->out);
		if (err) {
			spin_lock_irq(&ent->lock);
			ent->pending--;
			spin_unlock_irq(&ent->lock);
			mlx5_ib_warn(dev, "create mkey failed %d\n", err);
			kfree(mr);
			break;
		}
	}

	kfree(in);
	return err;
}

static void remove_keys(struct mlx5_ib_dev *dev, int c, int num)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[c];
	struct mlx5_ib_mr *mr;
	int err;
	int i;

	for (i = 0; i < num; i++) {
		spin_lock_irq(&ent->lock);
		if (list_empty(&ent->head)) {
			spin_unlock_irq(&ent->lock);
			return;
		}
		mr = list_first_entry(&ent->head, struct mlx5_ib_mr, list);
		list_del(&mr->list);
		ent->cur--;
		ent->size--;
		spin_unlock_irq(&ent->lock);
		err = destroy_mkey(dev, mr);
		if (err)
			mlx5_ib_warn(dev, "failed destroy mkey\n");
		else
			kfree(mr);
	}
}

static int someone_adding(struct mlx5_mr_cache *cache)
{
	int i;

	for (i = 0; i < MAX_MR_CACHE_ENTRIES; i++) {
		if (cache->ent[i].cur < cache->ent[i].limit)
			return 1;
	}

	return 0;
}

static void __cache_work_func(struct mlx5_cache_ent *ent)
{
	struct mlx5_ib_dev *dev = ent->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	int i = order2idx(dev, ent->order);
	int err;

	if (cache->stopped)
		return;

	ent = &dev->cache.ent[i];
	if (ent->cur < 2 * ent->limit && !dev->fill_delay) {
		err = add_keys(dev, i, 1);
		if (ent->cur < 2 * ent->limit) {
			if (err == -EAGAIN) {
				mlx5_ib_dbg(dev, "returned eagain, order %d\n",
					    i + 2);
				queue_delayed_work(cache->wq, &ent->dwork,
						   msecs_to_jiffies(3));
			} else if (err) {
				mlx5_ib_warn(dev, "command failed order %d, err %d\n",
					     i + 2, err);
				queue_delayed_work(cache->wq, &ent->dwork,
						   msecs_to_jiffies(1000));
			} else {
				queue_work(cache->wq, &ent->work);
			}
		}
	} else if (ent->cur > 2 * ent->limit) {
		if (!someone_adding(cache) &&
		    time_after(jiffies, cache->last_add + 300 * HZ)) {
			remove_keys(dev, i, 1);
			if (ent->cur > ent->limit)
				queue_work(cache->wq, &ent->work);
		} else {
			queue_delayed_work(cache->wq, &ent->dwork, 300 * HZ);
		}
	}
}

static void delayed_cache_work_func(struct work_struct *work)
{
	struct mlx5_cache_ent *ent;

	ent = container_of(work, struct mlx5_cache_ent, dwork.work);
	__cache_work_func(ent);
}

static void cache_work_func(struct work_struct *work)
{
	struct mlx5_cache_ent *ent;

	ent = container_of(work, struct mlx5_cache_ent, work);
	__cache_work_func(ent);
}

static struct mlx5_ib_mr *alloc_cached_mr(struct mlx5_ib_dev *dev, int order)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_ib_mr *mr = NULL;
	struct mlx5_cache_ent *ent;
	int c;
	int i;

	c = order2idx(dev, order);
	if (c < 0 || c >= MAX_MR_CACHE_ENTRIES) {
		mlx5_ib_warn(dev, "order %d, cache index %d\n", order, c);
		return NULL;
	}

	for (i = c; i < MAX_MR_CACHE_ENTRIES; i++) {
		ent = &cache->ent[i];

		mlx5_ib_dbg(dev, "order %d, cache index %d\n", ent->order, i);

		spin_lock_irq(&ent->lock);
		if (!list_empty(&ent->head)) {
			mr = list_first_entry(&ent->head, struct mlx5_ib_mr,
					      list);
			list_del(&mr->list);
			ent->cur--;
			spin_unlock_irq(&ent->lock);
			if (ent->cur < ent->limit)
				queue_work(cache->wq, &ent->work);
			break;
		}
		spin_unlock_irq(&ent->lock);

		queue_work(cache->wq, &ent->work);

		if (mr)
			break;
	}

	if (!mr)
		cache->ent[c].miss++;

	return mr;
}

static void free_cached_mr(struct mlx5_ib_dev *dev, struct mlx5_ib_mr *mr)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent;
	int shrink = 0;
	int c;

	c = order2idx(dev, mr->order);
	if (c < 0 || c >= MAX_MR_CACHE_ENTRIES) {
		mlx5_ib_warn(dev, "order %d, cache index %d\n", mr->order, c);
		return;
	}
	ent = &cache->ent[c];
	spin_lock_irq(&ent->lock);
	list_add_tail(&mr->list, &ent->head);
	ent->cur++;
	if (ent->cur > 2 * ent->limit)
		shrink = 1;
	spin_unlock_irq(&ent->lock);

	if (shrink)
		queue_work(cache->wq, &ent->work);
}

static void clean_keys(struct mlx5_ib_dev *dev, int c)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[c];
	struct mlx5_ib_mr *mr;
	int err;

	cancel_delayed_work(&ent->dwork);
	while (1) {
		spin_lock_irq(&ent->lock);
		if (list_empty(&ent->head)) {
			spin_unlock_irq(&ent->lock);
			return;
		}
		mr = list_first_entry(&ent->head, struct mlx5_ib_mr, list);
		list_del(&mr->list);
		ent->cur--;
		ent->size--;
		spin_unlock_irq(&ent->lock);
		err = destroy_mkey(dev, mr);
		if (err)
			mlx5_ib_warn(dev, "failed destroy mkey\n");
		else
			kfree(mr);
	}
}

static void delay_time_func(unsigned long ctx)
{
	struct mlx5_ib_dev *dev = (struct mlx5_ib_dev *)ctx;

	dev->fill_delay = 0;
}

int mlx5_mr_cache_init(struct mlx5_ib_dev *dev)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent;
	int limit;
	int err;
	int i;

	cache->wq = create_singlethread_workqueue("mkey_cache");
	if (!cache->wq) {
		mlx5_ib_warn(dev, "failed to create work queue\n");
		return -ENOMEM;
	}

	setup_timer(&dev->delay_timer, delay_time_func, (unsigned long)dev);
	for (i = 0; i < MAX_MR_CACHE_ENTRIES; i++) {
		INIT_LIST_HEAD(&cache->ent[i].head);
		spin_lock_init(&cache->ent[i].lock);

		ent = &cache->ent[i];
		INIT_LIST_HEAD(&ent->head);
		spin_lock_init(&ent->lock);
		ent->order = i + 2;
		ent->dev = dev;

		if (dev->mdev->profile->mask & MLX5_PROF_MASK_MR_CACHE)
			limit = dev->mdev->profile->mr_cache[i].limit;
		else
			limit = 0;

		INIT_WORK(&ent->work, cache_work_func);
		INIT_DELAYED_WORK(&ent->dwork, delayed_cache_work_func);
		ent->limit = limit;
		queue_work(cache->wq, &ent->work);
	}

	err = mlx5_mr_sysfs_init(dev);
	if (err)
		mlx5_ib_warn(dev, "failed to init mr cache sysfs\n");

	return 0;
}

int mlx5_mr_cache_cleanup(struct mlx5_ib_dev *dev)
{
	int i;

	dev->cache.stopped = 1;
	flush_workqueue(dev->cache.wq);

	mlx5_mr_sysfs_cleanup(dev);

	for (i = 0; i < MAX_MR_CACHE_ENTRIES; i++)
		clean_keys(dev, i);

	destroy_workqueue(dev->cache.wq);
	del_timer_sync(&dev->delay_timer);

	return 0;
}

struct ib_mr *mlx5_ib_get_dma_mr(struct ib_pd *pd, int acc)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_core_dev *mdev = dev->mdev;
	struct mlx5_create_mkey_mbox_in *in;
	struct mlx5_mkey_seg *seg;
	struct mlx5_ib_mr *mr;
	int err;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_free;
	}

	seg = &in->seg;
	seg->flags = convert_access(acc) | MLX5_ACCESS_MODE_PA;
	seg->flags_pd = cpu_to_be32(to_mpd(pd)->pdn | MLX5_MKEY_LEN64);
	seg->qpn_mkey7_0 = cpu_to_be32(0xffffff << 8);
	seg->start_addr = 0;

	err = mlx5_core_create_mkey(mdev, &mr->mmr, in, sizeof(*in), NULL, NULL,
				    NULL);
	if (err)
		goto err_in;

	kfree(in);
	mr->ibmr.lkey = mr->mmr.key;
	mr->ibmr.rkey = mr->mmr.key;
	mr->umem = NULL;

	return &mr->ibmr;

err_in:
	kfree(in);

err_free:
	kfree(mr);

	return ERR_PTR(err);
}

static int get_octo_len(u64 addr, u64 len, int page_size)
{
	u64 offset;
	int npages;

	offset = addr & (page_size - 1);
	npages = ALIGN(len + offset, page_size) >> ilog2(page_size);
	return (npages + 1) / 2;
}

static int use_umr(int order)
{
	return order <= MLX5_MAX_UMR_SHIFT;
}

static int use_klm(int order)
{
	return order <= 31;
}

static void prep_umr_reg_wqe(struct ib_pd *pd, struct ib_send_wr *wr,
			     struct ib_sge *sg, u64 dma, int n, u32 key,
			     int page_shift, u64 virt_addr, u64 len,
			     int access_flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct ib_mr *mr = dev->umrc.mr;
	struct mlx5_umr_wr *umrwr = (struct mlx5_umr_wr *)&wr->wr.fast_reg;

	sg->addr = dma;
	sg->length = ALIGN(sizeof(u64) * n, 64);
	sg->lkey = mr->lkey;

	wr->next = NULL;
	wr->send_flags = 0;
	wr->sg_list = sg;
	if (n)
		wr->num_sge = 1;
	else
		wr->num_sge = 0;

	wr->opcode = MLX5_IB_WR_UMR;

	umrwr->npages = n;
	umrwr->page_shift = page_shift;
	umrwr->mkey = key;
	umrwr->target.virt_addr = virt_addr;
	umrwr->length = len;
	umrwr->access_flags = access_flags;
	umrwr->pd = pd;
}

static void prep_umr_unreg_wqe(struct mlx5_ib_dev *dev,
			       struct ib_send_wr *wr, u32 key)
{
	struct mlx5_umr_wr *umrwr = (struct mlx5_umr_wr *)&wr->wr.fast_reg;

	wr->send_flags = MLX5_IB_SEND_UMR_UNREG | MLX5_IB_SEND_UMR_FAIL_IF_FREE;
	wr->opcode = MLX5_IB_WR_UMR;
	umrwr->mkey = key;
}

void mlx5_umr_cq_handler(struct ib_cq *cq, void *cq_context)
{
	struct mlx5_ib_umr_context *context;
	struct ib_wc wc;
	int err;

	while (1) {
		err = ib_poll_cq(cq, 1, &wc);
		if (err < 0) {
			pr_warn("poll cq error %d\n", err);
			return;
		}
		if (err == 0)
			break;

		context = (struct mlx5_ib_umr_context *) (unsigned long) wc.wr_id;
		context->status = wc.status;
		complete(&context->done);
	}
	ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
}

static struct mlx5_ib_mr *reg_umr(struct ib_pd *pd, struct ib_umem *umem,
				  u64 virt_addr, u64 len, int npages,
				  int page_shift, int order, int access_flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct device *ddev = dev->ib_dev.dma_device;
	struct umr_common *umrc = &dev->umrc;
	struct mlx5_ib_umr_context umr_context;
	struct ib_send_wr wr, *bad;
	struct mlx5_ib_mr *mr;
	struct ib_sge sg;
	int size;
	__be64 *mr_pas;
	__be64 *pas;
	dma_addr_t dma;
	int err = 0;
	int i;

	for (i = 0; i < 1; i++) {
		mr = alloc_cached_mr(dev, order);
		if (mr)
			break;

		err = add_keys(dev, order2idx(dev, order), 1);
		if (err && err != -EAGAIN) {
			mlx5_ib_warn(dev, "add_keys failed, err %d\n", err);
			break;
		}
	}

	if (!mr)
		return ERR_PTR(-EAGAIN);

	/* UMR copies MTTs in units of MLX5_UMR_MTT_ALIGNMENT bytes.
	 * To avoid copying garbage after the pas array, we allocate
	 * a little more. */
	size = ALIGN(sizeof(u64) * npages, MLX5_UMR_MTT_ALIGNMENT);
	mr_pas = kmalloc(size + MLX5_UMR_ALIGN - 1, GFP_KERNEL);
	if (!mr_pas) {
		err = -ENOMEM;
		goto free_mr;
	}

	pas = PTR_ALIGN(mr_pas, MLX5_UMR_ALIGN);
	mlx5_ib_populate_pas(dev, umem, page_shift, pas, MLX5_IB_MTT_PRESENT);
	/* Clear padding after the actual pages. */
	memset(pas + npages, 0, size - npages * sizeof(u64));

	dma = dma_map_single(ddev, pas, size, DMA_TO_DEVICE);
	if (dma_mapping_error(ddev, dma)) {
		err = -ENOMEM;
		goto free_pas;
	}

	memset(&wr, 0, sizeof(wr));
	wr.wr_id = (u64)(unsigned long)&umr_context;
	prep_umr_reg_wqe(pd, &wr, &sg, dma, npages, mr->mmr.key, page_shift,
			 virt_addr, len, access_flags);

	mlx5_ib_init_umr_context(&umr_context);
	down(&umrc->sem);
	err = ib_post_send(umrc->qp, &wr, &bad);
	if (err) {
		mlx5_ib_warn(dev, "post send failed, err %d\n", err);
		goto unmap_dma;
	} else {
		wait_for_completion(&umr_context.done);
		if (umr_context.status != IB_WC_SUCCESS) {
			mlx5_ib_warn(dev, "reg umr failed\n");
			err = -EFAULT;
		}
	}

	mr->mmr.iova = virt_addr;
	mr->mmr.size = len;
	mr->mmr.pd = to_mpd(pd)->pdn;

	mr->live = 1;

unmap_dma:
	up(&umrc->sem);
	dma_unmap_single(ddev, dma, size, DMA_TO_DEVICE);

free_pas:
	kfree(mr_pas);

free_mr:
	if (err) {
		free_cached_mr(dev, mr);
		return ERR_PTR(err);
	}

	return mr;
}

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
int mlx5_ib_update_mtt(struct mlx5_ib_mr *mr, u64 start_page_index, int npages,
		       int zap)
{
	struct mlx5_ib_dev *dev = mr->dev;
	struct device *ddev = dev->ib_dev.dma_device;
	struct umr_common *umrc = &dev->umrc;
	struct mlx5_ib_umr_context umr_context;
	struct ib_umem *umem = mr->umem;
	int size;
	__be64 *pas;
	dma_addr_t dma;
	struct ib_send_wr wr, *bad;
	struct mlx5_umr_wr *umrwr = (struct mlx5_umr_wr *)&wr.wr.fast_reg;
	struct ib_sge sg;
	int err = 0;
	const int page_index_alignment = MLX5_UMR_MTT_ALIGNMENT / sizeof(u64);
	const int page_index_mask = page_index_alignment - 1;
	size_t pages_mapped = 0;
	size_t pages_to_map = 0;
	size_t pages_iter = 0;
	int use_emergency_buf = 0;

	/* UMR copies MTTs in units of MLX5_UMR_MTT_ALIGNMENT bytes,
	 * so we need to align the offset and length accordingly */
	if (start_page_index & page_index_mask) {
		npages += start_page_index & page_index_mask;
		start_page_index &= ~page_index_mask;
	}

	pages_to_map = ALIGN(npages, page_index_alignment);

	if (start_page_index + pages_to_map > MLX5_MAX_UMR_PAGES)
		return -EINVAL;

	size = sizeof(u64) * pages_to_map;
	size = min_t(int, PAGE_SIZE, size);
	/* We allocate with GFP_ATOMIC to avoid recursion into page-reclaim
	 * code, when we are called from an invalidation. The pas buffer must
	 * be 2k-aligned for Connect-IB. */
	pas = (__be64 *)get_zeroed_page(GFP_ATOMIC);
	if (!pas) {
		mlx5_ib_warn(dev, "unable to allocate memory during MTT update, falling back to slower chunked mechanism.\n");
		pas = mlx5_ib_update_mtt_emergency_buffer;
		size = MLX5_UMR_MTT_MIN_CHUNK_SIZE;
		use_emergency_buf = 1;
		mutex_lock(&mlx5_ib_update_mtt_emergency_buffer_mutex);
		memset(pas, 0, size);
	}
	pages_iter = size / sizeof(u64);
	dma = dma_map_single(ddev, pas, size, DMA_TO_DEVICE);
	if (dma_mapping_error(ddev, dma)) {
		mlx5_ib_err(dev, "unable to map DMA during MTT update.\n");
		err = -ENOMEM;
		goto free_pas;
	}

	for (pages_mapped = 0;
	     pages_mapped < pages_to_map && !err;
	     pages_mapped += pages_iter, start_page_index += pages_iter) {
		dma_sync_single_for_cpu(ddev, dma, size, DMA_TO_DEVICE);

		npages = min_t(size_t,
			       pages_iter,
			       ib_umem_num_pages(umem) - start_page_index);

		if (!zap) {
			__mlx5_ib_populate_pas(dev, umem, PAGE_SHIFT,
					       start_page_index, npages, pas,
					       MLX5_IB_MTT_PRESENT);
			/* Clear padding after the pages brought from the
			 * umem. */
			memset(pas + npages, 0, size - npages * sizeof(u64));
		}

		dma_sync_single_for_device(ddev, dma, size, DMA_TO_DEVICE);

		memset(&wr, 0, sizeof(wr));
		wr.wr_id = (u64)(unsigned long)&umr_context;

		sg.addr = dma;
		sg.length = ALIGN(npages * sizeof(u64),
				MLX5_UMR_MTT_ALIGNMENT);
		sg.lkey = dev->umrc.mr->lkey;

		wr.send_flags = MLX5_IB_SEND_UMR_FAIL_IF_FREE |
				MLX5_IB_SEND_UMR_UPDATE_MTT;
		wr.sg_list = &sg;
		wr.num_sge = 1;
		wr.opcode = MLX5_IB_WR_UMR;
		umrwr->npages = sg.length / sizeof(u64);
		umrwr->page_shift = PAGE_SHIFT;
		umrwr->mkey = mr->mmr.key;
		umrwr->target.offset = start_page_index;

		mlx5_ib_init_umr_context(&umr_context);
		down(&umrc->sem);
		err = ib_post_send(umrc->qp, &wr, &bad);
		if (err) {
			mlx5_ib_err(dev, "UMR post send failed, err %d\n", err);
		} else {
			wait_for_completion(&umr_context.done);
			if (umr_context.status != IB_WC_SUCCESS) {
				mlx5_ib_err(dev, "UMR completion failed, code %d\n",
					    umr_context.status);
				err = -EFAULT;
			}
		}
		up(&umrc->sem);
	}
	dma_unmap_single(ddev, dma, size, DMA_TO_DEVICE);

free_pas:
	if (!use_emergency_buf)
		free_page((unsigned long)pas);
	else
		mutex_unlock(&mlx5_ib_update_mtt_emergency_buffer_mutex);

	return err;
}
#endif

static struct mlx5_ib_mr *reg_create(struct ib_pd *pd, u64 virt_addr,
				     u64 length, struct ib_umem *umem,
				     int npages, int page_shift,
				     int access_flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_create_mkey_mbox_in *in;
	struct mlx5_ib_mr *mr;
	int inlen;
	int err;
	bool pg_cap = !!(MLX5_CAP_GEN(dev->mdev, pg));

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	inlen = sizeof(*in) + sizeof(*in->pas) * ((npages + 1) / 2) * 2;
	in = mlx5_vzalloc(inlen);
	if (!in) {
		err = -ENOMEM;
		goto err_1;
	}
	mlx5_ib_populate_pas(dev, umem, page_shift, in->pas,
			     pg_cap ? MLX5_IB_MTT_PRESENT : 0);

	/* The MLX5_MKEY_INBOX_PG_ACCESS bit allows setting the access flags
	 * in the page list submitted with the command. */
	in->flags = pg_cap ? cpu_to_be32(MLX5_MKEY_INBOX_PG_ACCESS) : 0;
	in->seg.flags = convert_access(access_flags) |
		MLX5_ACCESS_MODE_MTT;
	in->seg.flags_pd = cpu_to_be32(to_mpd(pd)->pdn);
	in->seg.start_addr = cpu_to_be64(virt_addr);
	in->seg.len = cpu_to_be64(length);
	in->seg.bsfs_octo_size = 0;
	in->seg.xlt_oct_size = cpu_to_be32(get_octo_len(virt_addr, length, 1 << page_shift));
	in->seg.log2_page_size = page_shift;
	in->seg.qpn_mkey7_0 = cpu_to_be32(0xffffff << 8);
	in->xlat_oct_act_size = cpu_to_be32(get_octo_len(virt_addr, length,
							 1 << page_shift));
	err = mlx5_core_create_mkey(dev->mdev, &mr->mmr, in, inlen, NULL,
				    NULL, NULL);
	if (err) {
		mlx5_ib_warn(dev, "create mkey failed\n");
		goto err_2;
	}
	mr->umem = umem;
	mr->dev = dev;
	mr->live = 1;
	kvfree(in);

	mlx5_ib_dbg(dev, "mkey = 0x%x\n", mr->mmr.key);

	return mr;

err_2:
	kvfree(in);

err_1:
	kfree(mr);

	return ERR_PTR(err);
}

enum {
	MLX5_MAX_REG_ORDER = MAX_MR_CACHE_ENTRIES + 1,
	MLX5_MAX_REG_SIZE = 2ul * 1024 * 1024 * 1024,
};

static u64 get_lsize(int page_shift)
{
	u64 l1;
	u64 l2;

	l1 = (u64)1 << (page_shift + MLX5_MAX_REG_ORDER);
	l2 = MLX5_MAX_REG_SIZE;

	if (l1 > l2)
		return l2;

	return l1;
}

static int alloc_mrs(struct mlx5_ib_dev *dev, struct mlx5_ib_mr **lmr, int n,
		     int order, u64 size, int nchild, int sorder, u64 len,
		     u64 off, int npages)
{
	int err = 0;
	int i;
	int k;

	for (i = 0, k = 0; i < n; i++) {
again:
		if (k++ > 3)
			goto out;
		lmr[i] = alloc_cached_mr(dev, order);
		if (!lmr[i]) {
			err = add_keys(dev, order2idx(dev, order), n - i);
			if (err) {
				mlx5_ib_warn(dev, "add_keys failed to add %d keys\n", n - i);
				goto out;
			}
			goto again;
		}
		lmr[i]->size = size;
		lmr[i]->page_count = 1 << order;
		k = 0;
	}

	if (nchild == n)
		return 0;

	for (k = 0; k < 3; k++) {
		lmr[i] = alloc_cached_mr(dev, sorder);
		if (lmr[i])
			break;
		err = add_keys(dev, order2idx(dev, sorder), 1);
		if (err) {
			mlx5_ib_warn(dev, "add_keys failed, err %d\n", err);
			goto out;
		}
	}

	lmr[i]->size = len - size * n + off;
	lmr[i]->page_count = npages - (n << order);

	return 0;

out:
	for (--i; i >= 0; --i)
		free_cached_mr(dev, lmr[i]);

	return err;
}

static int create_indirect_key(struct mlx5_ib_dev *dev, struct ib_pd *pd,
			       struct mlx5_ib_mr *mr, unsigned n)
{
	struct mlx5_create_mkey_mbox_in *in;
	int err;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	mr->dev = dev;
	in->seg.status = 1 << 6; /* free */;
	in->seg.flags = MLX5_ACCESS_MODE_KLM | MLX5_PERM_UMR_EN;
	in->seg.qpn_mkey7_0 = cpu_to_be32(0xffffff << 8);
	in->seg.flags_pd = cpu_to_be32(to_mpd(pd)->pdn);
	in->seg.xlt_oct_size = cpu_to_be32(ALIGN(n, 4));
	err = mlx5_core_create_mkey(dev->mdev, &mr->mmr, in, sizeof(*in),
				    NULL, NULL, NULL);

	kfree(in);
	return err;
}

static int unreg_umr(struct mlx5_ib_dev *dev, struct mlx5_ib_mr *mr)
{
	struct mlx5_core_dev *mdev = dev->mdev;
	struct umr_common *umrc = &dev->umrc;
	struct mlx5_ib_umr_context umr_context;
	struct ib_send_wr wr, *bad;
	int err;

	if (mdev->state == MLX5_DEVICE_STATE_INTERNAL_ERROR)
		return 0;

	memset(&wr, 0, sizeof(wr));
	wr.wr_id = (u64)(unsigned long)&umr_context;
	prep_umr_unreg_wqe(dev, &wr, mr->mmr.key);

	mlx5_ib_init_umr_context(&umr_context);
	down(&umrc->sem);
	err = ib_post_send(umrc->qp, &wr, &bad);
	if (err) {
		up(&umrc->sem);
		mlx5_ib_dbg(dev, "err %d\n", err);
		goto error;
	} else {
		wait_for_completion(&umr_context.done);
		up(&umrc->sem);
	}
	if (umr_context.status != IB_WC_SUCCESS) {
		mlx5_ib_warn(dev, "unreg umr failed\n");
		err = -EFAULT;
		goto error;
	}
	return 0;

error:
	return err;
}

static int reg_mrs(struct ib_pd *pd, struct mlx5_ib_mr **mrs, int n,
		   dma_addr_t dma, int copy, int page_shift, void *dptr,
		   __be64 *pas, int access_flags, u64 maxorder)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct umr_common *umrc = &dev->umrc;
	struct mlx5_ib_umr_context umr_context;
	struct ib_send_wr *bad;
	struct ib_send_wr wr;
	struct ib_sge sg;
	int err1;
	int err;
	int i;

	for (i = 0; i < n; ++i) {
		if (copy) {
			memcpy(dptr, pas + (i << maxorder),
			       sizeof(__be64) * mrs[i]->page_count);
			mrs[i]->dma = dma;
		} else {
			mrs[i]->dma = dma + (sizeof(__be64) << maxorder) * i;
		}

		memset(&wr, 0, sizeof(wr));
		wr.wr_id = (u64)(unsigned long)&umr_context;
		prep_umr_reg_wqe(pd,
				 &wr,
				 &sg,
				 mrs[i]->dma,
				 mrs[i]->page_count,
				 mrs[i]->mmr.key,
				 page_shift,
				 0,
				 mrs[i]->size,
				 access_flags);
		down(&umrc->sem);
		mlx5_ib_init_umr_context(&umr_context);
		err = ib_post_send(umrc->qp, &wr, &bad);
		if (err) {
			mlx5_ib_warn(dev, "post send failed, err %d\n", err);
			up(&umrc->sem);
			goto out;
		}
		wait_for_completion(&umr_context.done);
		up(&umrc->sem);
		if (umr_context.status != IB_WC_SUCCESS) {
			mlx5_ib_warn(dev, "reg umr failed\n");
			err = -EFAULT;
			goto out;
		}
	}
	return 0;
out:
	for (--i; i >= 0; --i) {
		err1 = unreg_umr(dev, mrs[i]);
		if (err1)
			mlx5_ib_warn(dev, "unreg_umr failed %d\n", err1);
	}

	return err;
}

static void populate_klm(void *dma, struct mlx5_ib_mr **lmr, int n, u64 off)
{
	struct mlx5_wqe_data_seg *dseg = dma;
	int i;

	for (i = 0; i < n; i++) {
		dseg[i].lkey = cpu_to_be32(lmr[i]->mmr.key);
		if (!i) {
			dseg[i].byte_count = cpu_to_be32((u32)(lmr[i]->size - off));
			dseg[0].addr = cpu_to_be64(off);
		} else {
			dseg[i].byte_count = cpu_to_be32((u32)(lmr[i]->size));
			dseg[i].addr = 0;
		}
	}
}

static void prep_indirect_wqe(struct ib_pd *pd, struct ib_send_wr *wr,
			      struct ib_sge *sg, u64 dma, int n, u32 key,
			      int page_shift, u64 virt_addr, u64 len,
			      int access_flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct ib_mr *mr = dev->umrc.mr;
	struct mlx5_umr_wr *umrwr = (struct mlx5_umr_wr *)&wr->wr.fast_reg;

	sg->addr = dma;
	sg->length = ALIGN(sizeof(u64) * n, 64);
	sg->lkey = mr->lkey;

	wr->next = NULL;
	wr->send_flags = 0;
	wr->sg_list = sg;
	wr->num_sge = 1;
	wr->opcode = MLX5_IB_WR_UMR;
	wr->send_flags = 0;
	/* since post send interprets this as MTTs and since a KLM
	   is two MTTs, we multiply by two to have  */
	umrwr->npages = n * 2;
	umrwr->page_shift = page_shift;
	umrwr->mkey = key;
	umrwr->target.virt_addr = virt_addr;
	umrwr->length = len;
	umrwr->access_flags = access_flags;
	umrwr->pd = pd;
}

static void free_mrs(struct mlx5_ib_dev *dev, struct mlx5_ib_mr **lmr, int n)
{
	int i;

	for (i = 0; i < n; i++)
		if (lmr[i])
			free_cached_mr(dev, lmr[i]);
}

static int get_nchild(int npages, int page_shift, u64 *maxorder, int *sorder, int *quot)
{
	int res;
	int denom;

	denom = min_t(int, 1 << MLX5_MAX_REG_ORDER, MLX5_MAX_REG_SIZE >> page_shift);
	res = npages % denom;
	*quot = npages / denom;
	*maxorder = ilog2(denom);
	*sorder = max_t(int, ilog2(roundup_pow_of_two(res)), 2);
	return *quot + (res ? 1 : 0);
}

static struct mlx5_ib_mr *reg_klm(struct ib_pd *pd, struct ib_umem *umem,
				  u64 virt_addr, u64 len, int npages,
				  int page_shift, int order, int access_flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct device *ddev = dev->ib_dev.dma_device;
	unsigned size = sizeof(__be64) * npages;
	struct umr_common *umrc = &dev->umrc;
	struct mlx5_ib_mr **lmr = NULL;
	struct mlx5_ib_mr *imr = NULL;
	struct ib_send_wr *bad;
	struct ib_send_wr wr;
	struct mlx5_ib_umr_context umr_context;
	__be64 *spas = NULL;
	__be64 *pas = NULL;
	dma_addr_t dma = 0;
	unsigned dsize;
	int err = -ENOMEM;
	struct ib_sge sg;
	int nchild;
	int sorder;
	void *dptr;
	u64 lsize;
	int i = 0;
	int err1;
	int quot;
	u64 off;
	u64 maxorder;

	mlx5_ib_dbg(dev, "addr 0x%llx, len 0x%llx, npages %d, page_shift %d, order %d, access_flags 0x%x\n",
		    virt_addr, len, npages, page_shift, order, access_flags);
	lsize = get_lsize(page_shift);
	nchild = get_nchild(npages, page_shift, &maxorder, &sorder, &quot);
	off = (virt_addr & ((1 << page_shift) - 1));
	lmr = kcalloc(nchild, sizeof(*lmr), GFP_KERNEL);
	if (!lmr) {
		mlx5_ib_warn(dev, "allocation failed\n");
		err = -ENOMEM;
		goto out;
	}

	pas = mlx5_vmalloc(size);
	if (!pas) {
		mlx5_ib_warn(dev, "allocation failed\n");
		err = -ENOMEM;
		goto out;
	}

	mlx5_ib_populate_pas(dev, umem, page_shift, pas, MLX5_IB_MTT_PRESENT);
	if (is_vmalloc_addr(pas)) {
		dsize = sizeof(__be64) << maxorder;
		spas = kmalloc(dsize, GFP_KERNEL);
		if (!spas) {
			err = -ENOMEM;
			mlx5_ib_warn(dev, "allocation failed\n");
			goto out;
		}
		dptr = spas;
	} else {
		dsize = size;
		dptr = pas;
	}

	dma = dma_map_single(ddev, dptr, dsize, DMA_TO_DEVICE);
	if (dma_mapping_error(ddev, dma)) {
		err = -ENOMEM;
		mlx5_ib_warn(dev, "dma map failed\n");
		goto out;
	}

	err = alloc_mrs(dev, lmr, quot, maxorder, lsize, nchild, sorder, len, off, npages);
	if (err)
		goto out_map;

	imr = kzalloc(sizeof(*imr), GFP_KERNEL);
	if (!imr) {
		err = -ENOMEM;
		mlx5_ib_warn(dev, "failed allocation\n");
		goto out_mrs;
	}

	err = create_indirect_key(dev, pd, imr, nchild);
	if (err) {
		mlx5_ib_warn(dev, "failed creating indirect key %d\n", err);
		goto out_mrs;
	}
	imr->size = len;

	err = reg_mrs(pd, lmr, nchild, dma, !!spas,
		      page_shift, dptr, pas, access_flags, maxorder);
	if (err) {
		mlx5_ib_warn(dev, "reg_mrs failed %d\n", err);
		goto out_indir;
	}

	populate_klm(dptr, lmr, nchild, off);
	memset(&wr, 0, sizeof(wr));
	wr.wr_id = (u64)(unsigned long)&umr_context;
	imr->dma = dma;
	prep_indirect_wqe(pd, &wr, &sg, dma, nchild, imr->mmr.key, page_shift,
			  virt_addr, len, access_flags);
	down(&umrc->sem);
	mlx5_ib_init_umr_context(&umr_context);
	err = ib_post_send(umrc->qp, &wr, &bad);
	if (err) {
		mlx5_ib_warn(dev, "post send failed, err %d\n", err);
		up(&umrc->sem);
		goto out_unreg;
	}
	wait_for_completion(&umr_context.done);
	up(&umrc->sem);
	if (umr_context.status != IB_WC_SUCCESS) {
		mlx5_ib_warn(dev, "reg umr failed\n");
		err = -EFAULT;
		goto out_unreg;
	}
	imr->children = lmr;
	imr->nchild = nchild;

	dma_unmap_single(ddev, dma, dsize, DMA_TO_DEVICE);
	kfree(spas);
	kvfree(pas);

	return imr;

out_unreg:
	for (i = 0; i < nchild; ++i) {
		err1 = unreg_umr(dev, lmr[i]);
		if (err1)
			mlx5_ib_warn(dev, "unreg_umr failed %d\n", err1);
	}
out_indir:
	err1 = mlx5_core_destroy_mkey(dev->mdev, &imr->mmr);
	if (err1)
		mlx5_ib_warn(dev, "destroy imr mkey failed %d\n", err1);
out_mrs:
	kfree(imr);
	free_mrs(dev, lmr, nchild);
out_map:
	dma_unmap_single(ddev, dma, dsize, DMA_TO_DEVICE);
out:
	kfree(spas);
	kvfree(pas);
	kfree(lmr);
	return ERR_PTR(err);
}

static int clean_mr(struct mlx5_ib_mr *mr)
{
	struct mlx5_ib_dev *dev = to_mdev(mr->ibmr.device);
	int umred = mr->umred;
	int err;

	if (!umred) {
		err = destroy_mkey(dev, mr);
		if (err) {
			mlx5_ib_warn(dev, "failed to destroy mkey 0x%x (%d)\n",
				     mr->mmr.key, err);
			return err;
		}
	} else {
		err = unreg_umr(dev, mr);
		if (err) {
			mlx5_ib_warn(dev, "failed unregister\n");
			return err;
		}
	}

	if (!umred)
		kfree(mr);

	return 0;
}

struct ib_mr *mlx5_ib_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				  u64 virt_addr, int access_flags,
				  struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_ib_mr *mr = NULL;
	struct ib_umem *umem;
	int page_shift;
	int npages;
	int ncont;
	int order;
	int err;

	mlx5_ib_dbg(dev, "start 0x%llx, virt_addr 0x%llx, length 0x%llx, access_flags 0x%x\n",
		    start, virt_addr, length, access_flags);
	umem = ib_umem_get(pd->uobject->context, start, length, access_flags,
			   0);
	if (IS_ERR(umem)) {
		mlx5_ib_dbg(dev, "umem get failed (%ld)\n", PTR_ERR(umem));
		return (void *)umem;
	}

	mlx5_ib_cont_pages(umem, start, &npages, &page_shift, &ncont, &order);
	if (!npages) {
		mlx5_ib_warn(dev, "avoid zero region\n");
		err = -EINVAL;
		goto error;
	}

	mlx5_ib_dbg(dev, "npages %d, ncont %d, order %d, page_shift %d\n",
		    npages, ncont, order, page_shift);

	if (use_umr(order)) {
		mr = reg_umr(pd, umem, virt_addr, length, ncont, page_shift,
			     order, access_flags);
		if (PTR_ERR(mr) == -EAGAIN) {
			mlx5_ib_dbg(dev, "cache empty for order %d", order);
			mr = NULL;
		}
	} else if (use_klm(order) && !(access_flags & IB_ACCESS_ON_DEMAND)) {
		mr = reg_klm(pd, umem, virt_addr, length, ncont, page_shift,
			     order, access_flags);
		if (IS_ERR(mr)) {
			mlx5_ib_dbg(dev, "reg_klm failed for order %d (%ld)", order, PTR_ERR(mr));
			mr = NULL;
		}
	} else if (access_flags & IB_ACCESS_ON_DEMAND) {
		err = -EINVAL;
		pr_err("Got MR registration for ODP MR > 512MB, not supported for Connect-IB");
		goto error;
	}

	if (!mr)
		mr = reg_create(pd, virt_addr, length, umem, ncont, page_shift,
				access_flags);

	if (IS_ERR(mr)) {
		err = PTR_ERR(mr);
		goto error;
	}

	mlx5_ib_dbg(dev, "mkey 0x%x\n", mr->mmr.key);

	mr->umem = umem;
	mr->npages = npages;
	atomic_add(npages, &dev->mdev->priv.reg_pages);
	mr->ibmr.lkey = mr->mmr.key;
	mr->ibmr.rkey = mr->mmr.key;

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	if (umem->odp_data) {
		/*
		 * This barrier prevents the compiler from moving the
		 * setting of umem->odp_data->private to point to our
		 * MR, before reg_umr finished, to ensure that the MR
		 * initialization have finished before starting to
		 * handle invalidations.
		 */
		smp_wmb();
		mr->umem->odp_data->private = mr;
		/*
		 * Make sure we will see the new
		 * umem->odp_data->private value in the invalidation
		 * routines, before we can get page faults on the
		 * MR. Page faults can happen once we put the MR in
		 * the tree, below this line. Without the barrier,
		 * there can be a fault handling and an invalidation
		 * before umem->odp_data->private == mr is visible to
		 * the invalidation handler.
		 */
		smp_wmb();
	}
#endif

	return &mr->ibmr;

error:
	/*
	 * Destroy the umem *before* destroying the MR, to ensure we
	 * will not have any in-flight notifiers when destroying the
	 * MR.
	 *
	 * As the MR is completely invalid to begin with, and this
	 * error path is only taken if we can't push the mr entry into
	 * the pagefault tree, this is safe.
	 */

	ib_umem_release(umem);
	/* Kill the MR, and return an error code. */
	clean_mr(mr);
	return ERR_PTR(err);
}

int mlx5_ib_dereg_mr(struct ib_mr *ibmr)
{
	struct mlx5_ib_dev *dev = to_mdev(ibmr->device);
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	int npages = mr->npages;
	struct ib_umem *umem = mr->umem;

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	if (umem && umem->odp_data) {
		/* Prevent new page faults from succeeding */
		mr->live = 0;
		/* Wait for all running page-fault handlers to finish. */
		synchronize_srcu(&dev->mr_srcu);
		/* Destroy all page mappings */
		mlx5_ib_invalidate_range(umem, ib_umem_start(umem),
					 ib_umem_end(umem));
		/*
		 * We kill the umem before the MR for ODP,
		 * so that there will not be any invalidations in
		 * flight, looking at the *mr struct.
		 */
		ib_umem_release(umem);
		atomic_sub(npages, &dev->mdev->priv.reg_pages);

		/* Avoid double-freeing the umem. */
		umem = NULL;
	}
#endif

	clean_mr(mr);

	if (umem) {
		ib_umem_release(umem);
		atomic_sub(npages, &dev->mdev->priv.reg_pages);
	}

	return 0;
}

static int create_mr_sig(struct ib_pd *pd,
			 struct ib_mr_init_attr *mr_init_attr,
			 struct mlx5_create_mkey_mbox_in *in,
			 struct mlx5_ib_mr *mr)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	int access_mode, err;
	int ndescs = roundup(mr_init_attr->max_reg_descriptors, 4);


	in->seg.status = MLX5_MKEY_STATUS_FREE;
	in->seg.xlt_oct_size = cpu_to_be32(ndescs);
	in->seg.qpn_mkey7_0 = cpu_to_be32(0xffffff << 8);
	in->seg.flags_pd = cpu_to_be32(to_mpd(pd)->pdn);
	access_mode = MLX5_ACCESS_MODE_MTT;

	if (mr_init_attr->flags & IB_MR_SIGNATURE_EN) {
		u32 psv_index[2];

		in->seg.flags_pd = cpu_to_be32(be32_to_cpu(in->seg.flags_pd) |
							   MLX5_MKEY_BSF_EN);
		in->seg.bsfs_octo_size = cpu_to_be32(MLX5_MKEY_BSF_OCTO_SIZE);
		mr->sig = kzalloc(sizeof(*mr->sig), GFP_KERNEL);
		if (!mr->sig)
			return -ENOMEM;

		/* create mem & wire PSVs */
		err = mlx5_core_create_psv(dev->mdev, to_mpd(pd)->pdn,
					   2, psv_index);
		if (err)
			goto err_free_sig;

		access_mode = MLX5_ACCESS_MODE_KLM;
		mr->sig->psv_memory.psv_idx = psv_index[0];
		mr->sig->psv_wire.psv_idx = psv_index[1];

		mr->sig->sig_status_checked = true;
		mr->sig->sig_err_exists = false;
		/* Next UMR, Arm SIGERR */
		++mr->sig->sigerr_count;
	}

	in->seg.flags = MLX5_PERM_UMR_EN | access_mode;
	err = mlx5_core_create_mkey(dev->mdev, &mr->mmr, in, sizeof(*in),
				    NULL, NULL, NULL);
	if (err)
		goto err_destroy_psv;

	mr->ibmr.lkey = mr->mmr.key;
	mr->ibmr.rkey = mr->mmr.key;
	mr->umem = NULL;

	return 0;

err_destroy_psv:
	if (mr->sig) {
		if (mlx5_core_destroy_psv(dev->mdev,
					  mr->sig->psv_memory.psv_idx))
			mlx5_ib_warn(dev, "failed to destroy mem psv %d\n",
				     mr->sig->psv_memory.psv_idx);
		if (mlx5_core_destroy_psv(dev->mdev,
					  mr->sig->psv_wire.psv_idx))
			mlx5_ib_warn(dev, "failed to destroy wire psv %d\n",
				     mr->sig->psv_wire.psv_idx);
	}
err_free_sig:
	kfree(mr->sig);
	return err;
}

static int create_mr_noncontig(struct ib_pd *pd,
			       struct ib_mr_init_attr *attr,
			       struct mlx5_create_mkey_mbox_in *in,
			       struct mlx5_ib_mr *mr)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	int err;

	mr->dev = dev;
	in->seg.status = 1 << 6; /* free */;
	in->seg.flags = MLX5_ACCESS_MODE_KLM | MLX5_PERM_UMR_EN;
	in->seg.qpn_mkey7_0 = cpu_to_be32(0xffffff << 8);
	in->seg.flags_pd = cpu_to_be32(to_mpd(pd)->pdn);
	in->seg.xlt_oct_size = cpu_to_be32(ALIGN(attr->max_reg_descriptors + 1, 4));
	err = mlx5_core_create_mkey(dev->mdev, &mr->mmr, in, sizeof(*in),
				    NULL, NULL, NULL);
	if (!err) {
		mr->ibmr.lkey = mr->mmr.key;
		mr->ibmr.rkey = mr->mmr.key;
		mr->max_reg_descriptors = ALIGN(attr->max_reg_descriptors, 4);
	}

	return err;
}

struct ib_mr *mlx5_ib_create_mr(struct ib_pd *pd,
				struct ib_mr_init_attr *mr_init_attr)
{
	struct mlx5_create_mkey_mbox_in *in;
	struct mlx5_ib_mr *mr;
	int err;

	if (!(mr_init_attr->flags &
	      (IB_MR_SIGNATURE_EN | IB_MR_INDIRECT_REG)))
		return ERR_PTR(-EINVAL);

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_free;
	}

	if (mr_init_attr->flags & IB_MR_SIGNATURE_EN)
		err = create_mr_sig(pd, mr_init_attr, in, mr);
	else
		err = create_mr_noncontig(pd, mr_init_attr, in, mr);

	kfree(in);
	if (err)
		goto err_free;

	return &mr->ibmr;

err_free:
	kfree(mr);
	return ERR_PTR(err);
}

int mlx5_ib_destroy_mr(struct ib_mr *ibmr)
{
	struct mlx5_ib_dev *dev = to_mdev(ibmr->device);
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	int err;

	if (mr->sig) {
		if (mlx5_core_destroy_psv(dev->mdev,
					  mr->sig->psv_memory.psv_idx))
			mlx5_ib_warn(dev, "failed to destroy mem psv %d\n",
				     mr->sig->psv_memory.psv_idx);
		if (mlx5_core_destroy_psv(dev->mdev,
					  mr->sig->psv_wire.psv_idx))
			mlx5_ib_warn(dev, "failed to destroy wire psv %d\n",
				     mr->sig->psv_wire.psv_idx);
		kfree(mr->sig);
	}

	err = destroy_mkey(dev, mr);
	if (err) {
		mlx5_ib_warn(dev, "failed to destroy mkey 0x%x (%d)\n",
			     mr->mmr.key, err);
		return err;
	}

	kfree(mr);

	return err;
}

struct ib_mr *mlx5_ib_alloc_fast_reg_mr(struct ib_pd *pd,
					int max_page_list_len)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_create_mkey_mbox_in *in;
	struct mlx5_ib_mr *mr;
	int err;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_free;
	}

	in->seg.status = MLX5_MKEY_STATUS_FREE;
	in->seg.xlt_oct_size = cpu_to_be32((max_page_list_len + 1) / 2);
	in->seg.qpn_mkey7_0 = cpu_to_be32(0xffffff << 8);
	in->seg.flags = MLX5_PERM_UMR_EN | MLX5_ACCESS_MODE_MTT;
	in->seg.flags_pd = cpu_to_be32(to_mpd(pd)->pdn);
	/*
	 * TBD not needed - issue 197292 */
	in->seg.log2_page_size = PAGE_SHIFT;

	err = mlx5_core_create_mkey(dev->mdev, &mr->mmr, in, sizeof(*in), NULL,
				    NULL, NULL);
	kfree(in);
	if (err)
		goto err_free;

	mr->ibmr.lkey = mr->mmr.key;
	mr->ibmr.rkey = mr->mmr.key;
	mr->umem = NULL;

	return &mr->ibmr;

err_free:
	kfree(mr);
	return ERR_PTR(err);
}

struct ib_fast_reg_page_list *mlx5_ib_alloc_fast_reg_page_list(struct ib_device *ibdev,
							       int page_list_len)
{
	struct mlx5_ib_fast_reg_page_list *mfrpl;
	int size = page_list_len * sizeof(u64);

	mfrpl = kmalloc(sizeof(*mfrpl), GFP_KERNEL);
	if (!mfrpl)
		return ERR_PTR(-ENOMEM);

	mfrpl->ibfrpl.page_list = kmalloc(size, GFP_KERNEL);
	if (!mfrpl->ibfrpl.page_list)
		goto err_free;

	mfrpl->mapped_page_list = dma_alloc_coherent(ibdev->dma_device,
						     size, &mfrpl->map,
						     GFP_KERNEL);
	if (!mfrpl->mapped_page_list)
		goto err_free;

	WARN_ON(mfrpl->map & 0x3f);

	return &mfrpl->ibfrpl;

err_free:
	kfree(mfrpl->ibfrpl.page_list);
	kfree(mfrpl);
	return ERR_PTR(-ENOMEM);
}

void mlx5_ib_free_fast_reg_page_list(struct ib_fast_reg_page_list *page_list)
{
	struct mlx5_ib_fast_reg_page_list *mfrpl = to_mfrpl(page_list);
	struct mlx5_ib_dev *dev = to_mdev(page_list->device);
	int size = page_list->max_page_list_len * sizeof(u64);

	dma_free_coherent(&dev->mdev->pdev->dev, size, mfrpl->mapped_page_list,
			  mfrpl->map);
	kfree(mfrpl->ibfrpl.page_list);
	kfree(mfrpl);
}

int mlx5_ib_check_mr_status(struct ib_mr *ibmr, u32 check_mask,
			    struct ib_mr_status *mr_status)
{
	struct mlx5_ib_mr *mmr = to_mmr(ibmr);
	int ret = 0;

	if (check_mask & ~IB_MR_CHECK_SIG_STATUS) {
		pr_err("Invalid status check mask\n");
		ret = -EINVAL;
		goto done;
	}

	mr_status->fail_status = 0;
	if (check_mask & IB_MR_CHECK_SIG_STATUS) {
		if (!mmr->sig) {
			ret = -EINVAL;
			pr_err("signature status check requested on a non-signature enabled MR\n");
			goto done;
		}

		mmr->sig->sig_status_checked = true;
		if (!mmr->sig->sig_err_exists)
			goto done;

		if (ibmr->lkey == mmr->sig->err_item.key)
			memcpy(&mr_status->sig_err, &mmr->sig->err_item,
			       sizeof(mr_status->sig_err));
		else {
			mr_status->sig_err.err_type = IB_SIG_BAD_GUARD;
			mr_status->sig_err.sig_err_offset = 0;
			mr_status->sig_err.key = mmr->sig->err_item.key;
		}

		mmr->sig->sig_err_exists = false;
		mr_status->fail_status |= IB_MR_CHECK_SIG_STATUS;
	}

done:
	return ret;
}

struct order_attribute {
	struct attribute attr;
	ssize_t (*show)(struct cache_order *, struct order_attribute *, char *buf);
	ssize_t (*store)(struct cache_order *, struct order_attribute *,
			 const char *buf, size_t count);
};

static ssize_t cur_show(struct cache_order *co, struct order_attribute *oa,
			char *buf)
{
	struct mlx5_ib_dev *dev = co->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[co->index];
	int err;

	err = snprintf(buf, 20, "%d\n", ent->cur);
	return err;
}

static ssize_t limit_show(struct cache_order *co, struct order_attribute *oa,
			  char *buf)
{
	struct mlx5_ib_dev *dev = co->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[co->index];
	int err;

	err = snprintf(buf, 20, "%d\n", ent->limit);
	return err;
}

static ssize_t limit_store(struct cache_order *co, struct order_attribute *oa,
			   const char *buf, size_t count)
{
	struct mlx5_ib_dev *dev = co->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[co->index];
	u32 var;
	int err;

	if (kstrtouint(buf, 0, &var))
		return -EINVAL;

	if (var > ent->size)
		return -EINVAL;

	ent->limit = var;

	if (ent->cur < ent->limit) {
		err = add_keys(dev, co->index, 2 * ent->limit - ent->cur);
		if (err)
			return err;
	}

	return count;
}

static ssize_t miss_show(struct cache_order *co, struct order_attribute *oa,
			 char *buf)
{
	struct mlx5_ib_dev *dev = co->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[co->index];
	int err;

	err = snprintf(buf, 20, "%d\n", ent->miss);
	return err;
}

static ssize_t miss_store(struct cache_order *co, struct order_attribute *oa,
			  const char *buf, size_t count)
{
	struct mlx5_ib_dev *dev = co->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[co->index];
	u32 var;

	if (kstrtouint(buf, 0, &var))
		return -EINVAL;

	if (var != 0)
		return -EINVAL;

	ent->miss = var;

	return count;
}

static ssize_t size_show(struct cache_order *co, struct order_attribute *oa,
			 char *buf)
{
	struct mlx5_ib_dev *dev = co->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[co->index];
	int err;

	err = snprintf(buf, 20, "%d\n", ent->size);
	return err;
}

static ssize_t size_store(struct cache_order *co, struct order_attribute *oa,
			  const char *buf, size_t count)
{
	struct mlx5_ib_dev *dev = co->dev;
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent = &cache->ent[co->index];
	u32 var;
	int err;

	if (kstrtouint(buf, 0, &var))
		return -EINVAL;

	if (var < ent->limit)
		return -EINVAL;

	if (var > ent->size) {
		do {
			err = add_keys(dev, co->index, var - ent->size);
			if (err && err != -EAGAIN)
				return err;

			usleep_range(3000, 5000);
		} while (err);
	} else if (var < ent->size) {
		remove_keys(dev, co->index, ent->size - var);
	}

	return count;
}

static ssize_t order_attr_show(struct kobject *kobj,
			       struct attribute *attr, char *buf)
{
	struct order_attribute *oa =
		container_of(attr, struct order_attribute, attr);
	struct cache_order *co = container_of(kobj, struct cache_order, kobj);

	if (!oa->show)
		return -EIO;

	return oa->show(co, oa, buf);
}

static ssize_t order_attr_store(struct kobject *kobj,
				struct attribute *attr, const char *buf, size_t size)
{
	struct order_attribute *oa =
		container_of(attr, struct order_attribute, attr);
	struct cache_order *co = container_of(kobj, struct cache_order, kobj);

	if (!oa->store)
		return -EIO;

	return oa->store(co, oa, buf, size);
}

static const struct sysfs_ops order_sysfs_ops = {
	.show = order_attr_show,
	.store = order_attr_store,
};

#define ORDER_ATTR(_name) struct order_attribute order_attr_##_name = \
	__ATTR(_name, 0644, _name##_show, _name##_store)
#define ORDER_ATTR_RO(_name) struct order_attribute order_attr_##_name = \
	__ATTR(_name, 0444, _name##_show, NULL)

static ORDER_ATTR_RO(cur);
static ORDER_ATTR(limit);
static ORDER_ATTR(miss);
static ORDER_ATTR(size);

static struct attribute *order_default_attrs[] = {
	&order_attr_cur.attr,
	&order_attr_limit.attr,
	&order_attr_miss.attr,
	&order_attr_size.attr,
	NULL
};

static struct kobj_type order_type = {
	.sysfs_ops     = &order_sysfs_ops,
	.default_attrs = order_default_attrs
};

static int mlx5_mr_sysfs_init(struct mlx5_ib_dev *dev)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct device *device = &dev->ib_dev.dev;
	struct cache_order *co;
	int o;
	int i;
	int err;

	dev->mr_cache = kobject_create_and_add("mr_cache", &device->kobj);
	if (!dev->mr_cache)
		return -ENOMEM;

	for (o = 2, i = 0; i < MAX_MR_CACHE_ENTRIES; o++, i++) {
		co = &cache->ent[i].co;
		co->order = o;
		co->index = i;
		co->dev = dev;
		err = kobject_init_and_add(&co->kobj, &order_type,
					   dev->mr_cache, "%d", o);
		if (err)
			goto err_put;

		kobject_uevent(&co->kobj, KOBJ_ADD);
	}

	return 0;

err_put:
	for (; i >= 0; i--) {
		co = &cache->ent[i].co;
		kobject_put(&co->kobj);
	}
	kobject_put(dev->mr_cache);
	dev->mr_cache = NULL;
	return err;
}

static void mlx5_mr_sysfs_cleanup(struct mlx5_ib_dev *dev)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct cache_order *co;
	int i;

	for (i = MAX_MR_CACHE_ENTRIES - 1; i >= 0; i--) {
		co = &cache->ent[i].co;
		kobject_put(&co->kobj);
	}
	if (dev->mr_cache)
		kobject_put(dev->mr_cache);
}

int mlx5_ib_exp_query_mkey(struct ib_mr *mr, u64 mkey_attr_mask,
			   struct ib_mkey_attr *mkey_attr)
{
	struct mlx5_ib_mr *mmr = to_mmr(mr);

	mkey_attr->max_reg_descriptors = mmr->max_reg_descriptors;

	return 0;
}
struct ib_indir_reg_list *
mlx5_ib_alloc_indir_reg_list(struct ib_device *device,
			     unsigned int max_indir_list_len)
{
	struct device *ddev = device->dma_device;
	struct mlx5_ib_indir_reg_list *mirl = NULL;
	int dsize;
	int err;

	mirl = kzalloc(sizeof(*mirl), GFP_KERNEL);
	if (!mirl)
		return ERR_PTR(-ENOMEM);

	mirl->ib_irl.sg_list = kcalloc(max_indir_list_len,
				       sizeof(*mirl->ib_irl.sg_list),
				       GFP_KERNEL);
	if (!mirl->ib_irl.sg_list) {
		err = -ENOMEM;
		goto err_sg_list;
	}

	dsize = sizeof(*mirl->klms) * max_indir_list_len;
	dsize += max_t(int, MLX5_UMR_ALIGN - ARCH_KMALLOC_MINALIGN, 0);
	mirl->mapped_ilist = kzalloc(dsize, GFP_KERNEL);
	if (!mirl->mapped_ilist) {
		err = -ENOMEM;
		goto err_mapped_list;
	}

	mirl->klms = (void *)ALIGN((unsigned long long)mirl->mapped_ilist,
			      MLX5_UMR_ALIGN);
	mirl->map = dma_map_single(ddev, mirl->klms,
				   dsize, DMA_TO_DEVICE);
	if (dma_mapping_error(ddev, mirl->map)) {
		err = -ENOMEM;
		goto err_dma_map;
	}

	return &mirl->ib_irl;
err_dma_map:
	kfree(mirl->mapped_ilist);
err_mapped_list:
	kfree(mirl->ib_irl.sg_list);
err_sg_list:
	kfree(mirl);

	return ERR_PTR(err);
}

void
mlx5_ib_free_indir_reg_list(struct ib_indir_reg_list *indir_list)
{
	struct mlx5_ib_indir_reg_list *mirl = to_mindir_list(indir_list);
	struct device *ddev = indir_list->device->dma_device;
	int dsize;

	dsize = sizeof(*mirl->klms) * indir_list->max_indir_list_len;
	dma_unmap_single(ddev, mirl->map, dsize, DMA_TO_DEVICE);
	kfree(mirl->mapped_ilist);
	kfree(mirl->ib_irl.sg_list);
	kfree(mirl);
}
