/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Cisco Systems.  All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies. All rights reserved.
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

#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/sched.h>
#include <linux/export.h>
#include <linux/hugetlb.h>
#include <linux/dma-attrs.h>
#include <linux/slab.h>
#include <rdma/ib_umem_odp.h>

#include "uverbs.h"




static void ib_cmem_release(struct kref *ref)
{

	struct ib_cmem *cmem;
	struct ib_cmem_block *cmem_block, *tmp;

	cmem = container_of(ref, struct ib_cmem, refcount);

	list_for_each_entry_safe(cmem_block, tmp, &cmem->ib_cmem_block, list) {
		__free_pages(cmem_block->page, cmem->block_order);
		list_del(&cmem_block->list);
		kfree(cmem_block);
	}

	kfree(cmem);

}

/**
 * ib_cmem_release_contiguous_pages - release memory allocated by
 *                                              ib_cmem_alloc_contiguous_pages.
 * @cmem: cmem struct to release
 */
void ib_cmem_release_contiguous_pages(struct ib_cmem *cmem)
{
	kref_put(&cmem->refcount, ib_cmem_release);
}
EXPORT_SYMBOL(ib_cmem_release_contiguous_pages);

static void __ib_umem_release(struct ib_device *dev, struct ib_umem *umem, int dirty)
{
	struct scatterlist *sg;
	struct page *page;
	int i;

	if (umem->nmap > 0)
		ib_dma_unmap_sg(dev, umem->sg_head.sgl,
				umem->nmap,
				DMA_BIDIRECTIONAL);

	for_each_sg(umem->sg_head.sgl, sg, umem->npages, i) {

		page = sg_page(sg);
		if (umem->writable && dirty)
			set_page_dirty_lock(page);
		put_page(page);
	}

	sg_free_table(&umem->sg_head);
	return;

}

void ib_umem_activate_invalidation_notifier(struct ib_umem *umem,
					       umem_invalidate_func_t func,
					       void *cookie)
{
	struct invalidation_ctx *invalidation_ctx = umem->invalidation_ctx;

	invalidation_ctx->func = func;
	invalidation_ctx->cookie = cookie;

	/* from that point any pending invalidations can be called */
	mutex_unlock(&umem->ib_peer_mem->lock);
	return;
}
EXPORT_SYMBOL(ib_umem_activate_invalidation_notifier);

static void cmem_vma_open(struct vm_area_struct *area)
{
	struct ib_cmem *ib_cmem;
	ib_cmem = (struct ib_cmem *)(area->vm_private_data);

	kref_get(&ib_cmem->refcount);
}

static void cmem_vma_close(struct vm_area_struct *area)
{
	struct ib_cmem *cmem;
	cmem = (struct ib_cmem *)(area->vm_private_data);

	ib_cmem_release_contiguous_pages(cmem);

}


static const struct vm_operations_struct cmem_contig_pages_vm_ops = {
	.open = cmem_vma_open,
	.close = cmem_vma_close
};

/**
 * ib_cmem_map_contiguous_pages_to_vma - map contiguous pages into VMA
 * @ib_cmem: cmem structure returned by ib_cmem_alloc_contiguous_pages
 * @vma: VMA to inject pages into.
 */
int ib_cmem_map_contiguous_pages_to_vma(struct ib_cmem *ib_cmem,
						struct vm_area_struct *vma)
{

	int ret;
	unsigned long page_entry;
	unsigned long ntotal_pages;
	unsigned long ncontig_pages;
	unsigned long total_size;
	struct page *page;
	unsigned long vma_entry_number = 0;
	struct ib_cmem_block *ib_cmem_block = NULL;

	total_size = vma->vm_end - vma->vm_start;
	if (ib_cmem->length != total_size)
		return -EINVAL;

	if (total_size != PAGE_ALIGN(total_size)) {
		WARN(1,
		"ib_cmem_map: total size %lu not aligned to page size\n",
		total_size);
		return -EINVAL;
	}

	ntotal_pages = total_size >> PAGE_SHIFT;
	ncontig_pages = 1 << ib_cmem->block_order;

	list_for_each_entry(ib_cmem_block, &(ib_cmem->ib_cmem_block), list) {
		page = ib_cmem_block->page;
		for (page_entry = 0; page_entry < ncontig_pages; page_entry++) {
			/* We reached end of vma - going out from both loops */
			if (vma_entry_number >= ntotal_pages)
				goto end;

			ret = vm_insert_page(vma, vma->vm_start +
				(vma_entry_number << PAGE_SHIFT), page);
			if (ret < 0)
				goto err_vm_insert;

			vma_entry_number++;
			page++;
		}
	}

end:

	/* We expect to have enough pages   */
	if (vma_entry_number >= ntotal_pages) {
		vma->vm_ops =  &cmem_contig_pages_vm_ops;
		vma->vm_private_data = ib_cmem;
		return 0;
	}
	/* Not expected but if we reached here
	    not enough contiguous pages were registered
	*/
	ret = -EINVAL;

err_vm_insert:

	zap_vma_ptes(vma, vma->vm_start, total_size);
	return ret;

}
EXPORT_SYMBOL(ib_cmem_map_contiguous_pages_to_vma);



/**
 * ib_cmem_alloc_contiguous_pages - allocate contiguous pages
*  @context: userspace context to allocate memory for
 * @total_size: total required size for that allocation.
 * @page_size_order: order of one contiguous page.
 */
struct ib_cmem *ib_cmem_alloc_contiguous_pages(struct ib_ucontext *context,
				unsigned long total_size,
				unsigned long page_size_order)
{
	struct ib_cmem *cmem;
	unsigned long ntotal_pages;
	unsigned long ncontiguous_pages;
	unsigned long ncontiguous_groups;
	struct page *page;
	int i;
	int ncontiguous_pages_order;
	struct ib_cmem_block *ib_cmem_block;
	unsigned long locked;
	unsigned long lock_limit;

	if (page_size_order < PAGE_SHIFT || page_size_order > 31)
		return ERR_PTR(-EINVAL);

	cmem = kzalloc(sizeof *cmem, GFP_KERNEL);
	if (!cmem)
		return ERR_PTR(-ENOMEM);

	kref_init(&cmem->refcount);
	cmem->context   = context;
	INIT_LIST_HEAD(&cmem->ib_cmem_block);

	/* Total size is expected to be already page aligned -
	    verifying anyway.
	*/
	ntotal_pages = PAGE_ALIGN(total_size) >> PAGE_SHIFT;
	/* ib_cmem_alloc_contiguous_pages is called as part of mmap
	with mm->mmap_sem held for writing.
	No need to lock
	 */
	locked     = ntotal_pages + current->mm->pinned_vm;
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

	if ((locked > lock_limit) && !capable(CAP_IPC_LOCK))
		goto err_alloc;

	/* How many contiguous pages do we need in 1 block */
	ncontiguous_pages = (1 << page_size_order) >> PAGE_SHIFT;
	ncontiguous_pages_order = ilog2(ncontiguous_pages);
	ncontiguous_groups = (ntotal_pages >> ncontiguous_pages_order)  +
		(!!(ntotal_pages & (ncontiguous_pages - 1)));

	/* Checking MAX_ORDER to prevent WARN via calling alloc_pages below */
	if (ncontiguous_pages_order >= MAX_ORDER)
		goto err_alloc;
	/* we set block_order before starting allocation to prevent
	   a leak in a failure flow in ib_cmem_release.
	   cmem->length has at that step value 0 from kzalloc as expected */
	cmem->block_order = ncontiguous_pages_order;
	for (i = 0; i < ncontiguous_groups; i++) {
		/* Allocating the managed entry */
		ib_cmem_block = kmalloc(sizeof(struct ib_cmem_block),
				GFP_KERNEL);
		if (!ib_cmem_block)
			goto err_alloc;

		page =  alloc_pages(GFP_HIGHUSER | __GFP_ZERO | __GFP_COMP |
					__GFP_NOWARN, ncontiguous_pages_order);
		if (!page) {
			kfree(ib_cmem_block);
			/* We should deallocate previous succeeded allocatations
			     if exists.
			*/
			goto err_alloc;
		}

		ib_cmem_block->page = page;
		list_add_tail(&ib_cmem_block->list, &cmem->ib_cmem_block);
	}

	cmem->length = total_size;
	return cmem;

err_alloc:
	ib_cmem_release_contiguous_pages(cmem);
	return ERR_PTR(-ENOMEM);

}
EXPORT_SYMBOL(ib_cmem_alloc_contiguous_pages);


/**
 * ib_umem_get - Pin and DMA map userspace memory.
 *
 * If access flags indicate ODP memory, avoid pinning. Instead, stores
 * the mm for future page fault handling in conjunction with MMU notifiers.
 *
 * @context: userspace context to pin memory for
 * @addr: userspace virtual address to start at
 * @size: length of region to pin
 * @access: IB_ACCESS_xxx flags for memory being pinned
 * @dmasync: flush in-flight DMA when the memory region is written
 */
struct ib_umem *ib_umem_get(struct ib_ucontext *context, unsigned long addr,
			    size_t size, int access, int dmasync)
{
	struct ib_umem *umem;
	struct page **page_list;
	struct vm_area_struct **vma_list;
	unsigned long locked;
	unsigned long lock_limit;
	unsigned long cur_base;
	unsigned long npages;
	int ret;
	int i;
	DEFINE_DMA_ATTRS(attrs);
	struct scatterlist *sg, *sg_list_start;
	int need_release = 0;

	if (dmasync)
		dma_set_attr(DMA_ATTR_WRITE_BARRIER, &attrs);

	/*
	 * If the combination of the addr and size requested for this memory
	 * region causes an integer overflow, return error.
	 */
	if ((PAGE_ALIGN(addr + size) <= size) ||
	    (PAGE_ALIGN(addr + size) <= addr))
		return ERR_PTR(-EINVAL);

	if (!can_do_mlock())
		return ERR_PTR(-EPERM);

	umem = kzalloc(sizeof *umem, GFP_KERNEL);
	if (!umem)
		return ERR_PTR(-ENOMEM);

	umem->context   = context;
	umem->length    = size;
	umem->address   = addr;
	umem->page_size = PAGE_SIZE;
	umem->pid       = get_task_pid(current, PIDTYPE_PID);
	/*
	 * We ask for writable memory if any of the following
	 * access flags are set.  "Local write" and "remote write"
	 * obviously require write access.  "Remote atomic" can do
	 * things like fetch and add, which will modify memory, and
	 * "MW bind" can change permissions by binding a window.
	 */
	umem->writable  = !!(access &
		(IB_ACCESS_LOCAL_WRITE   | IB_ACCESS_REMOTE_WRITE |
		 IB_ACCESS_REMOTE_ATOMIC | IB_ACCESS_MW_BIND));

	if (access & IB_ACCESS_ON_DEMAND) {
		ret = ib_umem_odp_get(context, umem);
		if (ret) {
			kfree(umem);
			return ERR_PTR(ret);
		}
		return umem;
	}

	umem->odp_data = NULL;

	/* We assume the memory is from hugetlb until proved otherwise */
	umem->hugetlb   = 1;

	page_list = (struct page **) __get_free_page(GFP_KERNEL);
	if (!page_list) {
		kfree(umem);
		return ERR_PTR(-ENOMEM);
	}

	/*
	 * if we can't alloc the vma_list, it's not so bad;
	 * just assume the memory is not hugetlb memory
	 */
	vma_list = (struct vm_area_struct **) __get_free_page(GFP_KERNEL);
	if (!vma_list)
		umem->hugetlb = 0;

	npages = ib_umem_num_pages(umem);

	down_write(&current->mm->mmap_sem);

	locked     = npages + current->mm->pinned_vm;
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

	if ((locked > lock_limit) && !capable(CAP_IPC_LOCK)) {
		ret = -ENOMEM;
		goto out;
	}

	cur_base = addr & PAGE_MASK;

	if (npages == 0) {
		ret = -EINVAL;
		goto out;
	}

	ret = sg_alloc_table(&umem->sg_head, npages, GFP_KERNEL);
	if (ret)
		goto out;

	need_release = 1;
	sg_list_start = umem->sg_head.sgl;

	while (npages) {
		ret = get_user_pages(current, current->mm, cur_base,
				     min_t(unsigned long, npages,
					   PAGE_SIZE / sizeof (struct page *)),
				     1, !umem->writable, page_list, vma_list);

		if (ret < 0)
			goto out;

		umem->npages += ret;
		cur_base += ret * PAGE_SIZE;
		npages   -= ret;

		for_each_sg(sg_list_start, sg, ret, i) {
			if (vma_list && !is_vm_hugetlb_page(vma_list[i]))
				umem->hugetlb = 0;

			sg_set_page(sg, page_list[i], PAGE_SIZE, 0);
		}

		/* preparing for next loop */
		sg_list_start = sg;
	}

	umem->nmap = ib_dma_map_sg_attrs(context->device,
				  umem->sg_head.sgl,
				  umem->npages,
				  DMA_BIDIRECTIONAL,
				  &attrs);

	if (umem->nmap <= 0) {
		ret = -ENOMEM;
		goto out;
	}

	ret = 0;

out:
	if (ret < 0) {
		if (need_release)
			__ib_umem_release(context->device, umem, 0);
		put_pid(umem->pid);
		kfree(umem);
	} else
		current->mm->pinned_vm = locked;

	up_write(&current->mm->mmap_sem);
	if (vma_list)
		free_page((unsigned long) vma_list);
	free_page((unsigned long) page_list);

	return ret < 0 ? ERR_PTR(ret) : umem;
}
EXPORT_SYMBOL(ib_umem_get);

static void ib_umem_account(struct work_struct *work)
{
	struct ib_umem *umem = container_of(work, struct ib_umem, work);

	down_write(&umem->mm->mmap_sem);
	umem->mm->pinned_vm -= umem->diff;
	up_write(&umem->mm->mmap_sem);
	mmput(umem->mm);
	kfree(umem);
}

/**
 * ib_umem_release - release memory pinned with ib_umem_get
 * @umem: umem struct to release
 */
void ib_umem_release(struct ib_umem *umem)
{
	struct ib_ucontext *context = umem->context;
	struct mm_struct *mm;
	struct task_struct *task;
	unsigned long diff;

	if (umem->odp_data) {
		ib_umem_odp_release(umem);
		return;
	}

	__ib_umem_release(umem->context->device, umem, 1);

	task = get_pid_task(umem->pid, PIDTYPE_PID);
	put_pid(umem->pid);
	if (!task)
		goto out;
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		goto out;

	diff = ib_umem_num_pages(umem);

	/*
	 * We may be called with the mm's mmap_sem already held.  This
	 * can happen when a userspace munmap() is the call that drops
	 * the last reference to our file and calls our release
	 * method.  If there are memory regions to destroy, we'll end
	 * up here and not be able to take the mmap_sem.  In that case
	 * we defer the vm_locked accounting to the system workqueue.
	 */
	if (context->closing) {
		if (!down_write_trylock(&mm->mmap_sem)) {
			INIT_WORK(&umem->work, ib_umem_account);
			umem->mm   = mm;
			umem->diff = diff;

			queue_work(ib_wq, &umem->work);
			return;
		}
	} else
		down_write(&mm->mmap_sem);

	mm->pinned_vm -= diff;
	up_write(&mm->mmap_sem);
	mmput(mm);
out:
	kfree(umem);
}
EXPORT_SYMBOL(ib_umem_release);

int ib_umem_page_count(struct ib_umem *umem)
{
	int shift;
	int i;
	int n;
	struct scatterlist *sg;

	if (umem->odp_data)
		return ib_umem_num_pages(umem);

	shift = ilog2(umem->page_size);

	n = 0;
	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, i)
		n += sg_dma_len(sg) >> shift;

	return n;
}
EXPORT_SYMBOL(ib_umem_page_count);

/*
 * Copy from the given ib_umem's pages to the given buffer.
 *
 * umem - the umem to copy from
 * offset - offset to start copying from
 * dst - destination buffer
 * length - buffer length
 *
 * Returns 0 on success, or an error code.
 */
int ib_umem_copy_from(void *dst, struct ib_umem *umem, size_t offset,
		      size_t length)
{
	size_t end = offset + length;
	int ret;

	if (offset > umem->length || length > umem->length - offset) {
		pr_err("ib_umem_copy_from not in range. offset: %zd umem length: %zd end: %zd\n",
		       offset, umem->length, end);
		return -EINVAL;
	}

	ret = sg_pcopy_to_buffer(umem->sg_head.sgl, umem->nmap, dst, length,
				 offset + ib_umem_offset(umem));

	if (ret < 0)
		return ret;
	else if (ret != length)
		return -EINVAL;
	else
		return 0;
}
EXPORT_SYMBOL(ib_umem_copy_from);
