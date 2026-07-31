// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021, Linaro Limited
// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

#include "ar_kcompat.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/genalloc.h>
#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/iosys-map.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_reserved_mem.h>
#include <linux/ioctl.h>
#include <linux/platform_device.h>
#include <linux/firmware/qcom/qcom_scm.h>
#include <linux/scatterlist.h>
#include <dt-bindings/firmware/qcom,scm.h>
#include <sound/soc.h>
#include <linux/msm_audio.h>
#include "q6apm_audio.h"
#include "q6prm_audioreach.h"
#include <linux/version.h>

int  q6apm_audio_mem_cma_init(void);
void q6apm_audio_mem_cma_exit(void);
int  msm_audio_cma_get_phy_addr(int fd, dma_addr_t *paddr, size_t *pa_len);

#define DRV_NAME "q6apm-audio-mem"

#define MSM_AUDIO_MEM_PROBED (1 << 0)

#define MSM_AUDIO_MEM_PHYS_ADDR(alloc_data) \
	alloc_data->table->sgl->dma_address

#define MSM_AUDIO_SMMU_SID_OFFSET 32
#define MINOR_NUMBER_COUNT 1
#define QCOM_SMMU_SID_MASK 0xF
#define MSM_AUDIO_HEAP_NAME "qcom,audio"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	#define AR_USE_VOID_RETURN_TYPE 1
#else
	#define AR_USE_VOID_RETURN_TYPE 0
#endif

#if AR_USE_VOID_RETURN_TYPE
#define AR_DMA_HEAP_FD_FLAGS_TYPE u32
#define AR_DMA_HEAP_HEAP_FLAGS_TYPE u64
#else
#define AR_DMA_HEAP_FD_FLAGS_TYPE unsigned long
#define AR_DMA_HEAP_HEAP_FLAGS_TYPE unsigned long
#endif

#if AR_USE_VOID_RETURN_TYPE || defined(HAVE_EXPORTED_DMA_HEAP_API)
#define AR_HAVE_EXPORTED_DMA_HEAP_API 1
#else
#define AR_HAVE_EXPORTED_DMA_HEAP_API 0
#endif


struct msm_audio_mem_private {
	bool smmu_enabled;
	struct device *cb_dev;
	u8 device_status;
	struct list_head alloc_list;
	struct mutex list_mutex;
	u64 smmu_sid_bits;
	char *driver_name;
	struct platform_device *cma_pdev;
	/*char dev related data */
	dev_t mem_major;
	struct class *mem_class;
	struct device *chardev;
	struct cdev cdev;
	bool use_mss_msa_vmid;
	struct gen_pool *audio_heap_pool;
	struct dma_heap *audio_heap;
	phys_addr_t audio_heap_base;
	size_t audio_heap_size;
	bool audio_heap_hyp_assigned;
	u64 audio_heap_perms;
	phys_addr_t audio_aux_region_base;
	size_t audio_aux_region_size;
	bool audio_aux_region_hyp_assigned;
	u64 audio_aux_region_perms;
};

#if AR_HAVE_EXPORTED_DMA_HEAP_API
struct msm_audio_heap_buffer {
	struct msm_audio_mem_private *mem_data;
	struct list_head attachments;
	struct mutex lock;
	unsigned long len;
	phys_addr_t phys;
	void *vaddr;
	int vmap_cnt;
};

struct msm_audio_heap_attachment {
	struct device *dev;
	struct sg_table table;
	struct list_head list;
	bool mapped;
};
#endif

struct msm_audio_alloc_data {
	size_t len;
	struct iosys_map *vmap;
	struct dma_buf *dma_buf;
	struct dma_buf_attachment *attach;
	struct sg_table *table;
	struct list_head list;
};


struct msm_audio_mem_fd_list_private {
	struct mutex list_mutex;
	/*list to store fd, phy. addr and handle data */
	struct list_head fd_list;
};

static struct msm_audio_mem_fd_list_private msm_audio_mem_fd_list = {0,};
static bool msm_audio_mem_fd_list_init;

struct msm_audio_fd_data {
	int fd;
	size_t plen;
	void *handle;
	dma_addr_t paddr;
	struct device *dev;
	struct list_head list;
	bool hyp_assign;
	bool use_mss_msa_vmid;
};

#ifdef QCOM_HYP_ASSIGN
static bool msm_audio_mem_range_in_audio_heap(struct msm_audio_mem_private *mem_data,
					      dma_addr_t paddr, size_t len);
#endif
static void msm_audio_mem_unassign_audio_heap(struct device *dev,
		struct msm_audio_mem_private *mem_data);

#if AR_HAVE_EXPORTED_DMA_HEAP_API
static int msm_audio_heap_attach(struct dma_buf *dmabuf,
				 struct dma_buf_attachment *attachment)
{
	struct msm_audio_heap_buffer *buffer = dmabuf->priv;
	struct msm_audio_heap_attachment *attach;
	struct page *page;
	int ret;

	attach = kzalloc(sizeof(*attach), GFP_KERNEL);
	if (!attach)
		return -ENOMEM;

	ret = sg_alloc_table(&attach->table, 1, GFP_KERNEL);
	if (ret) {
		kfree(attach);
		return ret;
	}

	page = pfn_to_page(PHYS_PFN(buffer->phys));
	sg_set_page(attach->table.sgl, page, buffer->len, 0);
	sg_dma_address(attach->table.sgl) = buffer->phys;
	sg_dma_len(attach->table.sgl) = buffer->len;
	attach->dev = attachment->dev;
	attach->mapped = false;
	INIT_LIST_HEAD(&attach->list);
	attachment->priv = attach;

	mutex_lock(&buffer->lock);
	list_add(&attach->list, &buffer->attachments);
	mutex_unlock(&buffer->lock);

	return 0;
}

static void msm_audio_heap_detach(struct dma_buf *dmabuf,
				  struct dma_buf_attachment *attachment)
{
	struct msm_audio_heap_buffer *buffer = dmabuf->priv;
	struct msm_audio_heap_attachment *attach = attachment->priv;

	mutex_lock(&buffer->lock);
	list_del(&attach->list);
	mutex_unlock(&buffer->lock);

	sg_free_table(&attach->table);
	kfree(attach);
}

static struct sg_table *msm_audio_heap_map_dma_buf(struct dma_buf_attachment *attachment,
						   enum dma_data_direction direction)
{
	struct msm_audio_heap_attachment *attach = attachment->priv;

	attach->mapped = true;

	return &attach->table;
}

static void msm_audio_heap_unmap_dma_buf(struct dma_buf_attachment *attachment,
						 struct sg_table *table,
						 enum dma_data_direction direction)
{
	struct msm_audio_heap_attachment *attach = attachment->priv;

	attach->mapped = false;
}

static int msm_audio_heap_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
							   enum dma_data_direction direction)
{
	struct msm_audio_heap_buffer *buffer = dmabuf->priv;
	struct msm_audio_heap_attachment *attach;

	mutex_lock(&buffer->lock);
	if (buffer->vmap_cnt && buffer->vaddr)
		invalidate_kernel_vmap_range(buffer->vaddr, buffer->len);

	list_for_each_entry(attach, &buffer->attachments, list) {
		if (!attach->mapped)
			continue;
		dma_sync_sgtable_for_cpu(attach->dev, &attach->table, direction);
	}
	mutex_unlock(&buffer->lock);

	return 0;
}

static int msm_audio_heap_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
							 enum dma_data_direction direction)
{
	struct msm_audio_heap_buffer *buffer = dmabuf->priv;
	struct msm_audio_heap_attachment *attach;

	mutex_lock(&buffer->lock);
	if (buffer->vmap_cnt && buffer->vaddr)
		flush_kernel_vmap_range(buffer->vaddr, buffer->len);

	list_for_each_entry(attach, &buffer->attachments, list) {
		if (!attach->mapped)
			continue;
		dma_sync_sgtable_for_device(attach->dev, &attach->table, direction);
	}
	mutex_unlock(&buffer->lock);

	return 0;
}

static int msm_audio_heap_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct msm_audio_heap_buffer *buffer = dmabuf->priv;
	unsigned long size = vma->vm_end - vma->vm_start;

	if (size > buffer->len)
		return -EINVAL;

	vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	return remap_pfn_range(vma, vma->vm_start, PHYS_PFN(buffer->phys),
					     size, vma->vm_page_prot);
}

static int msm_audio_heap_vmap(struct dma_buf *dmabuf, struct iosys_map *map)
{
	struct msm_audio_heap_buffer *buffer = dmabuf->priv;

	mutex_lock(&buffer->lock);
	if (!buffer->vmap_cnt) {
		buffer->vaddr = memremap(buffer->phys, buffer->len, MEMREMAP_WB);
		if (!buffer->vaddr) {
			mutex_unlock(&buffer->lock);
			return -ENOMEM;
		}
	}
	buffer->vmap_cnt++;
	iosys_map_set_vaddr(map, buffer->vaddr);
	mutex_unlock(&buffer->lock);

	return 0;
}

static void msm_audio_heap_vunmap(struct dma_buf *dmabuf, struct iosys_map *map)
{
	struct msm_audio_heap_buffer *buffer = dmabuf->priv;

	mutex_lock(&buffer->lock);
	if (buffer->vmap_cnt && !--buffer->vmap_cnt) {
		memunmap(buffer->vaddr);
		buffer->vaddr = NULL;
	}
	mutex_unlock(&buffer->lock);
	iosys_map_clear(map);
}

static void msm_audio_heap_dma_buf_release(struct dma_buf *dmabuf)
{
	struct msm_audio_heap_buffer *buffer = dmabuf->priv;

	if (buffer->vmap_cnt) {
		memunmap(buffer->vaddr);
		buffer->vaddr = NULL;
		buffer->vmap_cnt = 0;
	}

	gen_pool_free(buffer->mem_data->audio_heap_pool, buffer->phys, buffer->len);
	kfree(buffer);
}

static const struct dma_buf_ops msm_audio_heap_buf_ops = {
	.attach = msm_audio_heap_attach,
	.detach = msm_audio_heap_detach,
	.map_dma_buf = msm_audio_heap_map_dma_buf,
	.unmap_dma_buf = msm_audio_heap_unmap_dma_buf,
	.begin_cpu_access = msm_audio_heap_dma_buf_begin_cpu_access,
	.end_cpu_access = msm_audio_heap_dma_buf_end_cpu_access,
	.mmap = msm_audio_heap_mmap,
	.vmap = msm_audio_heap_vmap,
	.vunmap = msm_audio_heap_vunmap,
	.release = msm_audio_heap_dma_buf_release,
};

static struct dma_buf *msm_audio_heap_allocate(struct dma_heap *heap,
					       unsigned long len,
					       AR_DMA_HEAP_FD_FLAGS_TYPE fd_flags,
					       AR_DMA_HEAP_HEAP_FLAGS_TYPE heap_flags)
{
	struct msm_audio_mem_private *mem_data = dma_heap_get_drvdata(heap);
	struct msm_audio_heap_buffer *buffer;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct dma_buf *dmabuf;
	size_t size = PAGE_ALIGN(len);
	unsigned long phys;
	int ret = -ENOMEM;

	if (!size || size > mem_data->audio_heap_size)
		return ERR_PTR(-EINVAL);


	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	phys = gen_pool_alloc(mem_data->audio_heap_pool, size);
	if (!phys)
		goto free_buffer;

	buffer->mem_data = mem_data;
	buffer->len = size;
	buffer->phys = phys;
	INIT_LIST_HEAD(&buffer->attachments);
	mutex_init(&buffer->lock);

	exp_info.exp_name = MSM_AUDIO_HEAP_NAME;
	exp_info.ops = &msm_audio_heap_buf_ops;
	exp_info.size = buffer->len;
	exp_info.flags = fd_flags;
	exp_info.priv = buffer;
	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto free_pool;
	}


	return dmabuf;

free_pool:
	gen_pool_free(mem_data->audio_heap_pool, phys, size);
free_buffer:
	kfree(buffer);
	return ERR_PTR(ret);
}

static const struct dma_heap_ops msm_audio_heap_ops = {
	.allocate = msm_audio_heap_allocate,
};
#endif

#ifdef QCOM_HYP_ASSIGN
static bool msm_audio_mem_range_in_audio_heap(struct msm_audio_mem_private *mem_data,
					      dma_addr_t paddr, size_t len)
{
	phys_addr_t base;
	size_t offset;

	if (!mem_data || !mem_data->audio_heap_size || !len)
		return false;

	base = mem_data->audio_heap_base;
	if (paddr < base || len > mem_data->audio_heap_size)
		return false;

	offset = paddr - base;

	return offset <= mem_data->audio_heap_size - len;
}

static bool msm_audio_mem_skip_buffer_hyp_assign(
		struct msm_audio_mem_private *mem_data, dma_addr_t paddr, size_t len)
{
	return mem_data && mem_data->audio_heap_hyp_assigned &&
		msm_audio_mem_range_in_audio_heap(mem_data, paddr, len);
}

static int msm_audio_mem_assign_aux_audio_region(struct device *dev,
		struct msm_audio_mem_private *mem_data,
		struct qcom_scm_vmperm *dst_perms, int dst_count)
{
	struct device_node *rmem_node;
	struct reserved_mem *rmem;
	u64 src_perms = BIT(QCOM_SCM_VMID_HLOS);
	int ret;

	rmem_node = of_parse_phandle(dev->of_node, "memory-region", 0);
	if (!rmem_node)
		return 0;

	rmem = of_reserved_mem_lookup(rmem_node);
	of_node_put(rmem_node);
	if (!rmem)
		return 0;

	if (rmem->base == mem_data->audio_heap_base &&
	    rmem->size == mem_data->audio_heap_size)
		return 0;

	ret = qcom_scm_assign_mem(rmem->base, rmem->size, &src_perms,
					       dst_perms, dst_count);
	if (ret) {
		dev_err(dev,
			"%s: aux audio region assign failed ret=%d base=%pa size=%zu\n",
			__func__, ret, &rmem->base, (size_t)rmem->size);
		return ret;
	}

	mem_data->audio_aux_region_base = rmem->base;
	mem_data->audio_aux_region_size = rmem->size;
	mem_data->audio_aux_region_hyp_assigned = true;
	mem_data->audio_aux_region_perms = src_perms;

	return 0;
}

static int msm_audio_mem_assign_audio_heap(struct device *dev,
						   struct msm_audio_mem_private *mem_data)
{
	struct qcom_scm_vmperm *dst_perms;
	u64 src_perms = BIT(QCOM_SCM_VMID_HLOS);
	int num_vmids, dst_count = 0;
	int ret = 0;
	int i;
	u32 vmid;

	if (!mem_data->use_mss_msa_vmid || mem_data->audio_heap_hyp_assigned)
		return 0;

	num_vmids = of_property_count_u32_elems(dev->of_node, "qcom,vmid");
	if (num_vmids < 0) {
		dev_err(dev, "%s: qcom,vmid missing for MDSP audio heap\n",
			__func__);
		return num_vmids;
	}

	dst_perms = kcalloc(num_vmids + 1, sizeof(*dst_perms), GFP_KERNEL);
	if (!dst_perms)
		return -ENOMEM;

	dst_perms[dst_count].vmid = QCOM_SCM_VMID_HLOS;
	dst_perms[dst_count].perm = QCOM_SCM_PERM_RW;
	dst_count++;

	for (i = 0; i < num_vmids; i++) {
		ret = of_property_read_u32_index(dev->of_node, "qcom,vmid", i, &vmid);
		if (ret)
			goto free_dst_perms;

		if (vmid == QCOM_SCM_VMID_HLOS)
			continue;

		dst_perms[dst_count].vmid = vmid;
		dst_perms[dst_count].perm = QCOM_SCM_PERM_RW;
		dst_count++;
	}

	ret = qcom_scm_assign_mem(mem_data->audio_heap_base,
					       mem_data->audio_heap_size, &src_perms,
					       dst_perms, dst_count);
	if (ret) {
		dev_err(dev,
			"%s: audio heap assign failed ret=%d base=%pa size=%zu\n",
			__func__, ret, &mem_data->audio_heap_base,
			mem_data->audio_heap_size);
		goto free_dst_perms;
	}

	mem_data->audio_heap_hyp_assigned = true;
	mem_data->audio_heap_perms = src_perms;

	ret = msm_audio_mem_assign_aux_audio_region(dev, mem_data,
						     dst_perms, dst_count);
	if (ret)
		msm_audio_mem_unassign_audio_heap(dev, mem_data);

free_dst_perms:
	kfree(dst_perms);
	return ret;
}

static void msm_audio_mem_unassign_audio_heap(struct device *dev,
						     struct msm_audio_mem_private *mem_data)
{
	struct qcom_scm_vmperm hlos_perm = {
		.vmid = QCOM_SCM_VMID_HLOS,
		.perm = QCOM_SCM_PERM_RW,
	};
	u64 src_perms;
	int ret;

	if (!mem_data || !mem_data->audio_heap_hyp_assigned)
		return;

	if (mem_data->audio_aux_region_hyp_assigned) {
		src_perms = mem_data->audio_aux_region_perms;
		ret = qcom_scm_assign_mem(mem_data->audio_aux_region_base,
					       mem_data->audio_aux_region_size,
					       &src_perms, &hlos_perm, 1);
		if (ret) {
			dev_err(dev,
				"%s: aux audio region unassign failed ret=%d base=%pa size=%zu\n",
				__func__, ret, &mem_data->audio_aux_region_base,
				mem_data->audio_aux_region_size);
			return;
		}

		mem_data->audio_aux_region_hyp_assigned = false;
		mem_data->audio_aux_region_perms = src_perms;
	}

	src_perms = mem_data->audio_heap_perms;
	ret = qcom_scm_assign_mem(mem_data->audio_heap_base,
					       mem_data->audio_heap_size, &src_perms,
					       &hlos_perm, 1);
	if (ret) {
		dev_err(dev,
			"%s: audio heap unassign failed ret=%d base=%pa size=%zu\n",
			__func__, ret, &mem_data->audio_heap_base,
			mem_data->audio_heap_size);
		return;
	}

	mem_data->audio_heap_hyp_assigned = false;
	mem_data->audio_heap_perms = src_perms;
}
#else
static int msm_audio_mem_assign_audio_heap(struct device *dev,
						   struct msm_audio_mem_private *mem_data)
{
	return 0;
}

static void msm_audio_mem_unassign_audio_heap(struct device *dev,
						     struct msm_audio_mem_private *mem_data)
{
}
#endif

#if AR_HAVE_EXPORTED_DMA_HEAP_API
static int msm_audio_mem_register_audio_heap(struct platform_device *pdev,
						     struct msm_audio_mem_private *mem_data)
{
	struct dma_heap_export_info exp_info = { };
	struct device *dev = &pdev->dev;
	struct device_node *rmem_node;
	struct reserved_mem *rmem = NULL;
	int rmem_indices[] = { 1, 0 };
	int ret;
	int i;

	if (!mem_data->use_mss_msa_vmid)
		return 0;

	for (i = 0; i < ARRAY_SIZE(rmem_indices); i++) {
		rmem_node = of_parse_phandle(dev->of_node, "memory-region",
						     rmem_indices[i]);
		if (!rmem_node)
			continue;

	rmem = of_reserved_mem_lookup(rmem_node);
	of_node_put(rmem_node);
	if (rmem)
		break;

	}

	if (!rmem)
		return 0;

	mem_data->audio_heap_pool = gen_pool_create(PAGE_SHIFT, dev_to_node(dev));
	if (!mem_data->audio_heap_pool)
		return -ENOMEM;

	ret = gen_pool_add(mem_data->audio_heap_pool, rmem->base, rmem->size,
			   dev_to_node(dev));
	if (ret) {
		gen_pool_destroy(mem_data->audio_heap_pool);
		mem_data->audio_heap_pool = NULL;
		return ret;
	}

	mem_data->audio_heap_base = rmem->base;
	mem_data->audio_heap_size = rmem->size;
	ret = msm_audio_mem_assign_audio_heap(dev, mem_data);
	if (ret) {
		gen_pool_destroy(mem_data->audio_heap_pool);
		mem_data->audio_heap_pool = NULL;
		return ret;
	}

	exp_info.name = MSM_AUDIO_HEAP_NAME;
	exp_info.ops = &msm_audio_heap_ops;
	exp_info.priv = mem_data;
	mem_data->audio_heap = dma_heap_add(&exp_info);
	if (IS_ERR(mem_data->audio_heap)) {
		ret = PTR_ERR(mem_data->audio_heap);
		mem_data->audio_heap = NULL;
		msm_audio_mem_unassign_audio_heap(dev, mem_data);
		gen_pool_destroy(mem_data->audio_heap_pool);
		mem_data->audio_heap_pool = NULL;
		return ret;
	}

	return 0;
}
#else
static int
msm_audio_mem_register_audio_heap(struct platform_device *pdev,
				  struct msm_audio_mem_private *mem_data)
{
	if (mem_data->use_mss_msa_vmid)
		dev_warn(&pdev->dev,
			 "audio heap registration is not supported by this kernel\n");

	return 0;
}
#endif

static bool msm_audio_mem_uses_mss_msa_vmid(struct device *dev)
{
	int num_vmids;
	int i;
	u32 vmid;

	if (!dev || !dev->of_node)
		return false;

	num_vmids = of_property_count_u32_elems(dev->of_node, "qcom,vmid");
	if (num_vmids <= 0)
		return false;

	for (i = 0; i < num_vmids; i++) {
		if (of_property_read_u32_index(dev->of_node, "qcom,vmid", i, &vmid))
			return false;

		if (vmid == QCOM_SCM_VMID_MSS_MSA)
			return true;
	}

	return false;
}

#ifdef QCOM_HYP_ASSIGN
static int msm_audio_mem_get_hyp_map_perms(struct msm_audio_mem_private *mem_data,
		u64 *src_vmid_map_list, struct qcom_scm_vmperm **dst_vmids_map,
		int *dst_vmids_map_count)
{
	static struct qcom_scm_vmperm mss_dst_vmids_map[] = {
		{QCOM_SCM_VMID_MSS_MSA, QCOM_SCM_PERM_RW},
	};
	static struct qcom_scm_vmperm adsp_dst_vmids_map[] = {
		{QCOM_SCM_VMID_LPASS, QCOM_SCM_PERM_RW},
		{QCOM_SCM_VMID_ADSP_HEAP, QCOM_SCM_PERM_RW},
	};

	*src_vmid_map_list = BIT(QCOM_SCM_VMID_HLOS);
	if (mem_data->use_mss_msa_vmid) {
		*dst_vmids_map = mss_dst_vmids_map;
		*dst_vmids_map_count = ARRAY_SIZE(mss_dst_vmids_map);
	} else {
		*dst_vmids_map = adsp_dst_vmids_map;
		*dst_vmids_map_count = ARRAY_SIZE(adsp_dst_vmids_map);
	}

	return 0;
}

static void msm_audio_mem_get_hyp_unmap_perms(bool use_mss_msa_vmid,
		u64 *src_vmid_unmap_list, struct qcom_scm_vmperm **dst_vmids_unmap,
		int *dst_vmids_unmap_count)
{
	static struct qcom_scm_vmperm hlos_dst_vmids_unmap[] = {
		{QCOM_SCM_VMID_HLOS, QCOM_SCM_PERM_RWX},
	};

	if (use_mss_msa_vmid)
		*src_vmid_unmap_list = BIT(QCOM_SCM_VMID_MSS_MSA);
	else
		*src_vmid_unmap_list = BIT(QCOM_SCM_VMID_LPASS) |
					       BIT(QCOM_SCM_VMID_ADSP_HEAP);

	*dst_vmids_unmap = hlos_dst_vmids_unmap;
	*dst_vmids_unmap_count = ARRAY_SIZE(hlos_dst_vmids_unmap);
}
#endif

static void msm_audio_mem_add_allocation(
	struct msm_audio_mem_private *msm_audio_mem_data,
	struct msm_audio_alloc_data *alloc_data)
{
	/*
	 * Since these APIs can be invoked by multiple
	 * clients, there is need to make sure the list
	 * of allocations is always protected
	 */
	mutex_lock(&(msm_audio_mem_data->list_mutex));
	list_add_tail(&(alloc_data->list),
		      &(msm_audio_mem_data->alloc_list));
	mutex_unlock(&(msm_audio_mem_data->list_mutex));
}

static int msm_audio_mem_map_kernel(struct dma_buf *dma_buf,
	struct msm_audio_mem_private *mem_data, struct iosys_map *iosys_vmap)
{
	int rc = 0;
	struct msm_audio_alloc_data *alloc_data = NULL;

	rc = dma_buf_begin_cpu_access(dma_buf, DMA_BIDIRECTIONAL);
	if (rc) {
		pr_err("%s: kmap dma_buf_begin_cpu_access fail\n", __func__);
		goto exit;
	}

	rc = dma_buf_vmap(dma_buf, iosys_vmap);
	if (rc) {
		pr_err("%s: kernel mapping of dma_buf failed\n",
		       __func__);
		goto exit;
	}

	/*
	 * TBD: remove the below section once new API
	 * for mapping kernel virtual address is available.
	 */
	mutex_lock(&(mem_data->list_mutex));
	list_for_each_entry(alloc_data, &(mem_data->alloc_list),
			    list) {
		if (alloc_data->dma_buf == dma_buf) {
			alloc_data->vmap = iosys_vmap;
			break;
		}
	}
	mutex_unlock(&(mem_data->list_mutex));

exit:
	return rc;
}

static int msm_audio_dma_buf_map(struct dma_buf *dma_buf,
				 dma_addr_t *addr, size_t *len, bool is_iova,
				 struct msm_audio_mem_private *mem_data)
{

	struct msm_audio_alloc_data *alloc_data = NULL;
	int rc = 0;
	struct iosys_map *iosys_vmap = NULL;
	struct device *cb_dev = mem_data->cb_dev;

	iosys_vmap = kzalloc(sizeof(*iosys_vmap), GFP_KERNEL);
	if (!iosys_vmap)
		return -ENOMEM;
	/* Data required per buffer mapping */
	alloc_data = kzalloc(sizeof(*alloc_data), GFP_KERNEL);
	if (!alloc_data) {
		kfree(iosys_vmap);
		return -ENOMEM;
	}
	alloc_data->dma_buf = dma_buf;
	alloc_data->len = dma_buf->size;
	*len = dma_buf->size;

	/* Attach the dma_buf to context bank device */
	alloc_data->attach = dma_buf_attach(alloc_data->dma_buf,
					    cb_dev);
	if (IS_ERR(alloc_data->attach)) {
		rc = PTR_ERR(alloc_data->attach);
		dev_err(cb_dev,
			"%s: Fail to attach dma_buf to CB, rc = %d\n",
			__func__, rc);
		goto free_alloc_data;
	}

	/*
	 * Get the scatter-gather list.
	 * There is no info as this is a write buffer or
	 * read buffer, hence the request is bi-directional
	 * to accommodate both read and write mappings.
	 */
	alloc_data->table = dma_buf_map_attachment(alloc_data->attach,
						DMA_BIDIRECTIONAL);
	if (IS_ERR(alloc_data->table)) {
		rc = PTR_ERR(alloc_data->table);
		dev_err(cb_dev,
			"%s: Fail to map attachment, rc = %d\n",
			__func__, rc);
		goto detach_dma_buf;
	}

	/* physical address from mapping */
	if (!is_iova) {
		*addr = sg_phys(alloc_data->table->sgl);
		rc = msm_audio_mem_map_kernel((void *)dma_buf, mem_data,
					       iosys_vmap);
		if (rc) {
			pr_err("%s: MEM memory mapping for AUDIO failed, err:%d\n",
			       __func__, rc);
			rc = -ENOMEM;
			goto detach_dma_buf;
		}
		alloc_data->vmap = iosys_vmap;
	} else {
		*addr = MSM_AUDIO_MEM_PHYS_ADDR(alloc_data);
	}

	msm_audio_mem_add_allocation(mem_data, alloc_data);
	return rc;

detach_dma_buf:
	dma_buf_detach(alloc_data->dma_buf,
		       alloc_data->attach);
free_alloc_data:
	kfree(iosys_vmap);
	kfree(alloc_data);
	alloc_data = NULL;

	return rc;
}

static int msm_audio_dma_buf_unmap(struct dma_buf *dma_buf, struct msm_audio_mem_private *mem_data)
{
	int rc = 0;
	struct msm_audio_alloc_data *alloc_data = NULL;
	struct list_head *ptr, *next;
	bool found = false;
	struct device *cb_dev = mem_data->cb_dev;

	/*
	 * Though list_for_each_safe is delete safe, lock
	 * should be explicitly acquired to avoid race condition
	 * on adding elements to the list.
	 */
	mutex_lock(&(mem_data->list_mutex));
	list_for_each_safe(ptr, next,
			    &(mem_data->alloc_list)) {

		alloc_data = list_entry(ptr, struct msm_audio_alloc_data,
					list);

		if (alloc_data->dma_buf == dma_buf) {
			found = true;
			dma_buf_unmap_attachment(alloc_data->attach,
						 alloc_data->table,
						 DMA_BIDIRECTIONAL);

			dma_buf_detach(alloc_data->dma_buf,
				       alloc_data->attach);

			dma_buf_put(alloc_data->dma_buf);

			list_del(&(alloc_data->list));
			kfree(alloc_data->vmap);
			kfree(alloc_data);
			alloc_data = NULL;
			break;
		}
	}
	mutex_unlock(&(mem_data->list_mutex));

	if (!found) {
		dev_err(cb_dev,
			"%s: cannot find allocation, dma_buf %pK\n",
			__func__, dma_buf);
		rc = -EINVAL;
	}

	return rc;
}

static int msm_audio_mem_get_phys(struct dma_buf *dma_buf,
				  dma_addr_t *addr, size_t *len, bool is_iova,
				  struct msm_audio_mem_private *mem_data)
{
	int rc = 0;

	rc = msm_audio_dma_buf_map(dma_buf, addr, len, is_iova, mem_data);
	if (rc) {
		pr_err("%s: failed to map DMA buf, err = %d\n",
			__func__, rc);
		goto err;
	}
	if (mem_data->smmu_enabled && is_iova) {
		/* Append the SMMU SID information to the IOVA address */
		*addr |= mem_data->smmu_sid_bits;
	}

	pr_debug("phys=%pK, len=%zd, rc=%d\n", &(*addr), *len, rc);
err:
	return rc;
}

static int msm_audio_mem_unmap_kernel(struct dma_buf *dma_buf,
		struct msm_audio_mem_private *mem_data)
{
	int rc = 0;
	struct iosys_map *iosys_vmap = NULL;
	struct msm_audio_alloc_data *alloc_data = NULL;
	struct device *cb_dev = mem_data->cb_dev;

	/*
	 * TBD: remove the below section once new API
	 * for unmapping kernel virtual address is available.
	 */
	mutex_lock(&(mem_data->list_mutex));
	list_for_each_entry(alloc_data, &(mem_data->alloc_list),
			    list) {
		if (alloc_data->dma_buf == dma_buf) {
			iosys_vmap = alloc_data->vmap;
			break;
		}
	}
	mutex_unlock(&(mem_data->list_mutex));

	if (!iosys_vmap) {
		dev_err(cb_dev,
			"%s: cannot find allocation for dma_buf %pK\n",
			__func__, dma_buf);
		rc = -EINVAL;
		goto err;
	}

	dma_buf_vunmap(dma_buf, iosys_vmap);

	rc = dma_buf_end_cpu_access(dma_buf, DMA_BIDIRECTIONAL);
	if (rc) {
		dev_err(cb_dev, "%s: kmap dma_buf_end_cpu_access fail\n",
			__func__);
		goto err;
	}

err:
	return rc;
}

static int msm_audio_mem_map_buf(struct dma_buf *dma_buf, dma_addr_t *paddr,
				 size_t *plen, struct iosys_map *iosys_vmap,
				 struct msm_audio_mem_private *mem_data)
{
	int rc = 0;
	bool is_iova = true;

	if (!dma_buf || !paddr || !plen) {
		pr_err("%s: Invalid params\n", __func__);
		return -EINVAL;
	}

	rc = msm_audio_mem_get_phys(dma_buf, paddr, plen, is_iova, mem_data);
	if (rc) {
		pr_err("%s: MEM Get Physical for AUDIO failed, rc = %d\n",
				__func__, rc);
		dma_buf_put(dma_buf);
		goto err;
	}

	rc = msm_audio_mem_map_kernel(dma_buf, mem_data, iosys_vmap);
	if (rc) {
		pr_err("%s: MEM memory mapping for AUDIO failed, err:%d\n",
			__func__, rc);
		rc = -ENOMEM;
		msm_audio_dma_buf_unmap(dma_buf, mem_data);
		goto err;
	}

err:
	return rc;
}


static void msm_audio_update_fd_list(struct msm_audio_fd_data *msm_audio_fd_data)
{
	struct msm_audio_fd_data *msm_audio_fd_data1 = NULL;

	mutex_lock(&(msm_audio_mem_fd_list.list_mutex));
	list_for_each_entry(msm_audio_fd_data1,
			&msm_audio_mem_fd_list.fd_list, list) {
		if (msm_audio_fd_data1->fd == msm_audio_fd_data->fd) {
			pr_err("%s fd already present, not updating the list\n",
				__func__);
			mutex_unlock(&(msm_audio_mem_fd_list.list_mutex));
			return;
		}
	}
	list_add_tail(&msm_audio_fd_data->list, &msm_audio_mem_fd_list.fd_list);
	mutex_unlock(&(msm_audio_mem_fd_list.list_mutex));
}

static void msm_audio_delete_fd_entry(void *handle)
{
	struct msm_audio_fd_data *msm_audio_fd_data = NULL;
	struct list_head *ptr, *next;

	mutex_lock(&(msm_audio_mem_fd_list.list_mutex));
	list_for_each_safe(ptr, next,
			&msm_audio_mem_fd_list.fd_list) {
		msm_audio_fd_data = list_entry(ptr, struct msm_audio_fd_data,
					list);
		if (msm_audio_fd_data->handle == handle) {
			pr_debug("%s deleting handle %pK entry from list\n",
				__func__, handle);
			list_del(&(msm_audio_fd_data->list));
			kfree(msm_audio_fd_data);
			break;
		}
	}
	mutex_unlock(&(msm_audio_mem_fd_list.list_mutex));
}

int msm_audio_get_phy_addr(int fd, dma_addr_t *paddr, size_t *pa_len)
{
	struct msm_audio_fd_data *msm_audio_fd_data = NULL;
	int status = -EINVAL;

	if (!paddr) {
		pr_err("%s Invalid paddr param status %d\n", __func__, status);
		return status;
	}
	pr_debug("%s, fd %d\n", __func__, fd);
	mutex_lock(&(msm_audio_mem_fd_list.list_mutex));
	list_for_each_entry(msm_audio_fd_data,
			&msm_audio_mem_fd_list.fd_list, list) {
		if (msm_audio_fd_data->fd == fd) {
			*paddr = msm_audio_fd_data->paddr;
			*pa_len = msm_audio_fd_data->plen;
			status = 0;
			pr_debug("%s Found fd %d paddr %pK\n",
				__func__, fd, paddr);
			mutex_unlock(&(msm_audio_mem_fd_list.list_mutex));
			return status;
		}
	}
	mutex_unlock(&(msm_audio_mem_fd_list.list_mutex));

	/* fd not found in SMMU list — check CMA driver's fd-list */
	if (status)
		status = msm_audio_cma_get_phy_addr(fd, paddr, pa_len);

	return status;
}

#ifdef QCOM_HYP_ASSIGN
static int msm_audio_set_hyp_assign(int fd, bool assign)
{
	struct msm_audio_fd_data *msm_audio_fd_data = NULL;
	int status = -EINVAL;

	mutex_lock(&(msm_audio_mem_fd_list.list_mutex));
	list_for_each_entry(msm_audio_fd_data,
			&msm_audio_mem_fd_list.fd_list, list) {
		if (msm_audio_fd_data->fd == fd) {
			status = 0;
			pr_debug("%s Found fd %d\n", __func__, fd);
			msm_audio_fd_data->hyp_assign = assign;
			mutex_unlock(&(msm_audio_mem_fd_list.list_mutex));
			return status;
		}
	}
	mutex_unlock(&(msm_audio_mem_fd_list.list_mutex));
	return status;
}
#endif

static void msm_audio_get_handle(int fd, void **handle)
{
	struct msm_audio_fd_data *msm_audio_fd_data = NULL;

	pr_debug("%s fd %d\n", __func__, fd);
	mutex_lock(&(msm_audio_mem_fd_list.list_mutex));
	list_for_each_entry(msm_audio_fd_data,
			&msm_audio_mem_fd_list.fd_list, list) {
		if (msm_audio_fd_data->fd == fd) {
			*handle = (struct dma_buf *)msm_audio_fd_data->handle;
			pr_debug("%s handle %pK\n", __func__, *handle);
			break;
		}
	}
	mutex_unlock(&(msm_audio_mem_fd_list.list_mutex));
}

/**
 * msm_audio_mem_import-
 *        Import MEM buffer with given file descriptor
 *
 * @dma_buf: dma_buf for the MEM memory
 * @fd: file descriptor for the MEM memory
 * @bufsz: buffer size
 * @paddr: Physical address to be assigned with allocated region
 * @plen: length of allocated region to be assigned
 * @iosys_vmap: Virtual mapping vmap pointer to be assigned
 *
 * Returns 0 on success or error on failure
 */
static int msm_audio_mem_import(struct dma_buf **dma_buf, int fd,
			size_t bufsz, dma_addr_t *paddr,
			size_t *plen, struct iosys_map *iosys_vmap,
			struct msm_audio_mem_private *mem_data)
{
	int rc = 0;

	if (!(mem_data->device_status & MSM_AUDIO_MEM_PROBED)) {
		pr_debug("%s: probe is not done, deferred\n", __func__);
		return -EPROBE_DEFER;
	}

	if (!dma_buf || !paddr || !plen) {
		pr_err("%s: Invalid params\n", __func__);
		return -EINVAL;
	}

	/* bufsz should be 0 and fd shouldn't be 0 as of now */
	*dma_buf = dma_buf_get(fd);
	pr_debug("%s: dma_buf =%pK, fd=%d\n", __func__, *dma_buf, fd);
	if (IS_ERR_OR_NULL((void *)(*dma_buf))) {
		pr_err("%s: dma_buf_get failed\n", __func__);
		return -EINVAL;
	}

	if (mem_data->smmu_enabled) {
		rc = msm_audio_mem_map_buf(*dma_buf, paddr, plen, iosys_vmap, mem_data);
		if (rc) {
			pr_err("%s: failed to map MEM buf, rc = %d\n", __func__, rc);
			goto err;
		}
		pr_debug("%s: mapped address = %pK, size=%zd\n", __func__,
				iosys_vmap->vaddr, bufsz);
	} else {
		msm_audio_dma_buf_map(*dma_buf, paddr, plen, true, mem_data);
	}
	return 0;
err:
	dma_buf_put(*dma_buf);
	*dma_buf = NULL;
	return rc;
}

/**
 * msm_audio_mem_free -
 *        fress MEM memory for given client and handle
 *
 * @dma_buf: dma_buf for the MEM memory
 *
 * Returns 0 on success or error on failure
 */
static int msm_audio_mem_free(struct dma_buf *dma_buf, struct msm_audio_mem_private *mem_data)
{
	int ret = 0;

	if (!dma_buf) {
		pr_err("%s: dma_buf invalid\n", __func__);
		return -EINVAL;
	}

	if (mem_data->smmu_enabled) {
		ret = msm_audio_mem_unmap_kernel(dma_buf, mem_data);
		if (ret)
			return ret;
	}

	msm_audio_dma_buf_unmap(dma_buf, mem_data);

	return 0;
}

#ifdef QCOM_HYP_ASSIGN
static int msm_audio_hyp_unassign(struct msm_audio_fd_data *msm_audio_fd_data)
{
	int ret = 0;
	u64 src_vmid_unmap_list;
	struct qcom_scm_vmperm *dst_vmids_unmap;
	int dst_vmids_unmap_count;

	if (msm_audio_fd_data->hyp_assign) {
		msm_audio_mem_get_hyp_unmap_perms(msm_audio_fd_data->use_mss_msa_vmid,
				&src_vmid_unmap_list, &dst_vmids_unmap,
				&dst_vmids_unmap_count);
		ret = qcom_scm_assign_mem(msm_audio_fd_data->paddr,
					  msm_audio_fd_data->plen,
					  &src_vmid_unmap_list,
					  dst_vmids_unmap,
					  dst_vmids_unmap_count);
		if (ret < 0) {
			pr_err("%s: qcom assign unmap failed result = %d addr = 0x%llx size = %zu\n",
				__func__, ret, msm_audio_fd_data->paddr, msm_audio_fd_data->plen);
		}
		msm_audio_fd_data->hyp_assign = false;
		pr_debug("%s: qcom scm unmap success\n", __func__);
	}
	return ret;
}
#endif

/**
 * msm_audio_mem_crash_handler -
 *        handles cleanup after userspace crashes.
 *
 * To be called from machine driver.
 */
void msm_audio_mem_crash_handler(void)
{
	struct msm_audio_fd_data *msm_audio_fd_data = NULL;
	struct list_head *ptr, *next;
	void *handle = NULL;
	struct msm_audio_mem_private *mem_data = NULL;

	mutex_lock(&(msm_audio_mem_fd_list.list_mutex));
	list_for_each_entry(msm_audio_fd_data,
		&msm_audio_mem_fd_list.fd_list, list) {
		handle = msm_audio_fd_data->handle;
		mem_data = dev_get_drvdata(msm_audio_fd_data->dev);
		/*  clean if CMA was used*/
#ifdef QCOM_HYP_ASSIGN
		if (msm_audio_fd_data->hyp_assign)
			msm_audio_hyp_unassign(msm_audio_fd_data);
#endif
		if (handle)
			msm_audio_mem_free(handle, mem_data);
	}
	list_for_each_safe(ptr, next,
		&msm_audio_mem_fd_list.fd_list) {
		msm_audio_fd_data = list_entry(ptr, struct msm_audio_fd_data,
						list);
		list_del(&(msm_audio_fd_data->list));
		kfree(msm_audio_fd_data);
	}
	mutex_unlock(&(msm_audio_mem_fd_list.list_mutex));
}

static int msm_audio_mem_open(struct inode *inode, struct file *file)
{
	struct msm_audio_mem_private *mem_data = container_of(inode->i_cdev,
						struct msm_audio_mem_private,
						cdev);
	struct device *dev = mem_data->chardev;

	get_device(dev);
	return 0;
}

static int msm_audio_mem_release(struct inode *inode, struct file *file)
{
	struct msm_audio_mem_private *mem_data = container_of(inode->i_cdev,
						struct msm_audio_mem_private,
						cdev);
	struct device *dev = mem_data->chardev;

	put_device(dev);
	return 0;
}

static long msm_audio_mem_ioctl(struct file *file, unsigned int ioctl_num,
				unsigned long __user ioctl_param)
{
	void *mem_handle;
	dma_addr_t paddr;
	size_t pa_len = 0;
	struct iosys_map *iosys_vmap = NULL;
	int ret = 0;
	struct msm_audio_fd_data *msm_audio_fd_data = NULL;
	struct msm_audio_mem_private *mem_data =
			container_of(file->f_inode->i_cdev, struct msm_audio_mem_private, cdev);
#ifdef QCOM_HYP_ASSIGN
	u64 src_vmid_map_list = BIT(QCOM_SCM_VMID_HLOS);
	struct qcom_scm_vmperm *dst_vmids_map;
	int dst_vmids_map_count;
	u64 src_vmid_unmap_list;
	struct qcom_scm_vmperm *dst_vmids_unmap;
	int dst_vmids_unmap_count;
#endif

	switch (ioctl_num) {
	case IOCTL_MAP_PHYS_ADDR:
		iosys_vmap = kzalloc(sizeof(*iosys_vmap), GFP_KERNEL);
		if (!iosys_vmap)
			return -ENOMEM;
		msm_audio_fd_data = kzalloc(sizeof(*msm_audio_fd_data), GFP_KERNEL);
		if (!msm_audio_fd_data) {
			kfree(iosys_vmap);
			return -ENOMEM;
		}
		ret = msm_audio_mem_import((struct dma_buf **)&mem_handle, (int)ioctl_param,
					0, &paddr, &pa_len, iosys_vmap, mem_data);
		if (ret < 0) {
			pr_err("%s Memory map Failed %d\n", __func__, ret);
			kfree(iosys_vmap);
			kfree(msm_audio_fd_data);
			return ret;
		}
		msm_audio_fd_data->fd = (int)ioctl_param;
		msm_audio_fd_data->handle = mem_handle;
		msm_audio_fd_data->paddr = paddr;
		msm_audio_fd_data->plen = pa_len;
		msm_audio_fd_data->dev = mem_data->cb_dev;
		msm_audio_fd_data->use_mss_msa_vmid = mem_data->use_mss_msa_vmid;
		msm_audio_update_fd_list(msm_audio_fd_data);
		break;
	case IOCTL_UNMAP_PHYS_ADDR:
		msm_audio_get_handle((int)ioctl_param, &mem_handle);
		ret = msm_audio_mem_free(mem_handle, mem_data);
		if (ret < 0) {
			pr_err("%s Ion free failed %d\n", __func__, ret);
			return ret;
		}
		msm_audio_delete_fd_entry(mem_handle);
		break;
#ifdef QCOM_HYP_ASSIGN
	case IOCTL_MAP_HYP_ASSIGN:
		ret = msm_audio_get_phy_addr((int)ioctl_param, &paddr, &pa_len);
		if (ret < 0) {
			pr_err("%s get phys addr failed %d\n", __func__, ret);
			return ret;
		}
		if (msm_audio_mem_skip_buffer_hyp_assign(mem_data, paddr, pa_len)) {
			msm_audio_set_hyp_assign((int)ioctl_param, false);
			break;
		}
		msm_audio_mem_get_hyp_map_perms(mem_data, &src_vmid_map_list,
					    &dst_vmids_map, &dst_vmids_map_count);
		ret = qcom_scm_assign_mem(paddr, pa_len, &src_vmid_map_list,
					  dst_vmids_map, dst_vmids_map_count);
		if (ret < 0) {
			pr_err("%s: qcom_assign failed result = %d addr = 0x%llx size = %lu\n",
			       __func__, ret, paddr, pa_len);
			return ret;
		}
		pr_debug("%s: qcom scm assign success\n", __func__);
		msm_audio_set_hyp_assign((int)ioctl_param, true);
		break;
	case IOCTL_UNMAP_HYP_ASSIGN:
		ret = msm_audio_get_phy_addr((int)ioctl_param, &paddr, &pa_len);
		if (ret < 0) {
			pr_err("%s get phys addr failed %d\n", __func__, ret);
			return ret;
		}
		if (msm_audio_mem_skip_buffer_hyp_assign(mem_data, paddr, pa_len)) {
			msm_audio_set_hyp_assign((int)ioctl_param, false);
			break;
		}
		msm_audio_mem_get_hyp_unmap_perms(mem_data->use_mss_msa_vmid,
					      &src_vmid_unmap_list, &dst_vmids_unmap,
					      &dst_vmids_unmap_count);
		ret = qcom_scm_assign_mem(paddr, pa_len, &src_vmid_unmap_list,
					  dst_vmids_unmap, dst_vmids_unmap_count);
		if (ret < 0) {
			pr_err("%s: qcom scm unassign failed result = %d addr = 0x%llx size = %lu\n",
			       __func__, ret, paddr, pa_len);
			return ret;
		}
		pr_debug("%s: qcom scm unassign success\n", __func__);
		msm_audio_set_hyp_assign((int)ioctl_param, false);
		break;
#endif
	default:
		pr_err_ratelimited("%s Entered default. Invalid ioctl num %u\n",
				   __func__, ioctl_num);
		ret = -EINVAL;
		break;
	}
	return ret;
}


static const struct snd_soc_component_driver q6apm_audio_mem_component = {
	.name		= DRV_NAME,
};


static const struct file_operations msm_audio_mem_fops = {
	.owner = THIS_MODULE,
	.open = msm_audio_mem_open,
	.release = msm_audio_mem_release,
	.unlocked_ioctl = msm_audio_mem_ioctl,
};

static int msm_audio_mem_reg_chrdev(struct msm_audio_mem_private *mem_data)
{
	int ret = 0;

	ret = alloc_chrdev_region(&mem_data->mem_major, 0,
				MINOR_NUMBER_COUNT, mem_data->driver_name);
	if (ret < 0) {
		pr_err("%s alloc_chr_dev_region failed ret : %d\n",
			__func__, ret);
		return ret;
	}
	pr_debug("%s major number %d\n", __func__, MAJOR(mem_data->mem_major));
	mem_data->mem_class = class_create(mem_data->driver_name);
	if (IS_ERR(mem_data->mem_class)) {
		ret = PTR_ERR(mem_data->mem_class);
		pr_err("%s class create failed. ret : %d\n", __func__, ret);
		goto err_class;
	}
	mem_data->chardev = device_create(mem_data->mem_class, NULL,
				mem_data->mem_major, NULL,
				mem_data->driver_name);
	if (IS_ERR(mem_data->chardev)) {
		ret = PTR_ERR(mem_data->chardev);
		pr_err("%s device create failed ret : %d\n", __func__, ret);
		goto err_device;
	}
	cdev_init(&mem_data->cdev, &msm_audio_mem_fops);
	ret = cdev_add(&mem_data->cdev, mem_data->mem_major, 1);
	if (ret) {
		pr_err("%s cdev add failed, ret : %d\n", __func__, ret);
		goto err_cdev;
	}
	return ret;

err_cdev:
	device_destroy(mem_data->mem_class, mem_data->mem_major);
err_device:
	class_destroy(mem_data->mem_class);
err_class:
	unregister_chrdev_region(0, MINOR_NUMBER_COUNT);
	return ret;
}

static int msm_audio_mem_unreg_chrdev(struct msm_audio_mem_private *mem_data)
{
	cdev_del(&mem_data->cdev);
	device_destroy(mem_data->mem_class, mem_data->mem_major);
	class_destroy(mem_data->mem_class);
	unregister_chrdev_region(0, MINOR_NUMBER_COUNT);
	return 0;
}

static int q6apm_audio_mem_probe(struct platform_device *pdev)
{
	int rc = 0;
	u64 smmu_sid = 0;
	u64 smmu_sid_mask = 0;
	struct device *dev = &pdev->dev;
	struct of_phandle_args iommuspec;
	struct msm_audio_mem_private *msm_audio_mem_data = NULL;

	if (dev->of_node == NULL) {
		dev_err(dev,
			"%s: device tree is not found\n",
			__func__);
		return 0;
	}

	msm_audio_mem_data = devm_kzalloc(&pdev->dev, (sizeof(struct msm_audio_mem_private)),
			GFP_KERNEL);
	if (!msm_audio_mem_data)
		return -ENOMEM;


	msm_audio_mem_data->driver_name = "msm_audio_mem";
	msm_audio_mem_data->use_mss_msa_vmid = msm_audio_mem_uses_mss_msa_vmid(dev);

	/* Enable SMMU only if DT has an 'iommus' property */
	if (of_find_property(dev->of_node, "iommus", NULL))
		msm_audio_mem_data->smmu_enabled = true;
	else
		msm_audio_mem_data->smmu_enabled = false;

	dev_info(dev, "%s: SMMU is %s\n", __func__,
		 (!msm_audio_mem_data->smmu_enabled) ? "Disabled" : "Enabled");

	AR_SET_DMA_COHERENT(dev);
	if (msm_audio_mem_data->smmu_enabled) {
		/* Get SMMU SID information from Devicetree */
		smmu_sid_mask = QCOM_SMMU_SID_MASK;

		rc = of_parse_phandle_with_args(dev->of_node, "iommus",
						"#iommu-cells", 0, &iommuspec);
		if (rc) {
			dev_err(dev, "%s: could not get smmu SID, ret = %d\n",
				__func__, rc);
			/* Parsing failed; disable SMMU safely */
			msm_audio_mem_data->smmu_enabled = false;
		} else {
			smmu_sid = (iommuspec.args[0] & smmu_sid_mask);
		}
		if (msm_audio_mem_data->smmu_enabled)
			msm_audio_mem_data->smmu_sid_bits = smmu_sid << MSM_AUDIO_SMMU_SID_OFFSET;
	}

	if (!rc) {
		msm_audio_mem_data->device_status |= MSM_AUDIO_MEM_PROBED;
	}
	msm_audio_mem_data->cb_dev = dev;
	dev_set_drvdata(dev, msm_audio_mem_data);
	rc = msm_audio_mem_register_audio_heap(pdev, msm_audio_mem_data);
	if (rc) {
		dev_err(dev, "%s: audio heap registration failed %d\n",
			__func__, rc);
		return rc;
	}
	if (!msm_audio_mem_fd_list_init) {
		INIT_LIST_HEAD(&msm_audio_mem_fd_list.fd_list);
		mutex_init(&(msm_audio_mem_fd_list.list_mutex));
		msm_audio_mem_fd_list_init = true;
	}
	INIT_LIST_HEAD(&msm_audio_mem_data->alloc_list);
	mutex_init(&(msm_audio_mem_data->list_mutex));
	rc = msm_audio_mem_reg_chrdev(msm_audio_mem_data);
	if (rc) {
		pr_err("%s register char dev failed, rc : %d\n", __func__, rc);
		msm_audio_mem_unassign_audio_heap(dev, msm_audio_mem_data);
		return rc;
	}

	rc = devm_snd_soc_register_component(dev, &q6apm_audio_mem_component,
					       NULL, 0);
	if (rc) {
		pr_err("%s register component failed, rc : %d\n", __func__, rc);
		msm_audio_mem_unreg_chrdev(msm_audio_mem_data);
		msm_audio_mem_unassign_audio_heap(dev, msm_audio_mem_data);
		return rc;
	}

	/*
	 * Spawn the CMA child driver only if DT has a memory-region property
	 * and we are not using the MSS MSA VMID path (Shikra uses the
	 * dedicated audio heap instead of CMA).
	 */
	if (!msm_audio_mem_data->use_mss_msa_vmid &&
	    of_find_property(dev->of_node, "memory-region", NULL)) {
		msm_audio_mem_data->cma_pdev =
			platform_device_register_data(dev, "q6apm-audio-mem-cma",
						      PLATFORM_DEVID_NONE, NULL, 0);
		if (IS_ERR(msm_audio_mem_data->cma_pdev)) {
			dev_err(dev, "%s: CMA child pdev register failed rc=%ld\n",
				__func__, PTR_ERR(msm_audio_mem_data->cma_pdev));
			msm_audio_mem_data->cma_pdev = NULL;
		}
	} else if (!msm_audio_mem_data->use_mss_msa_vmid) {
		dev_info(dev, "%s: no memory-region, CMA driver not spawned\n", __func__);
	}

	return 0;
}

#if AR_USE_VOID_RETURN_TYPE
static void q6apm_audio_mem_remove(struct platform_device *pdev)
{
	struct msm_audio_mem_private *mem_data = dev_get_drvdata(&pdev->dev);

	if (mem_data->cma_pdev)
		platform_device_unregister(mem_data->cma_pdev);
	mem_data->smmu_enabled = false;
	mem_data->device_status = 0;
	msm_audio_mem_unassign_audio_heap(&pdev->dev, mem_data);
	msm_audio_mem_unreg_chrdev(mem_data);
}
#else
static int q6apm_audio_mem_remove(struct platform_device *pdev)
{
	struct msm_audio_mem_private *mem_data = dev_get_drvdata(&pdev->dev);

	if (mem_data->cma_pdev)
		platform_device_unregister(mem_data->cma_pdev);
	mem_data->smmu_enabled = false;
	mem_data->device_status = 0;
	msm_audio_mem_unassign_audio_heap(&pdev->dev, mem_data);
	msm_audio_mem_unreg_chrdev(mem_data);
	return 0;
}
#endif

#ifdef CONFIG_OF
static const struct of_device_id q6apm_audio_mem_device_id[] = {
	{ .compatible = "qcom,q6apm-dais" },
	{},
};
MODULE_DEVICE_TABLE(of, q6apm_audio_mem_device_id);
#endif


static struct platform_driver q6apm_audio_mem_platform_driver = {
	.driver = {
		.name = "q6apm-audio-mem",
		.of_match_table = of_match_ptr(q6apm_audio_mem_device_id),
	},
	.probe = q6apm_audio_mem_probe,
	.remove = q6apm_audio_mem_remove,
};
//module_platform_driver(q6apm_audio_mem_platform_driver);

int q6apm_audio_mem_init(void)
{
	int ret;

	ret = q6apm_audio_mem_cma_init();
	if (ret) {
		pr_err("%s: CMA driver register failed ret=%d\n", __func__, ret);
		return ret;
	}
	ret = platform_driver_register(&q6apm_audio_mem_platform_driver);
	if (ret) {
		pr_err("%s: SMMU driver register failed ret=%d\n", __func__, ret);
		q6apm_audio_mem_cma_exit();
	}
	return ret;
}

void q6apm_audio_mem_exit(void)
{
	platform_driver_unregister(&q6apm_audio_mem_platform_driver);
	q6apm_audio_mem_cma_exit();
}

MODULE_DESCRIPTION("Q6APM audio mem driver");
MODULE_LICENSE("GPL");
AR_MODULE_IMPORT_NS(DMA_BUF);
MODULE_IMPORT_NS("DMA_BUF_HEAP");
