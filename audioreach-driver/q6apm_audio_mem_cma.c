// SPDX-License-Identifier: GPL-2.0
// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

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
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/iosys-map.h>
#include <linux/of_platform.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>
#include <linux/iommu.h>
#include <linux/firmware/qcom/qcom_scm.h>
#include <dt-bindings/firmware/qcom,scm.h>
#include <sound/soc.h>
#include <linux/msm_audio.h>
#include "q6apm_audio.h"
#include <linux/version.h>

#define DRV_NAME_CMA "msm_audio_mem_cma"

#define MSM_AUDIO_MEM_CMA_PROBED (1 << 0)

#define MSM_AUDIO_MEM_CMA_PHYS_ADDR(alloc_data) \
	alloc_data->table->sgl->dma_address

#define MINOR_NUMBER_COUNT_CMA 1

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define AR_USE_VOID_RETURN_TYPE 1
#else
#define AR_USE_VOID_RETURN_TYPE 0
#endif

struct msm_audio_mem_cma_private {
	bool has_iommu;
	struct device *cb_dev;
	u8 device_status;
	struct list_head alloc_list;
	struct mutex list_mutex;
	struct iommu_domain *rproc_domain;
	/* chardev */
	dev_t mem_major;
	struct class *mem_class;
	struct device *chardev;
	struct cdev cdev;
};

struct msm_audio_cma_alloc_data {
	size_t len;
	struct iosys_map *vmap;
	struct dma_buf *dma_buf;
	struct dma_buf_attachment *attach;
	struct sg_table *table;
	struct list_head list;
};

struct msm_audio_cma_fd_list_private {
	struct mutex list_mutex;
	struct list_head fd_list;
};

static struct msm_audio_cma_fd_list_private msm_audio_cma_fd_list = {0,};
static bool msm_audio_cma_fd_list_init;

struct msm_audio_cma_fd_data {
	int fd;
	size_t plen;
	void *handle;
	dma_addr_t paddr;
	struct device *dev;
	struct list_head list;
	bool hyp_assign;
};

/* ------------------------------------------------------------------ */
/* alloc_list helpers                                                  */
/* ------------------------------------------------------------------ */

static void msm_audio_cma_add_allocation(struct msm_audio_mem_cma_private *priv,
					 struct msm_audio_cma_alloc_data *alloc_data)
{
	mutex_lock(&priv->list_mutex);
	list_add_tail(&alloc_data->list, &priv->alloc_list);
	mutex_unlock(&priv->list_mutex);
}

static int msm_audio_cma_map_kernel(struct dma_buf *dma_buf,
				    struct msm_audio_mem_cma_private *priv,
				    struct iosys_map *iosys_vmap)
{
	int rc;
	struct msm_audio_cma_alloc_data *alloc_data;

	rc = dma_buf_begin_cpu_access(dma_buf, DMA_BIDIRECTIONAL);
	if (rc) {
		pr_err("%s: dma_buf_begin_cpu_access fail\n", __func__);
		return rc;
	}

	rc = dma_buf_vmap(dma_buf, iosys_vmap);
	if (rc) {
		pr_err("%s: dma_buf_vmap failed\n", __func__);
		return rc;
	}

	mutex_lock(&priv->list_mutex);
	list_for_each_entry(alloc_data, &priv->alloc_list, list) {
		if (alloc_data->dma_buf == dma_buf) {
			alloc_data->vmap = iosys_vmap;
			break;
		}
	}
	mutex_unlock(&priv->list_mutex);
	return 0;
}

static int msm_audio_cma_dma_buf_map(struct dma_buf *dma_buf,
				     dma_addr_t *addr, size_t *len,
				     struct msm_audio_mem_cma_private *priv)
{
	struct msm_audio_cma_alloc_data *alloc_data;
	struct iosys_map *iosys_vmap;
	struct device *cb_dev = priv->cb_dev;
	int rc = 0;

	iosys_vmap = kzalloc(sizeof(*iosys_vmap), GFP_KERNEL);
	if (!iosys_vmap)
		return -ENOMEM;

	alloc_data = kzalloc(sizeof(*alloc_data), GFP_KERNEL);
	if (!alloc_data) {
		kfree(iosys_vmap);
		return -ENOMEM;
	}

	alloc_data->dma_buf = dma_buf;
	alloc_data->len     = dma_buf->size;
	*len                = dma_buf->size;

	alloc_data->attach = dma_buf_attach(dma_buf, cb_dev);
	if (IS_ERR(alloc_data->attach)) {
		rc = PTR_ERR(alloc_data->attach);
		dev_err(cb_dev, "%s: dma_buf_attach failed rc=%d\n", __func__, rc);
		goto free_alloc;
	}

	alloc_data->table = dma_buf_map_attachment(alloc_data->attach,
						   DMA_BIDIRECTIONAL);
	if (IS_ERR(alloc_data->table)) {
		rc = PTR_ERR(alloc_data->table);
		dev_err(cb_dev, "%s: dma_buf_map_attachment failed rc=%d\n", __func__, rc);
		goto detach;
	}

	*addr = MSM_AUDIO_MEM_CMA_PHYS_ADDR(alloc_data);

	rc = msm_audio_cma_map_kernel(dma_buf, priv, iosys_vmap);
	if (rc) {
		pr_err("%s: kernel mapping failed rc=%d\n", __func__, rc);
		goto detach;
	}
	alloc_data->vmap = iosys_vmap;

	msm_audio_cma_add_allocation(priv, alloc_data);
	return 0;

detach:
	dma_buf_detach(dma_buf, alloc_data->attach);
free_alloc:
	kfree(iosys_vmap);
	kfree(alloc_data);
	return rc;
}

static int msm_audio_cma_dma_buf_unmap(struct dma_buf *dma_buf,
					struct msm_audio_mem_cma_private *priv)
{
	struct msm_audio_cma_alloc_data *alloc_data;
	struct list_head *ptr, *next;
	bool found = false;

	mutex_lock(&priv->list_mutex);
	list_for_each_safe(ptr, next, &priv->alloc_list) {
		alloc_data = list_entry(ptr, struct msm_audio_cma_alloc_data, list);
		if (alloc_data->dma_buf != dma_buf)
			continue;
		found = true;
		dma_buf_vunmap(dma_buf, alloc_data->vmap);
		dma_buf_end_cpu_access(dma_buf, DMA_BIDIRECTIONAL);
		dma_buf_unmap_attachment(alloc_data->attach, alloc_data->table,
					 DMA_BIDIRECTIONAL);
		dma_buf_detach(dma_buf, alloc_data->attach);
		dma_buf_put(dma_buf);
		list_del(&alloc_data->list);
		kfree(alloc_data->vmap);
		kfree(alloc_data);
		break;
	}
	mutex_unlock(&priv->list_mutex);

	if (!found) {
		dev_err(priv->cb_dev, "%s: dma_buf %pK not found\n", __func__, dma_buf);
		return -EINVAL;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* fd-list helpers (own private list, no sharing with parent)         */
/* ------------------------------------------------------------------ */

static void msm_audio_cma_update_fd_list(struct msm_audio_cma_fd_data *fd_data)
{
	struct msm_audio_cma_fd_data *entry;

	mutex_lock(&msm_audio_cma_fd_list.list_mutex);
	list_for_each_entry(entry, &msm_audio_cma_fd_list.fd_list, list) {
		if (entry->fd == fd_data->fd) {
			pr_err("%s: fd %d already present\n", __func__, fd_data->fd);
			mutex_unlock(&msm_audio_cma_fd_list.list_mutex);
			return;
		}
	}
	list_add_tail(&fd_data->list, &msm_audio_cma_fd_list.fd_list);
	mutex_unlock(&msm_audio_cma_fd_list.list_mutex);
}

static void msm_audio_cma_delete_fd_entry(void *handle)
{
	struct msm_audio_cma_fd_data *entry;
	struct list_head *ptr, *next;

	mutex_lock(&msm_audio_cma_fd_list.list_mutex);
	list_for_each_safe(ptr, next, &msm_audio_cma_fd_list.fd_list) {
		entry = list_entry(ptr, struct msm_audio_cma_fd_data, list);
		if (entry->handle == handle) {
			list_del(&entry->list);
			kfree(entry);
			break;
		}
	}
	mutex_unlock(&msm_audio_cma_fd_list.list_mutex);
}

static void msm_audio_cma_get_handle(int fd, void **handle)
{
	struct msm_audio_cma_fd_data *entry;

	mutex_lock(&msm_audio_cma_fd_list.list_mutex);
	list_for_each_entry(entry, &msm_audio_cma_fd_list.fd_list, list) {
		if (entry->fd == fd) {
			*handle = entry->handle;
			break;
		}
	}
	mutex_unlock(&msm_audio_cma_fd_list.list_mutex);
}

int msm_audio_cma_get_phy_addr(int fd, dma_addr_t *paddr, size_t *pa_len)
{
	struct msm_audio_cma_fd_data *entry;
	int status = -EINVAL;

	if (!paddr)
		return status;

	mutex_lock(&msm_audio_cma_fd_list.list_mutex);
	list_for_each_entry(entry, &msm_audio_cma_fd_list.fd_list, list) {
		if (entry->fd == fd) {
			*paddr  = entry->paddr;
			*pa_len = entry->plen;
			status  = 0;
			break;
		}
	}
	mutex_unlock(&msm_audio_cma_fd_list.list_mutex);
	return status;
}

#ifdef QCOM_HYP_ASSIGN
static int msm_audio_cma_set_hyp_assign(int fd, bool assign)
{
	struct msm_audio_cma_fd_data *entry;
	int status = -EINVAL;

	mutex_lock(&msm_audio_cma_fd_list.list_mutex);
	list_for_each_entry(entry, &msm_audio_cma_fd_list.fd_list, list) {
		if (entry->fd == fd) {
			entry->hyp_assign = assign;
			status = 0;
			break;
		}
	}
	mutex_unlock(&msm_audio_cma_fd_list.list_mutex);
	return status;
}

static int msm_audio_cma_hyp_unassign(struct msm_audio_cma_fd_data *fd_data)
{
	int ret = 0;
	u64 src_vmid_unmap_list = BIT(QCOM_SCM_VMID_LPASS) | BIT(QCOM_SCM_VMID_ADSP_HEAP);
	struct qcom_scm_vmperm dst_vmids_unmap[] = {{QCOM_SCM_VMID_HLOS, QCOM_SCM_PERM_RWX}};

	if (fd_data->hyp_assign) {
		ret = qcom_scm_assign_mem(fd_data->paddr, fd_data->plen,
					  &src_vmid_unmap_list,
					  dst_vmids_unmap, ARRAY_SIZE(dst_vmids_unmap));
		if (ret < 0)
			pr_err("%s: scm unmap failed ret=%d addr=0x%llx size=%zu\n",
			       __func__, ret, fd_data->paddr, fd_data->plen);
		fd_data->hyp_assign = false;
	}
	return ret;
}
#endif

/* ------------------------------------------------------------------ */
/* import / free                                                       */
/* ------------------------------------------------------------------ */

static int msm_audio_cma_mem_free(struct dma_buf *dma_buf,
				  struct msm_audio_mem_cma_private *priv)
{
	if (!dma_buf) {
		pr_err("%s: NULL dma_buf\n", __func__);
		return -EINVAL;
	}
	return msm_audio_cma_dma_buf_unmap(dma_buf, priv);
}

/* ------------------------------------------------------------------ */
/* crash handler                                                       */
/* ------------------------------------------------------------------ */

void msm_audio_mem_cma_crash_handler(void)
{
	struct msm_audio_cma_fd_data *fd_data;
	struct list_head *ptr, *next;
	void *handle;
	struct msm_audio_mem_cma_private *priv;

	mutex_lock(&msm_audio_cma_fd_list.list_mutex);
	list_for_each_entry(fd_data, &msm_audio_cma_fd_list.fd_list, list) {
		handle = fd_data->handle;
		priv   = dev_get_drvdata(fd_data->dev);
#ifdef QCOM_HYP_ASSIGN
		if (fd_data->hyp_assign)
			msm_audio_cma_hyp_unassign(fd_data);
#endif
		if (handle)
			msm_audio_cma_mem_free(handle, priv);
	}
	list_for_each_safe(ptr, next, &msm_audio_cma_fd_list.fd_list) {
		fd_data = list_entry(ptr, struct msm_audio_cma_fd_data, list);
		list_del(&fd_data->list);
		kfree(fd_data);
	}
	mutex_unlock(&msm_audio_cma_fd_list.list_mutex);
}

/* ------------------------------------------------------------------ */
/* chardev file operations                                             */
/* ------------------------------------------------------------------ */

static int msm_audio_cma_open(struct inode *inode, struct file *file)
{
	struct msm_audio_mem_cma_private *priv =
		container_of(inode->i_cdev, struct msm_audio_mem_cma_private, cdev);

	get_device(priv->chardev);
	return 0;
}

static int msm_audio_cma_release(struct inode *inode, struct file *file)
{
	struct msm_audio_mem_cma_private *priv =
		container_of(inode->i_cdev, struct msm_audio_mem_cma_private, cdev);

	put_device(priv->chardev);
	return 0;
}

static long msm_audio_cma_ioctl(struct file *file, unsigned int ioctl_num,
				unsigned long __user ioctl_param)
{
	struct msm_audio_mem_cma_private *priv =
		container_of(file->f_inode->i_cdev,
			     struct msm_audio_mem_cma_private, cdev);
	void *mem_handle = NULL;
	dma_addr_t paddr = 0;
	size_t pa_len = 0;
	int ret = 0;
	struct msm_audio_cma_fd_data *fd_data = NULL;
#ifdef QCOM_HYP_ASSIGN
	u64 src_vmid_map_list = BIT(QCOM_SCM_VMID_HLOS);
	struct qcom_scm_vmperm dst_vmids_map[] = {
		{QCOM_SCM_VMID_LPASS,     QCOM_SCM_PERM_RW},
		{QCOM_SCM_VMID_ADSP_HEAP, QCOM_SCM_PERM_RW},
	};
	u64 src_vmid_unmap_list =
		BIT(QCOM_SCM_VMID_LPASS) | BIT(QCOM_SCM_VMID_ADSP_HEAP);
	struct qcom_scm_vmperm dst_vmids_unmap[] = {
		{QCOM_SCM_VMID_HLOS, QCOM_SCM_PERM_RWX},
	};
#endif

	switch (ioctl_num) {
	case IOCTL_MAP_PHYS_ADDR:
		if (!(priv->device_status & MSM_AUDIO_MEM_CMA_PROBED)) {
			pr_debug("%s: probe not done, deferred\n", __func__);
			return -EPROBE_DEFER;
		}
		fd_data = kzalloc(sizeof(*fd_data), GFP_KERNEL);
		if (!fd_data)
			return -ENOMEM;

		mem_handle = dma_buf_get((int)ioctl_param);
		if (IS_ERR_OR_NULL(mem_handle)) {
			pr_err("%s: dma_buf_get failed\n", __func__);
			kfree(fd_data);
			return -EINVAL;
		}
		ret = msm_audio_cma_dma_buf_map(mem_handle, &paddr, &pa_len, priv);
		if (ret) {
			pr_err("%s: dma_buf_map failed ret=%d\n", __func__, ret);
			dma_buf_put(mem_handle);
			kfree(fd_data);
			return ret;
		}
		fd_data->fd     = (int)ioctl_param;
		fd_data->handle = mem_handle;
		fd_data->paddr  = paddr;
		fd_data->plen   = pa_len;
		fd_data->dev    = priv->cb_dev;
		msm_audio_cma_update_fd_list(fd_data);
		break;

	case IOCTL_UNMAP_PHYS_ADDR:
		msm_audio_cma_get_handle((int)ioctl_param, &mem_handle);
		ret = msm_audio_cma_mem_free(mem_handle, priv);
		if (ret < 0) {
			pr_err("%s: free failed ret=%d\n", __func__, ret);
			return ret;
		}
		msm_audio_cma_delete_fd_entry(mem_handle);
		break;

#ifdef QCOM_HYP_ASSIGN
	case IOCTL_MAP_HYP_ASSIGN:
		ret = msm_audio_cma_get_phy_addr((int)ioctl_param, &paddr, &pa_len);
		if (ret < 0) {
			pr_err("%s: get phys addr failed %d\n", __func__, ret);
			return ret;
		}
		if (priv->has_iommu && priv->rproc_domain) {
			ret = iommu_map(priv->rproc_domain, paddr, paddr, pa_len,
					IOMMU_READ | IOMMU_WRITE, GFP_KERNEL);
			if (ret) {
				pr_err("%s: iommu_map failed ret=%d\n", __func__, ret);
				return ret;
			}
		} else {
			ret = qcom_scm_assign_mem(paddr, pa_len, &src_vmid_map_list,
						  dst_vmids_map,
						  ARRAY_SIZE(dst_vmids_map));
			if (ret < 0) {
				pr_err("%s: scm_assign failed ret=%d\n", __func__, ret);
				return ret;
			}
		}
		msm_audio_cma_set_hyp_assign((int)ioctl_param, true);
		break;

	case IOCTL_UNMAP_HYP_ASSIGN:
		ret = msm_audio_cma_get_phy_addr((int)ioctl_param, &paddr, &pa_len);
		if (ret < 0) {
			pr_err("%s: get phys addr failed %d\n", __func__, ret);
			return ret;
		}
		if (priv->has_iommu && priv->rproc_domain) {
			size_t unmapped = iommu_unmap(priv->rproc_domain, paddr, pa_len);

			if (unmapped != pa_len) {
				pr_err("%s: iommu_unmap partial %zu/%zu\n",
				       __func__, unmapped, pa_len);
				return -EINVAL;
			}
		} else {
			ret = qcom_scm_assign_mem(paddr, pa_len, &src_vmid_unmap_list,
						  dst_vmids_unmap,
						  ARRAY_SIZE(dst_vmids_unmap));
			if (ret < 0) {
				pr_err("%s: scm_unassign failed ret=%d\n", __func__, ret);
				return ret;
			}
		}
		msm_audio_cma_set_hyp_assign((int)ioctl_param, false);
		break;
#endif

	default:
		pr_err_ratelimited("%s: invalid ioctl 0x%x\n", __func__, ioctl_num);
		ret = -EINVAL;
		break;
	}
	return ret;
}

static const struct file_operations msm_audio_cma_fops = {
	.owner          = THIS_MODULE,
	.open           = msm_audio_cma_open,
	.release        = msm_audio_cma_release,
	.unlocked_ioctl = msm_audio_cma_ioctl,
};

/* ------------------------------------------------------------------ */
/* chardev register / unregister                                       */
/* ------------------------------------------------------------------ */

static int msm_audio_cma_reg_chrdev(struct msm_audio_mem_cma_private *priv)
{
	int ret;

	ret = alloc_chrdev_region(&priv->mem_major, 0,
				  MINOR_NUMBER_COUNT_CMA, DRV_NAME_CMA);
	if (ret < 0) {
		pr_err("%s: alloc_chrdev_region failed ret=%d\n", __func__, ret);
		return ret;
	}

	priv->mem_class = class_create(DRV_NAME_CMA);
	if (IS_ERR(priv->mem_class)) {
		ret = PTR_ERR(priv->mem_class);
		pr_err("%s: class_create failed ret=%d\n", __func__, ret);
		goto err_class;
	}

	priv->chardev = device_create(priv->mem_class, NULL,
				      priv->mem_major, NULL, DRV_NAME_CMA);
	if (IS_ERR(priv->chardev)) {
		ret = PTR_ERR(priv->chardev);
		pr_err("%s: device_create failed ret=%d\n", __func__, ret);
		goto err_device;
	}

	cdev_init(&priv->cdev, &msm_audio_cma_fops);
	ret = cdev_add(&priv->cdev, priv->mem_major, 1);
	if (ret) {
		pr_err("%s: cdev_add failed ret=%d\n", __func__, ret);
		goto err_cdev;
	}
	return 0;

err_cdev:
	device_destroy(priv->mem_class, priv->mem_major);
err_device:
	class_destroy(priv->mem_class);
err_class:
	unregister_chrdev_region(priv->mem_major, MINOR_NUMBER_COUNT_CMA);
	return ret;
}

static void msm_audio_cma_unreg_chrdev(struct msm_audio_mem_cma_private *priv)
{
	cdev_del(&priv->cdev);
	device_destroy(priv->mem_class, priv->mem_major);
	class_destroy(priv->mem_class);
	unregister_chrdev_region(priv->mem_major, MINOR_NUMBER_COUNT_CMA);
}

/* ------------------------------------------------------------------ */
/* IOMMU domain: walk parent chain for inherited iommus property      */
/* ------------------------------------------------------------------ */

static struct iommu_domain *msm_audio_cma_get_rproc_domain(struct device *dev)
{
	struct device_node *np;
	struct platform_device *iommu_pdev;
	struct iommu_domain *domain;

	/*
	 * The CMA node has no iommus property of its own.
	 * Walk up the parent chain to find the nearest ancestor
	 * that does (e.g. remoteproc_adsp) and inherit its domain.
	 */
	np = of_get_parent(dev->of_node);
	while (np) {
		if (!of_property_present(np, "iommus")) {
			np = of_get_next_parent(np);
			continue;
		}
		iommu_pdev = of_find_device_by_node(np);
		if (!iommu_pdev) {
			np = of_get_next_parent(np);
			continue;
		}
		domain = iommu_get_domain_for_dev(&iommu_pdev->dev);
		put_device(&iommu_pdev->dev);
		of_node_put(np);
		return domain;
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/* probe / remove                                                      */
/* ------------------------------------------------------------------ */

static int msm_audio_mem_cma_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct msm_audio_mem_cma_private *priv;
	int rc;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->cb_dev = dev;

	/*
	 * Inherit the reserved CMA memory from the parent DT node.
	 * dev->parent is the parent platform_device's device, which
	 * is the DT node that carries the memory-region property.
	 */
	rc = of_reserved_mem_device_init(dev->parent);
	if (rc) {
		dev_err(dev, "%s: of_reserved_mem_device_init failed rc=%d\n",
			__func__, rc);
		return rc;
	}

	priv->rproc_domain = msm_audio_cma_get_rproc_domain(dev->parent);
	priv->has_iommu    = !!priv->rproc_domain;
	dev_info(dev, "%s: remoteproc IOMMU %s\n", __func__,
		 priv->has_iommu ? "present" : "absent");

	INIT_LIST_HEAD(&priv->alloc_list);
	mutex_init(&priv->list_mutex);

	if (!msm_audio_cma_fd_list_init) {
		INIT_LIST_HEAD(&msm_audio_cma_fd_list.fd_list);
		mutex_init(&msm_audio_cma_fd_list.list_mutex);
		msm_audio_cma_fd_list_init = true;
	}

	priv->device_status |= MSM_AUDIO_MEM_CMA_PROBED;

	rc = msm_audio_cma_reg_chrdev(priv);
	if (rc) {
		dev_err(dev, "%s: chrdev registration failed rc=%d\n", __func__, rc);
		return rc;
	}

	platform_set_drvdata(pdev, priv);
	dev_info(dev, "%s: /dev/%s ready\n", __func__, DRV_NAME_CMA);
	return 0;
}

#if AR_USE_VOID_RETURN_TYPE
static void msm_audio_mem_cma_remove(struct platform_device *pdev)
{
	struct msm_audio_mem_cma_private *priv = platform_get_drvdata(pdev);

	priv->device_status = 0;
	msm_audio_cma_unreg_chrdev(priv);
}
#else
static int msm_audio_mem_cma_remove(struct platform_device *pdev)
{
	struct msm_audio_mem_cma_private *priv = platform_get_drvdata(pdev);

	priv->device_status = 0;
	msm_audio_cma_unreg_chrdev(priv);
	return 0;
}
#endif

static struct platform_driver q6apm_audio_mem_cma_driver = {
	.driver = {
		.name = "q6apm-audio-mem-cma",
	},
	.probe  = msm_audio_mem_cma_probe,
	.remove = msm_audio_mem_cma_remove,
};

int q6apm_audio_mem_cma_init(void)
{
	return platform_driver_register(&q6apm_audio_mem_cma_driver);
}

void q6apm_audio_mem_cma_exit(void)
{
	platform_driver_unregister(&q6apm_audio_mem_cma_driver);
}

MODULE_DESCRIPTION("MSM Audio CMA memory driver");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("DMA_BUF");
