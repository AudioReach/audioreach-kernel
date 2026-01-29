// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020, Linaro Limited
// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

#include <dt-bindings/soc/qcom,gpr.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/refcount.h>
#include <linux/device.h>
#include <linux/skbuff.h>
#include <linux/cdev.h>
#include <linux/idr.h>
#include <linux/of.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/termios.h>
#include <linux/soc/qcom/apr.h>
#include <linux/wait.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/pcm.h>
#include "audioreach.h"
#include "q6apm.h"
#include "q6prm_audioreach.h"

#define APM_CMD_SHARED_MEM_MAP_REGIONS          0x0100100C
#define APM_MEMORY_MAP_BIT_MASK_IS_OFFSET_MODE  0x00000004UL

/* Define Logging Macros */
static int audio_pkt_debug_mask;
enum {
		AUDIO_PKT_INFO = 1U << 0,
};

#define AUDIO_PKT_INFO(x, ...)							\
do {										\
	if (audio_pkt_debug_mask & AUDIO_PKT_INFO) {				\
		pr_info_ratelimited("[%s]: "x, __func__, ##__VA_ARGS__);	\
	}									\
} while (0)

#define AUDIO_PKT_ERR(x, ...)							\
{										\
	pr_err_ratelimited("[%s]: "x, __func__, ##__VA_ARGS__);			\
}

#define MODULE_NAME "audio-pkt"
#define MINOR_NUMBER_COUNT 1
#define AUDPKT_DRIVER_NAME "aud_pasthru_adsp"

struct q6apm_audio_pkt {
        struct device *dev;
	gpr_port_t *port;
        gpr_device_t *adev;
        /* For Graph OPEN/START/STOP/CLOSE operations */
        //wait_queue_head_t wait;
        struct gpr_ibasic_rsp_result_t result;

        uint32_t state;

	struct cdev cdev;
	struct mutex lock;
	spinlock_t queue_lock;
	struct sk_buff_head queue;
	wait_queue_head_t readq;
	dev_t audio_pkt_major;
	struct class *audio_pkt_class;

	struct mutex audpkt_port_lock;
	struct idr audpkt_port_idr;
};

struct audio_pkt_apm_cmd_shared_mem_map_regions_t {
	uint16_t mem_pool_id;
	uint16_t num_regions;
	uint32_t property_flag;

};

struct audio_pkt_apm_shared_map_region_payload_t {
	uint32_t shm_addr_lsw;
	uint32_t shm_addr_msw;
	uint32_t mem_size_bytes;
};

struct audio_pkt_apm_mem_map {
	struct audio_pkt_apm_cmd_shared_mem_map_regions_t mmap_header;
	struct audio_pkt_apm_shared_map_region_payload_t mmap_payload;
};

struct audio_gpr_pkt {
	struct gpr_hdr audpkt_hdr;
	struct audio_pkt_apm_mem_map audpkt_mem_map;
};

typedef void (*audio_pkt_clnt_cb_fn)(void *buf, int len, void *priv);

struct audio_pkt_clnt_ch {
	int client_id;
	audio_pkt_clnt_cb_fn func;
};

struct gpr_port_map {
	u32 src_port;
	u32 dst_port;
};

#define dev_to_audpkt_dev(_dev) container_of(_dev, struct q6apm_audio_pkt, dev)
#define cdev_to_audpkt_dev(_cdev) container_of(_cdev, struct q6apm_audio_pkt, cdev)

static struct q6apm_audio_pkt *g_apm;

static int q6apm_send_audio_cmd_sync(struct device *dev, gpr_device_t *gdev,
			     struct gpr_ibasic_rsp_result_t *result, struct mutex *cmd_lock,
			     gpr_port_t *port, wait_queue_head_t *cmd_wait,
			     struct gpr_pkt *pkt, uint32_t rsp_opcode)
{

	struct gpr_hdr *hdr = &pkt->hdr;
	int rc, wait_time = 2;

	mutex_lock(cmd_lock);
	result->opcode = 0;
	result->status = 0;

	if (hdr->opcode == APM_CMD_CLOSE_ALL)
		wait_time = 20;

	if (port)
		rc = gpr_send_port_pkt(port, pkt);
	else if (gdev)
		rc = gpr_send_pkt(gdev, pkt);
	else
		rc = -EINVAL;

	if (rc < 0)
		goto err;

	if (rsp_opcode)
		rc = wait_event_timeout(*cmd_wait, (result->opcode == hdr->opcode) ||
					(result->opcode == rsp_opcode),	wait_time * HZ);
	else
		rc = wait_event_timeout(*cmd_wait, (result->opcode == hdr->opcode), wait_time * HZ);

	if (!rc) {
		dev_err(dev, "CMD timeout for [%x] opcode\n", hdr->opcode);
		rc = -ETIMEDOUT;
	} else if (result->status > 0) {
		dev_err(dev, "DSP returned error[%x] %x\n", hdr->opcode, result->status);
		rc = -EINVAL;
	} else {
		/* DSP successfully finished the command */
		rc = 0;
	}

err:
	mutex_unlock(cmd_lock);
	return rc;
}


static int q6apm_audio_send_cmd(struct q6apm_audio_pkt *apm, struct gpr_pkt *pkt, uint32_t rsp_opcode)
{
	gpr_device_t *gdev = apm->adev;

	return q6apm_send_audio_cmd_sync(&gdev->dev, gdev, &apm->result, &apm->lock,
					NULL, &apm->readq, pkt, rsp_opcode);
}

static void *__q6apm_audio_alloc_pkt(int payload_size, uint32_t opcode, uint32_t token,
				    uint32_t src_port, uint32_t dest_port, bool has_cmd_hdr)
{
	struct gpr_pkt *pkt;
	void *p;
	int pkt_size = GPR_HDR_SIZE + payload_size;

	if (has_cmd_hdr)
		pkt_size += APM_CMD_HDR_SIZE;

	p = kzalloc(pkt_size, GFP_KERNEL);
	if (!p)
		return ERR_PTR(-ENOMEM);

	pkt = p;
	pkt->hdr.version = GPR_PKT_VER;
	pkt->hdr.hdr_size = GPR_PKT_HEADER_WORD_SIZE;
	pkt->hdr.pkt_size = pkt_size;
	pkt->hdr.dest_port = dest_port;
	pkt->hdr.src_port = src_port;

	pkt->hdr.dest_domain = GPR_DOMAIN_ID_ADSP;
	pkt->hdr.src_domain = GPR_DOMAIN_ID_APPS;
	pkt->hdr.token = token;
	pkt->hdr.opcode = opcode;

	if (has_cmd_hdr) {
		struct apm_cmd_header *cmd_header;

		p = p + GPR_HDR_SIZE;
		cmd_header = p;
		cmd_header->payload_size = payload_size;
	}

	return pkt;
}

static void *q6apm_audio_alloc_apm_cmd_pkt(int pkt_size, uint32_t opcode, uint32_t token)
{
	return __q6apm_audio_alloc_pkt(pkt_size, opcode, token, GPR_APM_MODULE_IID,
				       APM_MODULE_INSTANCE_ID, true);
}

static int q6apm_audio_get_apm_state(struct q6apm_audio_pkt *apm)
{
	struct gpr_pkt *pkt;

	pkt = q6apm_audio_alloc_apm_cmd_pkt(0, APM_CMD_GET_SPF_STATE, 0);
	if (IS_ERR(pkt))
		return PTR_ERR(pkt);

	q6apm_audio_send_cmd(apm, pkt, APM_CMD_RSP_GET_SPF_STATE);

	kfree(pkt);

	return apm->state;
}

bool q6apm_audio_is_adsp_ready(void)
{
	if (g_apm)
		return q6apm_audio_get_apm_state(g_apm);

	return false;
}

static void q6apm_audio_close_all(void)
{
	struct gpr_pkt *pkt;

	pkt = q6apm_audio_alloc_apm_cmd_pkt(0, APM_CMD_CLOSE_ALL, 0);
	if (IS_ERR(pkt))
		return;

	q6apm_audio_send_cmd(g_apm, pkt, GPR_BASIC_RSP_RESULT);

	kfree(pkt);
}

static int audio_pkt_open(struct inode *inode, struct file *file)
{
	struct q6apm_audio_pkt *audpkt_dev = cdev_to_audpkt_dev(inode->i_cdev);
	struct device *dev = audpkt_dev->dev;

	get_device(dev);
	file->private_data = audpkt_dev;

	return 0;
}

/**
 * audio_pkt_release() - release operation on audio_pkt device
 * inode:	Pointer to the inode structure.
 * file:	Pointer to the file structure.
 *
 * This function is used to release the audio pkt device when
 * userspace client do a close() system call. All input arguments are
 * validated by the virtual file system before calling this function.
 */
static int audio_pkt_release(struct inode *inode, struct file *file)
{
	struct q6apm_audio_pkt *audpkt_dev = cdev_to_audpkt_dev(inode->i_cdev);
	struct device *dev = audpkt_dev->dev;
	struct sk_buff *skb;
	unsigned long flags;

	spin_lock_irqsave(&audpkt_dev->queue_lock, flags);

	/* Discard all SKBs */
	while (!skb_queue_empty(&audpkt_dev->queue)) {
		skb = skb_dequeue(&audpkt_dev->queue);
		kfree_skb(skb);
	}
	wake_up_interruptible(&audpkt_dev->readq);
	spin_unlock_irqrestore(&audpkt_dev->queue_lock, flags);

	put_device(dev);
	file->private_data = NULL;
	q6apm_audio_close_all();
	msm_audio_mem_crash_handler();

	return 0;
}

/**
 * audio_pkt_read() - read() syscall for the audio_pkt device
 * file:	Pointer to the file structure.
 * buf:		Pointer to the userspace buffer.
 * count:	Number bytes to read from the file.
 * ppos:	Pointer to the position into the file.
 *
 * This function is used to Read the data from audio pkt device when
 * userspace client do a read() system call. All input arguments are
 * validated by the virtual file system before calling this function.
 */
static ssize_t audio_pkt_read(struct file *file, char __user *buf,
		       size_t count, loff_t *ppos)
{
	struct q6apm_audio_pkt *audpkt_dev = file->private_data;
	unsigned long flags;
	struct sk_buff *skb;
	int use;

	if (!audpkt_dev) {
		AUDIO_PKT_ERR("invalid device handle\n");
		return -EINVAL;
	}

	spin_lock_irqsave(&audpkt_dev->queue_lock, flags);
	/* Wait for data in the queue */
	if (skb_queue_empty(&audpkt_dev->queue)) {
		spin_unlock_irqrestore(&audpkt_dev->queue_lock, flags);

		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		/* Wait until we get data or the endpoint goes away */
		if (wait_event_interruptible(audpkt_dev->readq,
					!skb_queue_empty(&audpkt_dev->queue)))
			return -ERESTARTSYS;

		spin_lock_irqsave(&audpkt_dev->queue_lock, flags);
	}

	skb = skb_dequeue(&audpkt_dev->queue);
	spin_unlock_irqrestore(&audpkt_dev->queue_lock, flags);
	if (!skb)
		return -EFAULT;

	use = min_t(size_t, count, skb->len);
	if (copy_to_user(buf, skb->data, use))
		use = -EFAULT;
	kfree_skb(skb);

	return use;
}

/**
 * audpkt_update_physical_addr - Update physical address
 * audpkt_hdr:	Pointer to the file structure.
 */
static int audpkt_chk_and_update_physical_addr(struct audio_gpr_pkt *gpr_pkt)
{
	size_t pa_len = 0;
	dma_addr_t paddr = 0;
	int ret = 0;

	if (gpr_pkt->audpkt_mem_map.mmap_header.property_flag &
				APM_MEMORY_MAP_BIT_MASK_IS_OFFSET_MODE) {

		/* TODO: move physical address mapping to use DMA-BUF heaps */
		ret = msm_audio_get_phy_addr(
				(int) gpr_pkt->audpkt_mem_map.mmap_payload.shm_addr_lsw,
				&paddr, &pa_len);
		if (ret < 0) {
			AUDIO_PKT_ERR("%s Get phy. address failed, ret %d\n",
					__func__, ret);
			return ret;
		}

		AUDIO_PKT_INFO("%s physical address %pK", __func__,
				(void *) paddr);
		gpr_pkt->audpkt_mem_map.mmap_payload.shm_addr_lsw = (uint32_t) paddr;
		gpr_pkt->audpkt_mem_map.mmap_payload.shm_addr_msw = (uint64_t) paddr >> 32;
	}
	return ret;
}

/**
 * audio_pkt_write() - write() syscall for the audio_pkt device
 * file:	Pointer to the file structure.
 * buf:		Pointer to the userspace buffer.
 * count:	Number bytes to read from the file.
 * ppos:	Pointer to the position into the file.
 *
 * This function is used to write the data to audio pkt device when
 * userspace client do a write() system call. All input arguments are
 * validated by the virtual file system before calling this function.
 */
static ssize_t audio_pkt_write(struct file *file, const char __user *buf,
			size_t count, loff_t *ppos)
{
	struct q6apm_audio_pkt *audpkt_dev = file->private_data;
	struct gpr_hdr *audpkt_hdr = NULL;
	void *kbuf;
	int ret;
	struct gpr_port_map *audpkt_port_map;

	if (!audpkt_dev)  {
		AUDIO_PKT_ERR("invalid device handle\n");
		return -EINVAL;
	}

	kbuf = memdup_user(buf, count);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	audpkt_hdr = (struct gpr_hdr *) kbuf;
	if (audpkt_hdr->opcode == APM_CMD_SHARED_MEM_MAP_REGIONS) {
		ret = audpkt_chk_and_update_physical_addr((struct audio_gpr_pkt *) audpkt_hdr);
		if (ret < 0) {
			AUDIO_PKT_ERR("Update Physical Address Failed -%d\n", ret);
			kfree(kbuf);
			return ret;
		}
	}

	audpkt_port_map = kmalloc(sizeof(*audpkt_port_map), GFP_KERNEL);
	if (!audpkt_port_map) {
		AUDIO_PKT_ERR("kmalloc FAILED !!\n");
		goto free_kbuf;
	}

	audpkt_port_map->src_port = audpkt_hdr->src_port;
	audpkt_port_map->dst_port = audpkt_hdr->dest_port;

	mutex_lock(&audpkt_dev->audpkt_port_lock);
	ret = idr_alloc(&audpkt_dev->audpkt_port_idr, audpkt_port_map,
			audpkt_hdr->token,
			audpkt_hdr->token + 1,
			GFP_KERNEL);
	mutex_unlock(&audpkt_dev->audpkt_port_lock);

	if (ret < 0) {
		kfree(audpkt_port_map);
		AUDIO_PKT_ERR("idr_alloc failed for token=%u\n", audpkt_hdr->token);
		goto free_kbuf;
	} else {
		audpkt_hdr->src_port = GPR_APM_MODULE_IID;
	}

	if (mutex_lock_interruptible(&audpkt_dev->lock)) {
		ret = -ERESTARTSYS;
		goto free_kbuf;
	}
	ret = gpr_send_pkt(audpkt_dev->adev, (struct gpr_pkt *) kbuf);
	if (ret < 0) {
		AUDIO_PKT_ERR("APR Send Packet Failed ret -%d\n", ret);
		mutex_unlock(&audpkt_dev->lock);
		kfree(kbuf);
		return ret;
	}
	mutex_unlock(&audpkt_dev->lock);

free_kbuf:
	kfree(kbuf);
	return ret < 0 ? ret : count;
}

/**
 * audio_pkt_poll() - poll() syscall for the audio_pkt device
 * file:	Pointer to the file structure.
 * wait:	pointer to Poll table.
 *
 * This function is used to poll on the audio pkt device when
 * userspace client do a poll() system call. All input arguments are
 * validated by the virtual file system before calling this function.
 */
static unsigned int audio_pkt_poll(struct file *file, poll_table *wait)
{
	struct q6apm_audio_pkt *audpkt_dev = file->private_data;
	unsigned int mask = 0;
	unsigned long flags;

	if (!audpkt_dev) {
		AUDIO_PKT_ERR("invalid device handle\n");
		return POLLERR;
	}

	poll_wait(file, &audpkt_dev->readq, wait);

	mutex_lock(&audpkt_dev->lock);

	spin_lock_irqsave(&audpkt_dev->queue_lock, flags);
	if (!skb_queue_empty(&audpkt_dev->queue))
		mask |= POLLIN | POLLRDNORM;

	spin_unlock_irqrestore(&audpkt_dev->queue_lock, flags);

	mutex_unlock(&audpkt_dev->lock);

	return mask;
}


static const struct file_operations audio_pkt_fops = {
	.owner = THIS_MODULE,
	.open = audio_pkt_open,
	.release = audio_pkt_release,
	.read = audio_pkt_read,
	.write = audio_pkt_write,
	.poll = audio_pkt_poll,
};

static int q6apm_audio_pkt_probe(gpr_device_t *adev)
{
	struct device *dev = &adev->dev;
	struct q6apm_audio_pkt *apm;
	int ret;

	apm = devm_kzalloc(dev, sizeof(*apm), GFP_KERNEL);
	if (!apm)
		return -ENOMEM;


	ret = alloc_chrdev_region(&apm->audio_pkt_major, 0,
				  MINOR_NUMBER_COUNT, AUDPKT_DRIVER_NAME);
	if (ret < 0) {
		pr_err("alloc_chrdev_region failed ret:%d\n", ret);
		goto err_chrdev;
	}

	apm->audio_pkt_class = class_create(AUDPKT_DRIVER_NAME);
	if (IS_ERR(apm->audio_pkt_class)) {
		ret = PTR_ERR(apm->audio_pkt_class);
		pr_err("class_create failed ret:%ld\n",
			      PTR_ERR(apm->audio_pkt_class));
		goto err_class;
	}

	apm->dev = device_create(apm->audio_pkt_class, NULL,
					apm->audio_pkt_major, NULL,
					AUDPKT_DRIVER_NAME);
	if (IS_ERR(apm->dev)) {
		ret = PTR_ERR(apm->dev);
		pr_err("device_create failed ret:%ld\n",
			      PTR_ERR(apm->dev));
		goto err_device;
	}

	dev_set_name(apm->dev, AUDPKT_DRIVER_NAME);

	dev_set_drvdata(dev, apm);

	mutex_init(&apm->lock);
	apm->adev = adev;


	spin_lock_init(&apm->queue_lock);
	skb_queue_head_init(&apm->queue);
	init_waitqueue_head(&apm->readq);

	mutex_init(&apm->audpkt_port_lock);
	idr_init(&apm->audpkt_port_idr);

	g_apm = apm;

	cdev_init(&apm->cdev, &audio_pkt_fops);
	apm->cdev.owner = THIS_MODULE;

	ret = cdev_add(&apm->cdev, apm->audio_pkt_major,
		       MINOR_NUMBER_COUNT);
	if (ret) {
		AUDIO_PKT_ERR("cdev_add failed with ret:%d\n",ret);
		goto free_dev;
	}

	q6apm_audio_is_adsp_ready();
	AUDIO_PKT_INFO("Audio Packet Port Driver Initialized\n");
	return of_platform_populate(dev->of_node, NULL, NULL, dev);

free_dev:
	put_device(dev);
	device_destroy(apm->audio_pkt_class, apm->audio_pkt_major);
err_device:
	class_destroy(apm->audio_pkt_class);
err_class:
	unregister_chrdev_region(apm->audio_pkt_major,
				 MINOR_NUMBER_COUNT);
err_chrdev:
	return ret;
}

static int q6apm_audio_pkt_callback(struct gpr_resp_pkt *data, void *priv, int op)
{
	gpr_device_t *gdev = priv;
	struct q6apm_audio_pkt *apm = dev_get_drvdata(&gdev->dev);
	struct gpr_ibasic_rsp_result_t *result;
	struct gpr_hdr *hdr = &data->hdr;
	struct device *dev = &gdev->dev;
	uint16_t hdr_size, pkt_size;
	unsigned long flags;
	struct sk_buff *skb;
	int ret;
	struct gpr_port_map *audpkt_port_map;

	if (!apm) {
		dev_dbg(dev, "callback with NULL drvdata\n");
		return -ENODEV;
	}

        hdr_size = hdr->hdr_size * 4;
        pkt_size = hdr->pkt_size;

	mutex_lock(&apm->audpkt_port_lock);
	audpkt_port_map = idr_find(&apm->audpkt_port_idr, hdr->token);
	if (audpkt_port_map) {
		hdr->dest_port = audpkt_port_map->src_port;
		hdr->src_port = audpkt_port_map->dst_port;

		idr_remove(&apm->audpkt_port_idr, hdr->token);
		kfree(audpkt_port_map);
	} else {
		dev_dbg(dev, "Token=%u not found\n", hdr->token);
	}
	mutex_unlock(&apm->audpkt_port_lock);

        skb = alloc_skb(pkt_size, GFP_ATOMIC);
        if (!skb)
                return -ENOMEM;

	skb_put_data(skb, (uint8_t *)data, hdr_size);
	skb_put_data(skb, (uint8_t *)data->payload, pkt_size - hdr_size);

        spin_lock_irqsave(&apm->queue_lock, flags);
        skb_queue_tail(&apm->queue, skb);
        spin_unlock_irqrestore(&apm->queue_lock, flags);


	/* wake up any blocking processes, waiting for new data */
	wake_up_interruptible(&apm->readq);
	if(hdr->opcode == APM_CMD_RSP_GET_SPF_STATE) {
		result = data->payload;
		apm->result.opcode = hdr->opcode;
		apm->result.status = 0;
		/* First word of result it state */
		apm->state = hdr->opcode;
	}

	return 0;
}

static void q6apm_audio_pkt_remove(gpr_device_t *adev)
{
	struct device *dev = &adev->dev;
	struct q6apm_audio_pkt *apm = dev_get_drvdata(dev);

	of_platform_depopulate(dev);

	if (!apm)
		return;

	cdev_del(&apm->cdev);
	device_destroy(apm->audio_pkt_class, apm->audio_pkt_major);
	class_destroy(apm->audio_pkt_class);
	unregister_chrdev_region(apm->audio_pkt_major, MINOR_NUMBER_COUNT);

	dev_set_drvdata(dev, NULL);
}

#ifdef CONFIG_OF
static const struct of_device_id q6apm_audio_device_id[]  = {
	{ .compatible = "qcom,q6apm" },
	{},
};
MODULE_DEVICE_TABLE(of, q6apm_audio_device_id);
#endif

static gpr_driver_t apm_driver = {
	.probe = q6apm_audio_pkt_probe,
	.remove = q6apm_audio_pkt_remove,
	.gpr_callback = q6apm_audio_pkt_callback,
	.driver = {
		.name = "qcom-apm-audio-pkt",
		.of_match_table = of_match_ptr(q6apm_audio_device_id),
	},
};

//module_gpr_driver(apm_driver);
int q6apm_audio_pkt_init(void)
{
	    return apr_driver_register(&apm_driver);;//gpr_driver_register(&apm_driver);
}

void q6apm_audio_pkt_exit(void)
{
	apr_driver_unregister(&apm_driver);
//	    gpr_driver_unregister(&apm_driver);
}
MODULE_DESCRIPTION("Audio Process Manager");
MODULE_LICENSE("GPL");
