// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021, Linaro Limited

#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/delay.h>
#include <linux/of_platform.h>
#include <linux/jiffies.h>
#include <linux/soc/qcom/apr.h>
#include <dt-bindings/soc/qcom,gpr.h>
#include <dt-bindings/sound/qcom,q6dsp-lpass-ports.h>
#include "q6apm.h"
#include "q6prm.h"
#include "audioreach.h"
#include "q6prm_audioreach.h"

struct q6prm {
	struct device *dev;
	gpr_device_t *gdev;
	wait_queue_head_t wait;
	struct gpr_ibasic_rsp_result_t result;
	struct mutex lock;
};

#define PRM_CMD_REQUEST_HW_RSC		0x0100100F
#define PRM_CMD_RSP_REQUEST_HW_RSC	0x02001002
#define PRM_CMD_RELEASE_HW_RSC		0x01001010
#define PRM_CMD_RSP_RELEASE_HW_RSC	0x02001003
#define PARAM_ID_RSC_HW_CORE		0x08001032
#define PARAM_ID_RSC_LPASS_CORE		0x0800102B
#define PARAM_ID_RSC_AUDIO_HW_CLK	0x0800102C

struct prm_cmd_request_hw_core {
	struct apm_module_param_data param_data;
	uint32_t hw_clk_id;
} __packed;

struct prm_cmd_request_rsc {
	struct apm_module_param_data param_data;
	uint32_t num_clk_id;
	struct audio_hw_clk_cfg clock_id;
} __packed;

struct prm_cmd_release_rsc {
	struct apm_module_param_data param_data;
	uint32_t num_clk_id;
	struct audio_hw_clk_rel_cfg clock_id;
} __packed;

int q6prm_audio_send_cmd_sync(struct device *dev, gpr_device_t *gdev,
			     struct gpr_ibasic_rsp_result_t *result, struct mutex *cmd_lock,
			     gpr_port_t *port, wait_queue_head_t *cmd_wait,
			     struct gpr_pkt *pkt, uint32_t rsp_opcode)
{

	struct gpr_hdr *hdr = &pkt->hdr;
	int rc;

	mutex_lock(cmd_lock);
	result->opcode = 0;
	result->status = 0;

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
					(result->opcode == rsp_opcode),	5 * HZ);
	else
		rc = wait_event_timeout(*cmd_wait, (result->opcode == hdr->opcode), 5 * HZ);

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
EXPORT_SYMBOL_GPL(q6prm_audio_send_cmd_sync);

static int q6prm_audioreach_send_cmd_sync(struct q6prm *prm, struct gpr_pkt *pkt, uint32_t rsp_opcode)
{
	return q6prm_audio_send_cmd_sync(prm->dev, prm->gdev, &prm->result, &prm->lock,
					NULL, &prm->wait, pkt, rsp_opcode);
}

static void *__q6prm_audioreach_alloc_pkt(int payload_size, uint32_t opcode, uint32_t token,
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

void *q6prm_audioreach_alloc_cmd_pkt(int payload_size, uint32_t opcode, uint32_t token,
			       uint32_t src_port, uint32_t dest_port)
{
	return __q6prm_audioreach_alloc_pkt(payload_size, opcode, token, src_port, dest_port, true);
}
EXPORT_SYMBOL_GPL(q6prm_audioreach_alloc_cmd_pkt);

static int q6prm_audioreach_set_hw_core_req(struct device *dev, uint32_t hw_block_id, bool enable)
{
	struct q6prm *prm = dev_get_drvdata(dev->parent);
	struct apm_module_param_data *param_data;
	struct prm_cmd_request_hw_core *req;
	gpr_device_t *gdev = prm->gdev;
	uint32_t opcode, rsp_opcode;
	struct gpr_pkt *pkt;
	int rc;

	if (enable) {
		opcode = PRM_CMD_REQUEST_HW_RSC;
		rsp_opcode = PRM_CMD_RSP_REQUEST_HW_RSC;
	} else {
		opcode = PRM_CMD_RELEASE_HW_RSC;
		rsp_opcode = PRM_CMD_RSP_RELEASE_HW_RSC;
	}

	pkt = q6prm_audioreach_alloc_cmd_pkt(sizeof(*req), opcode, 0, gdev->svc.id, GPR_PRM_MODULE_IID);
	if (IS_ERR(pkt))
		return PTR_ERR(pkt);

	req = (void *)pkt + GPR_HDR_SIZE + APM_CMD_HDR_SIZE;

	param_data = &req->param_data;

	param_data->module_instance_id = GPR_PRM_MODULE_IID;
	param_data->error_code = 0;
	param_data->param_id = PARAM_ID_RSC_HW_CORE;
	param_data->param_size = sizeof(*req) - APM_MODULE_PARAM_DATA_SIZE;

	req->hw_clk_id = hw_block_id;

	rc = q6prm_audioreach_send_cmd_sync(prm, pkt, rsp_opcode);

	kfree(pkt);

	return rc;
}

int q6prm_audioreach_vote_lpass_core_hw(struct device *dev, uint32_t hw_block_id,
			     const char *client_name, uint32_t *client_handle)
{
	return q6prm_audioreach_set_hw_core_req(dev, hw_block_id, true);

}
EXPORT_SYMBOL_GPL(q6prm_audioreach_vote_lpass_core_hw);

int q6prm_audioreach_unvote_lpass_core_hw(struct device *dev, uint32_t hw_block_id, uint32_t client_handle)
{
	return q6prm_audioreach_set_hw_core_req(dev, hw_block_id, false);
}
EXPORT_SYMBOL_GPL(q6prm_audioreach_unvote_lpass_core_hw);

static int q6prm_audioreach_request_lpass_clock(struct device *dev, int clk_id, int clk_attr, int clk_root,
				     unsigned int freq)
{
	struct q6prm *prm = dev_get_drvdata(dev->parent);
	struct apm_module_param_data *param_data;
	struct prm_cmd_request_rsc *req;
	gpr_device_t *gdev = prm->gdev;
	struct gpr_pkt *pkt;
	int rc;

	pkt = q6prm_audioreach_alloc_cmd_pkt(sizeof(*req), PRM_CMD_REQUEST_HW_RSC, 0, gdev->svc.id,
				       GPR_PRM_MODULE_IID);
	if (IS_ERR(pkt))
		return PTR_ERR(pkt);

	req = (void *)pkt + GPR_HDR_SIZE + APM_CMD_HDR_SIZE;

	param_data = &req->param_data;

	param_data->module_instance_id = GPR_PRM_MODULE_IID;
	param_data->error_code = 0;
	param_data->param_id = PARAM_ID_RSC_AUDIO_HW_CLK;
	param_data->param_size = sizeof(*req) - APM_MODULE_PARAM_DATA_SIZE;

	req->num_clk_id = 1;
	req->clock_id.clock_id = clk_id;
	req->clock_id.clock_freq = freq;
	req->clock_id.clock_attri = clk_attr;
	req->clock_id.clock_root = clk_root;

	rc = q6prm_audioreach_send_cmd_sync(prm, pkt, PRM_CMD_RSP_REQUEST_HW_RSC);

	kfree(pkt);

	return rc;
}

static int q6prm_audioreach_release_lpass_clock(struct device *dev, int clk_id, int clk_attr, int clk_root,
			  unsigned int freq)
{
	struct q6prm *prm = dev_get_drvdata(dev->parent);
	struct apm_module_param_data *param_data;
	struct prm_cmd_release_rsc *rel;
	gpr_device_t *gdev = prm->gdev;
	struct gpr_pkt *pkt;
	int rc;

	pkt = q6prm_audioreach_alloc_cmd_pkt(sizeof(*rel), PRM_CMD_RELEASE_HW_RSC, 0, gdev->svc.id,
				       GPR_PRM_MODULE_IID);
	if (IS_ERR(pkt))
		return PTR_ERR(pkt);

	rel = (void *)pkt + GPR_HDR_SIZE + APM_CMD_HDR_SIZE;

	param_data = &rel->param_data;

	param_data->module_instance_id = GPR_PRM_MODULE_IID;
	param_data->error_code = 0;
	param_data->param_id = PARAM_ID_RSC_AUDIO_HW_CLK;
	param_data->param_size = sizeof(*rel) - APM_MODULE_PARAM_DATA_SIZE;

	rel->num_clk_id = 1;
	rel->clock_id.clock_id = clk_id;

	rc = q6prm_audioreach_send_cmd_sync(prm, pkt, PRM_CMD_RSP_RELEASE_HW_RSC);

	kfree(pkt);

	return rc;
}

int q6prm_audioreach_set_lpass_clock(struct device *dev, int clk_id, int clk_attr, int clk_root,
			  unsigned int freq)
{
	if (freq)
		return q6prm_audioreach_request_lpass_clock(dev, clk_id, clk_attr, clk_root, freq);

	return q6prm_audioreach_release_lpass_clock(dev, clk_id, clk_attr, clk_root, freq);
}
EXPORT_SYMBOL_GPL(q6prm_audioreach_set_lpass_clock);

static int prm_audioreach_callback(struct gpr_resp_pkt *data, void *priv, int op)
{
	gpr_device_t *gdev = priv;
	struct q6prm *prm = dev_get_drvdata(&gdev->dev);
	struct gpr_ibasic_rsp_result_t *result;
	struct gpr_hdr *hdr = &data->hdr;

	switch (hdr->opcode) {
	case PRM_CMD_RSP_REQUEST_HW_RSC:
	case PRM_CMD_RSP_RELEASE_HW_RSC:
		result = data->payload;
		prm->result.opcode = hdr->opcode;
		prm->result.status = result->status;
		wake_up(&prm->wait);
		break;
	default:
		break;
	}

	return 0;
}

static int prm_audioreach_probe(gpr_device_t *gdev)
{
	struct device *dev = &gdev->dev;
	struct q6prm *cc;

	cc = devm_kzalloc(dev, sizeof(*cc), GFP_KERNEL);
	if (!cc)
		return -ENOMEM;

	cc->dev = dev;
	cc->gdev = gdev;
	mutex_init(&cc->lock);
	init_waitqueue_head(&cc->wait);
	dev_set_drvdata(dev, cc);

	if (!q6apm_audio_is_adsp_ready()) {
		pr_err("DEBUG:%s:%d: failed\n",__func__,__LINE__);
		return -EPROBE_DEFER;
	}

	return devm_of_platform_populate(dev);
}

#ifdef CONFIG_OF
static const struct of_device_id prm_audioreach_device_id[]  = {
	{ .compatible = "qcom,q6prm" },
	{},
};
MODULE_DEVICE_TABLE(of, prm_audioreach_device_id);
#endif

static gpr_driver_t prm_audioreach_driver = {
	.probe = prm_audioreach_probe,
	.gpr_callback = prm_audioreach_callback,
	.driver = {
		.name = "qcom-audioreach-prm",
		.of_match_table = of_match_ptr(prm_audioreach_device_id),
	},
};

//module_gpr_driver(prm_audioreach_driver);
int q6prm_audioreach_init(void)
{
	    return apr_driver_register(&prm_audioreach_driver);
}

void q6prm_audioreach_exit(void)
{
	  apr_driver_unregister(&prm_audioreach_driver);
}
MODULE_DESCRIPTION("Q6 Proxy Resource Manager");
MODULE_LICENSE("GPL");
