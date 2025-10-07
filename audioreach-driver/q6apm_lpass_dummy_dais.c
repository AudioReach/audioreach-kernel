// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021, Linaro Limited
// Copyright (c) 2023-2025 Qualcomm Innovation Center, Inc. All rights reserved.

#include <dt-bindings/sound/qcom,q6dsp-lpass-ports.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <sound/pcm.h>
#include <sound/soc.h>
#include <sound/pcm_params.h>
#include <linux/clk.h>
#include "q6dsp-lpass-ports.h"
#include "q6dsp-common.h"
#include "audioreach.h"
#include "q6apm.h"
#include "q6prm.h"
#include "q6dsp-lpass-clocks.h"

#include "q6prm_audioreach.h"

#define AUDIOREACH_BE_PCM_BASE	16

struct q6apm_lpass_dai_data {
	struct q6apm_graph *graph[APM_PORT_MAX];
	bool is_port_started[APM_PORT_MAX];
	struct audioreach_module_config module_config[APM_PORT_MAX];
};

static const struct snd_pcm_hardware q6apm_dummy_dma_hardware = {
	.info               = SNDRV_PCM_INFO_INTERLEAVED |
				SNDRV_PCM_INFO_BLOCK_TRANSFER,
	.buffer_bytes_max   = 128 * 1024,
	.period_bytes_min   = PAGE_SIZE,
	.period_bytes_max   = PAGE_SIZE * 2,
	.periods_min        = 2,
	.periods_max        = 128,
};

static int q6apm_lpass_dai_dummy_startup(struct snd_pcm_substream *substream,
					 struct snd_soc_dai *dai)
{
	snd_soc_set_runtime_hwparams(substream, &q6apm_dummy_dma_hardware);
	return 0;
}

static const struct snd_soc_dai_ops q6dummy_ops = {
	.startup	= q6apm_lpass_dai_dummy_startup,
};

static const struct snd_soc_dai_ops q6i2sdummy_ops = {
	.startup	= q6apm_lpass_dai_dummy_startup,
};

static const struct snd_soc_dai_ops q6tdmdummy_ops = {
	.startup	= q6apm_lpass_dai_dummy_startup,
};

static const struct snd_soc_component_driver q6apm_lpass_dummy_dai_component = {
	.name = "q6apm-be-dummy-dai-component",
	.of_xlate_dai_name = q6dsp_audio_ports_of_xlate_dai_name,
	.be_pcm_base = AUDIOREACH_BE_PCM_BASE,
	.use_dai_pcm_id = false,
};

static int q6apm_lpass_dummy_dai_dev_probe(struct platform_device *pdev)
{
	const struct snd_soc_component_driver *q6apm_lpass_component = NULL;
	struct q6dsp_audio_port_dai_driver_config cfg;
	struct q6apm_lpass_dai_data *dai_data;
	struct snd_soc_dai_driver *dais;
	struct device *dev = &pdev->dev;
	int num_dais;

	dai_data = devm_kzalloc(dev, sizeof(*dai_data), GFP_KERNEL);
	if (!dai_data)
		return -ENOMEM;

	dev_set_drvdata(dev, dai_data);

	memset(&cfg, 0, sizeof(cfg));

	dev_info(dev, "Q6 APM DAI uses dummy ops\n");
	cfg.q6i2s_ops = &q6i2sdummy_ops;
	cfg.q6dma_ops = &q6dummy_ops;
	cfg.q6hdmi_ops = &q6dummy_ops;
	cfg.q6tdm_ops = &q6tdmdummy_ops;
	cfg.q6slim_ops = &q6dummy_ops;
	q6apm_lpass_component = &q6apm_lpass_dummy_dai_component;

	dais = q6dsp_audio_ports_set_config(dev, &cfg, &num_dais);

	return devm_snd_soc_register_component(dev, q6apm_lpass_component, dais, num_dais);
}

#ifdef CONFIG_OF
static const struct of_device_id q6apm_lpass_dummy_dai_device_id[] = {
	{ .compatible = "qcom,q6apm-lpass-dais" },
	{},
};
MODULE_DEVICE_TABLE(of, q6apm_lpass_dummy_dai_device_id);
#endif

static struct platform_driver q6apm_lpass_dummy_dai_platform_driver = {
	.driver = {
		.name = "q6apm-lpass-dummy-dais",
		.of_match_table = of_match_ptr(q6apm_lpass_dummy_dai_device_id),
	},
	.probe = q6apm_lpass_dummy_dai_dev_probe,
};
//module_platform_driver(q6apm_lpass_dummy_dai_platform_driver);
int q6apm_lpass_dummy_dais_init(void)
{
	    return platform_driver_register(&q6apm_lpass_dummy_dai_platform_driver);
}

void q6apm_lpass_dummy_dais_exit(void)
{
	    platform_driver_unregister(&q6apm_lpass_dummy_dai_platform_driver);
}

MODULE_DESCRIPTION("AUDIOREACH APM LPASS dummy dai driver");
MODULE_LICENSE("GPL");
