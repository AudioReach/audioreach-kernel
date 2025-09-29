// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022, Linaro Limited
// Copyright (c) 2025 Qualcomm Innovation Center, Inc. All rights reserved.

#include <dt-bindings/sound/qcom,q6afe.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/pcm.h>
#include <linux/soundwire/sdw.h>
#include <sound/jack.h>
#include <linux/input-event-codes.h>
#include <sound/simple_card_utils.h>
#include "q6afe.h"
#include "sdw.h"
#include "q6prm_audioreach.h"

#define NAME_SIZE	32

struct qcs6490_snd_data {
	bool stream_prepared[AFE_PORT_MAX];
	struct snd_soc_card *card;
	struct sdw_stream_runtime *sruntime[AFE_PORT_MAX];
	struct snd_soc_jack jack;
	struct snd_soc_jack dp_jack[8];
	bool jack_setup;
};

struct qcom_snd_dailink_data {
	u32 mclk_fs;
	u32 mclk_id;
	u32 clk_direction;
};

struct qcom_snd_common_data {
	struct qcom_snd_dailink_data *link_data;
};

static const struct snd_soc_dapm_widget qcom_jack_snd_widgets[] = {
	SND_SOC_DAPM_HP("Headphone Jack", NULL),
	SND_SOC_DAPM_MIC("Mic Jack", NULL),
	SND_SOC_DAPM_SPK("DP0 Jack", NULL),
	SND_SOC_DAPM_SPK("DP1 Jack", NULL),
	SND_SOC_DAPM_SPK("DP2 Jack", NULL),
	SND_SOC_DAPM_SPK("DP3 Jack", NULL),
	SND_SOC_DAPM_SPK("DP4 Jack", NULL),
	SND_SOC_DAPM_SPK("DP5 Jack", NULL),
	SND_SOC_DAPM_SPK("DP6 Jack", NULL),
	SND_SOC_DAPM_SPK("DP7 Jack", NULL),
};


static struct snd_soc_jack_pin qcs6490_headset_jack_pins[] = {
	/* Headset */
	{
		.pin = "Mic Jack",
		.mask = SND_JACK_MICROPHONE,
	},
	{
		.pin = "Headphone Jack",
		.mask = SND_JACK_HEADPHONE,
	},
};


static int qcs6490_snd_dp_jack_setup(struct snd_soc_pcm_runtime *rtd,
			   struct snd_soc_jack *dp_jack, int dp_pcm_id)
{
	struct snd_soc_dai *codec_dai = snd_soc_rtd_to_codec(rtd, 0);
	struct snd_soc_card *card = rtd->card;
	char jack_name[NAME_SIZE];
	int rval, i;

	snprintf(jack_name, sizeof(jack_name), "DP%d Jack", dp_pcm_id);
	rval = snd_soc_card_jack_new(card, jack_name, SND_JACK_AVOUT, dp_jack);
	if (rval)
		return rval;

	for_each_rtd_codec_dais(rtd, i, codec_dai) {
		rval = snd_soc_component_set_jack(codec_dai->component, dp_jack, NULL);
		if (rval != 0 && rval != -ENOTSUPP) {
			dev_warn(card->dev, "Failed to set jack: %d\n", rval);
			return rval;
		}
	}

	return 0;
}

static int qcs6490_snd_wcd_jack_setup(struct snd_soc_pcm_runtime *rtd,
			    struct snd_soc_jack *jack, bool *jack_setup)
{
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
	struct snd_soc_dai *codec_dai = snd_soc_rtd_to_codec(rtd, 0);
	struct snd_soc_card *card = rtd->card;
	int rval, i;

	if (!*jack_setup) {
		rval = snd_soc_card_jack_new_pins(card, "Headset Jack",
					     SND_JACK_HEADSET | SND_JACK_LINEOUT |
					     SND_JACK_MECHANICAL |
					     SND_JACK_BTN_0 | SND_JACK_BTN_1 |
					     SND_JACK_BTN_2 | SND_JACK_BTN_3 |
					     SND_JACK_BTN_4 | SND_JACK_BTN_5,
					     jack, qcs6490_headset_jack_pins,
					     ARRAY_SIZE(qcs6490_headset_jack_pins));

		if (rval < 0) {
			dev_err(card->dev, "Unable to add Headphone Jack\n");
			return rval;
		}

		snd_jack_set_key(jack->jack, SND_JACK_BTN_0, KEY_MEDIA);
		snd_jack_set_key(jack->jack, SND_JACK_BTN_1, KEY_VOICECOMMAND);
		snd_jack_set_key(jack->jack, SND_JACK_BTN_2, KEY_VOLUMEUP);
		snd_jack_set_key(jack->jack, SND_JACK_BTN_3, KEY_VOLUMEDOWN);
		*jack_setup = true;
	}

	switch (cpu_dai->id) {
	case TX_CODEC_DMA_TX_0:
	case TX_CODEC_DMA_TX_1:
	case TX_CODEC_DMA_TX_2:
	case TX_CODEC_DMA_TX_3:
		for_each_rtd_codec_dais(rtd, i, codec_dai) {
			rval = snd_soc_component_set_jack(codec_dai->component,
							  jack, NULL);
			if (rval != 0 && rval != -ENOTSUPP) {
				dev_warn(card->dev, "Failed to set jack: %d\n", rval);
				return rval;
			}
		}

		break;
	default:
		break;
	}


	return 0;
}


static void audioreach_get_link_name(const char **link_name, int dai_id)
{
	switch (dai_id) {
        case WSA_CODEC_DMA_RX_0:
		*link_name = "CODEC_DMA-LPAIF_WSA-RX-0";
                break;
	case VA_CODEC_DMA_TX_0:
		*link_name = "CODEC_DMA-LPAIF_VA-TX-0";
		break;
	case RX_CODEC_DMA_RX_0:
		*link_name = "CODEC_DMA-LPAIF_RXTX-RX-0";
		break;
	case TX_CODEC_DMA_TX_0:
		*link_name = "CODEC_DMA-LPAIF_RXTX-TX-0";
		break;
	case TX_CODEC_DMA_TX_3:
		*link_name = "CODEC_DMA-LPAIF_RXTX-TX-3";
		break;
	case PRIMARY_MI2S_RX:
		if (strstr(*link_name, "HS") != NULL)
			*link_name = "MI2S-LPAIF_SDR-RX-PRIMARY";
		else
			*link_name = "MI2S-LPAIF-RX-PRIMARY";
		break;
	case PRIMARY_MI2S_TX:
		if (strstr(*link_name, "HS") != NULL)
			*link_name = "MI2S-LPAIF_SDR-TX-PRIMARY";
		else
			*link_name = "MI2S-LPAIF-TX-PRIMARY";
		break;
	case SECONDARY_MI2S_RX:
		if (strstr(*link_name, "HS") != NULL)
			*link_name = "MI2S-LPAIF_SDR-RX-SECONDARY";
		else
			*link_name = "MI2S-LPAIF-RX-SECONDARY";
		break;
	case SECONDARY_MI2S_TX:
		if (strstr(*link_name, "HS") != NULL)
			*link_name = "MI2S-LPAIF_SDR-TX-SECONDARY";
		else
			*link_name = "MI2S-LPAIF-TX-SECONDARY";
		break;
	case TERTIARY_MI2S_RX:
		if (strstr(*link_name, "HS") != NULL)
			*link_name = "MI2S-LPAIF_SDR-RX-TERTIARY";
		else
			*link_name = "MI2S-LPAIF-RX-TERTIARY";
		break;
	case TERTIARY_MI2S_TX:
		if (strstr(*link_name, "HS") != NULL)
			*link_name = "MI2S-LPAIF_SDR-TX-TERTIARY";
		else
			*link_name = "MI2S-LPAIF-TX-TERTIARY";
		break;
	default:
		break;
	}
}

static int qcs6490_snd_parse_of(struct snd_soc_card *card)
{
	struct device_node *np;
	struct device_node *codec = NULL;
	struct device_node *platform = NULL;
	struct device_node *cpu = NULL;
	struct device *dev = card->dev;
	struct snd_soc_dai_link *link;
	struct of_phandle_args args;
	struct snd_soc_dai_link_component *dlc;
	int ret, num_links;

	ret = snd_soc_of_parse_card_name(card, "model");
	if (ret == 0 && !card->name)
		/* Deprecated, only for compatibility with old device trees */
		ret = snd_soc_of_parse_card_name(card, "qcom,model");
	if (ret) {
		dev_err(dev, "Error parsing card name: %d\n", ret);
		return ret;
	}

	if (of_property_present(dev->of_node, "widgets")) {
		ret = snd_soc_of_parse_audio_simple_widgets(card, "widgets");
		if (ret)
			return ret;
	}

	/* DAPM routes */
	if (of_property_present(dev->of_node, "audio-routing")) {
		ret = snd_soc_of_parse_audio_routing(card, "audio-routing");
		if (ret)
			return ret;
	}
	/* Deprecated, only for compatibility with old device trees */
	if (of_property_present(dev->of_node, "qcom,audio-routing")) {
		ret = snd_soc_of_parse_audio_routing(card, "qcom,audio-routing");
		if (ret)
			return ret;
	}

	ret = snd_soc_of_parse_pin_switches(card, "pin-switches");
	if (ret)
		return ret;

	ret = snd_soc_of_parse_aux_devs(card, "aux-devs");
	if (ret)
		return ret;

	/* Populate links */
	num_links = of_get_available_child_count(dev->of_node);

	/* Allocate the DAI link array */
	card->dai_link = devm_kcalloc(dev, num_links, sizeof(*link), GFP_KERNEL);
	if (!card->dai_link)
		return -ENOMEM;

	card->num_links = num_links;
	link = card->dai_link;

	for_each_available_child_of_node(dev->of_node, np) {
		dlc = devm_kcalloc(dev, 2, sizeof(*dlc), GFP_KERNEL);
		if (!dlc) {
			ret = -ENOMEM;
			goto err_put_np;
		}

		link->cpus	= &dlc[0];
		link->platforms	= &dlc[1];

		link->num_cpus		= 1;
		link->num_platforms	= 1;

		ret = of_property_read_string(np, "link-name", &link->name);
		if (ret) {
			dev_err(card->dev, "error getting codec dai_link name\n");
			goto err_put_np;
		}

		cpu = of_get_child_by_name(np, "cpu");
		codec = of_get_child_by_name(np, "codec");

		if (!cpu) {
			dev_err(dev, "%s: Can't find cpu DT node\n", link->name);
			ret = -EINVAL;
			goto err;
		}

		ret = snd_soc_of_get_dlc(cpu, &args, link->cpus, 0);
		if (ret) {
			dev_err_probe(card->dev, ret,
				      "%s: error getting cpu dai name\n", link->name);
			goto err;
		}

		link->id = args.args[0];	
		link->platforms->of_node = link->cpus->of_node;

		if (codec) {
			ret = snd_soc_of_get_dai_link_codecs(dev, codec, link);
			if (ret < 0) {
				dev_err_probe(card->dev, ret,
					      "%s: codec dai not found\n", link->name);
				goto err;
			}

			if (platform) {
				/* DPCM backend */
				link->no_pcm = 1;
				link->ignore_pmdown_time = 1;
			}
		} else {
			/* DPCM frontend */
			link->codecs	 = &snd_soc_dummy_dlc;
			link->num_codecs = 1;
			link->dynamic = 1;
		}

		if (platform || !codec) {
			/* DPCM */
			link->ignore_suspend = 1;
			link->nonatomic = 1;
		}

		audioreach_get_link_name(&link->name, link->id);
		link->stream_name = link->name;
		link++;

		of_node_put(cpu);
		of_node_put(codec);
		of_node_put(platform);
	}

	if (!card->dapm_widgets) {
		card->dapm_widgets = qcom_jack_snd_widgets;
		card->num_dapm_widgets = ARRAY_SIZE(qcom_jack_snd_widgets);
	}

	return 0;
err:
	of_node_put(cpu);
	of_node_put(codec);
	of_node_put(platform);
err_put_np:
	of_node_put(np);
	return ret;
}

static int qcs6490_snd_init(struct snd_soc_pcm_runtime *rtd)
{
	struct qcs6490_snd_data *data = snd_soc_card_get_drvdata(rtd->card);
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
	struct snd_soc_card *card = rtd->card;
	struct snd_soc_jack *dp_jack  = NULL;
	int dp_pcm_id = 0;

	switch (cpu_dai->id) {
	case WSA_CODEC_DMA_RX_0:
	case WSA_CODEC_DMA_RX_1:
		/*
		 * Set limit of -3 dB on Digital Volume and 0 dB on PA Volume
		 * to reduce the risk of speaker damage until we have active
		 * speaker protection in place.
		 */
		snd_soc_limit_volume(card, "WSA_RX0 Digital Volume", 81);
		snd_soc_limit_volume(card, "WSA_RX1 Digital Volume", 81);
		snd_soc_limit_volume(card, "SpkrLeft PA Volume", 17);
		snd_soc_limit_volume(card, "SpkrRight PA Volume", 17);
		break;
	case DISPLAY_PORT_RX_0:
		/* DISPLAY_PORT dai ids are not contiguous */
		dp_pcm_id = 0;
		dp_jack = &data->dp_jack[dp_pcm_id];
		break;
	case DISPLAY_PORT_RX_1 ... DISPLAY_PORT_RX_7:
		dp_pcm_id = cpu_dai->id - DISPLAY_PORT_RX_1 + 1;
		dp_jack = &data->dp_jack[dp_pcm_id];
		break;
	default:
		break;
	}

	if (dp_jack)
		return qcs6490_snd_dp_jack_setup(rtd, dp_jack, dp_pcm_id);

	return qcs6490_snd_wcd_jack_setup(rtd, &data->jack, &data->jack_setup);
}

static void qcs6490_snd_shutdown(struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
	struct qcs6490_snd_data *pdata = snd_soc_card_get_drvdata(rtd->card);
	struct sdw_stream_runtime *sruntime = pdata->sruntime[cpu_dai->id];

	pdata->sruntime[cpu_dai->id] = NULL;
	sdw_release_stream(sruntime);
}

static int qcs6490_be_hw_params_fixup(struct snd_soc_pcm_runtime *rtd,
				     struct snd_pcm_hw_params *params)
{
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
	struct snd_interval *rate = hw_param_interval(params,
					SNDRV_PCM_HW_PARAM_RATE);
	struct snd_interval *channels = hw_param_interval(params,
					SNDRV_PCM_HW_PARAM_CHANNELS);

	rate->min = rate->max = 48000;
	channels->min = 2;
	channels->max = 2;
	switch (cpu_dai->id) {
	case TX_CODEC_DMA_TX_0:
	case TX_CODEC_DMA_TX_1:
	case TX_CODEC_DMA_TX_2:
	case TX_CODEC_DMA_TX_3:
		channels->min = 1;
		break;
	default:
		break;
	}


	return 0;
}

static int qcs6490_snd_hw_params(struct snd_pcm_substream *substream,
				struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
	struct qcs6490_snd_data *pdata = snd_soc_card_get_drvdata(rtd->card);

	return qcom_snd_sdw_hw_params(substream, params, &pdata->sruntime[cpu_dai->id]);
}

static int qcs6490_snd_prepare(struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
	struct qcs6490_snd_data *data = snd_soc_card_get_drvdata(rtd->card);
	struct sdw_stream_runtime *sruntime = data->sruntime[cpu_dai->id];

	return qcom_snd_sdw_prepare(substream, sruntime,
				    &data->stream_prepared[cpu_dai->id]);
}

static int qcs6490_snd_hw_free(struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct qcs6490_snd_data *data = snd_soc_card_get_drvdata(rtd->card);
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
	struct sdw_stream_runtime *sruntime = data->sruntime[cpu_dai->id];

	return qcom_snd_sdw_hw_free(substream, sruntime,
				    &data->stream_prepared[cpu_dai->id]);
}

static const struct snd_soc_ops qcs6490_be_ops = {
	.startup = qcom_snd_sdw_startup,
	.shutdown = qcs6490_snd_shutdown,
	.hw_params = qcs6490_snd_hw_params,
	.hw_free = qcs6490_snd_hw_free,
	.prepare = qcs6490_snd_prepare,
};

static void qcs6490_add_be_ops(struct snd_soc_card *card)
{
	struct snd_soc_dai_link *link;
	int i;

	for_each_card_prelinks(card, i, link) {
		if (link->no_pcm == 1 || link->num_codecs > 0) {
			link->init = qcs6490_snd_init;
			link->be_hw_params_fixup = qcs6490_be_hw_params_fixup;
			link->ops = &qcs6490_be_ops;
		}
	}
}

static int qcs6490_platform_probe(struct platform_device *pdev)
{
	struct snd_soc_card *card;
	struct qcs6490_snd_data *data;
	struct device *dev = &pdev->dev;
	int ret;

	card = devm_kzalloc(dev, sizeof(*card), GFP_KERNEL);
	if (!card)
		return -ENOMEM;
	card->owner = THIS_MODULE;
	/* Allocate the private data */
	data = devm_kzalloc(dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	card->dev = dev;
	dev_set_drvdata(dev, card);
	snd_soc_card_set_drvdata(card, data);
	ret = qcs6490_snd_parse_of(card);
	if (ret)
		return ret;

	card->driver_name = of_device_get_match_data(dev);
	qcs6490_add_be_ops(card);
	return devm_snd_soc_register_card(dev, card);
}

static const struct of_device_id snd_qcs6490_dt_match[] = {
	{.compatible = "qcom,qcm6490-idp-sndcard", "qcm6490"},
	{.compatible = "qcom,qcs6490-rb3gen2-sndcard", "qcs6490"},
	{.compatible = "qcom,qcs8275-sndcard", "qcs8275"},
	{.compatible = "qcom,qcs8300-sndcard", "qcs8300"},
	{.compatible = "qcom,qcs9075-sndcard", "qcs9075"},
	{.compatible = "qcom,qcs9100-sndcard", "qcs9100"},
	{}
};

MODULE_DEVICE_TABLE(of, snd_qcs6490_dt_match);

static struct platform_driver snd_qcs6490_driver = {
	.probe  = qcs6490_platform_probe,
	.driver = {
		.name = "snd-qcs6490",
		.of_match_table = snd_qcs6490_dt_match,
	},
};
int snd_qcs6490_init(void)
{
	    return platform_driver_register(&snd_qcs6490_driver);
}

void snd_qcs6490_exit(void)
{
	    platform_driver_unregister(&snd_qcs6490_driver);
}
static int __init audio_reach_driver_init(void)
{
    int ret;

    ret = q6apm_audio_mem_init();
    if (ret)
        return ret;

    ret = q6apm_audio_pkt_init();
    if (ret)
        goto err_mem;

    ret = q6apm_lpass_dummy_dais_init();
    if (ret)
        goto err_pkt;

    ret = q6prm_audioreach_init();
    if (ret)
        goto err_dais;

    ret = q6prm_audioreach_clock_init();
    if (ret)
        goto err_audioreach;

    ret = snd_qcs6490_init();
    if (ret)
        goto err_clock;

    return 0;

err_clock:
    q6prm_audioreach_clock_exit();
err_audioreach:
    q6prm_audioreach_exit();
err_dais:
    q6apm_lpass_dummy_dais_exit();
err_pkt:
    q6apm_audio_pkt_exit();
err_mem:
    q6apm_audio_mem_exit();
    return ret;
}

static void __exit audio_reach_driver_exit(void)
{
    snd_qcs6490_exit();
    q6prm_audioreach_clock_exit();
    q6prm_audioreach_exit();
    q6apm_lpass_dummy_dais_exit();
    q6apm_audio_pkt_exit();
    q6apm_audio_mem_exit();
}

module_init(audio_reach_driver_init);
module_exit(audio_reach_driver_exit);


//module_platform_driver(snd_qcs6490_driver);
MODULE_DESCRIPTION("QCS6490 ASoC Machine Driver");
MODULE_LICENSE("GPL");
