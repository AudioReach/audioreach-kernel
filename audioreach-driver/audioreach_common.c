// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022, Linaro Limited
// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

#include <dt-bindings/sound/qcom,q6afe.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/string.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <linux/soundwire/sdw.h>
#include <sound/jack.h>
#include <linux/input-event-codes.h>
#include <sound/simple_card_utils.h>
#include "q6prm_audioreach.h"

#define AFE_PORT_MAX   137
#define NAME_SIZE	32

#define I2S_MCLKFS 256

#define I2S_MCLK_RATE(rate) \
	((rate) * (I2S_MCLKFS))
#define I2S_BIT_RATE(rate, channels, format) \
	((rate) * (channels) * (format))

struct snd_soc_common {
	const char *driver_name;
	const struct snd_soc_dapm_widget *dapm_widgets;
	int num_dapm_widgets;
	const struct snd_soc_dapm_route *dapm_routes;
	int num_dapm_routes;
	const struct snd_kcontrol_new *controls;
	int num_controls;
	unsigned int codec_dai_fmt;
	int num_wsa_spkr;
	bool codec_sysclk_set;
	bool mi2s_mclk_enable;
	bool mi2s_bclk_enable;
	bool qaif_interface;
	bool wcd_jack;

};

struct qcs6490_snd_data {
	bool stream_prepared[AFE_PORT_MAX];
	struct snd_soc_card *card;
	struct sdw_stream_runtime *sruntime[AFE_PORT_MAX];
	struct snd_soc_jack jack;
	struct snd_soc_jack dp_jack[8];
	struct snd_soc_common *snd_soc_common_priv;
	bool jack_setup;
};

struct qcom_snd_common_data {
	struct qcom_snd_dailink_data *link_data;
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

static char *qcs6490_wsa_spk_to_prefix(const char *spk_name)
{
	if (!strcmp(spk_name, "WooferLeft Speaker"))
		return "WooferLeft";
	if (!strcmp(spk_name, "TweeterLeft Speaker"))
		return "TweeterLeft";
	if (!strcmp(spk_name, "WooferRight Speaker"))
		return "WooferRight";
	if (!strcmp(spk_name, "TweeterRight Speaker"))
		return "TweeterRight";
	if (!strcmp(spk_name, "SpkrLeft Speaker"))
		return "SpkrLeft";
	if (!strcmp(spk_name, "SpkrRight Speaker"))
		return "SpkrRight";

	return NULL;
}

static void qcs6490_wsa_mute_stream(struct snd_soc_card *card,
				    const char *prefix, int mute)
{
	struct snd_soc_pcm_runtime *rtd;
	struct snd_soc_dai *cpu_dai, *codec_dai;
	int i, ret;

	for_each_card_rtds(card, rtd) {
		cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
		if (cpu_dai->id != WSA_CODEC_DMA_RX_0 &&
		    cpu_dai->id != WSA_CODEC_DMA_RX_1)
			continue;

		for_each_rtd_codec_dais(rtd, i, codec_dai) {
			const char *name_prefix;

			if (!codec_dai->component || !codec_dai->driver ||
			    !codec_dai->driver->ops ||
			    !codec_dai->driver->ops->mute_stream)
				continue;

			name_prefix = codec_dai->component->name_prefix;
			if (!name_prefix || strcmp(name_prefix, prefix))
				continue;

			ret = codec_dai->driver->ops->mute_stream(codec_dai, mute,
						SNDRV_PCM_STREAM_PLAYBACK);
			if (ret && ret != -ENOTSUPP)
				dev_warn(card->dev,
					 "mute_stream failed for %s on %s: %d\n",
					 prefix, codec_dai->name, ret);
			return;
		}
	}
}

static int qcs6490_wsa_spk_event(struct snd_soc_dapm_widget *w,
				 struct snd_kcontrol *kcontrol,
				 int event)
{
	char *prefix = qcs6490_wsa_spk_to_prefix(w->name);

	if (!prefix)
		return 0;

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		qcs6490_wsa_mute_stream(snd_soc_dapm_to_card(w->dapm), prefix, 0);
		break;
	case SND_SOC_DAPM_PRE_PMD:
		qcs6490_wsa_mute_stream(snd_soc_dapm_to_card(w->dapm), prefix, 1);
		break;
	default:
		break;
	}

	return 0;
}

static struct snd_soc_dapm_widget qcs6490_dapm_widgets[] = {
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
	SND_SOC_DAPM_SPK("SpkrLeft Speaker", qcs6490_wsa_spk_event),
	SND_SOC_DAPM_SPK("SpkrRight Speaker", qcs6490_wsa_spk_event),

};

static const struct snd_soc_dapm_route qcs6490_dapm_routes[] = {
	{ "SpkrLeft Speaker", NULL, "SpkrLeft SPKR" },
	{ "SpkrRight Speaker", NULL, "SpkrRight SPKR" },
};

static const struct snd_soc_dapm_widget shikra_cqs_dapm_widgets[] = {
	SND_SOC_DAPM_HP("Headphone Jack", NULL),
	SND_SOC_DAPM_MIC("Mic Jack", NULL),
};

static const struct snd_soc_dapm_widget shikra_iqs_dapm_widgets[] = {
	SND_SOC_DAPM_HP("Headphone", NULL),
	SND_SOC_DAPM_MIC("Headset Mic", NULL),
	SND_SOC_DAPM_MIC("Int Mic", NULL),
	SND_SOC_DAPM_SPK("Speaker", NULL),
};

static const struct snd_kcontrol_new shikra_iqs_controls[] = {
	SOC_DAPM_PIN_SWITCH("Headset Mic"),
	SOC_DAPM_PIN_SWITCH("Headphone"),
	SOC_DAPM_PIN_SWITCH("Int Mic"),
	SOC_DAPM_PIN_SWITCH("Speaker"),
};

static struct snd_soc_dapm_widget glymur_dapm_widgets[] = {
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
	SND_SOC_DAPM_SPK("WooferLeft Speaker", qcs6490_wsa_spk_event),
	SND_SOC_DAPM_SPK("TweeterLeft Speaker", qcs6490_wsa_spk_event),
	SND_SOC_DAPM_SPK("WooferRight Speaker", qcs6490_wsa_spk_event),
	SND_SOC_DAPM_SPK("TweeterRight Speaker", qcs6490_wsa_spk_event),
};

static const struct snd_soc_dapm_route glymur_dapm_routes[] = {
	{ "WooferLeft Speaker", NULL, "WooferLeft SPKR" },
	{ "TweeterLeft Speaker", NULL, "TweeterLeft SPKR" },
	{ "WooferRight Speaker", NULL, "WooferRight SPKR" },
	{ "TweeterRight Speaker", NULL, "TweeterRight SPKR" },
};

static struct snd_soc_dapm_widget sa8775p_dapm_widgets[] = {
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

static inline int qcs6490_get_mclk_freq(struct snd_pcm_hw_params *params)
{
	int rate = params_rate(params);

	switch (rate) {
	case 11025:
	case 44100:
	case 88200:
		return I2S_MCLK_RATE(44100);
	default:
		break;
	}

	return I2S_MCLK_RATE(rate);
}

static inline int qcs6490_get_bclk_freq(struct snd_pcm_hw_params *params)
{
	return I2S_BIT_RATE(params_rate(params),
			    params_channels(params),
			    snd_pcm_format_width(params_format(params)));
}

static int qcs6490_snd_sdw_startup(struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
	u32 rx_ch[SDW_MAX_PORTS], tx_ch[SDW_MAX_PORTS];
	struct sdw_stream_runtime *sruntime;
	struct snd_soc_dai *codec_dai;
	u32 rx_ch_cnt = 0, tx_ch_cnt = 0;
	int ret, i, j;

	sruntime = sdw_alloc_stream(cpu_dai->name, SDW_STREAM_PCM);
	if (!sruntime)
		return -ENOMEM;

	for_each_rtd_codec_dais(rtd, i, codec_dai) {
		ret = snd_soc_dai_set_stream(codec_dai, sruntime,
					     substream->stream);
		if (ret < 0 && ret != -ENOTSUPP) {
			dev_err(rtd->dev, "Failed to set sdw stream on %s\n", codec_dai->name);
			goto err_set_stream;
		} else if (ret == -ENOTSUPP) {
			/* Ignore unsupported */
			continue;
		}

		ret = snd_soc_dai_get_channel_map(codec_dai, &tx_ch_cnt, tx_ch,
						  &rx_ch_cnt, rx_ch);
		if (ret != 0 && ret != -ENOTSUPP) {
			dev_err(rtd->dev, "Failed to get codec chan map %s\n", codec_dai->name);
			goto err_set_stream;
		} else if (ret == -ENOTSUPP) {
			/* Ignore unsupported */
			continue;
		}
	}

	switch (cpu_dai->id) {
	case RX_CODEC_DMA_RX_0:
	case TX_CODEC_DMA_TX_3:
		if (tx_ch_cnt || rx_ch_cnt) {
			for_each_rtd_codec_dais(rtd, j, codec_dai) {
				ret = snd_soc_dai_set_channel_map(codec_dai,
								  tx_ch_cnt, tx_ch,
								  rx_ch_cnt, rx_ch);
				if (ret != 0 && ret != -ENOTSUPP)
					goto err_set_stream;
			}
		}
	}

	return 0;

err_set_stream:
	sdw_release_stream(sruntime);

	return ret;
}

static int qcs6490_snd_sdw_prepare(struct snd_pcm_substream *substream,
				   struct sdw_stream_runtime *sruntime,
				   bool *stream_prepared)
{
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
	struct snd_soc_dai *codec_dai;
	int ret;

	if (!sruntime)
		return 0;

	switch (cpu_dai->id) {
	case WSA_CODEC_DMA_RX_0:
	case WSA_CODEC_DMA_RX_1:
	case RX_CODEC_DMA_RX_0:
	case RX_CODEC_DMA_RX_1:
	case TX_CODEC_DMA_TX_0:
	case TX_CODEC_DMA_TX_1:
	case TX_CODEC_DMA_TX_2:
	case TX_CODEC_DMA_TX_3:
		break;
	default:
		return 0;
	}

	if (*stream_prepared)
		return 0;

	ret = sdw_prepare_stream(sruntime);
	if (ret)
		return ret;

	/**
	 * NOTE: there is a strict hw requirement about the ordering of port
	 * enables and actual WSA881x PA enable. PA enable should only happen
	 * after soundwire ports are enabled if not DC on the line is
	 * accumulated resulting in Click/Pop Noise
	 * PA enable/mute are handled as part of codec DAPM and digital mute.
	 */

	ret = sdw_enable_stream(sruntime);
	if (ret) {
		sdw_deprepare_stream(sruntime);
		return ret;
	}
	*stream_prepared  = true;

	return ret;
}

static int qcs6490_snd_sdw_hw_params(struct snd_pcm_substream *substream,
				     struct snd_pcm_hw_params *params,
				     struct sdw_stream_runtime **psruntime)
{
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct snd_soc_dai *codec_dai;
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
	struct sdw_stream_runtime *sruntime;
	int i;

	switch (cpu_dai->id) {
	case WSA_CODEC_DMA_RX_0:
	case RX_CODEC_DMA_RX_0:
	case RX_CODEC_DMA_RX_1:
	case TX_CODEC_DMA_TX_0:
	case TX_CODEC_DMA_TX_1:
	case TX_CODEC_DMA_TX_2:
	case TX_CODEC_DMA_TX_3:
		for_each_rtd_codec_dais(rtd, i, codec_dai) {
			sruntime = snd_soc_dai_get_stream(codec_dai, substream->stream);
			if (sruntime != ERR_PTR(-ENOTSUPP))
				*psruntime = sruntime;
		}
		break;
	}

	return 0;
}

static int qcs6490_snd_sdw_hw_free(struct snd_pcm_substream *substream,
				   struct sdw_stream_runtime *sruntime,
				   bool *stream_prepared)
{
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);

	switch (cpu_dai->id) {
	case WSA_CODEC_DMA_RX_0:
	case WSA_CODEC_DMA_RX_1:
	case RX_CODEC_DMA_RX_0:
	case RX_CODEC_DMA_RX_1:
	case TX_CODEC_DMA_TX_0:
	case TX_CODEC_DMA_TX_1:
	case TX_CODEC_DMA_TX_2:
	case TX_CODEC_DMA_TX_3:
		if (sruntime && *stream_prepared) {
			sdw_disable_stream(sruntime);
			sdw_deprepare_stream(sruntime);
			*stream_prepared = false;
		}
		break;
	default:
		break;
	}

	return 0;
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


static void audioreach_get_link_name(const char **link_name, int dai_id,
				     bool qaif_interface)
{
	switch (dai_id) {
	case WSA_CODEC_DMA_RX_0:
		*link_name = "CODEC_DMA-LPAIF_WSA-RX-0";
		break;
	case VA_CODEC_DMA_TX_0:
		if (qaif_interface)
			*link_name = "CODEC_DMA-QAIF-TX-0";
		else
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
		if (qaif_interface)
			*link_name = "QAIF-QAIF_AUD-RX-0";
		else if (strstr(*link_name, "HS"))
			*link_name = "MI2S-LPAIF_SDR-RX-PRIMARY";
		else
			*link_name = "MI2S-LPAIF-RX-PRIMARY";
		break;
	case PRIMARY_MI2S_TX:
		if (strstr(*link_name, "HS"))
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
	case SECONDARY_TDM_RX_0:
		if (qaif_interface)
			*link_name = "QAIF-QAIF_AUD-RX-2";
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
	struct qcs6490_snd_data *data = snd_soc_card_get_drvdata(card);
	const struct snd_soc_common *common = data ? data->snd_soc_common_priv : NULL;
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

		audioreach_get_link_name(&link->name, link->id,
					 common && common->qaif_interface);
		link->stream_name = link->name;
		link++;

		of_node_put(cpu);
		of_node_put(codec);
		of_node_put(platform);
	}

	if (!card->dapm_widgets) {
		card->dapm_widgets = qcs6490_dapm_widgets;
		card->num_dapm_widgets = ARRAY_SIZE(qcs6490_dapm_widgets);
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
		if (data->snd_soc_common_priv->num_wsa_spkr == 4) {
			snd_soc_limit_volume(card, "WSA WSA_RX0 Digital Volume", 81);
			snd_soc_limit_volume(card, "WSA WSA_RX1 Digital Volume", 81);
			snd_soc_limit_volume(card, "WSA2 WSA_RX0 Digital Volume", 81);
			snd_soc_limit_volume(card, "WSA2 WSA_RX1 Digital Volume", 81);
			snd_soc_limit_volume(card, "SpkrLeft PA Volume", 6);
			snd_soc_limit_volume(card, "SpkrRight PA Volume", 6);
			snd_soc_limit_volume(card, "WooferLeft PA Volume", 6);
			snd_soc_limit_volume(card, "TweeterLeft PA Volume", 6);
			snd_soc_limit_volume(card, "WooferRight PA Volume", 6);
			snd_soc_limit_volume(card, "TweeterRight PA Volume", 6);
		} else {
			snd_soc_limit_volume(card, "WSA_RX0 Digital Volume", 81);
			snd_soc_limit_volume(card, "WSA_RX1 Digital Volume", 81);
			snd_soc_limit_volume(card, "SpkrLeft PA Volume", 17);
			snd_soc_limit_volume(card, "SpkrRight PA Volume", 17);
		}

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

	if (data->snd_soc_common_priv->wcd_jack)
		return qcs6490_snd_wcd_jack_setup(rtd, &data->jack, &data->jack_setup);

	return 0;
}

static int qcs6490_tdm_hw_params(struct snd_pcm_substream *substream,
				 struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct qcs6490_snd_data *data = snd_soc_card_get_drvdata(rtd->card);
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
	struct snd_soc_dai *codec_dai;
	unsigned int slots = params_channels(params);
	unsigned int slot_width = 32;
	unsigned int bclk_freq;
	int ret;
	int i;

	if (!slots || slots > 16)
		return -EINVAL;

	bclk_freq = snd_soc_tdm_params_to_bclk(params, slot_width, slots, 1);
	if (!bclk_freq)
		return -EINVAL;

	if (data->snd_soc_common_priv->mi2s_bclk_enable) {
		ret = snd_soc_dai_set_sysclk(cpu_dai, LPAIF_MI2S_BCLK,
					     bclk_freq, SND_SOC_CLOCK_IN);
		if (ret)
			return ret;
	}

	if (data->snd_soc_common_priv->codec_sysclk_set) {
		for_each_rtd_codec_dais(rtd, i, codec_dai) {
			ret = snd_soc_dai_set_sysclk(codec_dai, 0, bclk_freq,
						     SND_SOC_CLOCK_IN);
			if (ret)
				return ret;
		}
	}

	return 0;
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
	struct snd_soc_dai *codec_dai = snd_soc_rtd_to_codec(rtd, 0);
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
	struct qcs6490_snd_data *pdata = snd_soc_card_get_drvdata(rtd->card);
	int mclk_freq = qcs6490_get_mclk_freq(params);
	int bclk_freq = qcs6490_get_bclk_freq(params);
	int ret = 0;

	switch (cpu_dai->id) {
	case PRIMARY_MI2S_RX ... QUATERNARY_MI2S_TX:
	case QUINARY_MI2S_RX ... QUINARY_MI2S_TX:
		ret = snd_soc_dai_set_fmt(cpu_dai, SND_SOC_DAIFMT_BP_FP);
		if (ret && ret != -ENOTSUPP)
			return ret;

		if (pdata->snd_soc_common_priv->codec_dai_fmt) {
			ret = snd_soc_dai_set_fmt(codec_dai,
						  pdata->snd_soc_common_priv->codec_dai_fmt);
			if (ret && ret != -ENOTSUPP)
				return ret;
		}

		if (pdata->snd_soc_common_priv->mi2s_mclk_enable) {
			ret = snd_soc_dai_set_sysclk(cpu_dai,
						     LPAIF_MI2S_MCLK, mclk_freq,
						     SND_SOC_CLOCK_OUT);
			if (ret)
				return ret;
		}

		if (pdata->snd_soc_common_priv->mi2s_bclk_enable) {
			ret = snd_soc_dai_set_sysclk(cpu_dai,
						     LPAIF_MI2S_BCLK, bclk_freq,
						     SND_SOC_CLOCK_OUT);
			if (ret)
				return ret;
		}

		if (pdata->snd_soc_common_priv->codec_sysclk_set) {
			ret = snd_soc_dai_set_sysclk(codec_dai,
						     0, mclk_freq,
						     SND_SOC_CLOCK_IN);
			if (ret)
				return ret;
		}
		break;
	case PRIMARY_TDM_RX_0 ... QUINARY_TDM_TX_7:
		return qcs6490_tdm_hw_params(substream, params);
	default:
		break;
	}

	return qcs6490_snd_sdw_hw_params(substream, params, &pdata->sruntime[cpu_dai->id]);
}

static int qcs6490_snd_prepare(struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
	struct qcs6490_snd_data *data = snd_soc_card_get_drvdata(rtd->card);
	struct sdw_stream_runtime *sruntime = data->sruntime[cpu_dai->id];

	return qcs6490_snd_sdw_prepare(substream, sruntime, &data->stream_prepared[cpu_dai->id]);
}

static int qcs6490_snd_hw_free(struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct qcs6490_snd_data *data = snd_soc_card_get_drvdata(rtd->card);
	struct snd_soc_dai *cpu_dai = snd_soc_rtd_to_cpu(rtd, 0);
	struct sdw_stream_runtime *sruntime = data->sruntime[cpu_dai->id];

	return qcs6490_snd_sdw_hw_free(substream, sruntime, &data->stream_prepared[cpu_dai->id]);
}

static const struct snd_soc_ops qcs6490_be_ops = {
	.startup = qcs6490_snd_sdw_startup,
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

static struct snd_soc_common shikra_cqs_priv_data = {
	.driver_name = "shikra-cqs",
	.dapm_widgets = shikra_cqs_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(shikra_cqs_dapm_widgets),
	.qaif_interface = true,
	.mi2s_bclk_enable = true,
	.codec_sysclk_set = true,
};

static struct snd_soc_common shikra_iqs_priv_data = {
	.driver_name = "shikra-iqs",
	.dapm_widgets = shikra_iqs_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(shikra_iqs_dapm_widgets),
	.controls = shikra_iqs_controls,
	.num_controls = ARRAY_SIZE(shikra_iqs_controls),
	.qaif_interface = true,
	.codec_dai_fmt = SND_SOC_DAIFMT_CBP_CFP | SND_SOC_DAIFMT_NB_NF | SND_SOC_DAIFMT_I2S,
	.mi2s_bclk_enable = true,
	.codec_sysclk_set = true,
};

static int qcs6490_platform_probe(struct platform_device *pdev)
{
	struct snd_soc_card *card;
	struct qcs6490_snd_data *data;
	struct device *dev = &pdev->dev;
	int ret;

	card = devm_kzalloc(dev, sizeof(*card), GFP_KERNEL);
	if (!card)
		return -ENOMEM;
	/* Allocate the private data */
	data = devm_kzalloc(dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->snd_soc_common_priv = (struct snd_soc_common *)of_device_get_match_data(dev);
	if (!data->snd_soc_common_priv)
		return -ENODEV;

	card->owner = THIS_MODULE;
	card->dev = dev;
	dev_set_drvdata(dev, card);
	snd_soc_card_set_drvdata(card, data);
	card->dapm_widgets = data->snd_soc_common_priv->dapm_widgets;
	card->num_dapm_widgets = data->snd_soc_common_priv->num_dapm_widgets;
	card->dapm_routes = data->snd_soc_common_priv->dapm_routes;
	card->num_dapm_routes = data->snd_soc_common_priv->num_dapm_routes;
	card->controls = data->snd_soc_common_priv->controls;
	card->num_controls = data->snd_soc_common_priv->num_controls;

	ret = qcs6490_snd_parse_of(card);
	if (ret)
		return ret;

	card->driver_name = data->snd_soc_common_priv->driver_name;
	qcs6490_add_be_ops(card);
	ret = devm_snd_soc_register_card(dev, card);
	if (ret)
		return dev_err_probe(dev, ret, "sound card registration failed\n");

	return 0;
}

static struct snd_soc_common glymur_priv_data = {
	.driver_name = "glymur",
	.dapm_widgets = glymur_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(glymur_dapm_widgets),
	.dapm_routes = glymur_dapm_routes,
	.num_dapm_routes = ARRAY_SIZE(glymur_dapm_routes),
	.num_wsa_spkr = 4,
	.wcd_jack = true,
};

static struct snd_soc_common kaanapali_priv_data = {
	.driver_name = "kaanapali",
	.dapm_widgets = qcs6490_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(qcs6490_dapm_widgets),
	.dapm_routes = qcs6490_dapm_routes,
	.num_dapm_routes = ARRAY_SIZE(qcs6490_dapm_routes),
	.num_wsa_spkr = 2,
	.wcd_jack = true,
};

static struct snd_soc_common qcs9100_priv_data = {
	.driver_name = "sa8775p",
	.dapm_widgets = sa8775p_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(sa8775p_dapm_widgets),
};

static struct snd_soc_common qcs615_priv_data = {
	.driver_name = "qcs615",
	.dapm_widgets = sa8775p_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(sa8775p_dapm_widgets),
};

static struct snd_soc_common qcm6490_priv_data = {
	.driver_name = "qcm6490",
	.dapm_widgets = qcs6490_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(qcs6490_dapm_widgets),
	.dapm_routes = qcs6490_dapm_routes,
	.num_dapm_routes = ARRAY_SIZE(qcs6490_dapm_routes),
	.num_wsa_spkr = 2,
	.wcd_jack = true,
};

static struct snd_soc_common qcs6490_priv_data = {
	.driver_name = "qcs6490",
	.dapm_widgets = qcs6490_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(qcs6490_dapm_widgets),
	.dapm_routes = qcs6490_dapm_routes,
	.num_dapm_routes = ARRAY_SIZE(qcs6490_dapm_routes),
	.num_wsa_spkr = 2,
	.wcd_jack = true,
};

static struct snd_soc_common qcs8275_priv_data = {
	.driver_name = "qcs8300",
	.dapm_widgets = sa8775p_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(sa8775p_dapm_widgets),
};

static struct snd_soc_common sc8280xp_priv_data = {
	.driver_name = "sc8280xp",
	.dapm_widgets = qcs6490_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(qcs6490_dapm_widgets),
	.dapm_routes = qcs6490_dapm_routes,
	.num_dapm_routes = ARRAY_SIZE(qcs6490_dapm_routes),
	.num_wsa_spkr = 2,
	.wcd_jack = true,
};

static struct snd_soc_common sm8450_priv_data = {
	.driver_name = "sm8450",
	.dapm_widgets = qcs6490_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(qcs6490_dapm_widgets),
	.dapm_routes = qcs6490_dapm_routes,
	.num_dapm_routes = ARRAY_SIZE(qcs6490_dapm_routes),
	.num_wsa_spkr = 2,
	.wcd_jack = true,
};

static struct snd_soc_common sm8550_priv_data = {
	.driver_name = "sm8550",
	.dapm_widgets = qcs6490_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(qcs6490_dapm_widgets),
	.dapm_routes = qcs6490_dapm_routes,
	.num_dapm_routes = ARRAY_SIZE(qcs6490_dapm_routes),
	.num_wsa_spkr = 2,
	.wcd_jack = true,
};

static struct snd_soc_common sm8650_priv_data = {
	.driver_name = "sm8650",
	.dapm_widgets = qcs6490_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(qcs6490_dapm_widgets),
	.dapm_routes = qcs6490_dapm_routes,
	.num_dapm_routes = ARRAY_SIZE(qcs6490_dapm_routes),
	.num_wsa_spkr = 2,
	.wcd_jack = true,
};

static struct snd_soc_common sm8750_priv_data = {
	.driver_name = "sm8750",
	.dapm_widgets = qcs6490_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(qcs6490_dapm_widgets),
	.dapm_routes = qcs6490_dapm_routes,
	.num_dapm_routes = ARRAY_SIZE(qcs6490_dapm_routes),
	.num_wsa_spkr = 2,
	.wcd_jack = true,
};

static struct snd_soc_common x1e80100_priv_data = {
	.driver_name = "x1e80100",
	.dapm_widgets = glymur_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(glymur_dapm_widgets),
	.dapm_routes = glymur_dapm_routes,
	.num_dapm_routes = ARRAY_SIZE(glymur_dapm_routes),
	.num_wsa_spkr = 4,
	.wcd_jack = true,
};

static const struct of_device_id snd_qcs6490_dt_match[] = {
	{.compatible = "qcom,glymur-sndcard", .data = &glymur_priv_data},
	{.compatible = "qcom,kaanapali-sndcard", .data = &kaanapali_priv_data},
	{.compatible = "qcom,qcm6490-idp-sndcard", .data = &qcm6490_priv_data},
	{.compatible = "qcom,qcs615-sndcard", .data = &qcs615_priv_data},
	{.compatible = "qcom,qcs6490-rb3gen2-sndcard", .data = &qcs6490_priv_data},
	{.compatible = "qcom,qcs8275-sndcard", .data = &qcs8275_priv_data},
	{.compatible = "qcom,qcs9075-sndcard", .data = &qcs9100_priv_data},
	{.compatible = "qcom,qcs9100-sndcard", .data = &qcs9100_priv_data},
	{.compatible = "qcom,sc8280xp-sndcard", .data = &sc8280xp_priv_data},
	{.compatible = "qcom,sm8450-sndcard", .data = &sm8450_priv_data},
	{.compatible = "qcom,sm8550-sndcard", .data = &sm8550_priv_data},
	{.compatible = "qcom,sm8650-sndcard", .data = &sm8650_priv_data},
	{.compatible = "qcom,sm8750-sndcard", .data = &sm8750_priv_data},
	{.compatible = "qcom,x1e80100-sndcard", .data = &x1e80100_priv_data},
	{.compatible = "qcom,shikra-cqs-sndcard", .data = &shikra_cqs_priv_data},
	{.compatible = "qcom,shikra-iqs-sndcard", .data = &shikra_iqs_priv_data},
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
