/* SPDX-License-Identifier: GPL-2.0 */
// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

#ifndef __Q6APM_AUDIO_H__
#define __Q6APM_AUDIO_H__

#include <sound/soc.h>

#define AR_PCM_MAX_NUM_CHANNEL		8

struct audioreach_module_config {
	int	direction;
	u32	sample_rate;
	u16	bit_width;
	u16	bits_per_sample;

	u16	data_format;
	u16	num_channels;
	u16	dp_idx;
	u32	channel_allocation;
	u32	sd_line_mask;
	int	fmt;
	struct snd_codec codec;
	u8 channel_map[AR_PCM_MAX_NUM_CHANNEL];
};

struct q6dsp_audio_port_dai_driver_config {
	int (*probe)(struct snd_soc_dai *dai);
	int (*remove)(struct snd_soc_dai *dai);
	const struct snd_soc_dai_ops *q6hdmi_ops;
	const struct snd_soc_dai_ops *q6slim_ops;
	const struct snd_soc_dai_ops *q6i2s_ops;
	const struct snd_soc_dai_ops *q6tdm_ops;
	const struct snd_soc_dai_ops *q6dma_ops;
	const struct snd_soc_dai_ops *q6usb_ops;
};

struct apm_cmd_header {
	uint32_t payload_address_lsw;
	uint32_t payload_address_msw;
	uint32_t mem_map_handle;
	uint32_t payload_size;
} __packed;

#define APM_CMD_HDR_SIZE sizeof(struct apm_cmd_header)

struct apm_module_param_data  {
	uint32_t module_instance_id;
	uint32_t param_id;
	uint32_t param_size;
	uint32_t error_code;
} __packed;

#define APM_MODULE_PARAM_DATA_SIZE sizeof(struct apm_module_param_data)

#endif
