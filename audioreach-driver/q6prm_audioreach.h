/* SPDX-License-Identifier: GPL-2.0 */
// Copyright (c) 2025 Qualcomm Innovation Center, Inc. All rights reserved.

#ifndef __Q6PRM_AUDIOREACH_H__
#define __Q6PRM_AUDIOREACH_H__

#include <linux/dma-mapping.h>

int q6prm_audioreach_set_lpass_clock(struct device *dev, int clk_id, int clk_attr,
			  int clk_root, unsigned int freq);
int q6prm_audioreach_vote_lpass_core_hw(struct device *dev, uint32_t hw_block_id,
			     const char *client_name, uint32_t *client_handle);
int q6prm_audioreach_unvote_lpass_core_hw(struct device *dev, uint32_t hw_block_id,
			       uint32_t client_handle);

bool q6apm_audio_is_adsp_ready(void);
int msm_audio_get_phy_addr(int fd, dma_addr_t *paddr, size_t *pa_len);
void msm_audio_mem_crash_handler(void);

int q6apm_audio_mem_init(void);
void q6apm_audio_mem_exit(void);

int q6apm_audio_pkt_init(void);
void q6apm_audio_pkt_exit(void);

int q6apm_lpass_dummy_dais_init(void);
void q6apm_lpass_dummy_dais_exit(void);

int q6prm_audioreach_init(void);
void q6prm_audioreach_exit(void);

int q6prm_audioreach_clock_init(void);
void q6prm_audioreach_clock_exit(void);

int snd_qcs6490_init(void);
void snd_qcs6490_exit(void);

#endif
