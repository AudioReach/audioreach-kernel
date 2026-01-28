/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _MSM_AUDIO_MEM_H
#define _MSM_AUDIO_MEM_H

#include <linux/dma-mapping.h>
#include <uapi/linux/msm_audio.h>

int msm_audio_get_phy_addr(int fd, dma_addr_t *paddr, size_t *pa_len);
void msm_audio_mem_crash_handler(void);
#endif /* _LINUX_MSM_AUDIO_MEM_H */
