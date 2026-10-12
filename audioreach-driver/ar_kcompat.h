/* SPDX-License-Identifier: GPL-2.0 */
// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#ifndef __AR_KCOMPAT_H__
#define __AR_KCOMPAT_H__

#include <linux/version.h>
#include <linux/types.h>

/*
 * Detect whether the kernel expects GPR callback with:
 *   - <= 6.19 : struct gpr_resp_pkt * (non-const)
 *   - >= 7.0 : const struct gpr_resp_pkt * (const)
 *
 * Allow a build-time override (vendors may backport).
 *
 * Use:
 *   -D HAVE_GPR_CB_CONST   -> force >=7.0 behavior (const)
 *   -D HAVE_GPR_CB_MUTABLE -> force <=6.19 behavior (non-const)
 *
 * If neither is defined, pick based on LINUX_VERSION_CODE.
 */
#if defined(HAVE_GPR_CB_CONST) && defined(HAVE_GPR_CB_MUTABLE)
# error "Define at most one of HAVE_GPR_CB_CONST or HAVE_GPR_CB_MUTABLE"
#endif

#if defined(HAVE_GPR_CB_CONST)
# define AR_HAVE_GPR_CB_CONST 1
#elif defined(HAVE_GPR_CB_MUTABLE)
# define AR_HAVE_GPR_CB_CONST 0
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)
# define AR_HAVE_GPR_CB_CONST 1
#else
# define AR_HAVE_GPR_CB_CONST 0
#endif

/*
 * Thunk generator for GPR callbacks.
 *
 * The driver provides a version‑independent core:
 *     int name_core(const struct gpr_resp_pkt *data, void *priv, int op);
 *
 * This macro emits an ABI‑appropriate wrapper ('name') and forwards the
 * packet to the const‑correct core. Legacy kernels that pass a mutable
 * gpr_resp_pkt pointer are handled by accepting the mutable form and
 * forwarding it as const. The packet is not modified.
 *
 * For kernels that require in‑place packet modification, a local copy must
 * be created before invoking the core. Current code paths do not modify
 * the packet.
 */

#define AR_GPR_CB_WRAPPER(name)                                             \
	static int name##_core(const struct gpr_resp_pkt *data,                  \
					void *priv, int op);                              \
	__AR_GPR_CB_DECL(name)                                                  \
	{                                                                       \
		/* Non‑const legacy pointer; handled as read‑only. */               \
		return name##_core((const struct gpr_resp_pkt *)data, priv, op);    \
	}

/* Emit the kernel-facing callback prototype */
#if AR_HAVE_GPR_CB_CONST
# define __AR_GPR_CB_DECL(name) \
	static int name(const struct gpr_resp_pkt *data, void *priv, int op)
#else
# define __AR_GPR_CB_DECL(name) \
	static int name(struct gpr_resp_pkt *data, void *priv, int op)
#endif


/*
 * MODULE_IMPORT_NS syntax changed in kernel 6.13:
 *   - < 6.13 : MODULE_IMPORT_NS(DMA_BUF)    (unquoted token)
 *   - >= 6.13: MODULE_IMPORT_NS("DMA_BUF")  (quoted string)
 *
 * AR_MODULE_IMPORT_NS wraps this difference so the driver builds
 * correctly on both old and new kernels.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
# define AR_MODULE_IMPORT_NS(ns)	MODULE_IMPORT_NS(#ns)
#else
# define AR_MODULE_IMPORT_NS(ns)	MODULE_IMPORT_NS(ns)
#endif

/* dev->dma_coherent direct field access changed in newer kernels. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 2, 0)
# define AR_HAVE_DEV_SET_DMA_COHERENT 1
#else
# define AR_HAVE_DEV_SET_DMA_COHERENT 0
#endif

#if AR_HAVE_DEV_SET_DMA_COHERENT
# define AR_SET_DMA_COHERENT(dev) dev_set_dma_coherent(dev)
#else
# define AR_SET_DMA_COHERENT(dev) ((dev)->dma_coherent = true)
#endif

#endif /* __AR_KCOMPAT_H__ */

/*
 * snd_soc_dapm_to_card() was a downstream/vendor helper that never landed in
 * mainline.  Mainline kernels (including 6.8+) expose the card pointer
 * directly as dapm->card.  Provide a fallback so code that still calls the
 * macro compiles on kernels that lack it.
 */
#ifndef snd_soc_dapm_to_card
# define snd_soc_dapm_to_card(dapm)	((dapm)->card)
#endif

/*
 * LPI_MI2S_RX/TX port IDs were added in the Qualcomm downstream kernel
 * (qualcomm-linux/kernel-topics); they landed in mainline at v7.1
 * (commit e46957f27c60).  Define them here so the driver builds on kernels
 * older than v7.1 (all 6.x and v7.0).
 *
 * Values are taken from the Qualcomm downstream
 * include/dt-bindings/sound/qcom,q6dsp-lpass-ports.h.
 * They follow immediately after QUINARY_MI2S_TX (128) / USB_RX (136).
 */
#ifndef LPI_MI2S_RX_0
# define LPI_MI2S_RX_0	137
# define LPI_MI2S_TX_0	138
# define LPI_MI2S_RX_1	139
# define LPI_MI2S_TX_1	140
# define LPI_MI2S_RX_2	141
# define LPI_MI2S_TX_2	142
# define LPI_MI2S_RX_3	143
# define LPI_MI2S_TX_3	144
# define LPI_MI2S_RX_4	145
# define LPI_MI2S_TX_4	146
#endif
