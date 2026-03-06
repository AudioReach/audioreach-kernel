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

#endif /* __AR_KCOMPAT_H__ */
