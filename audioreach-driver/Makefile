obj-m += audioreach_driver.o

audioreach_driver-objs = q6apm_audio_mem.o

ifdef VENDOR_QCOM
	audioreach_driver-objs += q6apm_lpass_dummy_dais.o
	audioreach_driver-objs += q6prm_audioreach_clock.o
	audioreach_driver-objs += q6prm_audioreach.o
	audioreach_driver-objs += audioreach_common.o
	ccflags-y += -DQCOM_HYP_ASSIGN
else
	audioreach_driver-objs += q6apm_audio_pkt_rpmsg.o
endif

ccflags-y += -I$(KERNEL_SRC)/sound/soc/qcom/qdsp6 -I$(KERNEL_SRC)/sound/soc/qcom -I$(src)/../include/uapi
