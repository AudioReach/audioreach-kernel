obj-m += audioreach_driver.o

audioreach_driver-objs := \
    q6apm_audio_mem.o \
    q6apm_audio_pkt.o \
    q6apm_lpass_dummy_dais.o \
    q6prm_audioreach_clock.o \
    q6prm_audioreach.o \
    audioreach_common.o

ccflags-y += -I$(KERNEL_SRC)/sound/soc/qcom/qdsp6 -I$(KERNEL_SRC)/sound/soc/qcom -I$(src)/../include/uapi
