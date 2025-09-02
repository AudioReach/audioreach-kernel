obj-m += audioreach_driver.o

audioreach_driver-objs := \
    q6apm_audio_mem.o \
    q6apm_audio_pkt.o \
    q6apm_lpass_dummy-dais.o \
    q6prm_audioreach_clock.o \
    q6prm_audioreach.o \
    qcs6490_audioreach_common.o
ccflags-y += -I$(KERNEL_SRC)/sound/soc/qcom/qdsp6 -I$(KERNEL_SRC)/sound/soc/qcom


all:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules

modules_install:
	    $(MAKE) -C $(KERNEL_SRC) M=$(PWD) INSTALL_MOD_PATH=$(DESTDIR) modules_install

clean:
	@if [ -n "$(KERNEL_SRC)" ]; then \
		$(MAKE) -C $(KERNEL_SRC) M=$(shell pwd) clean; \
	elif [ -n "$(KERNELDIR)" ]; then \
		$(MAKE) -C $(KERNELDIR) M=$(shell pwd) clean; \
	else \
		rm -f *.o *.ko *.mod.c *.order *.symvers; \
	fi

