obj-m += audio_reach_driver.o

audio_reach_driver-objs := \
    q6apm-audio-mem.o \
    q6apm-audio-pkt.o \
    q6apm-lpass-dummy-dais.o \
    q6prm-audioreach-clock.o \
    q6prm-audioreach.o \
    qcs6490-audioreach-common.o
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

