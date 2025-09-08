#Top-level Makefile for AudioReach kernel modules

SUBDIRS := audioreach-driver

.PHONY: all clean modules_install

all:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir all; \
	done

modules_install:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir modules_install; \
	done

clean:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean; \
	done
