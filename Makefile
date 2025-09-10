# A list of subdirectories containing Kbuild Makefiles
SUBDIRS := audioreach-driver

# Define common targets using the special automatic variable $@
all modules clean modules_install:
	for dir in $(SUBDIRS); do \
        echo "Executing '$@' in $$dir..."; \
        $(MAKE) -C $(KERNEL_SRC) M=$(CURDIR)/$$dir $@; \
    done

# The 'modules' target is the default one, so when you run 'make'
# it will build the modules.
.PHONY: all modules clean modules_install
