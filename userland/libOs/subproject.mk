include includeme.mk

# Root rule: Build libOs.
libos: $(LIBOS_SOURCE_PATH)/build
	cd $(LIBOS_SOURCE_PATH) && cmake --build build/

# If build directory doesn't exist, configure libOs.
$(LIBOS_SOURCE_PATH)/build:
	cd $(LIBOS_SOURCE_PATH) && cmake -B build . -GNinja