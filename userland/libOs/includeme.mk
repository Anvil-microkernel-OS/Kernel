LIBOS_SOURCE_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
LIBOS_LIB := $(LIBOS_SOURCE_PATH)/build/libOs.a

