LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := csdknl
LOCAL_SRC_FILES := csdknl.c
LOCAL_LDLIBS :=-llog
include $(BUILD_SHARED_LIBRARY)

