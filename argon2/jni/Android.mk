LOCAL_DIR := $(call my-dir)
JNI_DIR := $(LOCAL_DIR)/../../phc-winner-argon2

include $(CLEAR_VARS)

LOCAL_MODULE     := argon2
LOCAL_C_INCLUDES := $(JNI_DIR)/include/
LOCAL_CFLAGS     += -Wall

LOCAL_SRC_FILES := $(LOCAL_DIR)/org_signal_argon2_Argon2Native.c \
                   $(JNI_DIR)/src/blake2/blake2b.c \
                   $(JNI_DIR)/src/argon2.c \
                   $(JNI_DIR)/src/core.c \
                   $(JNI_DIR)/src/encoding.c \
                   $(JNI_DIR)/src/genkat.c \
                   $(JNI_DIR)/src/ref.c \
                   $(JNI_DIR)/src/thread.c

include $(BUILD_SHARED_LIBRARY)
