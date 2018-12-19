LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_DEX_PREOPT := false
LOCAL_PACKAGE_NAME := WalletServer
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := $(call all-subdir-java-files)
LOCAL_RESOURCE_DIR := $(LOCAL_PATH)/res \

LOCAL_STATIC_JAVA_LIBRARIES := \
    bitcoinj-core \
    web3j-core \
    web3j-crypto \
    web3j-abi \
    web3j-rlp \
    web3j-tuples \
    web3j-utils \
    guava-18 \
    slf4j-jdk14 \
    spongycastle-core \
    spongycastle-prov \
    protobuf-java \
    lambda-scrypt \
    jackson-databind \
    jackson-core \
    jackson \
    reactivex-rxjava \
    reactivex-rxandroid \
    okhttp-3 \
    okhttp-logging \
    okio \
    guava-18 \

LOCAL_CERTIFICATE := platform
LOCAL_PRIVILEGED_MODULE := true

include $(BUILD_PACKAGE)

