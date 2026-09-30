ARCHS = arm64
THEOS_PLATFORM_DEB_COMPRESSION_TYPE = xz
TARGET = iphone:clang:latest:14.0
FINALPACKAGE = 1
FOR_RELEASE = 1
THEOS_PACKAGE_SCHEME = rootless
include $(THEOS)/makefiles/common.mk

TWEAK_NAME = APIKey

$(TWEAK_NAME)_FRAMEWORKS = UIKit Foundation SystemConfiguration SafariServices
$(TWEAK_NAME)_LDFLAGS += libPPAPIKey.a -Wl,-dead_strip
$(TWEAK_NAME)_CCFLAGS = -std=c++11 -O3 -fvisibility=hidden -fvisibility-inlines-hidden -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-value
$(TWEAK_NAME)_FILES = Key.mm
$(TWEAK_NAME)_LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS_MAKE_PATH)/tweak.mk