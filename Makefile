
# BUILD_DIR := ./build

# export NDK_PROJECT_PATH=.
# export APP_BUILD_SCRIPT=./Android.mk

# build:
# 	mkdir -p build
# 	ndk-build

# all: clean format deps build

# local:
# 	mkdir -p build
# 	$(CXX) src/main_fix.cpp src/elffix/fix.cpp -O2 -o $(BUILD_DIR)/sofix

# format:
# 	find src/ -regex '.*\.\(c\|h\|cpp\)'  -exec clang-format -style=file -i {} \;

# .PHONY: clean
# clean:
# 	rm -rf ${BUILD_DIR}


ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk NDK_APP_DST_DIR=./build NDK_APP_OUT=./build APP_PLATFORM=android-21 APP_ABI="armeabi-v7a arm64-v8a" APP_STL=none
