export ANDROID_HOME="$HOME/Library/Android/sdk"
export NDK_HOME="$ANDROID_HOME/ndk/$(ls $ANDROID_HOME/ndk | head -n 1)"
export CMAKE_MAKE_PROGRAM="$HOME/cmake/3.31.1/bin/cmake"
export ANDROID_NDK_ROOT="$NDK_HOME"
export ANDROID_NDK="$NDK_HOME"
export ANDROID_STANDALONE_TOOLCHAIN="$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64"
echo $CMAKE_MAKE_PROGRAM
