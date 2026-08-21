#!/usr/bin/env bash
#
# Build libezvpn.so for Android and stage it in the jniLibs layout the sibling
# Android app (../ezvpn-android) consumes:
#
#   dist/android/jniLibs/<abi>/libezvpn.so      (one per ABI below)
#   dist/android/libezvpn-android.zip            (the jniLibs tree, for releases)
#
# The app loads it through the JNI surface in src/ffi_android.rs. By default the
# Android project downloads the pinned release zip; for local FFI dev it links
# this dist/android tree when EZVPN_LOCAL_JNILIBS is exactly 1 (see that repo's
# README). This script only produces dist/android; it does not write into
# ../ezvpn-android.
#
# Requires the Android NDK (ANDROID_NDK_HOME, or ANDROID_HOME/ndk/<version>) and
# `cargo ndk` (cargo install cargo-ndk); the Rust targets are added on demand.
#
# Hosts without an NDK (Google ships Linux NDKs for x86_64 only, so e.g. an
# arm64 Linux build box has none): copy the `toolchains/llvm/prebuilt/*/sysroot`
# directory of any NDK there, add its per-arch `libunwind.a` (see the check
# below), and set EZVPN_NDK_SYSROOT to it. The script then drives the system
# `clang` + `lld` (same LLVM major as the NDK works best; Debian 13's clang 19
# matches NDK r28) against that sysroot instead of cargo-ndk — the sysroot is
# host-independent (headers + bionic stubs only). Apple-silicon Macs need none
# of this: the macOS NDK is universal and cargo-ndk works natively.
#
# Usage:
#   ./build-android.sh            # release build (default), all ABIs
#   ./build-android.sh debug      # debug build (faster compile, huge .so)
#   ABIS="armeabi-v7a" ./build-android.sh   # override the ABI list
#   EZVPN_NDK_SYSROOT=~/ndk-sysroot ./build-android.sh   # no-NDK host
#
set -euo pipefail

PROFILE="${1:-release}"
# arm64-v8a is every current phone and the arm64 Android VM used for
# development/testing; armeabi-v7a covers 32-bit-only devices (e.g. the 2013
# Nexus 7 that only gets the signed release APK); x86_64 is the stock emulator.
ABIS="${ABIS:-arm64-v8a armeabi-v7a x86_64}"
# Minimum Android API level the .so links against (must be <= the app's
# minSdk). 29 = Android 10.
ANDROID_API="${ANDROID_API:-29}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

case "$PROFILE" in
  release) CARGO_FLAGS="--release" ;;
  debug)   CARGO_FLAGS="" ;;
  *) echo "unknown profile '$PROFILE' (use 'release' or 'debug')" >&2; exit 1 ;;
esac

SYSROOT="${EZVPN_NDK_SYSROOT:-}"
if [ -z "$SYSROOT" ]; then
  if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo "cargo-ndk not found: install it with 'cargo install cargo-ndk'" >&2
    exit 1
  fi
  # cargo-ndk finds the NDK via ANDROID_NDK_HOME / ANDROID_NDK_ROOT, or the
  # newest one under ANDROID_HOME/ndk. Resolve the latter explicitly so the path
  # used is printed and reproducible.
  if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -z "${ANDROID_NDK_ROOT:-}" ]; then
    SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
    if [ -d "$SDK/ndk" ]; then
      ANDROID_NDK_HOME="$(ls -d "$SDK"/ndk/* | sort -V | tail -1)"
      export ANDROID_NDK_HOME
    fi
  fi
  echo "NDK: ${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-<cargo-ndk default>}}"
else
  for tool in clang ld.lld llvm-ar; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool not found (needed with EZVPN_NDK_SYSROOT)" >&2; exit 1; }
  done
  # Rust's Android std links -lunwind, which the NDK keeps in its clang
  # resource dir rather than the sysroot; a plain sysroot copy lacks it. Check
  # the sysroot and libunwind.a for every ABI selected, not just one.
  for abi in $ABIS; do
    case "$abi" in
      arm64-v8a)   libdir="aarch64-linux-android"; clangarch="aarch64" ;;
      armeabi-v7a) libdir="arm-linux-androideabi"; clangarch="arm" ;;
      x86_64)      libdir="x86_64-linux-android";  clangarch="x86_64" ;;
      x86)         libdir="i686-linux-android";    clangarch="i386" ;;
      *) echo "unknown ABI '$abi'" >&2; exit 1 ;;
    esac
    [ -d "$SYSROOT/usr/lib/$libdir" ] || {
      echo "EZVPN_NDK_SYSROOT=$SYSROOT does not look like an NDK sysroot (no usr/lib/$libdir for $abi)" >&2; exit 1; }
    if [ ! -e "$SYSROOT/usr/lib/$libdir/libunwind.a" ]; then
      cat >&2 <<HINT
EZVPN_NDK_SYSROOT=$SYSROOT has no libunwind.a for $abi. Copy it from the NDK the
sysroot came from, for every target you build:
  <ndk>/toolchains/llvm/prebuilt/*/lib/clang/<ver>/lib/linux/$clangarch/libunwind.a -> $SYSROOT/usr/lib/$libdir/
HINT
      exit 1
    fi
  done
  echo "NDK sysroot: $SYSROOT (system $(clang --version | head -1))"
fi

# ABI -> (Rust target, clang triple with API level, env-var suffix)
abi_target() {
  case "$1" in
    arm64-v8a)   echo "aarch64-linux-android" ;;
    armeabi-v7a) echo "armv7-linux-androideabi" ;;
    x86_64)      echo "x86_64-linux-android" ;;
    x86)         echo "i686-linux-android" ;;
    *) echo "unknown ABI '$1'" >&2; exit 1 ;;
  esac
}
abi_clang_triple() {
  case "$1" in
    arm64-v8a)   echo "aarch64-linux-android${ANDROID_API}" ;;
    armeabi-v7a) echo "armv7a-linux-androideabi${ANDROID_API}" ;;
    x86_64)      echo "x86_64-linux-android${ANDROID_API}" ;;
    x86)         echo "i686-linux-android${ANDROID_API}" ;;
  esac
}

for abi in $ABIS; do
  target="$(abi_target "$abi")"
  if ! rustup target list --installed | grep -q "^${target}$"; then
    echo "Installing Rust target ${target}..."
    rustup target add "$target"
  fi
done

DIST="$SCRIPT_DIR/dist/android"
JNILIBS="$DIST/jniLibs"
rm -rf "$JNILIBS"
mkdir -p "$JNILIBS"

if [ -z "$SYSROOT" ]; then
  # shellcheck disable=SC2086
  cargo ndk \
    $(for abi in $ABIS; do printf -- '-t %s ' "$abi"; done) \
    --platform "$ANDROID_API" \
    -o "$JNILIBS" \
    build --lib ${CARGO_FLAGS}
  # cargo-ndk stages every cdylib it finds; only libezvpn.so is wanted.
  find "$JNILIBS" -type f ! -name 'libezvpn.so' -delete
else
  # No cargo-ndk: do what it does by hand. Per target, a clang wrapper that
  # pins --target/--sysroot/lld serves as both the Rust linker and the `cc`
  # crate's C compiler (ring and friends), with llvm-ar as the archiver. The
  # 16 KiB max-page-size matches cargo-ndk's default (required by Android 15+
  # on arm64).
  WRAP_DIR="$SCRIPT_DIR/target/android-clang-wrappers"
  mkdir -p "$WRAP_DIR"
  case "$PROFILE" in release) OUT_SUBDIR="release" ;; *) OUT_SUBDIR="debug" ;; esac
  for abi in $ABIS; do
    target="$(abi_target "$abi")"
    triple="$(abi_clang_triple "$abi")"
    wrapper="$WRAP_DIR/$triple-clang"
    printf '#!/bin/sh\nexec clang --target=%s --sysroot=%s -fuse-ld=lld -Wl,-z,max-page-size=16384 "$@"\n' \
      "$triple" "$SYSROOT" > "$wrapper"
    chmod +x "$wrapper"
    env_suffix="$(echo "$target" | tr 'a-z-' 'A-Z_')"
    cc_suffix="$(echo "$target" | tr '-' '_')"
    echo "Building libezvpn.so [$PROFILE] for $target via $wrapper ..."
    # shellcheck disable=SC2086
    env "CARGO_TARGET_${env_suffix}_LINKER=$wrapper" \
        "CC_${cc_suffix}=$wrapper" \
        "AR_${cc_suffix}=llvm-ar" \
        "RANLIB_${cc_suffix}=llvm-ranlib" \
        cargo build --lib ${CARGO_FLAGS} --target "$target"
    mkdir -p "$JNILIBS/$abi"
    cp "$SCRIPT_DIR/target/$target/$OUT_SUBDIR/libezvpn.so" "$JNILIBS/$abi/libezvpn.so"
  done
fi

echo "Creating libezvpn-android.zip ..."
rm -f "$DIST/libezvpn-android.zip"
(cd "$DIST" && zip -qr libezvpn-android.zip jniLibs)

echo "Staged: $JNILIBS"
find "$JNILIBS" -name 'libezvpn.so' -exec ls -la {} \;
echo "        $DIST/libezvpn-android.zip"
echo
echo "For local Android FFI dev, build the app against this tree with:"
echo "    cd ../ezvpn-android"
echo "    EZVPN_LOCAL_JNILIBS=1 ./gradlew :app:installDebug"
echo "Done."
