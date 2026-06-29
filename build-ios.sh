#!/usr/bin/env bash
#
# Build libezvpn.a for a real iOS device (aarch64-apple-ios) and stage it with
# the C header for the separate Xcode project (../ezvpn-ios).
#
# Device-only by design: a Packet Tunnel Provider does not run in the iOS
# Simulator, so there is no simulator/x86_64 slice and no XCFramework here.
#
# Usage:
#   ./build-ios.sh            # release build (default)
#   ./build-ios.sh debug      # debug build (faster compile, huge .a)
#
set -euo pipefail

PROFILE="${1:-release}"
TARGET="aarch64-apple-ios"
# Minimum iOS version. Must be <= the Xcode project's deployment target, else
# the linker warns that the lib's objects target a newer OS. Override via env.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

case "$PROFILE" in
  release) CARGO_FLAGS="--release"; OUT_SUBDIR="release" ;;
  debug)   CARGO_FLAGS="";          OUT_SUBDIR="debug"   ;;
  *) echo "unknown profile '$PROFILE' (use 'release' or 'debug')" >&2; exit 1 ;;
esac

if ! rustup target list --installed | grep -q "^${TARGET}$"; then
  echo "Installing Rust target ${TARGET}..."
  rustup target add "$TARGET"
fi

echo "Building libezvpn.a [$PROFILE] for $TARGET ..."
cargo build --lib ${CARGO_FLAGS} --target "$TARGET"

DIST="$SCRIPT_DIR/dist/ios"
mkdir -p "$DIST"
cp "target/${TARGET}/${OUT_SUBDIR}/libezvpn.a" "$DIST/libezvpn.a"
cp "ios/ezvpn.h" "$DIST/ezvpn.h"
echo "Staged: $DIST/libezvpn.a"
echo "        $DIST/ezvpn.h"

# If the sibling Xcode project exists, sync the artifacts into its vendor dir so
# a rebuild there picks them up with no manual copy.
SIBLING_VENDOR="$SCRIPT_DIR/../ezvpn-ios/vendor"
if [ -d "$SIBLING_VENDOR" ]; then
  cp "$DIST/libezvpn.a" "$SIBLING_VENDOR/libezvpn.a"
  cp "$DIST/ezvpn.h"    "$SIBLING_VENDOR/ezvpn.h"
  echo "Synced into:  $SIBLING_VENDOR/"
fi

echo "Done."
