#!/bin/bash
# compiler.sh — multi-arch compilation for p2p_agent
# Usage: ./compiler.sh
# Generates static binaries compressed with UPX.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Configuration ────────────────────────────────────────────────────────────
TOOLCHAIN_DIR="/opt/toolchains"
OUTDIR="$SCRIPT_DIR/bin"

# Internal compiler options.
CPPFLAGS=(
    -Icore/include
    -DPOSIX
)
CFLAGS=(
    -Os
    -std=gnu11
    -ffunction-sections
    -fdata-sections
    -fno-strict-aliasing
)
CXXFLAGS=(
    -Os
    -std=gnu++11
    -ffunction-sections
    -fdata-sections
    -fno-exceptions
    -fno-rtti
    -fpermissive
    -Wno-sign-compare
    -Wno-unused-parameter
)
LDFLAGS=(
    -static
    -Wl,--gc-sections
    -nodefaultlibs
    -lc
    -lgcc
    -lm
)

# Sources (order matters: monocypher first so linker finds symbols).
C_SOURCES=(
    third_party/monocypher/monocypher.c
    core/hpv/state.c
    core/hpv/util.c
    core/crypto/crypto.c
    core/hpv/guard.c
    core/dht/dht.c
    core/hpv/registry.c
    core/gossip/gossip.c
    core/dht/bt_dht.c
    core/overlay/overlay.c
    core/overlay/udp.c
    core/hpv/transport.c
    core/hpv/iot_profile.c
    core/hpv/watchdog.c
    main/main.c
)
CXX_SOURCES=(
    core/overlay/minimal.cpp
)

if [[ $# -gt 0 ]]; then
    echo "compiler.sh does not accept arguments."
    exit 1
fi

mkdir -p "$OUTDIR"

# ── Detect compilers ─────────────────────────────────────────────────────────
declare -A COMPILERS
declare -A CXX_COMPILERS

# Only use musl toolchains (ignore glibc/buildroot)
if [[ -d "$TOOLCHAIN_DIR" ]]; then
    for toolchain in "$TOOLCHAIN_DIR"/*/; do
        TOOLCHAIN_NAME=$(basename "$toolchain")
        
        # Only musl toolchains (ignore glibc/buildroot)
        if [[ "$TOOLCHAIN_NAME" != *"musl"* ]]; then
            continue
        fi
        
        # Ignore mips big-endian (mips32, mips64, but NOT mipsel)
        if [[ "$TOOLCHAIN_NAME" =~ ^mips[0-9]+-linux-musl ]] || [[ "$TOOLCHAIN_NAME" =~ ^mips-linux-musl ]]; then
            continue
        fi
        
        ARCH=$(echo "$TOOLCHAIN_NAME" | cut -d'-' -f1)
        COMPILER_PATH=$(find "$toolchain/bin" -maxdepth 1 -name "*-gcc" 2>/dev/null | head -n1)
        if [[ -n "$COMPILER_PATH" ]]; then
            COMPILERS["$ARCH"]="$COMPILER_PATH"
            CXX_PATH="${COMPILER_PATH%gcc}g++"
            CXX_COMPILERS["$ARCH"]="$CXX_PATH"
        fi
    done
else
    echo "ERROR: TOOLCHAIN_DIR does not exist: $TOOLCHAIN_DIR"
    echo "Extract musl toolchains in $TOOLCHAIN_DIR"
    exit 1
fi

# ── Compile ──────────────────────────────────────────────────────────────────
echo "Starting massive compilation (${#COMPILERS[@]} arch)..."
echo "Link mode: static"
echo "UPX: mandatory"
echo ""

if ! command -v upx &>/dev/null; then
    echo "ERROR: upx not found and this version requires it."
    exit 1
fi

SUCCESS=0
FAIL=0

for ARCH in "${!COMPILERS[@]}"; do
    COMPILER="${COMPILERS[$ARCH]}"
    CXX_COMPILER="${CXX_COMPILERS[$ARCH]:-${COMPILER%gcc}g++}"
    BINARY="$OUTDIR/$ARCH"
    OBJDIR="$OUTDIR/.obj-$ARCH"

    echo "─── $ARCH ───────────────────────────────────────────────────────"
    rm -f "$BINARY"
    rm -rf "$OBJDIR"
    mkdir -p "$OBJDIR"

    # Verify that compilers exist. Minimal.cpp requires C++,
    # so cross g++ is mandatory.
    if ! command -v "$COMPILER" &>/dev/null; then
        echo "  SKIP: compiler not found ($COMPILER)"
        rm -rf "$OBJDIR"
        (( FAIL++ )) || true
        continue
    fi
    if ! command -v "$CXX_COMPILER" &>/dev/null; then
        echo "  SKIP: C++ compiler not found ($CXX_COMPILER)"
        echo "        Install the g++ package for that toolchain (e.g.: g++-aarch64-linux-gnu)."
        rm -rf "$OBJDIR"
        (( FAIL++ )) || true
        continue
    fi

    # Adjust LDFLAGS by architecture (fix UPX for ARM32)
    ARCH_LDFLAGS=("${LDFLAGS[@]}")
    if [[ "$ARCH" =~ ^arm.*l$ ]] && [[ "$ARCH" != "aarch64" ]]; then
        ARCH_LDFLAGS+=("-Wl,--hash-style=sysv")
    fi

    # 1. Compile
    OBJS=()
    BUILD_OK=1

    for SRC in "${C_SOURCES[@]}"; do
        OBJ="$OBJDIR/${SRC//\//_}.o"
        OBJS+=("$OBJ")
        if ! "$COMPILER" "${CPPFLAGS[@]}" "${CFLAGS[@]}" -c "$SRC" -o "$OBJ"; then
            BUILD_OK=0
            break
        fi
    done

    if [[ "$BUILD_OK" -eq 1 ]]; then
        for SRC in "${CXX_SOURCES[@]}"; do
            OBJ="$OBJDIR/${SRC//\//_}.o"
            OBJS+=("$OBJ")
            if ! "$CXX_COMPILER" "${CPPFLAGS[@]}" "${CXXFLAGS[@]}" -c "$SRC" -o "$OBJ"; then
                BUILD_OK=0
                break
            fi
        done
    fi

    if [[ "$BUILD_OK" -eq 1 ]] &&
       "$CXX_COMPILER" -o "$BINARY" "${OBJS[@]}" "${ARCH_LDFLAGS[@]}"; then
        SIZE_BEFORE=$(stat -c%s "$BINARY")

        # 2. Strip (use toolchain strip if exists)
        STRIP_CMD=$(echo "$COMPILER" | sed 's/gcc$/strip/')
        if command -v "$STRIP_CMD" &>/dev/null; then
            "$STRIP_CMD" -s "$BINARY"
        else
            strip -s "$BINARY" 2>/dev/null || true
        fi

        # 3. UPX (with fallback for ARM32)
        UPX_OK=1
        if upx --best --lzma --quiet "$BINARY" 2>&1; then
            SIZE_AFTER=$(stat -c%s "$BINARY")
            PCT=$(( 100 - SIZE_AFTER * 100 / SIZE_BEFORE ))
            echo "  OK  $BINARY  (${SIZE_BEFORE}B → ${SIZE_AFTER}B, -${PCT}%)"
        else
            # UPX failed (common on ARM32 with GNU hash). Deploy without compression.
            echo "  WARN: UPX failed, using uncompressed binary"
            SIZE_AFTER=$(stat -c%s "$BINARY")
            echo "  OK  $BINARY  (${SIZE_AFTER}B, without UPX)"
        fi

        (( SUCCESS++ )) || true
    else
        echo "  ERROR compiling for $ARCH"
        (( FAIL++ )) || true
    fi
    rm -rf "$OBJDIR"
done

echo ""
echo "Result: $SUCCESS OK, $FAIL errors."
[[ $FAIL -eq 0 ]]
