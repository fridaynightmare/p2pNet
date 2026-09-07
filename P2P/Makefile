# Makefile.musl - Compilation with static musl, maximum size reduction
# Usage: cd P2Pu/P2P && make -f ../Makefile.musl agent

# toolchain stuff
CC      := musl-gcc
CXX     := musl-gcc

# Aggressive flags for minimum size
CFLAGS  := -std=c11 \
	-Os \
	-ffunction-sections \
	-fdata-sections \
	-fno-unwind-tables \
	-fno-asynchronous-unwind-tables \
	-fno-ident \
	-fno-strict-aliasing \
	-Wl,-z,norelro \
	-Wl,-z,noseparate-code

CXXFLAGS := -std=c++11 \
	-Os \
	-ffunction-sections \
	-fdata-sections \
	-fno-unwind-tables \
	-fno-asynchronous-unwind-tables \
	-fno-ident \
	-fno-exceptions \
	-fno-rtti \
	-fpermissive \
	-Wno-sign-compare \
	-Wno-unused-parameter \
	-Wl,-z,norelro \
	-Wl,-z,noseparate-code

CPPFLAGS := -Icore/include \
	-MMD -MP -DPOSIX \
	-DNDEBUG

# Linker: static + gc-sections + strip
LDFLAGS := -static \
	-Wl,--gc-sections \
	-Wl,-s \
	-Wl,-z,relro \
	-pthread \
	-lm \
	-nodefaultlibs \
	-lc

# Binaries
AGENT_BIN    := p2p_agent
KEYGEN_BIN   := keygen

# source files
CORE_SRC := \
	third_party/monocypher/monocypher.c \
	core/hpv/state.c \
	core/hpv/util.c \
	core/crypto/crypto.c \
	core/hpv/guard.c \
	core/dht/dht.c \
	core/hpv/registry.c \
	core/gossip/gossip.c \
	core/dht/bt_dht.c \
	core/overlay/overlay.c \
	core/overlay/udp.c \
	core/hpv/transport.c \
	core/hpv/iot_profile.c \
	core/hpv/watchdog.c

CORE_CXX_SRC := \
	core/overlay/minimal.cpp

AGENT_C_SRC := $(CORE_SRC) main/main.c
AGENT_CXX_SRC := $(CORE_CXX_SRC)
AGENT_OBJ := $(AGENT_C_SRC:.c=.o) $(AGENT_CXX_SRC:.cpp=.o)
AGENT_DEP := $(AGENT_OBJ:.o=.d)

KEYGEN_DEP := $(KEYGEN_BIN).d

.PHONY: all agent tools clean info help

all: agent tools

agent: info $(AGENT_BIN)
	@echo "✓ $(AGENT_BIN) compiled with static musl"
	@ls -lh $(AGENT_BIN)

tools: info $(KEYGEN_BIN)

info:
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "Static MUSL compilation - Size optimized"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "CC:  $(CC)"
	@echo "CXX: $(CXX)"
	@echo ""

$(AGENT_BIN): $(AGENT_OBJ)
	@echo "Linking $(AGENT_BIN)..."
	$(CXX) $(CXXFLAGS) $(AGENT_OBJ) $(LDFLAGS) -o $@
	@echo "  Pre-strip:  $$(ls -lh $@ | awk '{print $$5}')"
	@strip --strip-all --remove-section=.comment --remove-section=.note $@
	@echo "  Post-strip: $$(ls -lh $@ | awk '{print $$5}')"
	@if command -v upx >/dev/null 2>&1; then \
		echo "  Compressing with UPX..."; \
		upx --best --lzma -q $@ 2>/dev/null || true; \
		echo "  Post-UPX:   $$(ls -lh $@ | awk '{print $$5}')"; \
	else \
		echo "  (upx not found, install it for -60% size reduction)"; \
	fi

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

$(KEYGEN_BIN): tools/keygen.c third_party/monocypher/monocypher.c core/include/monocypher.h
	@echo "Compiling $(KEYGEN_BIN)..."
	$(CC) $(CFLAGS) $(CPPFLAGS) tools/keygen.c third_party/monocypher/monocypher.c $(LDFLAGS) -o $@
	@strip --strip-all $@
	@ls -lh $@

clean:
	@rm -f $(AGENT_OBJ) $(AGENT_DEP) $(KEYGEN_DEP) $(AGENT_BIN) $(KEYGEN_BIN) keygen.d
	@echo "Cleaned"

help:
	@echo "Targets:"
	@echo "  make -f Makefile.musl agent      Build agent (musl static)"
	@echo "  make -f Makefile.musl tools      Build keygen (musl static)"
	@echo "  make -f Makefile.musl clean      Clean build outputs"
	@echo ""
	@echo "Prerequisites (Kali/Debian):"
	@echo "  sudo apt install musl-tools upx"
	@echo ""

-include $(AGENT_DEP) $(KEYGEN_DEP)
