# ANTA build. `make` builds the C++ engine; `make setup` creates the Python env.
CXX      ?= c++
UNAME    := $(shell uname -s)
WARN     := -Wall -Wextra -Wno-unused-parameter
# The engine parses hostile input, so build it hardened by default.
HARDEN   := -fstack-protector-strong -D_FORTIFY_SOURCE=2
ifeq ($(UNAME),Linux)
HARDEN   += -fPIE -fstack-clash-protection
LDHARDEN := -pie -Wl,-z,relro,-z,now,-z,noexecstack
endif
CXXFLAGS ?= -std=c++17 -O2 -g $(WARN) $(HARDEN)
LDFLAGS  += $(LDHARDEN)
LDLIBS   := -lpcap -lpthread
SAN      := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
PY       := .venv/bin/python
FUZZ_SECS ?= 120

SRC     := $(wildcard engine/src/*.cpp)
LIB_SRC := $(filter-out engine/src/main.cpp,$(SRC))
OBJ     := $(patsubst engine/src/%.cpp,build/obj/%.o,$(SRC))
HDR     := $(wildcard engine/src/*.h engine/src/*.inc)
BIN     := build/anta-engine

.PHONY: all clean setup demo test train fuzz asan app app-setup

all: $(BIN)

$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/obj/%.o: engine/src/%.cpp $(HDR) | build/obj
	$(CXX) $(CXXFLAGS) -c -o $@ $<

build/obj:
	mkdir -p $@

# Engine built with AddressSanitizer + UndefinedBehaviorSanitizer.
asan: build/anta-engine-asan
build/anta-engine-asan: $(SRC) $(HDR)
	@mkdir -p build
	$(CXX) -std=c++17 -O1 -g $(WARN) $(SAN) -o $@ $(SRC) $(LDLIBS)

# Mutation fuzzing of dissectors, reassembly and protocol parsers under ASan/UBSan.
fuzz: build/anta-fuzz build/fuzz-samples.pcap
	./build/anta-fuzz $(FUZZ_SECS) data/mixed_demo.pcap data/http_download.pcap data/edge_cases.pcap build/fuzz-samples.pcap \
		$(wildcard tests/fixtures/dtls/*.pcap)
# Seeds for protocols the generated captures don't carry: Kerberos, the Windows
# browser, chunked/gzip HTTP downloads, a custom protocol on port 443, QUIC,
# LDAP/CLDAP, SMB2 with NTLM and file copies, DCE/RPC, MySQL, PostgreSQL, SQL Server.
build/fuzz-samples.pcap: anta/tools/samples.py
	@mkdir -p build
	$(PY) -m anta.tools.samples $@ --fuzz-seeds
build/anta-fuzz: engine/fuzz/fuzz_engine.cpp $(LIB_SRC) $(HDR)
	@mkdir -p build
	$(CXX) -std=c++17 -O1 -g $(WARN) $(SAN) -o $@ engine/fuzz/fuzz_engine.cpp $(LIB_SRC) $(LDLIBS)

setup:
	uv venv -p 3.12 .venv
	uv pip install -p .venv --require-hashes -r requirements.lock

# Desktop application for this OS (macOS .app/.dmg, Windows installer, Linux tarball).
app-setup:
	uv pip install -p .venv --require-hashes -r requirements-app.lock
app:
	$(PY) packaging/build.py
	$(PY) packaging/smoke_test.py

# Generate synthetic captures, then train, calibrate on held-out data, and export.
train: $(BIN)
	$(PY) -m anta.tools.gen_traffic --out data
	$(PY) -m anta.train --engine $(BIN) --benign data/benign_train.pcap --benign data/benign_train_more.pcap \
		--validate data/benign_val.pcap --validate data/benign_val_more.pcap --test data/benign_holdout.pcap \
		--eval data/mixed_demo.pcap --eval-malicious 192.168.1.105,45.77.12.34,198.51.100.7,203.0.113.50 \
		--compare models --out models

demo: $(BIN)
	$(PY) -m anta serve --engine $(BIN) --pcap data/mixed_demo.pcap --replay-speed 20

test: $(BIN)
	$(PY) -m pytest -q tests

clean:
	rm -rf build dist
