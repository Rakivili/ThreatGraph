BIN_DIR := bin
APP := threatgraph
SRC := ./cmd/threatgraph

UNAME_S := $(shell uname -s 2>/dev/null)
WIN :=
ifeq ($(OS),Windows_NT)
WIN := 1
else ifneq (,$(findstring MINGW,$(UNAME_S)))
WIN := 1
else ifneq (,$(findstring MSYS,$(UNAME_S)))
WIN := 1
else ifneq (,$(findstring CYGWIN,$(UNAME_S)))
WIN := 1
endif

ifeq ($(WIN),1)
MKDIR := if not exist $(BIN_DIR) mkdir $(BIN_DIR)
RMDIR := if exist $(BIN_DIR) rmdir /S /Q $(BIN_DIR)
EXE := .exe
else
MKDIR := mkdir -p $(BIN_DIR)
RMDIR := rm -rf $(BIN_DIR)
EXE :=
endif

.PHONY: all build clean offline

all: build

build:
	@$(MKDIR)
	go build -o $(BIN_DIR)/$(APP)$(EXE) $(SRC)

clean:
	@$(RMDIR)

OFFLINE_CONFIG ?= example/threatgraph.clickhouse.example.yml
OFFLINE_OUT_DIR ?= output/offline
OFFLINE_IIP ?= $(OFFLINE_OUT_DIR)/iip.jsonl
OFFLINE_TPG ?= $(OFFLINE_OUT_DIR)/tpg.jsonl
OFFLINE_INCIDENTS ?= $(OFFLINE_OUT_DIR)/incidents.jsonl
OFFLINE_REPORT ?= $(OFFLINE_OUT_DIR)/report.html
OFFLINE_INCIDENT_MIN_SEQ ?= 2
OFFLINE_REPORT_TITLE ?= ThreatGraph Offline Report

offline: build
	@mkdir -p $(OFFLINE_OUT_DIR)
	./$(BIN_DIR)/$(APP)$(EXE) produce $(OFFLINE_CONFIG)
	./$(BIN_DIR)/$(APP)$(EXE) analyze --source clickhouse --config $(OFFLINE_CONFIG) --output $(OFFLINE_IIP) --tactical-output $(OFFLINE_TPG) --incident-output $(OFFLINE_INCIDENTS) --incident-min-seq $(OFFLINE_INCIDENT_MIN_SEQ)
	python3 tools/render_offline_html.py --incidents $(OFFLINE_INCIDENTS) --tactical $(OFFLINE_TPG) --out $(OFFLINE_REPORT) --title "$(OFFLINE_REPORT_TITLE)"
