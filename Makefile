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
OFFLINE_SUBGRAPH_DIR ?= $(OFFLINE_OUT_DIR)/incident_subgraphs
OFFLINE_INCIDENT_MIN_SEQ ?= 2

offline: build
	@mkdir -p $(OFFLINE_OUT_DIR)
	./$(BIN_DIR)/$(APP)$(EXE) produce $(OFFLINE_CONFIG)
	./$(BIN_DIR)/$(APP)$(EXE) analyze --source clickhouse --config $(OFFLINE_CONFIG) --output $(OFFLINE_IIP) --tactical-output $(OFFLINE_TPG) --incident-output $(OFFLINE_INCIDENTS) --incident-min-seq $(OFFLINE_INCIDENT_MIN_SEQ)
	@CH_URL=$$(python3 tools/offline_config_get.py --config $(OFFLINE_CONFIG) --path threatgraph.output.clickhouse.url); \
	CH_DB=$$(python3 tools/offline_config_get.py --config $(OFFLINE_CONFIG) --path threatgraph.output.clickhouse.database); \
	CH_TABLE=$$(python3 tools/offline_config_get.py --config $(OFFLINE_CONFIG) --path threatgraph.output.clickhouse.table); \
	ES_URL=$$(python3 tools/offline_config_get.py --config $(OFFLINE_CONFIG) --path threatgraph.input.elasticsearch.url); \
	ES_USER=$$(python3 tools/offline_config_get.py --config $(OFFLINE_CONFIG) --path threatgraph.input.elasticsearch.username); \
	ES_PASS=$$(python3 tools/offline_config_get.py --config $(OFFLINE_CONFIG) --path threatgraph.input.elasticsearch.password); \
	ES_INDEX=$$(python3 tools/offline_config_get.py --config $(OFFLINE_CONFIG) --path threatgraph.input.elasticsearch.index); \
	ES_CA=$$(python3 tools/offline_config_get.py --config $(OFFLINE_CONFIG) --path threatgraph.input.elasticsearch.ca_cert_path); \
	[ -n "$$CH_URL" ] || CH_URL="http://127.0.0.1:8123"; \
	[ -n "$$CH_DB" ] || CH_DB="threatgraph"; \
	[ -n "$$CH_TABLE" ] || CH_TABLE="adjacency"; \
	[ -n "$$ES_URL" ] || ES_URL="https://127.0.0.1:9200"; \
	[ -n "$$ES_USER" ] || ES_USER="elastic"; \
	[ -n "$$ES_INDEX" ] || ES_INDEX="edr-offline-ls-*"; \
	python3 tools/build_incident_subgraphs.py --incidents $(OFFLINE_INCIDENTS) --iip $(OFFLINE_IIP) --ch-url "$$CH_URL" --ch-db "$$CH_DB" --ch-table "$$CH_TABLE" --out-dir $(OFFLINE_SUBGRAPH_DIR); \
	python3 tools/make_viewer.py --all-in-dir $(OFFLINE_SUBGRAPH_DIR) --out $(OFFLINE_REPORT) --es-url "$$ES_URL" --es-user "$$ES_USER" --es-pass "$$ES_PASS" --es-index "$$ES_INDEX" --es-ca "$$ES_CA"
