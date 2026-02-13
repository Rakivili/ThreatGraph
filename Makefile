BIN_DIR := bin
APP := threatgraph
SRC := ./cmd/threatgraph
ANALYZER_APP := adjacency-analyzer
ANALYZER_SRC := ./cmd/adjacency-analyzer

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

.PHONY: all build build-analyzer clean

all: build

build:
	@$(MKDIR)
	go build -o $(BIN_DIR)/$(APP)$(EXE) $(SRC)

build-analyzer:
	@$(MKDIR)
	go build -o $(BIN_DIR)/$(ANALYZER_APP)$(EXE) $(ANALYZER_SRC)

clean:
	@$(RMDIR)
