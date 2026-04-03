all: test

TOIT_EXEC ?= $(shell which toit 2>/dev/null)
ifeq ($(TOIT_EXEC),)
  JAG_EXEC := $(shell which jag 2>/dev/null)
  ifneq ($(JAG_EXEC),)
    TOIT_EXEC := jag toit
  else
    TOIT_EXEC := toit
  endif
endif

.PHONY: build/CMakeCache.txt
build/CMakeCache.txt:
	$(MAKE) rebuild-cmake

install-pkgs: rebuild-cmake
	cmake --build build --target install-pkgs

test: install-pkgs rebuild-cmake
	cmake --build build --target check

rebuild-cmake:
	mkdir -p build
	cmake -B build -DCMAKE_BUILD_TYPE=Debug -DTOIT_EXEC="$(TOIT_EXEC)"

.PHONY: all test rebuild-cmake install-pkgs
