CARGO_PACKAGE_NAME=pe-parser

CARGO_BUILD_FLAGS+=--package pe-parser

ifdef NDEBUG
CARGO_BUILD_PROFILE=release
CARGO_BUILD_FLAGS+=--release
else
CARGO_BUILD_PROFILE=debug
endif

all: pe-parser

clean:
	cargo clean
	-rm pe-parser

.PHONY: all, clean, validation-pe-tests, import-dll-tests, import-function-tests

pe-parser:
	cargo build $(CARGO_BUILD_FLAGS)
	cp target/$(CARGO_BUILD_PROFILE)/$(CARGO_PACKAGE_NAME) pe-parser

validation-pe-tests: all
	python3 -m tests ValidatingPeTestCases -f

import-dll-tests: all
	python3 -m tests ImportDllTestCases -f

import-function-tests: all
	python3 -m tests ImportFunctionTestCases -f
