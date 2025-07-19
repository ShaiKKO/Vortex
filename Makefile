.PHONY: all build clean test install deps lint

all: build

build:
	dune build

clean:
	dune clean

test:
	dune runtest

install:
	dune install

deps:
	opam install . --deps-only --with-test --with-doc

lint:
	dune build @fmt --auto-promote

watch:
	dune build -w

doc:
	dune build @doc

utop:
	dune utop src

.DEFAULT_GOAL := build