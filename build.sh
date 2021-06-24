#!/bin/sh

set -e

(cd aya-template-bpf && cargo +nightly build --target=bpfel-unknown-none -Z build-std=core,alloc)

cargo build
