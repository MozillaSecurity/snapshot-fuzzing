#!/bin/bash
set -e
cd "$(dirname "$0")"

mkdir -p bin64/
mkdir -p sharedir/htools/

(cd ../../userspace-tools && sh compile_64.sh)
cp ../../userspace-tools/bin64/h* sharedir/htools/

make -B all

rm -f sharedir/ld_preload_fuzz.so sharedir/ld_preload_fuzz_no_pt.so
cp bin64/ld_preload_fuzz.so bin64/ld_preload_fuzz_no_pt.so sharedir/
