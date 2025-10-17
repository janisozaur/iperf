#!/bin/bash
pushd src
clang -g -fxray-instrument -fxray-instruction-threshold=1 -Wall -g -o iperf3 iperf3-main.o  .libs/libiperf.a -lpthread -pthread
objcopy --only-keep-debug iperf3 iperf3.debug
objcopy --strip-debug iperf3
objcopy --add-gnu-debuglink=iperf3.debug iperf3
popd
mkdir -p debugsymbols
mv src/iperf3.debug debugsymbols/
