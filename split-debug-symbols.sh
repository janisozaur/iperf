#!/bin/bash
clang -g -fxray-instrument -fxray-instruction-threshold=1 -Wall -g -o src/iperf3 src/iperf3-main.o  src/.libs/libiperf.a -lpthread -pthread
objcopy --only-keep-debug src/iperf3 src/iperf3.debug
objcopy --strip-debug src/iperf3
objcopy --add-gnu-debuglink=src/iperf3.debug src/iperf3
