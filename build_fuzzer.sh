#!/bin/bash
#
# Build script for iperf3 AFL fuzzer
#

set -e

echo "=== Building iperf3 AFL Fuzzer ==="

# Check if AFL++ is installed
if ! command -v afl-clang-fast &> /dev/null; then
    echo "ERROR: afl-clang-fast not found. Please install AFL++:"
    echo "  git clone https://github.com/AFLplusplus/AFLplusplus"
    echo "  cd AFLplusplus && make && sudo make install"
    exit 1
fi

# Clean previous build
echo "Cleaning previous build..."
make -f Makefile.fuzz clean 2>/dev/null || true

# Build the fuzzer
echo "Building fuzzer..."
make -f Makefile.fuzz

# Create seed corpus if it doesn't exist
if [ ! -d "fuzz_input" ]; then
    echo "Creating seed corpus..."
    make -f Makefile.fuzz seed
fi

echo ""
echo "=== Build Complete ==="
echo ""
echo "Fuzzer binary: ./iperf3_fuzz"
echo "Seed corpus: ./fuzz_input/"
echo ""
echo "To run the fuzzer:"
echo "  afl-fuzz -i fuzz_input -o fuzz_output -- ./iperf3_fuzz"
echo ""
echo "For better performance, consider:"
echo "  echo core | sudo tee /proc/sys/kernel/core_pattern"
echo "  echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"
echo ""
