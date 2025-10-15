#!/bin/bash
#
# Quick start script for fuzzing iperf3 server
#

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         iperf3 AFL Fuzzing - Quick Start Guide               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Check AFL++ installation
echo "Step 1/5: Checking AFL++ installation..."
if command -v afl-fuzz &> /dev/null; then
    echo "✓ AFL++ is installed: $(afl-fuzz --version 2>&1 | head -n1)"
else
    echo "✗ AFL++ is not installed!"
    echo ""
    echo "Please install AFL++:"
    echo "  git clone https://github.com/AFLplusplus/AFLplusplus"
    echo "  cd AFLplusplus"
    echo "  make"
    echo "  sudo make install"
    exit 1
fi

# Step 2: Build the fuzzer
echo ""
echo "Step 2/5: Building the fuzzer..."
if [ -f "./iperf3_fuzz" ]; then
    echo "✓ Fuzzer binary already exists"
else
    if [ -x "./build_fuzzer.sh" ]; then
        ./build_fuzzer.sh
    else
        echo "✗ build_fuzzer.sh not found or not executable"
        exit 1
    fi
fi

# Step 3: Create seed corpus
echo ""
echo "Step 3/5: Setting up seed corpus..."
if [ -d "fuzz_input" ] && [ "$(ls -A fuzz_input 2>/dev/null)" ]; then
    echo "✓ Seed corpus exists with $(ls fuzz_input | wc -l) files"
else
    make -f Makefile.fuzz seed
fi

# Step 4: System optimization suggestions
echo ""
echo "Step 4/5: System optimization recommendations..."
echo ""
echo "For better performance, run these commands (requires sudo):"
echo ""
echo "  # Disable core dumps (prevents slow core file writing)"
echo "  echo core | sudo tee /proc/sys/kernel/core_pattern"
echo ""
echo "  # Use performance CPU governor"
echo "  echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"
echo ""
echo "  # Disable address space randomization (optional, helps with determinism)"
echo "  echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"
echo ""

read -p "Apply these optimizations now? (y/N) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Applying optimizations..."
    echo core | sudo tee /proc/sys/kernel/core_pattern > /dev/null
    echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null
    echo "✓ Optimizations applied"
fi

# Step 5: Start fuzzing
echo ""
echo "Step 5/5: Ready to fuzz!"
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Fuzzing Commands                           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Single-core fuzzing:"
echo "  afl-fuzz -i fuzz_input -o fuzz_output -x iperf3.dict -- ./iperf3_fuzz"
echo ""
echo "Multi-core fuzzing (recommended):"
echo "  # Terminal 1 (master):"
echo "  afl-fuzz -i fuzz_input -o fuzz_output -M fuzzer01 -x iperf3.dict -- ./iperf3_fuzz"
echo ""
echo "  # Terminal 2 (secondary):"
echo "  afl-fuzz -i- -o fuzz_output -S fuzzer02 -x iperf3.dict -- ./iperf3_fuzz"
echo ""
echo "  # Terminal 3 (secondary):"
echo "  afl-fuzz -i- -o fuzz_output -S fuzzer03 -x iperf3.dict -- ./iperf3_fuzz"
echo ""
echo "Monitor fuzzing:"
echo "  watch -n 1 afl-whatsup fuzz_output"
echo ""
echo "Reproduce a crash:"
echo "  ./iperf3_fuzz < fuzz_output/crashes/id:000000,*"
echo ""
echo "Debug a crash with GDB:"
echo "  gdb --args ./iperf3_fuzz"
echo "  (gdb) run < fuzz_output/crashes/id:000000,*"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""

read -p "Start fuzzing now? (y/N) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting AFL fuzzer..."
    afl-fuzz -i fuzz_input -o fuzz_output -x iperf3.dict -- ./iperf3_fuzz
fi
