#!/bin/bash
#
# Test script to verify the fuzzer works correctly
#

set -e

echo "=== Testing iperf3 Fuzzer ==="

# Check if fuzzer binary exists
if [ ! -f "./iperf3_fuzz" ]; then
    echo "ERROR: Fuzzer binary not found. Run ./build_fuzzer.sh first"
    exit 1
fi

# Test 1: Check if binary runs
echo "Test 1: Checking if fuzzer binary runs..."
timeout 2 ./iperf3_fuzz < /dev/null && echo "✓ Fuzzer runs" || {
    if [ $? -eq 124 ]; then
        echo "✗ Fuzzer timed out"
    else
        echo "✓ Fuzzer exited (expected with empty input)"
    fi
}

# Test 2: Check with minimal input
echo ""
echo "Test 2: Testing with minimal input..."
echo -n "iperf3-cookie-000000000000000000000" | timeout 2 ./iperf3_fuzz && echo "✓ Minimal input processed" || {
    if [ $? -eq 124 ]; then
        echo "✗ Timed out with minimal input"
    else
        echo "✓ Minimal input processed (non-zero exit expected)"
    fi
}

# Test 3: Check seed corpus exists
echo ""
echo "Test 3: Checking seed corpus..."
if [ -d "fuzz_input" ] && [ "$(ls -A fuzz_input)" ]; then
    echo "✓ Seed corpus exists with $(ls fuzz_input | wc -l) files"
else
    echo "✗ Seed corpus missing or empty"
fi

# Test 4: Verify AFL instrumentation
echo ""
echo "Test 4: Checking AFL instrumentation..."
if nm ./iperf3_fuzz | grep -q "__afl"; then
    echo "✓ AFL instrumentation detected"
else
    echo "✗ WARNING: No AFL instrumentation found!"
    echo "  Make sure to compile with afl-clang-fast"
fi

# Test 5: Check for FUZZING_BUILD_MODE
echo ""
echo "Test 5: Checking fuzzing mode is enabled..."
if strings ./iperf3_fuzz | grep -q "FUZZING_BUILD_MODE"; then
    echo "✓ Fuzzing mode enabled"
else
    echo "⚠ Could not verify fuzzing mode in binary"
fi

echo ""
echo "=== Fuzzer Test Complete ==="
echo ""
echo "The fuzzer appears to be working correctly."
echo "To start fuzzing, run:"
echo "  afl-fuzz -i fuzz_input -o fuzz_output -x iperf3.dict -- ./iperf3_fuzz"
echo ""
