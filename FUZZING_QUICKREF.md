# iperf3 AFL Fuzzing - Quick Reference Card

## Build Commands
```bash
./build_fuzzer.sh              # Build everything
make -f Makefile.fuzz          # Build fuzzer only
make -f Makefile.fuzz clean    # Clean build
make -f Makefile.fuzz seed     # Create seed corpus
```

## Fuzzing Commands
```bash
# Single instance
afl-fuzz -i fuzz_input -o fuzz_output -x iperf3.dict -- ./iperf3_fuzz

# Multi-core (master)
afl-fuzz -i fuzz_input -o fuzz_output -M fuzzer01 -x iperf3.dict -- ./iperf3_fuzz

# Multi-core (secondary)
afl-fuzz -i- -o fuzz_output -S fuzzer02 -x iperf3.dict -- ./iperf3_fuzz
```

## Monitoring
```bash
afl-whatsup fuzz_output        # Overall status
watch -n 1 afl-whatsup fuzz_output  # Auto-refresh
```

## Crash Analysis
```bash
# List crashes
ls -lh fuzz_output/crashes/

# Reproduce crash
./iperf3_fuzz < fuzz_output/crashes/id:000000,*

# Debug with GDB
gdb --args ./iperf3_fuzz
(gdb) run < fuzz_output/crashes/id:000000,*

# Get backtrace
(gdb) bt full

# Examine crash with ASan (rebuild needed)
CC="afl-clang-fast -fsanitize=address" make -f Makefile.fuzz
./iperf3_fuzz < crash_file
```

## System Optimization
```bash
# Core dumps (run once)
echo core | sudo tee /proc/sys/kernel/core_pattern

# CPU governor (run once)
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Disable ASLR (optional, helps determinism)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

## File Locations
```
iperf3_fuzz              - Fuzzing binary
fuzz_input/              - Seed corpus (initial test cases)
fuzz_output/             - AFL output directory
  ├─ crashes/            - Crashing inputs
  ├─ hangs/              - Hanging inputs
  ├─ queue/              - Interesting inputs (new coverage)
  └─ fuzzer_stats        - Statistics file
iperf3.dict              - Protocol dictionary
```

## Important Macros
```c
FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION  // Enable fuzzing mode
__AFL_LOOP(UINT_MAX)                      // Persistent mode loop
__AFL_FUZZ_TESTCASE_BUF                   // Input buffer
__AFL_FUZZ_TESTCASE_LEN                   // Input length
```

## Fake File Descriptors
```
1000 - Listener socket
1001 - Control connection
1002 - Stream connection
```

## AFL Status Indicators
```
execs/sec    : Executions per second (higher = better)
stability    : Determinism % (should be ~100%)
crashes      : Unique crashes found
hangs        : Unique hangs found
paths total  : Unique code paths discovered
pending      : Inputs not yet fully fuzzed
```

## Typical Performance
```
execs/sec:   10,000 - 50,000 (with persistent mode)
stability:   99-100% (deterministic)
CPU usage:   100% per fuzzer instance
Memory:      ~50-100 MB per instance
```

## Troubleshooting

### "No instrumentation detected"
- Use afl-clang-fast, not regular gcc/clang
- Check AFL++ installation

### Low execs/sec (<1000)
- Ensure persistent mode is working
- Check for I/O operations
- Profile with `afl-showmap`

### Low stability (<95%)
- Check for uninitialized memory
- Look for time-dependent code
- Verify deterministic behavior

### Fuzzer stops immediately
- Check seed corpus exists and is readable
- Verify binary has execute permissions
- Run `./test_fuzzer.sh` to diagnose

## Example Workflow
```bash
# 1. Build
./build_fuzzer.sh

# 2. Test
./test_fuzzer.sh

# 3. Optimize system
echo core | sudo tee /proc/sys/kernel/core_pattern
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# 4. Start fuzzing (3 instances)
# Terminal 1:
afl-fuzz -i fuzz_input -o fuzz_output -M fuzzer01 -x iperf3.dict -- ./iperf3_fuzz

# Terminal 2:
afl-fuzz -i- -o fuzz_output -S fuzzer02 -x iperf3.dict -- ./iperf3_fuzz

# Terminal 3:
afl-fuzz -i- -o fuzz_output -S fuzzer03 -x iperf3.dict -- ./iperf3_fuzz

# 5. Monitor (Terminal 4)
watch -n 1 afl-whatsup fuzz_output

# 6. After finding crashes
./iperf3_fuzz < fuzz_output/crashes/id:000000,*
gdb --args ./iperf3_fuzz
(gdb) run < fuzz_output/crashes/id:000000,*
```

## Advanced Options

### Dictionary-based fuzzing
```bash
afl-fuzz -x iperf3.dict ...   # Use protocol dictionary
```

### Deterministic mode
```bash
afl-fuzz -d ...                # Deterministic fuzzing
```

### Memory limit
```bash
afl-fuzz -m 200 ...            # 200 MB memory limit
```

### Timeout
```bash
afl-fuzz -t 1000 ...           # 1000ms timeout
```

### Skip deterministic
```bash
afl-fuzz -D ...                # Skip deterministic stage (faster)
```

## Documentation
- `README.fuzzing.md` - Full documentation
- `FUZZING_SUMMARY.md` - Implementation summary
- `FUZZING_ARCHITECTURE.md` - Architecture diagrams
- AFL++ docs: https://github.com/AFLplusplus/AFLplusplus

## Safety Reminder
⚠️ **NEVER** deploy fuzzing builds to production!
- They bypass network operations
- They use fake file descriptors
- They are instrumented for coverage
- They are built with FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
