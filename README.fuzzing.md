# AFL Fuzzing for iperf3 Server

This directory contains modifications to enable AFL++ fuzzing of the iperf3 server in persistent mode.

## Overview

The fuzzing implementation intercepts network I/O operations and redirects them to read from AFL's shared memory buffer instead of actual network sockets. This allows AFL to efficiently fuzz the iperf server's protocol handling and data processing logic.

## Key Modifications

### Files Added

- `src/iperf_fuzz.c` - Main fuzzing harness implementing AFL persistent mode
- `src/iperf_fuzz.h` - Header file with fuzzing function declarations
- `Makefile.fuzz` - Makefile for building the fuzzing target
- `README.fuzzing.md` - This file

### Files Modified

- `src/net.c` - Network I/O functions wrapped with `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`
  - `Nrecv()` - Modified to read from AFL buffer instead of socket
  - `Nrecv_no_select()` - Modified to read from AFL buffer instead of socket

- `src/iperf_server_api.c` - Server functions modified for fuzzing
  - `iperf_server_listen()` - Bypasses actual socket listening, uses fake FD
  - `iperf_accept()` - Bypasses actual accept(), uses fake FD
  - Added include for `iperf_fuzz.h`

## Building

### Prerequisites

1. Install AFL++:
   ```bash
   git clone https://github.com/AFLplusplus/AFLplusplus
   cd AFLplusplus
   make
   sudo make install
   ```

2. Ensure iperf3 dependencies are installed (OpenSSL, etc.)

### Compile the Fuzzing Target

```bash
cd /home/janisozaur/workspace/iperf
make -f Makefile.fuzz
```

This will create the `iperf3_fuzz` binary compiled with AFL instrumentation and the fuzzing mode enabled.

## Running the Fuzzer

### Create Seed Corpus

```bash
make -f Makefile.fuzz seed
```

This creates a `fuzz_input/` directory with minimal seed inputs including:
- A valid iperf3 cookie (37 bytes)
- Test control messages

### Run AFL++

```bash
# Single core fuzzing
afl-fuzz -i fuzz_input -o fuzz_output -- ./iperf3_fuzz

# Multi-core fuzzing (recommended)
# Master instance
afl-fuzz -i fuzz_input -o fuzz_output -M fuzzer01 -- ./iperf3_fuzz

# Secondary instances (in separate terminals)
afl-fuzz -i- -o fuzz_output -S fuzzer02 -- ./iperf3_fuzz
afl-fuzz -i- -o fuzz_output -S fuzzer03 -- ./iperf3_fuzz
```

### Monitor Fuzzing Progress

AFL will display statistics including:
- `execs/sec` - Executions per second (should be high due to persistent mode)
- `stability` - Measure of determinism (should be ~100%)
- `crashes` - Number of unique crashes found
- `hangs` - Number of hanging inputs

## How It Works

### AFL Persistent Mode

The fuzzer uses AFL's persistent mode (`__AFL_LOOP(UINT_MAX)`) which:
1. Forks once and keeps the process alive
2. Runs the test harness thousands of times per fork
3. Achieves 10-20x speedup compared to forking for each test

### Data Flow

1. AFL generates mutated input and places it in shared memory
2. `iperf_fuzz_init_iteration()` initializes pointers to this buffer
3. When iperf server code calls `Nrecv()` or `read()`, it's redirected to `iperf_fuzz_read()`
4. `iperf_fuzz_read()` returns data from the AFL buffer instead of network
5. The server processes this data as if it came from a real client
6. The iteration completes and AFL mutates the input for the next run

### Fake Network Operations

In fuzzing mode:
- Socket listening is bypassed (fake FD 1000)
- Accept returns a fake FD (1001)
- All reads come from AFL buffer
- Writes are no-ops (data is discarded)
- select() and poll() always return "ready"

## Analyzing Crashes

When AFL finds a crash, it saves the input to `fuzz_output/crashes/`:

```bash
# Reproduce a crash
./iperf3_fuzz < fuzz_output/crashes/id:000000,sig:11,src:...

# Debug with GDB
gdb ./iperf3_fuzz
(gdb) run < fuzz_output/crashes/id:000000,sig:11,src:...
```

## Performance Tuning

### Expected Performance

With persistent mode, you should see:
- **10,000-50,000** execs/sec on modern hardware
- **~100%** stability (deterministic execution)

### If Performance Is Low

1. **Disable ASLR** (address space layout randomization):
   ```bash
   echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
   ```

2. **Use CPU governor**:
   ```bash
   echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
   ```

3. **Check for non-determinism**: If stability is low (<98%), the code may have:
   - Uninitialized memory reads
   - Time-dependent behavior
   - Non-deterministic algorithms

## Limitations

- Only fuzzes server-side code paths
- Network writes are discarded (can't fuzz bi-directional protocols fully)
- Some multi-threaded code paths may not be exercised
- SSL/TLS is not currently fuzzed (would need certificate handling)

## Safety

**IMPORTANT**: The fuzzing build is **NOT SAFE** for production use:
- `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` must be defined
- Never deploy fuzzing binaries to production
- Network operations are completely mocked
- Security features may be disabled for fuzzing efficiency

## Extending the Fuzzer

To fuzz additional code paths:

1. Add more seed inputs to `fuzz_input/` representing different protocol states
2. Modify `iperf_fuzz.c` to initialize different test configurations
3. Use AFL dictionaries to guide mutation toward valid protocol messages
4. Consider fuzzing UDP and SCTP protocols in addition to TCP

## Troubleshooting

### "No instrumentation detected"
- Make sure you're using `afl-clang-fast` or `afl-gcc`
- Check that AFL++ is properly installed

### Fuzzer hangs at startup
- Ensure seed corpus directory exists: `mkdir -p fuzz_input`
- Create at least one seed file
- Check file permissions

### Low exec/sec
- Verify persistent mode is working (check `__AFL_LOOP` in source)
- Profile with `afl-showmap` to check coverage
- Reduce initialization overhead outside the fuzzing loop

### Crashes don't reproduce
- Check for race conditions or time-dependent behavior
- Ensure same compilation flags are used
- Use `-d` flag with AFL for deterministic mode

## References

- [AFL++ Documentation](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/README.md)
- [Persistent Mode](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md)
- [iperf3 Protocol](https://github.com/esnet/iperf/blob/master/docs/dev.rst)
