# iperf3 AFL Fuzzing Implementation - Complete Guide

## 🎯 Overview

This is a complete AFL++ fuzzing implementation for the iperf3 server that enables high-performance security testing using persistent mode fuzzing. All network I/O is intercepted and redirected to AFL's shared memory buffer, allowing the fuzzer to test protocol handling without actual network operations.

## 📁 What's Included

### Source Files (Production Code Modified)
- `src/iperf_fuzz.c` - Main fuzzing harness (NEW)
- `src/iperf_fuzz.h` - Fuzzing header declarations (NEW)
- `src/net.c` - Modified with `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`
- `src/iperf_server_api.c` - Modified with fuzzing hooks
- `src/iperf_tcp.c` - Modified with fuzzing hooks

### Build System
- `Makefile.fuzz` - Standalone makefile for fuzzing build (NEW)
- `iperf3.dict` - AFL dictionary with iperf3 protocol tokens (NEW)

### Scripts
- `build_fuzzer.sh` - Automated build script (NEW)
- `test_fuzzer.sh` - Validation and testing script (NEW)
- `start_fuzzing.sh` - Interactive quick-start guide (NEW)

### Documentation
- `README.fuzzing.md` - Comprehensive usage guide (NEW)
- `FUZZING_SUMMARY.md` - Implementation details (NEW)
- `FUZZING_ARCHITECTURE.md` - Architecture diagrams (NEW)
- `FUZZING_QUICKREF.md` - Quick reference card (NEW)
- `README_FUZZING.md` - This file (NEW)

## 🚀 Quick Start

### 1. Prerequisites
```bash
# Install AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make
sudo make install
```

### 2. Build the Fuzzer
```bash
cd /home/janisozaur/workspace/iperf
./build_fuzzer.sh
```

### 3. Start Fuzzing
```bash
./start_fuzzing.sh
# OR manually:
afl-fuzz -i fuzz_input -o fuzz_output -x iperf3.dict -- ./iperf3_fuzz
```

## 📚 Documentation Index

Choose your path based on what you need:

### 🆕 **New to Fuzzing?**
Start with: `README.fuzzing.md`
- Detailed explanations
- Step-by-step tutorial
- Troubleshooting guide

### 🏗️ **Want to Understand the Implementation?**
Read: `FUZZING_SUMMARY.md` and `FUZZING_ARCHITECTURE.md`
- File-by-file changes
- Architecture diagrams
- Design decisions

### ⚡ **Just Need Commands?**
Use: `FUZZING_QUICKREF.md`
- Command cheat sheet
- Quick reference
- Common workflows

### 🔧 **Want to Extend or Modify?**
Check: `FUZZING_SUMMARY.md` + source code comments
- Implementation details
- Integration points
- Extension ideas

## 🎮 Interactive Scripts

### `./build_fuzzer.sh`
Builds the fuzzing binary with all dependencies.
- Checks for AFL++ installation
- Compiles with instrumentation
- Creates seed corpus

### `./test_fuzzer.sh`
Validates the fuzzing setup.
- Tests binary execution
- Verifies AFL instrumentation
- Checks seed corpus

### `./start_fuzzing.sh`
Interactive fuzzing wizard.
- System optimization tips
- Command examples
- One-command startup

## 🔍 Key Features

### ✅ AFL Persistent Mode
- **10-20x faster** than traditional fuzzing
- Reuses process for multiple iterations
- Minimal initialization overhead

### ✅ Complete Network I/O Mocking
- All socket operations intercepted
- Fake file descriptors (1000, 1001, 1002)
- Reads from AFL shared memory
- Writes silently succeed

### ✅ Production-Safe
- All fuzzing code behind `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`
- Normal builds completely unaffected
- No runtime overhead in production

### ✅ Comprehensive Testing
- Protocol parsing
- State machine transitions
- Error handling
- Buffer management

## 📊 Expected Performance

```
Executions/sec:  10,000 - 50,000
Stability:       99-100% (deterministic)
CPU per core:    100%
Memory per core: 50-100 MB
```

## 🎯 What Gets Fuzzed

1. **Cookie validation** - Initial handshake
2. **Control messages** - Protocol state machine
3. **Parameter exchange** - JSON parsing
4. **Stream creation** - Connection setup
5. **Data handling** - Buffer management
6. **Error paths** - Malformed inputs
7. **Statistics** - Calculation logic

## 🛡️ Safety

### ⚠️ Critical Warning
**NEVER deploy fuzzing binaries to production!**

Fuzzing builds:
- Mock all network operations
- Use fake file descriptors
- Have AFL instrumentation overhead
- Are built with unsafe compiler flags

### ✅ Safe Practices
- Keep fuzzing builds in separate directory
- Use different binary name (`iperf3_fuzz` vs `iperf3`)
- Never install fuzzing builds system-wide
- Always use `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`

## 🔬 Example Workflow

```bash
# Build and validate
./build_fuzzer.sh
./test_fuzzer.sh

# Optimize system
echo core | sudo tee /proc/sys/kernel/core_pattern
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Start fuzzing (3 parallel instances)
# Terminal 1 (master):
afl-fuzz -i fuzz_input -o fuzz_output -M fuzzer01 -x iperf3.dict -- ./iperf3_fuzz

# Terminal 2 (secondary):
afl-fuzz -i- -o fuzz_output -S fuzzer02 -x iperf3.dict -- ./iperf3_fuzz

# Terminal 3 (secondary):
afl-fuzz -i- -o fuzz_output -S fuzzer03 -x iperf3.dict -- ./iperf3_fuzz

# Terminal 4 (monitoring):
watch -n 1 afl-whatsup fuzz_output

# When crashes are found:
./iperf3_fuzz < fuzz_output/crashes/id:000000,sig:11,src:000000,time:1234,op:havoc
gdb --args ./iperf3_fuzz
(gdb) run < fuzz_output/crashes/id:000000,*
(gdb) bt full
```

## 🐛 Finding and Fixing Bugs

### Reproduce a Crash
```bash
./iperf3_fuzz < fuzz_output/crashes/id:000000,*
```

### Debug with GDB
```bash
gdb --args ./iperf3_fuzz
(gdb) run < fuzz_output/crashes/id:000000,*
(gdb) bt full
(gdb) print variable_name
```

### Use AddressSanitizer
```bash
# Rebuild with ASAN
CC="afl-clang-fast -fsanitize=address" make -f Makefile.fuzz clean all
./iperf3_fuzz < crash_file
```

### Minimize Crashing Input
```bash
afl-tmin -i crash_file -o minimized_crash -- ./iperf3_fuzz
```

## 📈 Monitoring Progress

### Real-time Status
```bash
afl-whatsup fuzz_output
```

### Key Metrics
- **execs/sec**: Higher is better (target: >10,000)
- **stability**: Should be ~100%
- **crashes**: Unique crashes found
- **paths total**: Code coverage expansion

## 🔧 Troubleshooting

### Issue: "No instrumentation detected"
**Solution**: Use `afl-clang-fast`, not regular `gcc`

### Issue: Low exec/sec (<1000)
**Solution**: 
- Verify persistent mode is working
- Check system optimization
- Ensure no actual I/O happening

### Issue: Low stability (<95%)
**Solution**:
- Check for uninitialized memory
- Look for time-dependent code
- Verify fuzzing mode is enabled

### Issue: Fuzzer exits immediately
**Solution**:
- Run `./test_fuzzer.sh` to diagnose
- Check seed corpus exists
- Verify binary has execute permission

## 🎓 Learning Resources

### AFL++ Documentation
- https://github.com/AFLplusplus/AFLplusplus
- https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/

### iperf3 Protocol
- https://github.com/esnet/iperf
- `docs/dev.rst` in iperf repository

### Fuzzing Best Practices
- https://github.com/google/fuzzing
- https://owasp.org/www-community/Fuzzing

## 🤝 Contributing

If you improve this fuzzing implementation:
1. Test thoroughly
2. Update documentation
3. Ensure production code remains safe
4. Submit PR with detailed description

## 📝 License

This fuzzing implementation follows iperf3's BSD license.

## ✨ Summary

You now have a complete, production-ready AFL fuzzing setup for iperf3 that:
- ✅ Uses persistent mode for maximum speed
- ✅ Mocks all network operations safely
- ✅ Includes comprehensive documentation
- ✅ Provides helper scripts for easy use
- ✅ Maintains production code safety
- ✅ Follows fuzzing best practices

**Start fuzzing and find those bugs! 🐛🔍**

---

**Questions or issues?** Check the documentation files or create an issue.

**Happy Fuzzing! 🎉**
