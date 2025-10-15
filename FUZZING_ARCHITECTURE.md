# iperf3 AFL Fuzzing Architecture

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         AFL++ Fuzzer                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Input Generation & Mutation                               │ │
│  │  - Mutate seed corpus                                      │ │
│  │  - Use dictionary for guided mutations                     │ │
│  │  - Track code coverage                                     │ │
│  └───────────────────────────┬────────────────────────────────┘ │
└────────────────────────────────┼───────────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │  AFL Shared Memory     │
                    │  __AFL_FUZZ_TESTCASE_  │
                    │         BUFFER         │
                    └────────────┬───────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    iperf3_fuzz Binary                            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  main() with __AFL_LOOP(UINT_MAX)                          │ │
│  │  - Persistent mode (reuse process)                         │ │
│  │  - Initialize test structure once                          │ │
│  │  - Reset state per iteration                               │ │
│  └───────────────────────────┬────────────────────────────────┘ │
│                               │                                  │
│  ┌────────────────────────────▼───────────────────────────────┐ │
│  │  iperf_fuzz_init_iteration()                               │ │
│  │  - Set __afl_fuzz_ptr to buffer start                      │ │
│  │  - Set __afl_fuzz_len to input length                      │ │
│  │  - Reset __afl_fuzz_pos to 0                               │ │
│  └───────────────────────────┬────────────────────────────────┘ │
│                               │                                  │
│  ┌────────────────────────────▼───────────────────────────────┐ │
│  │  iperf_run_server(test)                                    │ │
│  │  - Normal iperf server logic                               │ │
│  │  - State machine unchanged                                 │ │
│  └───────────────────────────┬────────────────────────────────┘ │
│                               │                                  │
│           ┌───────────────────┴───────────────────┐              │
│           │                                       │              │
│  ┌────────▼──────────┐                 ┌─────────▼────────────┐ │
│  │ Network Layer     │                 │  Protocol Layer      │ │
│  │ (src/net.c)       │                 │  (src/iperf_*.c)     │ │
│  │                   │                 │                      │ │
│  │ #ifdef FUZZING    │                 │  #ifdef FUZZING      │ │
│  ├───────────────────┤                 ├──────────────────────┤ │
│  │ Nrecv()           │◄────────────────│  accept()            │ │
│  │ ├─ fuzz_recv()    │                 │  └─ fake FD          │ │
│  │ Nwrite()          │                 │                      │ │
│  │ └─ return success │                 │  listen()            │ │
│  │                   │                 │  └─ fake FD          │ │
│  └───────┬───────────┘                 └──────────────────────┘ │
│          │                                                        │
│  ┌───────▼────────────────────────────────────────────────────┐ │
│  │  iperf_fuzz_read() / iperf_fuzz_recv()                     │ │
│  │  - Read from __afl_fuzz_ptr + __afl_fuzz_pos               │ │
│  │  - Increment __afl_fuzz_pos                                │ │
│  │  - Return data as if from network                          │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  Flow completes → AFL checks for crashes/hangs/coverage          │
│                → Next iteration begins                            │
└───────────────────────────────────────────────────────────────────┘
```

## Component Interaction

```
┌──────────────┐
│ Fuzzing Mode │
│   Enabled    │
└──────┬───────┘
       │
       ├─► Network Operations
       │   ├─ listen()  → Fake FD 1000
       │   ├─ accept()  → Fake FD 1001/1002
       │   ├─ select()  → Check fuzz buffer
       │   ├─ recv()    → iperf_fuzz_recv()
       │   ├─ read()    → iperf_fuzz_read()
       │   └─ write()   → Pretend success
       │
       ├─► State Machine
       │   ├─ IPERF_START
       │   ├─ PARAM_EXCHANGE
       │   ├─ CREATE_STREAMS
       │   ├─ TEST_START
       │   ├─ TEST_RUNNING
       │   ├─ TEST_END
       │   └─ IPERF_DONE
       │
       └─► Data Processing
           ├─ Cookie validation
           ├─ JSON parameter parsing
           ├─ Buffer management
           ├─ Statistics calculation
           └─ Result formatting
```

## File Descriptor Mapping

```
Normal Mode:
  Listener Socket:      socket() → Real FD (e.g., 3)
  Control Connection:   accept() → Real FD (e.g., 4)
  Stream Connection:    accept() → Real FD (e.g., 5)

Fuzzing Mode:
  Listener Socket:      Fake FD 1000 (no actual socket)
  Control Connection:   Fake FD 1001 (no actual socket)
  Stream Connection:    Fake FD 1002 (no actual socket)
  
  All I/O redirected to AFL shared memory buffer
```

## Code Coverage Strategy

```
┌─────────────────────────────────────┐
│     AFL Coverage Tracking           │
├─────────────────────────────────────┤
│                                     │
│  Each basic block instrumented:    │
│                                     │
│  prev_loc = cur_loc >> 1           │
│  map[prev_loc ^ cur_loc]++         │
│  prev_loc = cur_loc                │
│                                     │
│  Coverage bitmap tracks:           │
│  - Which code paths executed       │
│  - How many times (hit count)      │
│  - Edge transitions                │
│                                     │
│  New coverage → Keep input         │
│  No new coverage → Discard         │
└─────────────────────────────────────┘
```

## Persistent Mode Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│  Fork once                                                   │
│  ├─ AFL forks instrumented binary                           │
│  └─ Child process initialized                               │
└───────────┬─────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│  Initialization (outside loop)                               │
│  ├─ iperf_new_test()                                        │
│  ├─ iperf_defaults()                                        │
│  └─ Setup server configuration                              │
└───────────┬─────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│  __AFL_LOOP(UINT_MAX) - Run up to UINT_MAX iterations       │
│  ├─ AFL writes new test case to shared memory               │
│  ├─ iperf_fuzz_init_iteration()                             │
│  ├─ iperf_reset_test()                                      │
│  ├─ iperf_run_server()                                      │
│  ├─ AFL checks for crashes/coverage                         │
│  └─ Repeat...                                               │
└───────────┬─────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│  Exit after UINT_MAX iterations or crash                     │
│  └─ iperf_free_test()                                       │
└─────────────────────────────────────────────────────────────┘
```

## Build Modes Comparison

```
┌──────────────────┬─────────────────────┬─────────────────────┐
│    Aspect        │   Normal Build      │   Fuzzing Build     │
├──────────────────┼─────────────────────┼─────────────────────┤
│ Compiler         │ gcc/clang           │ afl-clang-fast      │
├──────────────────┼─────────────────────┼─────────────────────┤
│ Instrumentation  │ None                │ AFL edge coverage   │
├──────────────────┼─────────────────────┼─────────────────────┤
│ Network I/O      │ Real sockets        │ Mocked (AFL buffer) │
├──────────────────┼─────────────────────┼─────────────────────┤
│ FUZZING_BUILD... │ Not defined         │ Defined             │
├──────────────────┼─────────────────────┼─────────────────────┤
│ Binary name      │ iperf3              │ iperf3_fuzz         │
├──────────────────┼─────────────────────┼─────────────────────┤
│ Entry point      │ main() normal flow  │ main() with AFL loop│
├──────────────────┼─────────────────────┼─────────────────────┤
│ Use case         │ Production          │ Security testing    │
└──────────────────┴─────────────────────┴─────────────────────┘
```

## Memory Layout During Fuzzing

```
┌─────────────────────────────────────────────────────────────┐
│  Process Memory Map                                          │
├─────────────────────────────────────────────────────────────┤
│  Text Segment                                                │
│  ├─ Instrumented iperf3 code                                │
│  └─ AFL runtime library                                     │
├─────────────────────────────────────────────────────────────┤
│  Data Segment                                                │
│  ├─ struct iperf_test *test (persistent across iterations)  │
│  ├─ Global state                                            │
│  └─ AFL coverage bitmap                                     │
├─────────────────────────────────────────────────────────────┤
│  Heap                                                        │
│  ├─ iperf test structure                                    │
│  ├─ Stream structures                                       │
│  └─ Dynamically allocated buffers                           │
├─────────────────────────────────────────────────────────────┤
│  AFL Shared Memory                                           │
│  ├─ __AFL_FUZZ_TESTCASE_BUF (64KB default)                 │
│  │  ├─ __afl_fuzz_ptr → points here                        │
│  │  └─ __afl_fuzz_len = actual input size                  │
│  └─ Coverage bitmap shared with AFL parent                  │
├─────────────────────────────────────────────────────────────┤
│  Stack                                                       │
│  ├─ Call stack for current iteration                        │
│  └─ Local variables                                         │
└─────────────────────────────────────────────────────────────┘
```

This architecture ensures:
1. **Isolation**: Production code unaffected by fuzzing changes
2. **Efficiency**: Persistent mode minimizes overhead
3. **Coverage**: AFL tracks all executed code paths
4. **Safety**: Fake FDs prevent actual network operations
5. **Determinism**: Same input produces same execution path
