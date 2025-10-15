/*
 * iperf AFL fuzzing harness
 * 
 * This file implements AFL persistent mode fuzzing for iperf server.
 * It intercepts network I/O and feeds AFL-generated data instead.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>

#include "iperf_config.h"
#include "iperf.h"
#include "iperf_api.h"

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

/* AFL persistent mode buffer */
__AFL_FUZZ_INIT();

/* Global fuzzing state */
static unsigned char *fuzz_buf = NULL;
static int fuzz_len = 0;
static size_t fuzz_poz = 0;

/* Initialize fuzzing buffer for this iteration */
void iperf_fuzz_init_iteration(void) {
    fuzz_buf = __AFL_FUZZ_TESTCASE_BUF;
    fuzz_len = __AFL_FUZZ_TESTCASE_LEN;
    fuzz_poz = 0;
}

/* Get data from fuzzing buffer instead of network */
ssize_t iperf_fuzz_read(int fd, void *buf, size_t count) {
    (void)fd; /* Unused in fuzzing mode */
    
    if (fuzz_poz >= fuzz_len) {
        return 0; /* EOF */
    }
    
    size_t available = fuzz_len - fuzz_poz;
    size_t to_copy = (count < available) ? count : available;
    
    memcpy(buf, fuzz_buf + fuzz_poz, to_copy);
    fuzz_poz += to_copy;
    
    return (ssize_t)to_copy;
}

/* Mock recv for fuzzing */
ssize_t iperf_fuzz_recv(int fd, void *buf, size_t count, int flags) {
    (void)flags; /* Ignore flags in fuzzing mode */
    return iperf_fuzz_read(fd, buf, count);
}

/* Check if there's more data available */
int iperf_fuzz_has_data(void) {
    return fuzz_poz < fuzz_len;
}

/* Reset position for re-reading */
void iperf_fuzz_reset_pos(void) {
    fuzz_poz = 0;
}

/* Get remaining data size */
size_t iperf_fuzz_remaining(void) {
    if (fuzz_poz >= fuzz_len) {
        return 0;
    }
    return fuzz_len - fuzz_poz;
}

/* Main fuzzing entry point */
int main(int argc, char **argv) {
    struct iperf_test *test;
    int rc;

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    /* Initialize test once outside the loop */
    test = iperf_new_test();
    if (!test) {
        fprintf(stderr, "Failed to create iperf test\n");
        return 1;
    }
    
    /* Set up server defaults */
    iperf_defaults(test);
    test->role = 's';
    test->server_port = 5201; /* Use fake port */
    
    /* Disable JSON output and verbose for fuzzing */
    test->json_output = 0;
    test->verbose = 0;
    test->debug = 0;
    test->debug_level = 0;
    
    /* Set one-off mode to exit after one connection */
    iperf_set_test_one_off(test, 1);
    
    /* Disable features that may cause issues in fuzzing */
    test->no_delay = 1;
    test->settings->rcv_timeout.secs = 1;
    test->settings->rcv_timeout.usecs = 0;

    /* AFL persistent mode loop */
    while (__AFL_LOOP(UINT_MAX)) {
        /* Initialize fuzzing buffer for this iteration */
        iperf_fuzz_init_iteration();
        
        /* Skip if input is too small */
        if (fuzz_len < 37) { /* Minimum: cookie(37) */
            continue;
        }
        
        /* Reset test state for new iteration */
        iperf_reset_test(test);
        test->role = 's';
        
        /* Run the server with fuzzed input
         * In fuzzing mode, this will process data from AFL buffer
         * instead of actual network I/O
         */
        rc = iperf_run_server(test);
        
        /* Ignore return code - we just want to test for crashes */
        (void)rc;
    }
    
    /* Cleanup */
    iperf_free_test(test);
    
    return 0;
}

#else /* !FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */

/* If not fuzzing, provide empty main that errors */
int main(void) {
    fprintf(stderr, "This binary must be compiled with -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION\n");
    return 1;
}

#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
