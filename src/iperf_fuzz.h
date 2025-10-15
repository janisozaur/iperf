/*
 * iperf AFL fuzzing header
 * 
 * Declarations for fuzzing mode hooks
 */

#ifndef __IPERF_FUZZ_H
#define __IPERF_FUZZ_H

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

#include <sys/types.h>

/* Initialize fuzzing buffer for new iteration */
void iperf_fuzz_init_iteration(void);

/* Fuzzing replacements for network I/O */
ssize_t iperf_fuzz_read(int fd, void *buf, size_t count);
ssize_t iperf_fuzz_recv(int fd, void *buf, size_t count, int flags);

/* Fuzzing buffer state queries */
int iperf_fuzz_has_data(void);
void iperf_fuzz_reset_pos(void);
size_t iperf_fuzz_remaining(void);

#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */

#endif /* __IPERF_FUZZ_H */
