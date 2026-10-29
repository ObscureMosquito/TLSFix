#ifndef TLSFIX_BACKPRESSURE_H
#define TLSFIX_BACKPRESSURE_H

#include <stddef.h>

// Retry only if the transport callback has accepted no bytes.
// The buffer and length remain unchanged for each attempt.
typedef struct {
    int status;
    size_t processed;
} TLSFixIOResult;

typedef int (*TLSFixIOAttempt)(void *, const void *, size_t, size_t *);
typedef unsigned long long (*TLSFixClock)(void *);
typedef void (*TLSFixWait)(void *, unsigned);

static TLSFixIOResult tlsfix_retry_transport_write(TLSFixIOAttempt attempt,
                                                     void *connection, const void *data,
                                                     size_t length, int wouldBlock,
                                                     unsigned budgetMillis,
                                                     TLSFixClock clock, TLSFixWait wait,
                                                     void *waitContext) {
    TLSFixIOResult result;
    result.processed = length;
    result.status = attempt(connection, data, length, &result.processed);
    if (result.processed || (result.status != wouldBlock && result.status != 0) ||
        !budgetMillis)
        return result;

    const unsigned long long started = clock(waitContext);
    unsigned waited = 0;
    unsigned delay = 2;
    for (unsigned retries = 0; retries < 128; retries++) {
        unsigned long long elapsed = clock(waitContext) - started;
        if (elapsed < waited) elapsed = waited;
        if (elapsed >= budgetMillis) break;

        const unsigned remaining = (unsigned)(budgetMillis - elapsed);
        const unsigned pause = delay < remaining ? delay : remaining;
        wait(waitContext, pause);
        waited += pause;
        result.processed = length;
        result.status = attempt(connection, data, length, &result.processed);
        if (result.processed || (result.status != wouldBlock && result.status != 0))
            break;
        if (delay < 16) delay *= 2;
    }
    return result;
}

#endif
