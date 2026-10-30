#pragma once
#include "swoole.h"
#include "swoole_log.h"

// One-time library setup shared by every harness; silences the library's own logging.
static inline void swoole_fuzz_init() {
    static bool done = false;
    if (done) {
        return;
    }
    done = true;
    swoole_init();
    swoole_set_log_level(SW_LOG_NONE);
}
