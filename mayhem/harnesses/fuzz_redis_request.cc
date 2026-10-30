// swoole::redis::parse, the RESP request parser behind Swoole\Redis\Server.
#include "common.h"
#include "swoole_redis.h"

#include <string>

using namespace swoole;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    swoole_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > 65536) {
        return -1;
    }
    // the receive buffer is NUL terminated
    std::string nul_terminated(reinterpret_cast<const char *>(data), size);
    (void) redis::parse(nul_terminated.c_str(), nul_terminated.size());
    return 0;
}
