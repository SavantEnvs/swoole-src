// The bundled hiredis reply reader and swoole's RESP number parser.
#include "common.h"
#include "swoole_redis.h"

extern "C" {
#include "hiredis/hiredis.h"
#include "hiredis/read.h"
}

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
    // the parsers rely on the receive buffer being NUL terminated
    std::string nul_terminated(reinterpret_cast<const char *>(data), size);
    int number;
    (void) redis::get_number(nul_terminated.c_str(), &number);

    redisReader *reader = redisReaderCreate();
    if (reader == nullptr) {
        return -1;
    }
    // hiredis sizes an aggregate from its "*<n>" header alone, so a 5-byte input can request a multi-GB
    // allocation and trip libFuzzer's malloc limit; cap it like a real client would.
    reader->maxelements = 4096;
    redisReaderFeed(reader, reinterpret_cast<const char *>(data), size);
    void *reply = nullptr;
    while (redisReaderGetReply(reader, &reply) == REDIS_OK && reply != nullptr) {
        freeReplyObject(reply);
        reply = nullptr;
    }
    redisReaderFree(reader);
    return 0;
}
