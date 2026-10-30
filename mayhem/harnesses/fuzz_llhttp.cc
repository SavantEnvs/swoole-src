// The bundled llhttp parser in both request and response mode, fed in two chunks the way a socket would.
#include "common.h"
#include "swoole_llhttp.h"

static int data_cb(llhttp_t *, const char *, size_t) {
    return 0;
}
static int notify_cb(llhttp_t *) {
    return 0;
}

static const llhttp_settings_t settings = {
    notify_cb, data_cb,   data_cb,   data_cb,   data_cb,   data_cb,   data_cb,   data_cb,   data_cb,
    data_cb,   notify_cb, data_cb,   notify_cb, notify_cb, notify_cb, notify_cb, notify_cb, notify_cb,
    notify_cb, notify_cb, notify_cb, notify_cb, notify_cb, notify_cb, notify_cb,
};

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    swoole_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return -1;
    }
    const char *buf = reinterpret_cast<const char *>(data) + 1;
    size_t len = size - 1;
    llhttp_type_t type = (data[0] & 1) ? HTTP_RESPONSE : HTTP_REQUEST;

    llhttp_t parser;
    swoole_llhttp_parser_init(&parser, type, nullptr);
    size_t half = len / 2;
    size_t n = swoole_llhttp_parser_execute(&parser, &settings, buf, half);
    if (n == half) {
        swoole_llhttp_parser_execute(&parser, &settings, buf + half, len - half);
    }
    (void) llhttp_get_http_major(&parser);
    (void) llhttp_get_method(&parser);
    (void) llhttp_should_keep_alive(&parser);
    llhttp_finish(&parser);
    return 0;
}
