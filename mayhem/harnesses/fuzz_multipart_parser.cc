// The bundled multipart/form-data state machine, fed the body in two chunks with the boundary taken
// from the front of the input.
#include "common.h"
#include "multipart_parser.h"

#include <string>

static int on_data(multipart_parser *p, const char *at, size_t length) {
    static_cast<std::string *>(p->data)->append(at, length);
    return 0;
}
static int on_notify(multipart_parser *) {
    return 0;
}
static int on_data_cb(multipart_parser *, const char *, size_t) {
    return 0;
}

static const multipart_parser_settings settings = {
    on_data_cb, on_data_cb, on_notify, on_data, on_notify, on_notify, on_notify, on_notify,
};

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    swoole_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) {
        return -1;
    }
    size_t blen = (data[0] % 70) + 1;
    if (size < 1 + blen) {
        return -1;
    }
    const char *boundary = reinterpret_cast<const char *>(data) + 1;
    const char *body = boundary + blen;
    size_t body_len = size - 1 - blen;

    multipart_parser *p = multipart_parser_init(boundary, blen, &settings);
    if (!p) {
        return -1;
    }
    std::string collected;
    p->data = &collected;
    size_t half = body_len / 2;
    ssize_t n = multipart_parser_execute(p, body, half);
    if (n >= 0) {
        multipart_parser_execute(p, body + half, body_len - half);
    }
    char msg[256];
    (void) multipart_parser_error_msg(p, msg, sizeof(msg));
    (void) multipart_parser_is_complete(p);
    multipart_parser_free(p);
    return 0;
}
