// Drives swoole::http_server::Request the way the server's receive path does: request line,
// header terminator, header scan, chunked body framing and the multipart body parser, then the
// stand-alone URL-decode/cookie/boundary helpers on slices of the same input.
#include "common.h"
#include "swoole_http.h"
#include "swoole_server.h"
#include "swoole_string.h"

#include <cstdlib>
#include <string>

using namespace swoole;
using swoole::http_server::Request;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    swoole_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 65536) {
        return -1;
    }
    const char *tmp = getenv("TMPDIR");
    static Server serv(Server::MODE_BASE);
    serv.upload_tmp_dir = tmp ? tmp : "/tmp";

    {
        Request req;
        String buf(size + 1);
        buf.append(reinterpret_cast<const char *>(data), size);
        req.buffer_ = &buf;

        if (req.get_protocol() == SW_OK && req.method != SW_HTTP_PRI) {
            (void) req.has_expect_header();
            if (req.get_header_length() == SW_OK) {
                req.parse_header_info();
                if (req.chunked) {
                    (void) req.get_chunked_body_length();
                }
                if (req.form_data_ && req.init_multipart_parser(&serv)) {
                    String *body = req.buffer_;
                    (void) req.parse_multipart_data(body);
                }
                (void) req.get_header("content-type");
            }
        }
        // buffer_ may have been swapped by init_multipart_parser; the destructor restores it.
        if (req.form_data_) {
            req.destroy_multipart_parser();
        }
        req.buffer_ = nullptr;
    }

    std::string copy(reinterpret_cast<const char *>(data), size);
    http_server::url_decode(&copy[0], copy.size());
    http_server::parse_cookie(
        reinterpret_cast<const char *>(data), size, [](char *, size_t, char *, size_t) { return true; });
    char *boundary_str = nullptr;
    int boundary_len = 0;
    (void) http_server::parse_multipart_boundary(
        reinterpret_cast<const char *>(data), size, 0, &boundary_str, &boundary_len);
    size_t sp = copy.find(' ');
    if (sp != std::string::npos) {
        (void) http_server::get_method(copy.c_str(), sp);
    }
    return 0;
}
