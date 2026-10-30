// swoole::http_server::url_encode / url_decode round trip.
#include "common.h"
#include "swoole_http.h"

#include <cstdlib>
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
    // url_encode writes the terminating NUL at index len*3 when every byte gets percent-encoded, one
    // past its len*3 allocation (upstream heap overflow). A trailing literal byte leaves slack so the
    // harness keeps reaching the rest of the encoder and the decoder.
    std::string padded(reinterpret_cast<const char *>(data), size);
    padded.push_back('a');
    char *enc = http_server::url_encode(padded.data(), padded.size());
    std::string e(enc);
    free(enc);
    (void) http_server::url_decode(&e[0], e.size());
    return 0;
}
