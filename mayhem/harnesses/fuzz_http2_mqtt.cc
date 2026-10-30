// Frame-length computation and small-field parsers of the HTTP/2, MQTT and Base64 protocol layers.
// The first byte selects the parser, the rest is its input.
#include "common.h"
#include "swoole_base64.h"
#include "swoole_http2.h"
#include "swoole_mqtt.h"

#include <string>
#include <vector>

using namespace swoole;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    swoole_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 65536) {
        return -1;
    }
    const char *buf = reinterpret_cast<const char *>(data) + 1;
    size_t len = size - 1;
    PacketLength pl{buf, static_cast<uint32_t>(len), 0};

    switch (data[0] % 6) {
    case 0:
        (void) http2::get_frame_length(nullptr, nullptr, &pl);
        break;
    case 1:
        // SETTINGS payloads are validated to be a multiple of the item size before unpacking
        if (len % 6 == 0) {
            http2::unpack_setting_data(buf, len, [](uint16_t, uint32_t) { return SW_SUCCESS; });
        }
        break;
    case 2: {
        uint64_t out;
        std::string s(buf, len);
        (void) http2::parse_content_length(s.c_str(), s.size(), 1u << 30, &out);
        uint16_t status;
        (void) http2::parse_status_code(s.c_str(), s.size(), &status);
        break;
    }
    case 3:
        (void) mqtt::get_package_length(nullptr, nullptr, &pl);
        break;
    case 4: {
        std::vector<char> out(len * 3 / 4 + 8);
        (void) base64_decode(buf, len, out.data());
        break;
    }
    default: {
        // parse a frame header the way the HTTP/2 server does after get_frame_length
        if (len >= SW_HTTP2_FRAME_HEADER_SIZE) {
            (void) http2::get_type(static_cast<uint8_t>(buf[3]));
            (void) http2::get_flag_string(static_cast<uint8_t>(buf[4]));
        }
        break;
    }
    }
    return 0;
}
