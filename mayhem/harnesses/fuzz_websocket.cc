// WebSocket frame length computation, header parsing/unmasking, encode (all length classes, flags, mask)
// and close-frame packing.
#include "common.h"
#include "swoole_websocket.h"
#include "swoole_string.h"

#include <cstring>
#include <string>

using namespace swoole;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    swoole_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 65536) {
        return -1;
    }
    const char *cdata = reinterpret_cast<const char *>(data);

    // length computation on the whole input and on truncated prefixes (need-more-data paths)
    for (size_t n : {size, (size_t) 2, (size_t) 4, (size_t) 6, (size_t) 10, (size_t) 14}) {
        if (n <= size) {
            PacketLength pl{cdata, static_cast<uint32_t>(n), 0};
            (void) websocket::get_package_length(nullptr, nullptr, &pl);
        }
    }

    // parse (no unmask) and decode (unmask) on separate copies
    websocket::Frame parsed;
    memset(&parsed, 0, sizeof(parsed));
    (void) websocket::parse_frame(&parsed, cdata, size);

    std::string copy(cdata, size);
    websocket::Frame frame;
    memset(&frame, 0, sizeof(frame));
    if (websocket::decode(&frame, &copy[0], copy.size())) {
        // re-encode the decoded frame with its own opcode and flags, masked and unmasked
        uint8_t flags = frame.get_flags();
        String out(frame.payload_length + 32);
        websocket::encode(&out, frame.payload, frame.payload_length, frame.header.OPCODE, flags);
        String out_masked(frame.payload_length + 32);
        websocket::encode(&out_masked, frame.payload, frame.payload_length, frame.header.OPCODE,
                          flags | websocket::FLAG_MASK);
        websocket::Frame again;
        memset(&again, 0, sizeof(again));
        if (out_masked.length > 0) {
            (void) websocket::decode(&again, out_masked.str, out_masked.length);
        }
    }

    // header-only encode with an arbitrary declared length reaches the 7-bit / 16-bit / 64-bit encodings
    // without allocating the payload
    if (size >= 10) {
        uint64_t declared;
        memcpy(&declared, data + 2, sizeof(declared));
        if (size >= 12 && (data[1] & 1)) {
            declared &= 0xFFFF;
        }
        uint8_t opcode = data[0] & 0xf;
        uint8_t flags = (data[1] >> 1) & (websocket::FLAG_FIN | websocket::FLAG_RSV1 | websocket::FLAG_MASK);
        String hdr(32);
        websocket::encode(&hdr, nullptr, declared, opcode, flags | websocket::FLAG_ENCODE_HEADER_ONLY);
    }

    // masking helper over every alignment of the input
    if (size >= 6) {
        std::string m(cdata + 4, size - 4);
        websocket::mask(&m[0], m.size(), cdata);
        websocket::mask(&m[0], m.size(), cdata);
    }

    // close frame with the first two bytes as code and the rest as reason (rejected above 123 bytes)
    String close_buf(size + 16);
    websocket::pack_close_frame(&close_buf, (data[0] << 8) | data[1], cdata + 2, size - 2, data[0] & websocket::FLAG_MASK);
    return 0;
}
