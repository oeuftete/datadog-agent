#ifndef __GRPC_HELPERS_H
#define __GRPC_HELPERS_H

#include "bpf_builtins.h"

#include "protocols/grpc/defs.h"
#include "protocols/grpc/maps_defs.h"
#include "protocols/http2/helpers.h"

// The maximum number of headers which we process in the request.
#define GRPC_MAX_HEADERS_COUNT 20
// The maximum of frames we check for headers frame
#define GRPC_MAX_FRAMES_TO_PROCESS 5
// Static index for the content-type key
#define CONTENT_TYPE_IDX 31

#define consume_bytes(Buf, Size, N) \
    do {                            \
        (Buf) += (N);               \
        (Size) -= (N);              \
    } while (0);

// Huffman-encoded application/grpc
static const __u8 grpc_content_type[] = { 0x1d, 0x75, 0xd0, 0x62, 0x0d, 0x26, 0x3d, 0x4c, 0x4d, 0x65, 0x64 };

static __always_inline enum grpc_classification_status check_literal(const char **buf, __u32 *size, __u8 idx) {
    if (!*size) {
        return GRPC_UNKNOWN;
    }

    // Indexed name
    if (idx) {
        struct hpack_length len = **((struct hpack_length **)buf);
        if (len.length > *size) {
            consume_bytes(*buf, *size, *size);
            return GRPC_UNKNOWN;
        }

        bool is_grpc = false;

        if (len.length >= sizeof(grpc_content_type)) {
            // TODO: handle case where content-type is not huffman encoded
            is_grpc = !bpf_memcmp((*buf) + 1, grpc_content_type, sizeof(grpc_content_type));
        }

        consume_bytes(*buf, *size, 1 + len.length);
        return is_grpc ? GRPC_GRPC : GRPC_NOT_GRPC;
    }

    // TODO :method not POST or GET case

    return GRPC_UNKNOWN;
}

// filter_headers_frame tries to find the header fields necessary for the
// classification. Those are the Method and the Content-type fields.
static __always_inline enum grpc_classification_status parse_headers(struct http2_frame *frame, const char *buf, __u32 size) {
    if (size == 0) {
        return GRPC_UNKNOWN;
    }

    enum grpc_classification_status status = GRPC_UNKNOWN;

#pragma unroll(GRPC_MAX_HEADERS_COUNT)
    for (__u8 i = 0; i < GRPC_MAX_HEADERS_COUNT; ++i) {
        union field_index idx = { .raw = *buf };
        consume_bytes(buf, size, 1);

        if (is_indexed(idx.raw)) {
            // TODO: Check if POST or GET
            // Size: 1; no change to buf and size here
            continue;
        } else if (is_literal(idx.raw)) {
            status = check_literal(&buf, &size, idx.literal.index);
            if (status != GRPC_UNKNOWN)
                break;
        } else {
            continue;
        }
    }

    return status;
}

static __always_inline enum grpc_classification_status parse_frames(const char *buf, __u32 size) {
    struct http2_frame current_frame;

#pragma unroll(GRPC_MAX_FRAMES_TO_PROCESS)
    for (__u8 i = 0; i < GRPC_MAX_FRAMES_TO_PROCESS; ++i) {
        if (!read_http2_frame_header(buf, size, &current_frame)) {
            log_debug("[http2] unable to read_http2_frame_header\n");
            return GRPC_UNKNOWN;
        }

        consume_bytes(buf, size, HTTP2_FRAME_HEADER_SIZE);

        if (current_frame.type == kHeadersFrame) {
            break;
        }

        if (size <= current_frame.length) {
            // We have reached the end of the buffer
            return GRPC_UNKNOWN;
        }

        consume_bytes(buf, size, current_frame.length);
    }

    return parse_headers(&current_frame, buf, size);
}

#endif /* __GRPC_HELPERS_H */
