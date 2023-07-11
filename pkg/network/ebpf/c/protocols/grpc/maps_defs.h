#ifndef __GRPC_MAPS_DEFS_H
#define __GRPC_MAPS_DEFS_H

#include "protocols/http2/decoding-defs.h"

// We need at most two entries: one for the method, on for the content-type.
#define GRPC_MAX_HEADERS_COUNT_FOR_PROCESSING 2

BPF_PERCPU_ARRAY_MAP(grpc_headers_to_process, __u32, http2_header_t[GRPC_MAX_HEADERS_COUNT_FOR_PROCESSING], 1)

#endif
