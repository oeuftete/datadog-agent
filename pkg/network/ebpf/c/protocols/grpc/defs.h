#ifndef __GRPC_DEFS_H
#define __GRPC_DEFS_H

#include "bpf_builtins.h"

/* grpc_classification_status represents the result of the classification. */
enum grpc_classification_status
{
    GRPC_UNKNOWN = 0,
    GRPC_NOT_GRPC,
    GRPC_GRPC,
};

/* Header parsing helper macros */
#define is_indexed(x) ((x) & (1 << 7))
#define is_literal(x) ((x) & (1 << 6))

/* Header parsing helper structs */

union field_index {
    struct {
        __u8 index : 7;
        __u8 reserved : 1;
    } __attribute__((packed)) indexed;
    struct {
        __u8 index : 6;
        __u8 reserved : 2;
    } __attribute__((packed)) literal;
    __u8 raw;
} __attribute__((packed));

struct hpack_length {
    __u8 length : 7;
    __u8 is_huffman : 1;
} __attribute__((packed));

#endif
