#ifndef _STRUCTS_PATH_RESOLVER_H_
#define _STRUCTS_PATH_RESOLVER_H_

#define PR_RING_BUFFER_SIZE 131072

struct pr_ring_buffer {
    char buffer[PR_RING_BUFFER_SIZE];
};

// struct stored in per-cpu map
struct pr_ring_buffer_ctx {
    u64 hash;
    u64 len;
    u64 read_cursor;
    u64 write_cursor;
    u32 cpu;
};

// struct used by events structs
struct pr_ring_buffer_ref_t {
    u64 hash;
    u64 len;
    u64 read_cursor;
    u32 cpu;
    u32 padding;
};

#endif