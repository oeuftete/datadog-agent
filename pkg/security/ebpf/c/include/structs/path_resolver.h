#ifndef _STRUCTS_PATH_RESOLVER_H_
#define _STRUCTS_PATH_RESOLVER_H_

#define PR_RING_BUFFER_SIZE 131072

struct path_ring_buffer {
    u64 write_cursor;
    char buffer[PR_RING_BUFFER_SIZE];
};

struct path_ring_buffer_ref {
    u64 hash;
    u64 len;
    u64 read_cursor;
    u32 cpu;
};

#endif