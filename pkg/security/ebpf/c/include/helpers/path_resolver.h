#ifndef _HELPERS_PATH_RESOLVER_H_
#define _HELPERS_PATH_RESOLVER_H_

#include "maps.h"
#include "constants/custom.h"

int __attribute__((always_inline)) resolve_path(void *ctx, int dr_type) {
    if (dr_type == DR_KPROBE) {
        bpf_tail_call_compat(ctx, &path_resolver_kprobe_progs, PR_PROGKEY_ENTRYPOINT);
    } else if (dr_type == DR_TRACEPOINT) {
        bpf_tail_call_compat(ctx, &path_resolver_tracepoint_progs, PR_PROGKEY_ENTRYPOINT);
    }
    return 0;
}

void __attribute__((always_inline)) fill_path_ring_buffer_ref(struct pr_ring_buffer_ref_t *path_ref) {
    u32 zero = 0;
    struct pr_ring_buffer_ctx *ringbuf_ctx = bpf_map_lookup_elem(&pr_ringbuf_ctx, &zero);
    if (!ringbuf_ctx) {
        return;
    }
    path_ref->hash = ringbuf_ctx->hash;
    path_ref->len = ringbuf_ctx->len;
    path_ref->read_cursor = ringbuf_ctx->read_cursor;
    path_ref->cpu = ringbuf_ctx->cpu;
}

#endif
