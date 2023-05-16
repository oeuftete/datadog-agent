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

void __attribute__((always_inline)) fill_path_ring_buffer_ref(struct path_ring_buffer_ref *event_path_ref) {
    u32 zero = 0;
    struct path_ring_buffer_ref *path_ref = bpf_map_lookup_elem(&path_refs, &zero);
    if (!path_ref) {
        return;
    }
    bpf_probe_read(event_path_ref, sizeof(struct path_ring_buffer_ref), path_ref);
}

#endif
