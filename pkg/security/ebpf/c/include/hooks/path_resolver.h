#ifndef _HOOKS_PATH_RESOLVER_H_
#define _HOOKS_PATH_RESOLVER_H_

#include "maps.h"
#include "constants/custom.h"

#define PR_MAX_SEGMENT_LENGTH 255
#define PR_MAX_ITERATION_DEPTH 8
#define PR_MAX_TAIL_CALL 28

#define FNV_OFFSET_BASIS    ((__u64)14695981039346656037U)
#define FNV_PRIME           ((__u64)1099511628211U)

struct dentry_name {
    char name[PR_MAX_SEGMENT_LENGTH + 1];
};

int __attribute__((always_inline)) resolve_path_tail_call(void *ctx, struct dentry_resolver_input_t *input) {
    u32 zero = 0;
    struct path_key_t key = input->key;
    struct path_key_t next_key = input->key;
    struct qstr qstr;
    struct dentry *dentry = input->dentry;
    struct dentry *d_parent = NULL;
    struct dentry_name dname = {0};

    if (key.ino == 0) {
        return DENTRY_INVALID;
    }

    struct pr_ring_buffer_ctx *ringbuf_ctx = bpf_map_lookup_elem(&pr_ringbuf_ctx, &zero);
    if (!ringbuf_ctx) {
        return DENTRY_ERROR;
    }

    u32 cpu = bpf_get_smp_processor_id();
    struct pr_ring_buffer *rb = bpf_map_lookup_elem(&pr_ringbufs, &cpu);
    if (!rb) {
        return DENTRY_ERROR;
    }

    struct is_discarded_by_inode_t *params = bpf_map_lookup_elem(&is_discarded_by_inode_gen, &zero);
    if (!params) {
        return DENTRY_ERROR;
    }
    *params = (struct is_discarded_by_inode_t){
        .discarder_type = input->discarder_type,
        .now = bpf_ktime_get_ns(),
    };

    u64 write_cursor = ringbuf_ctx->write_cursor;

#pragma unroll
    for (int i = 0; i < PR_MAX_ITERATION_DEPTH; i++) {
        bpf_probe_read(&d_parent, sizeof(d_parent), &dentry->d_parent);

        key = next_key;
        if (dentry != d_parent) {
            next_key.ino = get_dentry_ino(d_parent);
        } else {
            next_key.ino = 0;
            next_key.mount_id = 0;
        }

        if (input->discarder_type && i <= 3) {
            params->discarder.path_key.ino = key.ino;
            params->discarder.path_key.mount_id = key.mount_id;
            params->discarder.is_leaf = i == 0;

            if (is_discarded_by_inode(params)) {
                if (input->flags & ACTIVITY_DUMP_RUNNING) {
                    input->flags |= SAVED_BY_ACTIVITY_DUMP;
                } else {
                    return DENTRY_DISCARDED;
                }
            }
        }

        bpf_probe_read(&qstr, sizeof(qstr), &dentry->d_name);
        long len = bpf_probe_read_str(&dname.name, sizeof(dname.name), (void *)qstr.name);
        if (dname.name[0] == 0) {
            return DENTRY_ERROR;
        }
        len -= 1; // do not process trailing zero

        if (dname.name[0] == '/') {
            if (ringbuf_ctx->len == 0) {
                ringbuf_ctx->hash ^= dname.name[0];
                ringbuf_ctx->hash *= FNV_PRIME;
                rb->buffer[write_cursor++ % PR_RING_BUFFER_SIZE] = dname.name[0];
                ringbuf_ctx->len += 1;
            }
            // mark the path resolution as complete which will stop the tail calls
            input->key.ino = 0;
            ringbuf_ctx->write_cursor = write_cursor % PR_RING_BUFFER_SIZE;
            return i + 1;
        }

#pragma unroll
        for (int j = 0; j < PR_MAX_SEGMENT_LENGTH; j++) {
            ringbuf_ctx->hash ^= dname.name[j];
            ringbuf_ctx->hash *= FNV_PRIME;
            rb->buffer[write_cursor++ % PR_RING_BUFFER_SIZE] = dname.name[j];
            if (j == (len - 1))
                break;
        }
        ringbuf_ctx->hash ^= '/';
        ringbuf_ctx->hash *= FNV_PRIME;
        rb->buffer[write_cursor++ % PR_RING_BUFFER_SIZE] = '/';
        ringbuf_ctx->len += len + 1;

        dentry = d_parent;
    }

    if (input->iteration == PR_MAX_TAIL_CALL) {
        return DENTRY_ERROR;
    }

    // prepare for the next iteration
    input->dentry = d_parent;
    input->key = next_key;
    ringbuf_ctx->write_cursor = write_cursor % PR_RING_BUFFER_SIZE;
    return PR_MAX_ITERATION_DEPTH;
}

#define path_resolver_loop(ctx, pr_progs_map)                                                                          \
    struct syscall_cache_t *syscall = peek_syscall(EVENT_ANY);                                                         \
    if (!syscall)                                                                                                      \
        return 0;                                                                                                      \
                                                                                                                       \
    syscall->resolver.iteration++;                                                                                     \
    syscall->resolver.ret = resolve_path_tail_call(ctx, &syscall->resolver);                                           \
                                                                                                                       \
    if (syscall->resolver.ret > 0) {                                                                                   \
        if (syscall->resolver.iteration < PR_MAX_TAIL_CALL && syscall->resolver.key.ino != 0) {                        \
            bpf_tail_call_compat(ctx, pr_progs_map, PR_PROGKEY_LOOP);                                                  \
        }                                                                                                              \
                                                                                                                       \
        syscall->resolver.ret += PR_MAX_ITERATION_DEPTH * (syscall->resolver.iteration - 1);                           \
    }                                                                                                                  \
                                                                                                                       \
    if (syscall->resolver.callback >= 0) {                                                                             \
        bpf_tail_call_compat(ctx, pr_progs_map, syscall->resolver.callback);                                           \
    }                                                                                                                  \

SEC("kprobe/path_resolver_entrypoint")
int kprobe_path_resolver_entrypoint(struct pt_regs *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_ANY);
    if (!syscall) {
        return 0;
    }

    if (is_activity_dump_running(ctx, bpf_get_current_pid_tgid() >> 32, bpf_ktime_get_ns(), syscall->type)) {
        syscall->resolver.flags |= ACTIVITY_DUMP_RUNNING;
    }

    u32 zero = 0;
    struct pr_ring_buffer_ctx *ringbuf_ctx = bpf_map_lookup_elem(&pr_ringbuf_ctx, &zero);
    if (!ringbuf_ctx) {
        return 0;
    }

    ringbuf_ctx->hash = FNV_OFFSET_BASIS;
    ringbuf_ctx->len = 0;
    ringbuf_ctx->read_cursor = ringbuf_ctx->write_cursor;
    ringbuf_ctx->cpu = bpf_get_smp_processor_id();

    syscall->resolver.iteration = 0;
    bpf_tail_call_compat(ctx, &path_resolver_kprobe_progs, PR_PROGKEY_LOOP);
    return 0;
}

SEC("tracepoint/path_resolver_entrypoint")
int tracepoint_path_resolver_entrypoint(void *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_ANY);
    if (!syscall) {
        return 0;
    }

    if (is_activity_dump_running(ctx, bpf_get_current_pid_tgid() >> 32, bpf_ktime_get_ns(), syscall->type)) {
        syscall->resolver.flags |= ACTIVITY_DUMP_RUNNING;
    }

    u32 zero = 0;
    struct pr_ring_buffer_ctx *ringbuf_ctx = bpf_map_lookup_elem(&pr_ringbuf_ctx, &zero);
    if (!ringbuf_ctx) {
        return 0;
    }

    ringbuf_ctx->hash = FNV_OFFSET_BASIS;
    ringbuf_ctx->len = 0;
    ringbuf_ctx->read_cursor = ringbuf_ctx->write_cursor;
    ringbuf_ctx->cpu = bpf_get_smp_processor_id();

    syscall->resolver.iteration = 0;
    bpf_tail_call_compat(ctx, &path_resolver_tracepoint_progs, PR_PROGKEY_LOOP);
    return 0;
}

SEC("kprobe/path_resolver_loop")
int kprobe_path_resolver_loop(struct pt_regs *ctx) {
    path_resolver_loop(ctx, &path_resolver_kprobe_progs);
    return 0;
}

SEC("tracepoint/path_resolver_loop")
int tracepoint_path_resolver_loop(void *ctx) {
    path_resolver_loop(ctx, &path_resolver_tracepoint_progs);
    return 0;
}

#endif
