/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include <bpf/bpf_core_read.h> /* bpf_core_type_id_local */

#include "xdp/parsing_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} counter_map SEC(".maps");


SEC("xdp")
int xdp_counter_func(struct xdp_md *ctx)
{
    __u32 k = 0, *v;
    v = bpf_map_lookup_elem(&counter_map, &k);
    if (v) {
        __sync_fetch_and_add(v, 1);
        bpf_map_update_elem(&counter_map, &k, v, BPF_ANY);
        bpf_printk("cont = %d\n", *v);
    }
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
