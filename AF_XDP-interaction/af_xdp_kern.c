/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include <bpf/bpf_core_read.h> /* bpf_core_type_id_local */

#include "xdp/parsing_helpers.h"
#include "af_xdp_kern_shared.h"

#include "common_kern_user.h"

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_AF_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAX_AF_SOCKS);
} xdp_stats_map SEC(".maps");

#define PORT_RANGE 65536
#define IDS_INSPECT_MAP_SIZE 65536
#define IDS_INSPECT_DEPTH 10
#define IDS_INSPECT_STRIDE 1

struct ids_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, IDS_INSPECT_MAP_SIZE);
    __type(key, struct ids_inspect_map_key);
    __type(value, struct ids_inspect_map_value);
} ids_map0 SEC(".maps"), ids_map1 SEC(".maps"), ids_map2 SEC(".maps"), ids_map3 SEC(".maps"), ids_map4 SEC(".maps"), ids_map5 SEC(".maps"), ids_map6 SEC(".maps"), ids_map7 SEC(".maps"), ids_map8 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, __u32);
    __uint(max_entries, 10);
    __array(values, struct ids_map);
} global_map SEC(".maps") = {
    .values = { &ids_map0,
                &ids_map1,
                &ids_map2,
                &ids_map3,
                &ids_map4,
                &ids_map5,
                &ids_map6,
                &ids_map7,
                &ids_map8 }
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PORT_RANGE);
    __type(key, struct port_map_key);
    __type(value, __u32);
} tcp_port_map SEC(".maps"), udp_port_map SEC(".maps");


/*
 * The xdp_hints_xxx struct's are stored in the XDP 'data_meta' area,
 * which is located just in-front-of the raw packet payload data.
 *
 * Explaining the struct attribute's:
 * ----------------------------------
 * The struct must be 4 byte aligned (kernel requirement), which here
 * is enforced by the struct __attribute__((aligned(4))).
 *
 * To avoid any C-struct padding attribute "packed" is used.
 *
 * NOTICE: Do NOT define __attribute__((preserve_access_index)) here,
 * as libbpf will try to find a matching kernel data-structure,
 * e.g. it will cause BPF-prog loading step to fail (with invalid func
 * unknown#195896080 which is 0xbad2310 in hex for "bad relo").
 */
struct xdp_hints_mark {
	__u32 mark;
	__u32 btf_id;
} __attribute__((aligned(4))) __attribute__((packed));

struct xdp_hints_rx_time {
	__u64 rx_ktime;
	__u32 xdp_rx_cpu;
	__u32 btf_id;
} __attribute__((aligned(4))) __attribute__((packed));

int meta_add_rx_time(struct xdp_md *ctx)
{
	struct xdp_hints_rx_time *meta;
	void *data;
	int err;

	/* Reserve space in-front of data pointer for our meta info.
	 * (Notice drivers not supporting data_meta will fail here!)
	 */
	err = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
	if (err)
		return -1;

	/* Notice: Kernel-side verifier requires that loading of
	 * ctx->data MUST happen _after_ helper bpf_xdp_adjust_meta(),
	 * as pkt-data pointers are invalidated.  Helpers that require
	 * this are determined/marked by bpf_helper_changes_pkt_data()
	 */
	data = (void *)(unsigned long)ctx->data;

	meta = (void *)(unsigned long)ctx->data_meta;
	if (meta + 1 > data) /* Verify meta area is accessible */
		return -2;

	meta->rx_ktime = bpf_ktime_get_ns();
	meta->xdp_rx_cpu = bpf_get_smp_processor_id();
	/* Userspace can identify struct used by BTF id */
	meta->btf_id = bpf_core_type_id_local(struct xdp_hints_rx_time);

	return 0;
}

int meta_add_mark(struct xdp_md *ctx, __u32 mark)
{
	struct xdp_hints_mark *meta;
	void *data;
	int err;

	/* Reserve space in-front of data pointer for our meta info */
	err = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
	if (err)
		return -1;

	data = (void *)(unsigned long)ctx->data;
	meta = (void *)(unsigned long)ctx->data_meta;
	if (meta + 1 > data) /* Verify meta area is accessible */
		return -2;

	meta->mark = mark;
	meta->btf_id = bpf_core_type_id_local(struct xdp_hints_mark);

	return 0;
}

static __always_inline int inspect_payload(struct ids_map* ids_inspect_map, int is_tcp, struct hdr_cursor *nh, void *data_end,
        __u32 queue_idx, __u32* action)
{
        ids_inspect_unit *ids_unit;
        struct ids_inspect_map_key ids_map_key;
        struct ids_inspect_map_value *ids_map_value;
        int i;

        ids_map_key.state = 0;
        ids_map_key.padding = 0;

        is_tcp = 1;

        #pragma unroll
        for (i = 0; i < IDS_INSPECT_DEPTH; i++) {
            ids_unit = nh->pos;
            if (ids_unit + 1 > data_end) {
                /* Reach the last byte of the packet */
                return 0;
            }
            // memcpy(ids_map_key.unit.unit, ids_unit, IDS_INSPECT_STRIDE);
            // memcpy(&(ids_map_key.unit), ids_unit, IDS_INSPECT_STRIDE);
            bpf_printk("%c", *ids_unit);
            ids_map_key.unit = *ids_unit;
            if(is_tcp)
                ids_map_value = bpf_map_lookup_elem(ids_inspect_map, &ids_map_key);
            else
                ids_map_value = bpf_map_lookup_elem(ids_inspect_map, &ids_map_key);
            if (ids_map_value) {
                /* Go to the next state according to DFA */
                ids_map_key.state = ids_map_value->state;
                if (ids_map_value->flag > 0) {
                    /* An acceptable state, return the hit pattern number */
                    *action = bpf_redirect_map(&xsks_map, queue_idx, 0);
                    bpf_printk("Ache padrão %d", ids_map_value->flag);
                    return ids_map_value->flag;
                }
            }
            /* Prepare for next scanning */
            nh->pos += 1;
        }

        /* The payload is not inspected completely (!!!!!!!!!!!!!!!!!!!!)*/
        return -1;
}

SEC("xdp")
int xdp_ids_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 rx_queue_index = ctx->rx_queue_index;
    // int send_to_userspace = 1;

    __u32 action = XDP_PASS; /* Default action */

    // bpf_printk("rx_queue_index = %d", rx_queue_index);
    // if(send_to_userspace){
    //     if(bpf_map_lookup_elem(&xsks_map, &rx_queue_index)){
    //         return bpf_redirect_map(&xsks_map, rx_queue_index, 0);
    //     }
    //     // action = bpf_redirect_map(&xsks_map, rx_queue_index, 0);
    //     // goto out;
    // }

    /* Parse packet */
    struct hdr_cursor nh;
    int eth_type, ip_type;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct udphdr *udph;
    struct tcphdr *tcph;
    int ids_state = 0;
    int is_tcp = 0;

    nh.pos = data;
    eth_type = parse_ethhdr(&nh, data_end, &eth);

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iph);
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        ip_type = parse_ip6hdr(&nh, data_end, &ip6h);
    } else {
        goto out;
    }

    if (ip_type == IPPROTO_TCP) {
        if (parse_tcphdr(&nh, data_end, &tcph) < 0) {
            action = XDP_ABORTED;
            goto out;
        }
        // ids_state = inspect_payload(tcp_ids_inspect_map, &nh, data_end);
        is_tcp = 1;
    } else if (ip_type == IPPROTO_UDP) {
        if (parse_udphdr(&nh, data_end, &udph) < 0) {
            action = XDP_ABORTED;
            goto out;
        // ids_state = inspect_payload(udp_ids_inspect_map, &nh, data_end);
        }
    } else {
            goto out;
    }

    ids_state = inspect_payload(&ids_map0, is_tcp, &nh, data_end, rx_queue_index, &action);
    if (ids_state > 0) {
        // bpf_printk("The %dth pattern is triggered\n", ids_state);
        /* before send packet to user space, write in IPC map the type of protocol and the flag */
        /* send packet to user space */
        // action = bpf_redirect_map(&xsks_map, rx_queue_index, 0);
        // bpf_printk("Achei padrão %d", ids_state);
        goto out;
    }

out:
    return action;
}

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	bpf_printk("AAAAA");
	int index = ctx->rx_queue_index;
	__u32 *pkt_count;
	int err, ret;

	pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
	if (!pkt_count)
		return XDP_ABORTED;
	__u64 cnt = (*pkt_count)++;
//	if (cnt == 0) {
//		if (bpf_ktime_get_ns() == 42)
//			return XDP_ABORTED;
//		cnt++;
//	}

	/* Notice how two different xdp_hints meta-data are used */
	if ((cnt % 2) == 0) {
		err = meta_add_rx_time(ctx);
		if (err < 0)
			return XDP_ABORTED;
	} else {
		err = meta_add_mark(ctx, 42);
		if (err < 0)
			return XDP_DROP;
	}

	/* Let network stack handle ARP and IPv6 Neigh Solicitation */
	ret = 3;
	if (ret < 0)
		return XDP_ABORTED;
	if (ret == 1)
		return XDP_PASS;

	/* A set entry here means that the correspnding queue_id
	 * has an active AF_XDP socket bound to it. */
	if (bpf_map_lookup_elem(&xsks_map, &index)){
		bpf_printk("Mandando pru userland");
		return bpf_redirect_map(&xsks_map, index, 0);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
