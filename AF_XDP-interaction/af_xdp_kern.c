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

#define PORT_RANGE 65536
#define IDS_INSPECT_MAP_SIZE 65536
#define IDS_INSPECT_DEPTH 1520  // MTU 1500 bytes
#define IDS_INSPECT_STRIDE 1
#define TAIL_CALL_MAP_SIZE 2

struct ids_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, IDS_INSPECT_MAP_SIZE);
    __type(key, struct ids_inspect_map_key);
    __type(value, struct ids_inspect_map_value);
} ids_map0 SEC(".maps"), ids_map1 SEC(".maps"), ids_map2 SEC(".maps"), ids_map3 SEC(".maps"), ids_map4 SEC(".maps"), ids_map5 SEC(".maps"), ids_map6 SEC(".maps"), ids_map7 SEC(".maps"), ids_map8 SEC(".maps");

struct global_map_t {
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

struct port_map_t {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PORT_RANGE);
    __type(key, struct port_map_key);
    __type(value, __u32);
} tcp_port_map SEC(".maps"), udp_port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, TAIL_CALL_MAP_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} tail_call_map SEC(".maps");

// os 4 primeiros campos foram registrados em seções BTF. Os últimos 3 são somente para tail call
struct xdp_hints_mark {
	__u32 mark;
    __u32 global_map_index;
    __u32 rule_index;
	__u32 btf_id;
} __attribute__((aligned(4))) __attribute__((packed));


SEC("xdp")
int xdp_inspect_payload(struct xdp_md *ctx)
{

    void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *data_meta = (void *)(long)ctx->data_meta;
	struct xdp_hints_mark *meta = data_meta;
	struct hdr_cursor nh;
    __u32 rx_queue_index = ctx->rx_queue_index;
	
	/* Compute current packet pointer */

	if (meta + 1 > data) {
		return XDP_ABORTED;
	}

    __u32 mark;
    if(meta->mark == 54){
        mark = 54;
    }
    else{
        mark = 42;
    }

	nh.pos = data;

    if (nh.pos + mark > data_end)
        return XDP_DROP;
    nh.pos += mark;

    ids_inspect_unit *ids_unit;
    struct ids_inspect_map_key ids_map_key;
    struct ids_inspect_map_value *ids_map_value;
    int i;

    __u32 global_map_index = meta->global_map_index;
    struct ids_map* ids_inspect_map = bpf_map_lookup_elem(&global_map, &global_map_index);
    if(!ids_inspect_map)
        return XDP_DROP;

    ids_map_key.state = 0;
    ids_map_key.padding = 0;
    #pragma unroll
    for (i = 0; i < IDS_INSPECT_DEPTH; i++) {
        ids_unit = nh.pos;
        if (ids_unit + 1 > data_end) {
            /* Reach the last byte of the packet (None fast pattern was found. Drop packet) */
            return XDP_DROP;
        }
        ids_map_key.unit = *ids_unit;
        ids_map_value = bpf_map_lookup_elem(ids_inspect_map, &ids_map_key);
        if (ids_map_value) {
            bpf_printk("%d %d\n", ids_map_key.state, ids_map_value->state);
            /* Go to the next state according to DFA */
            ids_map_key.state = ids_map_value->state;
            if (ids_map_value->flag > 0) {
                bpf_printk("rule_index = %d\n", ids_map_value->fp__rule_index);
                /* An acceptable state, return the hit pattern number */
                meta->rule_index = ids_map_value->fp__rule_index;
                meta->btf_id = bpf_core_type_id_local(struct xdp_hints_mark);

                return bpf_redirect_map(&xsks_map, rx_queue_index, 0);
            }
        }
        /* Prepare for next scanning */
        nh.pos += 1;
    }

    /* The payload is not inspected completely (!!!!!!!!!!!!!!!!!!!!)*/
    return XDP_DROP;
}

SEC("xdp")
int xdp_ids_func(struct xdp_md *ctx)
{
    struct xdp_hints_mark *meta;
    int err;
    /* Reserve space in-front of data pointer for our meta info */
	err = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));

	if (err)
		return XDP_DROP;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    meta = (void *)(unsigned long)ctx->data_meta;
    if (meta + 1 > data) /* Verify meta area is accessible */
        return XDP_DROP;

    __u32 action = XDP_PASS; /* Default action */

    /* Parse packet */
    struct hdr_cursor nh;
    int eth_type, ip_type;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct udphdr *udph;
    struct tcphdr *tcph;
    int is_tcp = 0;
    src_port_t pkt_src_port;

    // __u16 src_port, dst_port;
    struct port_map_key port_map_key;
    __u32* port_map_value = NULL;

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
        is_tcp = 1;
        port_map_key.src_port = bpf_ntohs(tcph->source);
        port_map_key.dst_port = bpf_ntohs(tcph->dest);

        // se não houver chave no mapa para esse par de portas, nem precisa processar o pacote

        // Primeiro, testa com as portas que estão no pacote
        port_map_value = bpf_map_lookup_elem(&tcp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (sport, dport) (do pacote)
            goto pg_found;
        
        pkt_src_port = port_map_key.src_port;

        // se não achei, vou procurar por (any, dport)
        port_map_key.src_port = 0;
        port_map_value = bpf_map_lookup_elem(&tcp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (any, dport)
            goto pg_found;

        // se não achei, vou procurar por (sport, any)
        port_map_key.src_port = pkt_src_port;
        port_map_key.dst_port = 0;
        port_map_value = bpf_map_lookup_elem(&tcp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (sport, any)
            goto pg_found;

        // se não achei, vou procurar por (any, any)
        port_map_key.src_port = 0;
        port_map_key.dst_port = 0;
        port_map_value = bpf_map_lookup_elem(&tcp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (any, any)
            goto pg_found;

        if(!port_map_value)
            return XDP_DROP;

    } else if (ip_type == IPPROTO_UDP) {
        if (parse_udphdr(&nh, data_end, &udph) < 0) {
            action = XDP_ABORTED;
            goto out;
        }
        port_map_key.src_port = bpf_ntohs(udph->source);
        port_map_key.dst_port = bpf_ntohs(udph->dest);

        // se não houver chave no mapa para esse par de portas, nem precisa processar o pacote
        
        // Primeiro, testa com as portas que estão no pacote
        port_map_value = bpf_map_lookup_elem(&udp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (sport, dport) (do pacote)
            goto pg_found;
        
        pkt_src_port = port_map_key.src_port;
        // dst_port_t pkt_dst_port = port_map_key->dst_port;

        // se não achei, vou procurar por (any, dport)
        port_map_key.src_port = 0;
        port_map_value = bpf_map_lookup_elem(&udp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (any, dport)
            goto pg_found;

        // se não achei, vou procurar por (sport, any)
        port_map_key.src_port = pkt_src_port;
        port_map_key.dst_port = 0;
        port_map_value = bpf_map_lookup_elem(&udp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (sport, any)
            goto pg_found;

        // se não achei, vou procurar por (any, any)
        port_map_key.src_port = 0;
        port_map_key.dst_port = 0;
        port_map_value = bpf_map_lookup_elem(&udp_port_map, &port_map_key);
        if(port_map_value)  // achei o port group (any, any)
            goto pg_found;

        if(!port_map_value)
            return XDP_DROP;
    } else {
            goto out;
    }
pg_found:
    bpf_printk("port_map_value = %d", *port_map_value);
    /* Only packet with valid TCP/UDP header and a valid port group will reach here */
    
    meta->global_map_index = *port_map_value;
    meta->mark = is_tcp;

    // Must use tail call, otherwise the instruction limit would be crossed.
    bpf_tail_call(ctx, &tail_call_map, 0);
    // The flow shoud had been deviated by the above line. If it was not, drop the packet
    action = XDP_DROP;

out:
    return action;
}

char _license[] SEC("license") = "GPL";
