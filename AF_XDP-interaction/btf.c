#include "btf.h"
#include <stdio.h>
#include <time.h>
#include <stdlib.h>


#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static uint64_t gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with clock_gettime! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

struct xdp_hints_rx_time xdp_hints_rx_time = { 0 };
// struct xdp_hints_mark xdp_hints_mark = { 0 };

struct xsk_btf_info *setup_btf_info(struct btf *btf,
				    const char *struct_name)
{
	struct xsk_btf_info *xbi = NULL;
	int err;

	err = xsk_btf__init_xdp_hint(btf, struct_name, &xbi);
	if (err) {
		fprintf(stderr, "WARN(%d): Cannot BTF locate valid struct:%s\n",
			err, struct_name);
		return NULL;
	}
	return xbi;
}

int init_btf_info_via_bpf_object(struct bpf_object *bpf_obj, struct xdp_hints_mark* xdp_hints_mark)
{
	struct btf *btf = bpf_object__btf(bpf_obj);
	struct xsk_btf_info *xbi;

	// xbi = setup_btf_info(btf, "xdp_hints_rx_time");
	// if (xbi) {
	// 	/* Lookup info on required member "rx_ktime" */
	// 	if (!xsk_btf__field_member("rx_ktime", xbi,
	// 				   &xdp_hints_rx_time.rx_ktime))
	// 		return -EBADSLT;
	// 	if (!xsk_btf__field_member("xdp_rx_cpu", xbi,
	// 				   &xdp_hints_rx_time.xdp_rx_cpu))
	// 		return -EBADSLT;
	// 	xdp_hints_rx_time.btf_type_id = xsk_btf__btf_type_id(xbi);
	// 	xdp_hints_rx_time.xbi = xbi;
	// }

	xbi = setup_btf_info(btf, "xdp_hints_mark");
	if (xbi) {
		if (!xsk_btf__field_member("mark", xbi, &xdp_hints_mark->mark))
			return -EBADSLT;
		xdp_hints_mark->btf_type_id = xsk_btf__btf_type_id(xbi);
		xdp_hints_mark->xbi = xbi;
	}

	return 0;
}

int print_meta_info_time(uint8_t *pkt, struct xdp_hints_rx_time *meta,
				__u32 qid)
{
	__u64 time_now; // = gettime();
	__u32 xdp_rx_cpu = 0xffff;
	__u32 cpu_running;
	__u64 *rx_ktime_ptr; /* Points directly to member memory */
	__u64 rx_ktime;
	__u64 diff;
	int err;

	/* Quick stats */
	static bool first = true;
	static unsigned int max = 0;
	static unsigned int min = -1;
	static double tot = 0;
	static __u64 cnt = 0;

	/* API doesn't involve allocations to access BTF struct member */
	err = xsk_btf__read((void **)&rx_ktime_ptr, sizeof(*rx_ktime_ptr),
			    &meta->rx_ktime, meta->xbi, pkt);
	if (err) {
		fprintf(stderr, "ERROR(%d) no rx_ktime?!\n", err);
		return err;
	}
	/* Notice how rx_ktime_ptr becomes a pointer into struct memory */
	rx_ktime = *rx_ktime_ptr;

	time_now = gettime();
	diff = time_now - rx_ktime;

	/* Quick stats, exclude first measurement */
	if (!first) {
		min = (min < diff) ? min : diff;
		max = (max > diff) ? max : diff;
		cnt++;
		tot += diff;
	}
	first = false;

	cpu_running = sched_getcpu();
	XSK_BTF_READ_INTO(xdp_rx_cpu,  &meta->xdp_rx_cpu, meta->xbi, pkt);

	printf("Q[%u] CPU[rx:%d/run:%d]:%s"
		       " meta-time rx_ktime:%llu time_now:%llu diff:%llu ns"
		       "(avg:%.0f min:%u max:%u )\n",
		       qid, xdp_rx_cpu, cpu_running,
		       (xdp_rx_cpu == cpu_running) ? "same" : "remote",
		       rx_ktime, time_now, diff,
		       tot / cnt, min , max);

	return 0;
}

bool is_tcp(uint8_t *pkt, struct xdp_hints_mark *meta){
    struct xsk_btf_info *xbi = meta->xbi;
	__u32 mark = 3;

	/* The 'mark' value is not updated in case of errors */
	XSK_BTF_READ_INTO(mark, &meta->mark, xbi, pkt);
    if(mark == 1)
        return true;
    return false;
}

// void print_meta_info_via_btf(uint8_t *pkt, struct xsk_socket_info *xsk)
// {
// 	__u32 btf_id = xsk_umem__btf_id(pkt);
// 	__u32 qid = xsk->queue_id;

// 	if (btf_id == 0) {
// 		printf("No meta BTF info (btf_id zero)\n");
// 		return;
// 	}

//     printf("btf_type_id = %d\n", btf_id);

// 	if (btf_id == xdp_hints_rx_time.btf_type_id) {
//         printf("AAA");
// 		print_meta_info_time(pkt, &xdp_hints_rx_time, qid);

// 	} else if (btf_id == xdp_hints_mark.btf_type_id) {
//         printf("BBB");
// 		print_meta_info_mark(pkt, &xdp_hints_mark, qid);
// 	}
// }
