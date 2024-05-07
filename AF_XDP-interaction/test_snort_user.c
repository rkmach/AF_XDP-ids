#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


#include <sys/resource.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>

#include "btf.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>

#include <linux/socket.h>

#include "af_xdp_kern_shared.h"
#include "common_params.h"
#include "common_user_bpf_xdp.h"


static const char *__doc__ = "AF_XDP kernel bypass example\n";

static bool global_exit;

static void exit_application(int signal)
{
	signal = signal;
	global_exit = true;
}

int main(int argc, char **argv)
{
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct config cfg = {
        .ifname = "amigo",
        .ifindex = 6,
		.filename = "test_snort_kern.o",
		.progsec = "xdp_counter_func",
	};

    struct bpf_object *bpf_obj = NULL;

    /* Global shutdown handler */
	signal(SIGINT, exit_application);

    bpf_obj = load_bpf_and_xdp_attach(&cfg);
    if (!bpf_obj) {
        /* Error handling done in load_bpf_and_xdp_attach() */
        exit(EXIT_FAILURE);
    }

    const char* pin_basedir = "/sys/fs/bpf";
    char pin_dir[1024];
    size_t len = snprintf(pin_dir, 1024, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	printf("\nmap dir: %s\n\n", pin_dir);
    strcpy(cfg.pin_dir, pin_dir);
    
    pin_maps_in_bpf_object(bpf_obj, &cfg, pin_basedir);

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
    // xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
    return 0;
}
