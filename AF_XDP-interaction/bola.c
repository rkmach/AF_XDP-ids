#define _GNU_SOURCE  /* Needed by sched_getcpu */
#include <sched.h>

#include <assert.h>
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

#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL     69
#endif
#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET     70
#endif


#include <bpf/btf.h> /* provided by libbpf */

#include "common_params.h"
#include "common_user_bpf_xdp.h"
// #include "common_libbpf.h"
#include "af_xdp_kern_shared.h"

#include "lib_xsk_extend.h"
#include "ethtool_utils.h"
#include "lib_checksum.h"

#define NUM_FRAMES         4096 /* Frames per queue */
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE /* 4096 */
#define FRAME_SIZE_MASK    (FRAME_SIZE - 1)
#define RX_BATCH_SIZE      64
#define FQ_REFILL_MAX      (RX_BATCH_SIZE * 2)
#define INVALID_UMEM_FRAME UINT64_MAX

#define DEFAULT_INTERVAL	1000000

static const struct option_wrapper long_options[] = {

	{{"help",	 no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",	 required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",	 no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",	 no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",	 no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"copy",        no_argument,		NULL, 'c' },
	 "Force copy mode"},

	{{"zero-copy",	 no_argument,		NULL, 'z' },
	 "Force zero-copy mode"},

	{{"queue",	 required_argument,	NULL, 'Q' },
	 "Configure single interface receive queue for AF_XDP"},

	{{"priority",	 required_argument,	NULL, 'p' },
	 "Setup real-time priority for process"},

	{{"wakeup-mode", no_argument,		NULL, 'w' },
	 "Use poll() API waiting for packets to arrive via wakeup from kernel"},

	{{"spin-mode", no_argument,		NULL, 's' },
	 "Let userspace process spin checking for packets (disable --wakeup-mode)"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",	 no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"pktinfo",	 no_argument,		NULL, 'P' },
	 "Print packet info output mode (debug)"},

	{{"metainfo",	 no_argument,		NULL, 'm' },
	 "Print XDP metadata info output mode (debug)"},

	{{"timedebug",	 no_argument,		NULL, 't' },
	 "Print timestamps info for wakeup accuracy (debug)"},

	{{"debug",	 no_argument,		NULL, 'D' },
	 "Debug info output mode (debug)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",	 required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{"src-ip",	 required_argument,	NULL,  4  },
	 "Change IPv4 source      address in generated packets", "<ip>"},

	{{"dst-ip",	 required_argument,	NULL,  5 },
	 "Change IPv4 destination address in generated packets", "<ip>"},

	{{"busy-poll",	 no_argument,		NULL, 'B' },
	 "Enable socket prefer NAPI busy-poll mode (remember adjust sysctl too)"},

	{{"tx-dmac",	 required_argument,	NULL, 'G' },
	 "Dest MAC addr of TX frame in aa:bb:cc:dd:ee:ff format", "aa:bb:cc:dd:ee:ff"},

	{{"tx-smac",	 required_argument,	NULL, 'H' },
	 "Src MAC addr of TX frame in aa:bb:cc:dd:ee:ff format", "aa:bb:cc:dd:ee:ff"},

	{{"interval",	 required_argument,	NULL, 'i' },
	 "Periodic TX-cyclic interval wakeup period in usec", "<usec>"},

	{{"batch-pkts",	 required_argument,	NULL, 'b' },
	 "Periodic TX-cyclic batch send pkts", "<pkts>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static bool global_exit;

struct xsk_umem_info {
	struct xsk_ring_prod fq;  // fill queue
	struct xsk_ring_cons cq;  // completion queue
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;
};

static void apply_setsockopt(struct xsk_socket_info *xsk, bool opt_busy_poll,
			     int opt_batch_size)
{
	int sock_opt;

	if (!opt_busy_poll)
		return;

	sock_opt = 1;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_PREFER_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

	sock_opt = 20;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

	sock_opt = opt_batch_size;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL_BUDGET,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);
}

struct xsk_umem_info* configure_umem(void* packet_buffer, size_t packet_buffer_size){
    struct xsk_umem_info* umem;
    umem = calloc(1, sizeof(*umem));
    if (!umem){
        printf("Problema no calloc para configurar UMEM\n");
        return NULL;
    }

    struct xsk_umem_config xsk_umem_cfg = {
		/* We recommend that you set the fill ring size >= HW RX ring size +
		 * AF_XDP RX ring size. Make sure you fill up the fill ring
		 * with buffers at regular intervals, and you will with this setting
		 * avoid allocation failures in the driver. These are usually quite
		 * expensive since drivers have not been written to assume that
		 * allocation failures are common. For regular sockets, kernel
		 * allocated memory is used that only runs out in OOM situations
		 * that should be rare.
		 */
//		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS, /* Fix later */
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = FRAME_SIZE,
		/* Notice XSK_UMEM__DEFAULT_FRAME_HEADROOM is zero */
		.frame_headroom = 256,
		//.frame_headroom = 0,
		.flags = 0
	};

    // UMEM está sendo criada com a configuração padrão (último parâmetro = NULL)
    int ret = xsk_umem__create(&umem->umem, packet_buffer, packet_buffer_size, &umem->fq, &umem->cq, &xsk_umem_cfg);
    if (ret){
        printf("problema para criar a UMEM usando libxdp\n");
        return NULL;
    }
    umem->buffer = packet_buffer;
    return umem;
}

uint64_t xsk_alloc_umem_frame(struct xsk_socket_info* xsk_info){
    uint64_t frame;
    if(xsk_info->umem_frame_free == 0){
        printf("Não dá pra alocar mais frames!\n LIMITE MÀXIMO ATINGIDO");
        return INVALID_UMEM_FRAME;
    }
    frame = xsk_info->umem_frame_addr[xsk_info->umem_frame_free-1];
    xsk_info->umem_frame_addr[xsk_info->umem_frame_free] = INVALID_UMEM_FRAME;
    xsk_info->umem_frame_free--;
    return frame;
}

struct xsk_socket_info* configure_socket(struct config *cfg, int i_queue, struct xsk_umem_info* umem){
    struct xsk_socket_config xsk_config;
    struct xsk_socket_info* xsk_info;

    xsk_info = calloc(1, sizeof(*xsk_info));
    if(!xsk_info){
        printf("Falha no calloc da xsk info\n");
        return NULL;
    }

    xsk_info->umem = umem;

    xsk_config.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;  // 2048
    xsk_config.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;  // 2048

    xsk_config.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;

    xsk_config.xdp_flags = cfg->xdp_flags;
    xsk_config.bind_flags = cfg->xsk_bind_flags;

    int ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname, i_queue, umem->umem, &xsk_info->rx, &xsk_info->tx, &xsk_config);

    if (ret != 0){
        printf("Erro na chamada de socket_create, dentro de configure_socket\n");
        errno = -ret;
        return NULL;
    }
    uint32_t prog_id = 0;
    ret = bpf_xdp_query_id(cfg->ifindex, cfg->xdp_flags, &prog_id);  // tá PREENCHENDO a variável prog_id
    if (ret){
        printf("Erro ao query id");
    }

    // alocação de frames na UMEM !!!

    for(int i = 0; i < NUM_FRAMES; i++){
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;  // o endereço do frame i é i*4096
    }
    xsk_info->umem_frame_free = NUM_FRAMES;  // significa que os 4096 frames estão livres 

    uint32_t idx;
    // reserva os slots do fill ring
    // acho que isso significa passar o fill ring para o kernel, para que ele possa ver onde colocar os pacotes de RX
    ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);  // PREENCHE a var idx

    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS){
        printf("Erro ao reservar os descritores que serão colocados os endereços no ring FILL\n");
        return NULL;
    }

    // agora sim eu vou colocar os endereços da UMEM no fill ring (!!!!!!!!!)
    for(int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++){
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx) = xsk_alloc_umem_frame(xsk_info);
        idx++;
    }
    
    // submetendo os slot do fill ring para os quais foram colocados endereços (todos, nesse caso)
    // significa que o kernel já pode ler e começar a preencher a UMEM com o que receber
    xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    // apply_setsockopt(xsk_info, cfg->opt_busy_poll, RX_BATCH_SIZE);

    return xsk_info;
}

static void enter_xsks_into_map(int xsks_map, struct xsk_socket_info **sockets, size_t len_sockets)
{
	int i;

	if (xsks_map < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(xsks_map));
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < len_sockets; i++) {
		int fd = xsk_socket__fd(sockets[i]->xsk);
		int key, ret;

		key = i;
		/* When entering XSK socket into map redirect have effect */
		ret = bpf_map_update_elem(xsks_map, &key, &fd, 0);
		if (ret) {
			fprintf(stderr, "ERROR: bpf_map_update_elem %d\n", i);
			exit(EXIT_FAILURE);
		}
		if (debug)
			printf("%s() enable redir for xsks_map_fd:%d Key:%d fd:%d\n",
			       __func__, xsks_map, key, fd);

	}
}

int af_xdp_init(struct xsk_umem_info **umems, struct xsk_socket_info **xsk_sockets, int n_queues, struct config* cfg){
    void *packet_buffer = NULL;
	size_t packet_buffer_size;
    struct xsk_umem_info* umem;
    struct xsk_socket_info* xsk_socket;

    packet_buffer_size = 4096 * 4096;  // NUM_FRAMES * FRAME_SIZE; número de packet buffers * tamanho de cada packet buffer  

    for(int i_queue = 0; i_queue < n_queues; i_queue++){
        if(posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size)){
            printf("Problema ao alocar memória do buffer da UMEM!");
        }
        
        umem = configure_umem(packet_buffer, packet_buffer_size);
        if (umem == NULL){
            printf("Não configurei UMEM corretamente!\n");
            return -1;
        }

        xsk_socket = configure_socket(cfg, i_queue, umem);
        if (xsk_socket == NULL) {
			fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
				strerror(errno));
			return EXIT_FAILURE;
		}

        umems[i_queue] = umem;
        xsk_sockets[i_queue] = xsk_socket;
    }

    return 0;
}

void xsk_free_umem_frame(struct xsk_socket_info* xsk_info, uint64_t frame){
    xsk_info->umem_frame_addr[xsk_info->umem_frame_free] = frame;
    xsk_info->umem_frame_free++;
}

void process_packet(){
    printf("Processando o pacote!!!\n");
}

void handle_receive_packets(struct xsk_socket_info* xsk_info){
    uint32_t idx_rx = 0;
    uint32_t idx_fq = 0;
    int ret;

    unsigned int frames_received, stock_frames;

    // ver se no RX tem alguma coisa
    frames_received = xsk_ring_cons__peek(&xsk_info->rx, RX_BATCH_SIZE, &idx_rx);  // prenche a var idx_rx
    // se não recebeu nada, volta pro loop de pool
    if(!frames_received)
        return;
    
    // se chegou aqui, recebi pelo menos um pacote nesse socket

    // stock frames é o número de frames recebidos!
    stock_frames = xsk_prod_nb_free(&xsk_info->umem->fq, xsk_info->umem_frame_free);

    if(stock_frames > 0){
        // reserva stock_frames slots no ring fill da UMEM
        ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, stock_frames, &idx_fq);

        /* This should not happen, but just in case */
		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, frames_received, &idx_fq);

        for(int i = 0; i < stock_frames; i++){
            *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx_fq++) = xsk_alloc_umem_frame(xsk_info);
        }
        xsk_ring_prod__submit(&xsk_info->umem->fq, stock_frames);
    }

    // só agora que vou tratar os pacotes recebidos (!!!!!!!!!)

    uint64_t addr;
    uint32_t len;

    for(int i = 0; i < frames_received; i++){
        // lê o descritor armazenado em idx_rx
        addr = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx)->addr;
        len = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx)->len;
        idx_rx++;

        // função que termina de verificar om pacote (AAAAAAAAAAAAAAAAAAAAAA)
        // process_packet(xsk_info, addr, len);
        printf("pacote len = %d", len);
        process_packet();

        // adiciona o endereço à lista de endereços disponíveis do fill ring da UMEM
        xsk_free_umem_frame(xsk_info, addr);
    }

    // libera os frames recebidos do RX (indica pro kernel que eu já li essas posições)
    xsk_ring_cons__release(&xsk_info->rx, frames_received);


    // complete_tx(xsk_info);
}

void rx_and_process(struct config* config, struct xsk_socket_info** xsk_sockets, int n_queues){
    struct pollfd fds[n_queues];  // essa estrutura é entendida pela syscall poll(), que é usada para verificar se há novos eventos no socket
    memset(fds, 0, sizeof(fds));
    int i_queue;

    for(i_queue = 0; i_queue < n_queues; i_queue++){
        fds[i_queue].fd = xsk_socket__fd(xsk_sockets[i_queue]->xsk);
        fds[i_queue].events = POLLIN;  // POLLIN = "there is data to read"
    }

    int ret;
    // fica nesse loop por toda a execução da IDS
    while(!global_exit){
        printf("loop\n");
        // supondo que a IDS rode somente no wake up mode para o FILL ring. Isso significa que o kernel vai ficar dormindo,
        // até que seja acordado // pela IDS. Quando for acordado, o kernel driver usará os endereços da fill ring para 
        //receber os pacotes. O kernel precisa ser devidamente acordado por uma syscall para continuar processando.
        // A função do pool é só verificar se houve evento, a syscall que acorda o kernel é outra (eu acho)

        // ret é o número de socket com algum evento (infelizmente não retorna quais os sockets :( 
        ret = poll(fds, n_queues, -1);  // timeout = -1. Sinifica que vai ficar bloqueado até que um evento ocorra.

        if(ret <= 0){
            continue;  // nenhum evento em nenhum socket
        }
        for(i_queue = 0; i_queue < n_queues; i_queue++){
            if(fds[i_queue].revents & POLLIN){
                printf("recebi na fila %d", i_queue);
                handle_receive_packets(xsk_sockets[i_queue]);
            }
        }
        

    }
}

static void exit_application(int signal)
{
	signal = signal;
	global_exit = true;
}

int main(int argc, char **argv)
{
	int xsks_map_fd;
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct config cfg = {
		.ifindex   = 6,  // iface amigo
		.do_unload = false,
		.filename = "af_xdp_kern.o",
		.progsec = "xdp",
		.xsk_wakeup_mode = true, /* Default, change via --spin */
		.xsk_if_queue = -1,
		.interval = DEFAULT_INTERVAL,
		.batch_pkts = BATCH_PKTS_DEFAULT,
	};
	struct xsk_umem_info **umems;
	struct xsk_socket_info **xsk_sockets;

    // flag de wakeup!!!!!!
    // cfg.xdp_flags = 
    cfg.xsk_bind_flags = XDP_COPY;

    struct bpf_object *bpf_obj = NULL;
	struct bpf_map *map;

    /* Global shutdown handler */
	signal(SIGINT, exit_application);

    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

    bpf_obj = load_bpf_and_xdp_attach(&cfg);
    if (!bpf_obj) {
        /* Error handling done in load_bpf_and_xdp_attach() */
        exit(EXIT_FAILURE);
    }

    /* We also need to load the xsks_map */
    map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
    xsks_map_fd = bpf_map__fd(map);
    if (xsks_map_fd < 0) {
        fprintf(stderr, "ERROR: no xsks map found: %s\n",
            strerror(xsks_map_fd));
        exit(EXIT_FAILURE);
    }

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

    /* Configure and initialize AF_XDP sockets  (vetor de ponteiros!!) */
    int n_queues = 1;

	umems = (struct xsk_umem_info **)
			malloc(sizeof(struct xsk_umem_info *) * n_queues);
	xsk_sockets = (struct xsk_socket_info **)
				  malloc(sizeof(struct xsk_socket_info *) * n_queues);

    if(!umems || !xsk_sockets){
        printf("Não consegui alocar o vetor de UMEMS ou o vetor de sockets!\n");
    }

    if(!af_xdp_init(umems, xsk_sockets, n_queues, &cfg)){
        printf("Tudo certo!!\n");
    }

    enter_xsks_into_map(xsks_map_fd, xsk_sockets, n_queues);

    rx_and_process(&cfg, xsk_sockets, n_queues);

    /* Cleanup */
	for (int i_queue = 0; i_queue < n_queues; i_queue++) {
		xsk_socket__delete(xsk_sockets[i_queue]->xsk);
		xsk_umem__delete(umems[i_queue]->umem);
	}
    free(umems);
    free(xsk_sockets);
    xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
    return 0;
}