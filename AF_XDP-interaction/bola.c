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

#include "str2dfa.h"
#include "common_kern_user.h"
#include "hashmap.h"

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

struct xdp_hints_mark xdp_hints_mark = { 0 };

/*
essa opção permite busy pool, porém a placa q temos não suporta
static void __exit_with_error(int error, const char *file, const char *func,
			      int line)
{
	fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func,
		line, error, strerror(error));
	exit(EXIT_FAILURE);
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, __LINE__)

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
*/

// criar e lógica para receber as info de metadado
// e pegar o autômato correto.
void process_packet(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len){
	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
    int offset;
	uint32_t global_map_index;

    offset = is_tcp(pkt, &xdp_hints_mark, &global_map_index) ? 54 : 42;

    char* first_char_payload = NULL;
    first_char_payload = (char*) pkt + offset;
    if (!first_char_payload)
        return;
    if (len > offset) {
        for(int i = 0; i<len-offset; i++){
            printf("%c\n", *first_char_payload);
            first_char_payload++;
        }
    }
}

void handle_receive_packets(struct xsk_socket_info* xsk_info){
    uint32_t idx_rx = 0;
    uint32_t idx_fq = 0;
    int ret;
    unsigned int frames_received, stock_frames;

    recvfrom(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);

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
        printf("pacote len = %d\n", len);
        process_packet(xsk_info, addr, len);

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

/* Follow struct declaration is for fixing the bug of bpf_map_update_elem */
struct ids_inspect_map_update_value {
	struct ids_inspect_map_value value;
	uint8_t padding[8 - sizeof(struct ids_inspect_map_value)];
};

static size_t __xsk_hash_fn(const void *key, void *ctx)
{
	/* Note that, the hashmap used to speed-up offset location into the BTF
	 * doesn't use the field name as a string as key to the hashmap. It
	 * directly uses the pointer value instead, as it is expected that most
	 * of time, field names will be addressed by a shared constant string
	 * residing on read-only memory, thus saving some time. If this
	 * assumption is not entirely true, this optimisation needs to be
	 * rethought (or discarded altogether).
	 */
	return (size_t)key;
}

static bool __xsk_equal_fn(const void *k1, const void *k2, void *ctx)
{
	return k1 == k2;
}

static void create_dfa_per_rule(struct rule_t* rule, struct dfa_struct* dfa){

	// inicia a hash
    _hashmap__init(&(rule->dfa), __xsk_hash_fn, __xsk_equal_fn, NULL);

	uint32_t i_entry, n_entry = dfa->entry_number;
	struct ids_inspect_map_key key;
	struct ids_inspect_map_value* value = malloc(sizeof(struct ids_inspect_map_value*));

	/* Initial */
	key.padding = 0;

	/* Convert dfa to hashmap */
	for (i_entry = 0; i_entry < n_entry; i_entry++) {
		key.state = dfa->entries[i_entry].key_state;
		key.unit = dfa->entries[i_entry].key_unit;
		value->state = dfa->entries[i_entry].value_state;
		value->flag = dfa->entries[i_entry].value_flag;
		printf("a\n");
		hashmap__add(&(rule->dfa), &key, value);
	}
}

static void free_hash(struct rule_t* rule)
{
	struct hashmap_entry *entry;
	int i;

	hashmap__for_each_entry((&(rule->dfa)), entry, i) {
		free(entry->value);
	}
	_hashmap__clear(&(rule)->dfa);
}

static int dfa2map(int ids_map_fd, struct dfa_struct *dfa)
{
	struct dfa_entry *map_entries = dfa->entries;
	uint32_t i_entry, n_entry = dfa->entry_number;
	int i_cpu, n_cpu = libbpf_num_possible_cpus();
	struct ids_inspect_map_key ids_map_key;
	struct ids_inspect_map_update_value ids_map_values[n_cpu];
	ids_inspect_state value_state;
	accept_state_flag value_flag;
	int16_t rule_index;

	printf("Number of CPUs: %d\n\n", n_cpu);

	/* Initial */
	ids_map_key.padding = 0;
	memset(ids_map_values, 0, sizeof(ids_map_values));

	/* Convert dfa to map */
	for (i_entry = 0; i_entry < n_entry; i_entry++) {
		ids_map_key.state = map_entries[i_entry].key_state;
		ids_map_key.unit = map_entries[i_entry].key_unit;
		value_state = map_entries[i_entry].value_state;
		value_flag = map_entries[i_entry].value_flag;
		rule_index = map_entries[i_entry].fp__rule_index;
		for (i_cpu = 0; i_cpu < n_cpu; i_cpu++) {
			ids_map_values[i_cpu].value.state = value_state;
			ids_map_values[i_cpu].value.flag = value_flag;
			ids_map_values[i_cpu].value.fp__rule_index = rule_index;
		}
		if (bpf_map_update_elem(ids_map_fd,
								&ids_map_key, ids_map_values, 0) < 0) {
			fprintf(stderr,
				"WARN: Failed to update bpf map file: err(%d):%s\n",
				errno, strerror(errno));
			return -1;
		} else {
			if (true) {
				printf("---------------------------------------------------\n");
				// printf("New element is added in to map (%s)\n",
				// 		ids_inspect_map_name);
				printf("Key - state: %d, unit: %c\n",
						ids_map_key.state, ids_map_key.unit);
				printf("Value - state: %d, flag: %d, rule_index: %d\n",
						value_state, value_flag, rule_index);
				printf("---------------------------------------------------\n");
			}
		}
	}
	printf("Total %d entries are inserted\n\n", n_entry);

	return 0;
}

void check_end_line(char* token){
	size_t len = strcspn(token, "\n");
	if(len == strlen(token))
		return;
	token[len] = '\0';
}

int initialize_fast_pattern_port_group_map(int port_map_fd, int* index, uint16_t src, uint16_t dst,
    struct fast_p* fast_patterns_array, size_t len_fp_arr)
{
    char map_name[24];
    struct dfa_struct dfa;
    
    const char *pin_dir = "/sys/fs/bpf/amigo";  //MUDAR

    /* In this moment, every pattern in the port group has been collected, so it's possible to create dfas */
	str2dfa(fast_patterns_array, len_fp_arr, &dfa);

    for(int k = 0; k < dfa.entry_number; k++){
        printf("entries[%d]:  (%d, %c)  (%d, %d, %d)\n", k, dfa.entries[k].key_state, dfa.entries[k].key_unit, 
			dfa.entries[k].value_state, dfa.entries[k].value_flag, dfa.entries[k].fp__rule_index);
    }

	struct port_map_key key;
	key.src_port = src;
	key.dst_port = dst;

	// no mapa de portas, cria a chave com base nas duas portas, o valor é o índice no mapa global
    if (bpf_map_update_elem(port_map_fd, &key, index, BPF_ANY) < 0) {
        fprintf(stderr,
            "ERROR: Failed to update bpf map file: err(%d):%s\n",
            errno, strerror(errno));
        return -1;
    }

    // pega o mapa correto e adiciona o DFA recém criado
    sprintf(map_name, "ids_map%d", *index);
    printf("\nColocando esse automato no mapa %s\n", map_name);
    int ids_map_fd = open_bpf_map_file(pin_dir, map_name, NULL);
    if (ids_map_fd < 0) {
        fprintf(stderr,
            "ERROR: Failed to open bpf ids map: err(%d):%s\n",
            errno, strerror(errno));
        return -1;
    }
    if (dfa2map(ids_map_fd, &dfa) < 0) {
        fprintf(stderr,
            "ERROR: Failed to put dfa on ids map: err(%d):%s\n",
            errno, strerror(errno));
        return -1;
    }
	free(dfa.entries);
    return 0;
}

// criar um port_group para cada linha do arquivo
struct port_group_t** create_port_groups(const char* rules_file, int* n_pgs, int global_map_fd, int port_map_fd){
	char line[1024];
	FILE *file;
	char* token, *aux_token;
	char* inner_token, *aux_inner_token, *src_port, *dst_port;
	char* subtoken, *aux_subtoken;
	struct port_group_t* current_port_group;
	struct rule_t* rule;
	int rule_index = 0, pgs_index = 0;
	uint64_t fast_pattern;
	uint32_t sid;
	int M = 500;
	int N = 500;
	struct dfa_struct per_rule_dfa;

	struct fast_p fast_patterns_array[300];
	size_t index_fp = 0;

	char* rule_contents[600];
	int index_rule_contents = 0;

	file = fopen(rules_file, "r");
	if (file == NULL) {
		printf("Error opening file!\n");
		return NULL;
	}
	struct port_group_t** port_groups = (struct port_group_t**)malloc(sizeof(struct port_group_t*)*M);

	while(fgets(line, 1024, file)){
		token = __strtok_r(line, "~", &aux_token);  // these are the src and dst ports
		current_port_group = (struct port_group_t*)malloc(sizeof(struct port_group_t));

		if(pgs_index >= M){
			M = M + 100;
			current_port_group->rules = (struct rule_t**)realloc(current_port_group->rules, sizeof(struct rule_t*)*M);
		}

    	current_port_group->n_rules = 0;
		inner_token = __strtok_r(token, ";", &aux_inner_token);
		src_port = inner_token;
		if(strcmp(src_port, "any") == 0)
			current_port_group->src_port = 0;
		else
			current_port_group->src_port = atoi(src_port);
		inner_token = __strtok_r(NULL, ";", &aux_inner_token);
    	dst_port = inner_token;
		if(strcmp(dst_port, "any") == 0)
			current_port_group->dst_port = 0;
		else
			current_port_group->dst_port = atoi(dst_port);

		current_port_group->rules = (struct rule_t**)malloc(sizeof(struct rule_t*)*N);

		token = __strtok_r(NULL, "~", &aux_token);

		while(token != NULL){  // start to parse the actual rules
			// Needs to realloc
			if (current_port_group->n_rules >= N){
				N = N + 50;
				current_port_group->rules = (struct rule_t**)realloc(current_port_group->rules, sizeof(struct rule_t*)*N);
			}

			rule = (struct rule_t*)malloc(sizeof(struct rule_t));

			inner_token = __strtok_r(token, ";", &aux_inner_token);

			// add fp in array
			fast_patterns_array[index_fp].fp = inner_token;

			fast_pattern = hash((unsigned char*)inner_token);
			inner_token = __strtok_r(NULL, ";", &aux_inner_token);
      		check_end_line(inner_token);  // remove '\n'
			sid = atoi(inner_token);

			rule->fast_pattern = fast_pattern;
			rule->sid = sid;

			inner_token = __strtok_r(NULL, ";", &aux_inner_token);
			if(inner_token){
			
				subtoken = __strtok_r(inner_token, ",", &aux_subtoken);
				while(subtoken != NULL){
				check_end_line(subtoken);  // remove '\n'

				// regular_patterns_array[index_rp++] = subtoken;

				rule_contents[index_rule_contents++] = subtoken;
				subtoken = __strtok_r(NULL, ",", &aux_subtoken);
				}
				rule->n_contents++;
			}
			else{
				rule->n_contents = 0;
			}

			// aqui, já tenho todos os contents da regra no vetor rule_contents (vetor de strings)
			// preencher o automato pra esses contents
			if(index_rule_contents > 0){
				str2dfa__to_contents(rule_contents, index_rule_contents, &per_rule_dfa);
				// settar o automato na regra
				create_dfa_per_rule(rule, &per_rule_dfa);
				free(per_rule_dfa.entries);
			}
			fast_patterns_array[index_fp].idx = rule_index;
			index_fp++;

			current_port_group->rules[rule_index] = rule;
			
			rule_index++;
			current_port_group->n_rules++;
			index_rule_contents = 0;

			token = __strtok_r(NULL, "~", &aux_token);
		}
    	port_groups[pgs_index] = current_port_group;
  		rule_index = 0;

        if (initialize_fast_pattern_port_group_map(port_map_fd, &pgs_index, current_port_group->src_port,
                current_port_group->dst_port, fast_patterns_array, index_fp) < 0) {
            fprintf(stderr,
                "WARN: Failed to update bpf map file: err(%d):%s\n",
                errno, strerror(errno));
            return NULL;
        }
		pgs_index++;
		index_fp = 0;

	}
	// py_finalize();
    fclose(file);
	*n_pgs = pgs_index;
	return port_groups;
}

void destroy_port_groups(struct protocol_port_groups_t* protocol_port_group){
	for(ssize_t i = 0; i < protocol_port_group->n_port_groups; i++){
		for (ssize_t j = 0; j < protocol_port_group->port_groups_array[i]->n_rules; j++){
			if(protocol_port_group->port_groups_array[i]->rules[j]->n_contents > 0)
				free_hash(protocol_port_group->port_groups_array[i]->rules[j]);
			free(protocol_port_group->port_groups_array[i]->rules[j]);
		}
        free(protocol_port_group->port_groups_array[i]->rules);
		free(protocol_port_group->port_groups_array[i]);
	}
	free(protocol_port_group->port_groups_array);
}

// void fill_userspace_dfa(struct ids_inspect_map_value* ids_inspect_array, struct dfa_struct *dfa){
// 	struct dfa_entry *map_entries = dfa->entries;
// 	struct ids_inspect_map_key ids_map_key;
// 	memset(ids_inspect_array, 0, sizeof(IDS_INSPECT_ARRAY_SIZE));
// 	uint32_t array_index;
// 	uint32_t i_entry, n_entry = dfa->entry_number;
// 	for (i_entry = 0; i_entry < n_entry; i_entry++) {
// 		ids_map_key.state = map_entries[i_entry].key_state;
// 		ids_map_key.unit = map_entries[i_entry].key_unit;
// 		array_index = *(uint32_t *)&ids_map_key;
// 		ids_inspect_array[array_index].state = map_entries[i_entry].value_state;
// 		ids_inspect_array[array_index].flag = map_entries[i_entry].value_flag;
// 	}
// }

int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg, const char* pin_basedir)
{
	char map_filename[1024];
	int err, len;

	len = snprintf(map_filename, 1024, "%s/%s/%s",
		       pin_basedir, cfg->ifname, "map_name");
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAIL_OPTION;
	}

	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK ) != -1 ) {
		if (verbose)
			printf(" - Unpinning (remove) prev maps in %s/\n",
			       cfg->pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, cfg->pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", cfg->pin_dir);
			return EXIT_FAIL_BPF;
		}
	}
	if (verbose)
		printf(" - Pinning maps in %s/\n", cfg->pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, cfg->pin_dir);
	if (err)
		return EXIT_FAIL_BPF;

	return 0;
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


    // inicia as estruturas BTF
    int err = init_btf_info_via_bpf_object(bpf_obj, &xdp_hints_mark);
	if (err) {
		fprintf(stderr, "ERROR(%d): Invalid BTF info: errno:%s\n",
			err, strerror(errno));
		return EXIT_FAILURE;
	}

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

    int tcp_port_map_fd = open_bpf_map_file(pin_dir, "tcp_port_map", NULL);
	if (tcp_port_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	int udp_port_map_fd = open_bpf_map_file(pin_dir, "udp_port_map", NULL);
	if (udp_port_map_fd < 0){
		return EXIT_FAIL_BPF;
	}

    int global_map_fd = open_bpf_map_file(pin_dir, "global_map", NULL);
	if (global_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	int tcp_num_port_groups;
	struct protocol_port_groups_t tcp_port_groups;
    const char* tcp_fast_patterns_with_sid_file_name = "./patterns/tcp-fp_with_sid.txt";
	tcp_port_groups.port_groups_array = create_port_groups(tcp_fast_patterns_with_sid_file_name, &tcp_num_port_groups,
        global_map_fd, tcp_port_map_fd);
    if (!tcp_port_groups.port_groups_array ) {
		return EXIT_FAIL_BPF;
	}
    tcp_port_groups.n_port_groups = tcp_num_port_groups;




    /* --- In this moment, every possible DFA has been filled --- */

    /* We also need to load the xsks_map */
    map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
    // xsks_map_fd = open_bpf_map_file(pin_dir, "xsks_map", NULL);
    xsks_map_fd = bpf_map__fd(map);
    if (xsks_map_fd < 0) {
        fprintf(stderr, "ERROR: no xsks map found: %s\n",
            strerror(xsks_map_fd));
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

    // this function configures UMEMs and XSKs
    if(!af_xdp_init(umems, xsk_sockets, n_queues, &cfg)){
        printf("Tudo certo!!\n");
    }

    /* fill xsks map */
    enter_xsks_into_map(xsks_map_fd, xsk_sockets, n_queues);

    rx_and_process(&cfg, xsk_sockets, n_queues);

    /* Cleanup */
	for (int i_queue = 0; i_queue < n_queues; i_queue++) {
		xsk_socket__delete(xsk_sockets[i_queue]->xsk);
		xsk_umem__delete(umems[i_queue]->umem);
	}
    free(umems);
    free(xsk_sockets);
    destroy_port_groups(&tcp_port_groups);
    xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

    return 0;
}