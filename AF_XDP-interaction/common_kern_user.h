/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

/* IDS Inspect Unit */
typedef __u8 ids_inspect_unit;
// struct ids_inspect_unit {
	// __u8 unit[IDS_INSPECT_STRIDE];
// };

/* IDS Inspect State */
typedef __u16 ids_inspect_state;

/* Accept state flag */
typedef __u16 accept_state_flag;

/* Alias for TCP / UDP ports */
typedef __u16 src_port_t;
typedef __u16 dst_port_t;

struct port_map_key {
	src_port_t src_port;
	dst_port_t dst_port;
};

/* Key-Value of ids_inspect_map */
struct ids_inspect_map_key {
	ids_inspect_state state;
	ids_inspect_unit unit;
	__u8 padding;  /* this padding is mandatory because values must be 32-bit sized when using BPF_MAP_TYPE_ARRAYBPF_MAP_TYPE_ARRAY */
};

struct ids_inspect_map_value {
	ids_inspect_state state;
	accept_state_flag flag;
};

#endif /* __COMMON_KERN_USER_H */
