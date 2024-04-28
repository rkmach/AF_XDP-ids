#ifndef _STR2DFA_H
#define _STR2DFA_H

#include "rule.h"

struct dfa_struct {
	uint32_t entry_number;
	struct dfa_entry *entries;
};

struct dfa_entry {
	uint16_t key_state;
	uint8_t key_unit;
	uint16_t value_state;
	uint16_t value_flag;
	int16_t fp__rule_index;
};

struct port_group_t {
	uint16_t src_port;
	uint16_t dst_port;

	ssize_t n_rules;
	struct rule_t** rules;
	
	struct dfa_struct* dfa;
	uint32_t global_map_index;  // isso aqui é o índice do dfa no mapa de dfas
};

struct protocol_port_groups_t {
	struct port_group_t** port_groups_array;
	ssize_t n_port_groups;
};

int str2dfa(struct fast_p* , size_t, struct dfa_struct *);
int str2dfa__to_contents(char** , size_t, struct dfa_struct *);

#endif
