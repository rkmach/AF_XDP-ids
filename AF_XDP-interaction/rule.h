#ifndef RULE_H
#define RULE_H

#include <stdint.h>
#include <unistd.h>
#include "hashmap.h"

struct fast_p {
	char* fp;
	uint32_t idx;
};

struct rule_t {
    uint64_t fast_pattern;  // fast pattern hash
    // char contents[10];  // arrays of hashes, representing the contents of the rule
    ssize_t n_contents;     // number of elements in the array
    uint32_t sid;           // rule signature id
    // struct dfa_struct* ac_entries;
    struct hashmap dfa;
};

uint64_t hash(unsigned char *str);  // djb2 hash algorithm

#endif