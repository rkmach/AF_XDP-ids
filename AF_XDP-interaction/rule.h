#ifndef RULE_H
#define RULE_H

#include <stdint.h>
#include <unistd.h>
#include "aho-corasick.h"

struct fast_p {
	char* fp;
	uint32_t idx;
};

struct rule_t {
    ssize_t n_contents;     // number of elements in the array
    uint32_t sid;           // rule signature id
    struct ac_root dfa;
};

uint64_t hash(unsigned char *str);  // djb2 hash algorithm

#endif