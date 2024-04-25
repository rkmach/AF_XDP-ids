#ifndef RULE_H
#define RULE_H

#include <stdint.h>
#include <unistd.h>

struct rule_t {
    uint64_t fast_pattern;  // fast pattern hash
    uint64_t contents[10];  // arrays of hashes, representing the contents of the rule
    ssize_t n_contents;     // number of elements in the array
    uint32_t sid;           // rule signature id
};

uint64_t hash(unsigned char *str);  // djb2 hash algorithm

#endif