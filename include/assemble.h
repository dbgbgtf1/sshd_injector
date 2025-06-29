#ifndef ASSEMBLE
#define ASSEMBLE

#include <stddef.h>
#include <stdint.h>

uint8_t *assemble (char *text, uint64_t *count);
void free_ks (unsigned char *encode);

#endif
