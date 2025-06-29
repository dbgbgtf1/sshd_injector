#ifndef ASSEMBLE
#define ASSEMBLE

#include <stddef.h>
#include <stdint.h>

uint8_t *assemble (char *text);
void free_ks (unsigned char *encode);

#endif
