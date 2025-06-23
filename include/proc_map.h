#ifndef ELF_BASE
#define ELF_BASE

#include <stdint.h>
#include <sys/mman.h>

uint64_t parse_maps (uint32_t pid, char *flag);

#endif
